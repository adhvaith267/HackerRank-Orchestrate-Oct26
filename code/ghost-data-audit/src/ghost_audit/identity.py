"""
identity.py — Identity resolution engine for ghost-data-audit.

Provides:
  - normalize_email(raw) -> str
  - EdgeType enum
  - IdentityEdge dataclass
  - IdentityGraph class
  - AmbiguityKind enum
  - AmbiguityRecord dataclass
  - IdentityResolution dataclass
  - IdentityLoader class
  - IdentityResolver class

Resolution algorithm (see resolve() docstring):
  1. Normalize email (NFC casefold, no dot/plus stripping)
  2. Match current email index -> 'current'
  3. Match historical email index -> 'historical' (with reuse detection)
  4. Fallback: SHA-256(normalized_email) against hash index -> 'hash'
  5. Build alias list from identities + audit log
  6. Detect contradictory timestamps, cycles, ambiguities
  7. Populate citations

Constraints:
  - Never merge users on name similarity, email substring, or phone fragment
  - Do not strip dots or plus-signs from emails
  - Do not use LLM for identity links
  - Never synthesize a source_row_id
  - Logs must not emit raw emails; use user_id and match_type only
"""

from __future__ import annotations

import csv
import hashlib
import logging
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from .schemas import IdentifierType, IdentityAlias, _parse_utc

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 1. Email normalization
# ---------------------------------------------------------------------------

def normalize_email(raw: str) -> str:
    """
    Return the canonical form of an email address.

    - Strip leading/trailing whitespace
    - Apply Unicode NFC normalization
    - Casefold (locale-independent lowercase)
    - No dot-stripping, no plus-stripping (provider-specific, must not be assumed)
    - Never mutates the raw value
    """
    return unicodedata.normalize("NFC", raw.strip()).casefold()


# ---------------------------------------------------------------------------
# 2. EdgeType enum
# ---------------------------------------------------------------------------

class EdgeType(str, Enum):
    """Typed edge labels for the identity graph."""
    CURRENT_EMAIL = "CURRENT_EMAIL"
    FORMER_EMAIL = "FORMER_EMAIL"
    CURRENT_PHONE = "CURRENT_PHONE"
    FORMER_PHONE = "FORMER_PHONE"
    CURRENT_EMAIL_HASH = "CURRENT_EMAIL_HASH"
    FORMER_EMAIL_HASH = "FORMER_EMAIL_HASH"
    USER_ID = "USER_ID"
    ACCOUNT_ID = "ACCOUNT_ID"
    EXTERNAL_CUSTOMER_ID = "EXTERNAL_CUSTOMER_ID"


# ---------------------------------------------------------------------------
# 3. IdentityEdge dataclass
# ---------------------------------------------------------------------------

@dataclass
class IdentityEdge:
    """A typed edge connecting an identifier to a user_id."""
    edge_type: EdgeType
    from_node: str          # identifier value
    to_node: str            # user_id or another identifier
    source_file: str        # e.g. 'user_identities.csv'
    source_row_id: str      # e.g. 'user_01' or 'audit_05'
    valid_from: Optional[datetime]   # UTC, None if unknown
    valid_until: Optional[datetime]  # UTC, None if still current
    is_current: bool


# ---------------------------------------------------------------------------
# 4. IdentityGraph
# ---------------------------------------------------------------------------

class IdentityGraph:
    """
    Bi-directional adjacency structure for identity edges.

    Internally stores:
      _user_to_edges: user_id -> List[IdentityEdge]   (edges from user)
      _identifier_to_users: identifier -> List[user_id]  (reverse index)
    """

    def __init__(self) -> None:
        self._user_to_edges: Dict[str, List[IdentityEdge]] = {}
        self._identifier_to_users: Dict[str, List[str]] = {}
        self._all_edges: List[IdentityEdge] = []

    def add_edge(self, edge: IdentityEdge) -> None:
        """Add an edge to the graph."""
        self._all_edges.append(edge)
        # Index edge under user (to_node is always the user_id for our edges)
        user_id = edge.to_node
        self._user_to_edges.setdefault(user_id, []).append(edge)
        # Reverse index: identifier -> [user_ids]
        identifier = edge.from_node
        uids = self._identifier_to_users.setdefault(identifier, [])
        if user_id not in uids:
            uids.append(user_id)

    def get_user_id_for(self, identifier: str) -> List[str]:
        """
        Return all user_ids associated with this identifier.
        A list with >1 element indicates identifier reuse.
        """
        return list(self._identifier_to_users.get(identifier, []))

    def get_edges_for_user(self, user_id: str) -> List[IdentityEdge]:
        """Return all edges associated with a user_id."""
        return list(self._user_to_edges.get(user_id, []))

    def all_identifiers_for_user(
        self, user_id: str, at: Optional[datetime] = None
    ) -> Set[str]:
        """
        Return all identifier values linked to the user.

        If at is provided, only include identifiers whose time window covers
        that timestamp (valid_from <= at and (valid_until is None or valid_until > at)).
        Current identifiers (valid_until=None) are always included unless
        at-filtering reveals they weren't yet valid.
        """
        result: Set[str] = set()
        for edge in self._user_to_edges.get(user_id, []):
            if at is not None:
                # Filter: valid_from must be <= at (None means unknown/always)
                if edge.valid_from is not None and edge.valid_from > at:
                    continue
                # Filter: valid_until must be > at for non-current (None means still current)
                if not edge.is_current and edge.valid_until is not None:
                    if edge.valid_until <= at:
                        continue
            result.add(edge.from_node)
        return result

    def detect_reused_emails(self) -> Dict[str, List[str]]:
        """
        Return a mapping of normalized email -> [user_ids] for any email
        that maps to more than one distinct user_id (current or former).
        """
        reused: Dict[str, List[str]] = {}
        email_edge_types = {
            EdgeType.CURRENT_EMAIL, EdgeType.FORMER_EMAIL
        }
        # Build email -> set of user_ids
        email_to_users: Dict[str, Set[str]] = {}
        for edge in self._all_edges:
            if edge.edge_type in email_edge_types:
                email_to_users.setdefault(edge.from_node, set()).add(edge.to_node)
        for email, user_set in email_to_users.items():
            if len(user_set) > 1:
                reused[email] = sorted(user_set)
        return reused

    def detect_cycles(self) -> List[List[str]]:
        """
        Detect cycles via DFS walking user -> identifier -> user paths.

        A cycle occurs when following identifier links from a user leads back
        to the same user or creates a loop through multiple users.

        Returns a list of cycle paths (each path is a list of node IDs).
        Only true structural cycles are reported (not normal bidirectional edges).
        """
        cycles: List[List[str]] = []
        visited_users: Set[str] = set()

        def dfs(user_id: str, path: List[str], visited: Set[str]) -> None:
            if user_id in visited:
                # Found a cycle: extract the cycle portion
                cycle_start = path.index(user_id)
                cycle = path[cycle_start:]
                # Avoid reporting the same cycle multiple times
                cycle_sorted = sorted(cycle)
                if cycle_sorted not in [sorted(c) for c in cycles]:
                    cycles.append(cycle + [user_id])
                return
            if user_id in visited_users:
                return  # Already explored from here

            visited = visited | {user_id}
            path = path + [user_id]

            for edge in self._user_to_edges.get(user_id, []):
                # From this identifier, find other users
                other_users = self._identifier_to_users.get(edge.from_node, [])
                for other_uid in other_users:
                    if other_uid != user_id:
                        dfs(other_uid, path, visited)

        for uid in self._user_to_edges:
            if uid not in visited_users:
                dfs(uid, [], set())
                visited_users.add(uid)

        return cycles

    def user_ids(self) -> Set[str]:
        """Return all known user_ids in the graph."""
        return set(self._user_to_edges.keys())


# ---------------------------------------------------------------------------
# 5. AmbiguityKind enum
# ---------------------------------------------------------------------------

class AmbiguityKind(str, Enum):
    """Kinds of identity ambiguity that can be detected."""
    NO_MATCH = "NO_MATCH"
    REUSED_EMAIL = "REUSED_EMAIL"
    CONFLICTING_HISTORY = "CONFLICTING_HISTORY"
    CYCLE_DETECTED = "CYCLE_DETECTED"
    MULTIPLE_USERS_SAME_HASH = "MULTIPLE_USERS_SAME_HASH"
    MISSING_USER_ID = "MISSING_USER_ID"
    CONTRADICTORY_TIMESTAMPS = "CONTRADICTORY_TIMESTAMPS"


# ---------------------------------------------------------------------------
# 7. AmbiguityRecord dataclass (defined before IdentityResolution uses it)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AmbiguityRecord:
    """A record of an identity ambiguity (no PII in description)."""
    kind: AmbiguityKind
    description: str   # no PII
    citations: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# 6. IdentityResolution dataclass
# ---------------------------------------------------------------------------

@dataclass
class IdentityResolution:
    """
    Result of resolving a request email to a known user.

    input_email is stored for provenance only and must never be logged.
    Use user_id and match_type for any logging.
    """

    input_email: str              # raw (for provenance only, never logged)
    normalized_email: str         # normalize_email(input_email)
    user_id: Optional[str]        # stable internal reference
    match_type: str               # 'current'|'historical'|'hash'|'direct'|'none'
    aliases: List[IdentityAlias] = field(default_factory=list)
    ambiguities: List[AmbiguityRecord] = field(default_factory=list)
    citations: List[str] = field(default_factory=list)

    @property
    def found(self) -> bool:
        """True when a user was resolved."""
        return self.user_id is not None

    @property
    def all_emails(self) -> List[str]:
        """All known email values (current and historical)."""
        return [
            a.value
            for a in self.aliases
            if a.identifier_type == IdentifierType.EMAIL
        ]

    @property
    def all_email_hashes(self) -> List[str]:
        """All known email hash values."""
        return [
            a.value
            for a in self.aliases
            if a.identifier_type == IdentifierType.EMAIL_HASH
        ]

    @property
    def all_phones(self) -> List[str]:
        """All known phone values (current and historical)."""
        return [
            a.value
            for a in self.aliases
            if a.identifier_type == IdentifierType.PHONE
        ]

    @property
    def all_identifiers(self) -> Set[str]:
        """All identifier values (emails, hashes, phones) plus user_id as a set."""
        vals: Set[str] = set()
        for a in self.aliases:
            vals.add(a.value)
        if self.user_id:
            vals.add(self.user_id)
        return vals

    @property
    def is_ambiguous(self) -> bool:
        """True when any ambiguity record is present."""
        return len(self.ambiguities) > 0


# ---------------------------------------------------------------------------
# 8. IdentityLoader
# ---------------------------------------------------------------------------

class IdentityLoader:
    """
    Static factory to load identity data from CSV files.
    """

    # Expected columns for validation / warnings
    _IDENTITY_COLS = {"user_id", "name", "email", "phone", "email_hash", "updated_at"}
    _AUDIT_COLS = {"audit_id", "user_id", "event_time", "field_name", "old_value", "new_value"}

    @staticmethod
    def from_csv_paths(
        identities_path: Path,
        audit_log_path: Path,
    ) -> Tuple[Dict[str, Dict], List[Dict]]:
        """
        Load user_identities.csv and user_audit_log.csv.

        Parameters
        ----------
        identities_path:
            Path to user_identities.csv
        audit_log_path:
            Path to user_audit_log.csv

        Returns
        -------
        (identities, audit_log) where:
          identities: Dict[user_id, row_dict]
          audit_log: List[row_dict]
        """
        identities: Dict[str, Dict] = {}
        audit_log: List[Dict] = []

        # Load identities
        try:
            with open(identities_path, newline="", encoding="utf-8") as fh:
                reader = csv.DictReader(fh)
                if reader.fieldnames:
                    missing_cols = IdentityLoader._IDENTITY_COLS - set(reader.fieldnames)
                    if missing_cols:
                        logger.warning(
                            "user_identities.csv missing columns: %s", missing_cols
                        )
                for row in reader:
                    # Skip blank rows
                    if not any(v.strip() for v in row.values() if v):
                        continue
                    uid = row.get("user_id", "").strip()
                    if not uid:
                        logger.warning("Skipping identity row with missing user_id")
                        continue
                    identities[uid] = dict(row)
        except FileNotFoundError:
            logger.warning("user_identities.csv not found at %s", identities_path)
        except Exception as exc:
            logger.error("Error loading user_identities.csv: %s", exc)

        # Load audit log
        try:
            with open(audit_log_path, newline="", encoding="utf-8") as fh:
                reader = csv.DictReader(fh)
                if reader.fieldnames:
                    missing_cols = IdentityLoader._AUDIT_COLS - set(reader.fieldnames)
                    if missing_cols:
                        logger.warning(
                            "user_audit_log.csv missing columns: %s", missing_cols
                        )
                for row in reader:
                    # Skip blank rows
                    if not any(v.strip() for v in row.values() if v):
                        continue
                    audit_log.append(dict(row))
        except FileNotFoundError:
            logger.warning("user_audit_log.csv not found at %s", audit_log_path)
        except Exception as exc:
            logger.error("Error loading user_audit_log.csv: %s", exc)

        return identities, audit_log


# ---------------------------------------------------------------------------
# 9. IdentityResolver
# ---------------------------------------------------------------------------

class IdentityResolver:
    """
    Resolves an email address to a user_id and builds the full alias set.

    Construction is O(N) in the size of identities and audit_log;
    lookups are O(1) via pre-built indexes.

    Parameters
    ----------
    identities:
        Dict[user_id, row_dict] as returned by IdentityLoader.from_csv_paths()
    audit_log:
        List[row_dict] as returned by IdentityLoader.from_csv_paths()
    dataset_root:
        String prefix used for provenance source_file fields.
    """

    def __init__(
        self,
        identities: Dict[str, Dict],
        audit_log: List[Dict],
        dataset_root: str = "dataset",
    ) -> None:
        self._identities = identities
        self._audit_log = audit_log
        self._dataset_root = dataset_root

        # Index: normalized current email -> user_id
        self._email_to_uid: Dict[str, str] = {}
        self._email_to_uids: Dict[str, Set[str]] = {}
        # Index: current email_hash (lower) -> user_id
        self._hash_to_uid: Dict[str, str] = {}
        self._hash_to_uids: Dict[str, Set[str]] = {}
        # Index: normalized historical email -> List[(user_id, audit_row)]
        self._hist_email_to_uid: Dict[str, List[Tuple[str, Dict]]] = {}
        # Index: user_id -> List of audit rows (sorted by event_time asc)
        self._uid_audit_rows: Dict[str, List[Dict]] = {}

        # Lazy-built identity graph
        self._graph: Optional[IdentityGraph] = None

        self._build_indexes()

    # ------------------------------------------------------------------
    # Index construction
    # ------------------------------------------------------------------

    def _build_indexes(self) -> None:
        """Build all lookup indexes from identities and audit log."""
        for uid, row in self._identities.items():
            raw_email = row.get("email", "")
            if raw_email:
                norm = normalize_email(raw_email)
                self._email_to_uid[norm] = uid
                self._email_to_uids.setdefault(norm, set()).add(uid)
            eh = (row.get("email_hash") or "").strip().lower()
            if eh:
                self._hash_to_uid[eh] = uid
                self._hash_to_uids.setdefault(eh, set()).add(uid)

        for entry in self._audit_log:
            uid = entry.get("user_id", "").strip()
            if not uid:
                continue
            self._uid_audit_rows.setdefault(uid, []).append(entry)
            field_name = entry.get("field_name", "")
            if field_name == "email":
                old_val = entry.get("old_value", "")
                if old_val:
                    norm = normalize_email(old_val)
                    self._hist_email_to_uid.setdefault(norm, []).append((uid, entry))

        # Sort audit rows per user by event_time ascending
        for uid in self._uid_audit_rows:
            try:
                self._uid_audit_rows[uid].sort(
                    key=lambda r: _parse_utc(r["event_time"])
                )
            except Exception:
                pass  # keep original order on parse failure

    # ------------------------------------------------------------------
    # Graph construction
    # ------------------------------------------------------------------

    def build_graph(self) -> IdentityGraph:
        """
        Build and return the IdentityGraph from all loaded identity data.
        Result is cached on the resolver instance.
        """
        if self._graph is not None:
            return self._graph

        graph = IdentityGraph()

        for uid, row in self._identities.items():
            source_file = f"{self._dataset_root}/user_identities.csv"

            # User ID self-edge
            graph.add_edge(IdentityEdge(
                edge_type=EdgeType.USER_ID,
                from_node=uid,
                to_node=uid,
                source_file=source_file,
                source_row_id=uid,
                valid_from=None,
                valid_until=None,
                is_current=True,
            ))

            raw_email = row.get("email", "")
            if raw_email:
                graph.add_edge(IdentityEdge(
                    edge_type=EdgeType.CURRENT_EMAIL,
                    from_node=normalize_email(raw_email),
                    to_node=uid,
                    source_file=source_file,
                    source_row_id=uid,
                    valid_from=None,
                    valid_until=None,
                    is_current=True,
                ))

            eh = (row.get("email_hash") or "").strip().lower()
            if eh:
                graph.add_edge(IdentityEdge(
                    edge_type=EdgeType.CURRENT_EMAIL_HASH,
                    from_node=eh,
                    to_node=uid,
                    source_file=source_file,
                    source_row_id=uid,
                    valid_from=None,
                    valid_until=None,
                    is_current=True,
                ))

            phone = row.get("phone", "")
            if phone:
                graph.add_edge(IdentityEdge(
                    edge_type=EdgeType.CURRENT_PHONE,
                    from_node=phone,
                    to_node=uid,
                    source_file=source_file,
                    source_row_id=uid,
                    valid_from=None,
                    valid_until=None,
                    is_current=True,
                ))

        # Historical from audit log
        audit_source = f"{self._dataset_root}/user_audit_log.csv"
        for uid, audit_rows in self._uid_audit_rows.items():
            for i, row in enumerate(audit_rows):
                field_name = row.get("field_name", "")
                old_val = row.get("old_value", "")
                if not old_val:
                    continue

                event_time = None
                try:
                    event_time = _parse_utc(row["event_time"])
                except Exception:
                    pass

                # valid_until is when the old value was replaced = this event_time
                # valid_from would be the previous event_time for same field
                valid_from: Optional[datetime] = None
                valid_until: Optional[datetime] = event_time

                # Find previous change for same field to get valid_from
                for prev_row in reversed(audit_rows[:i]):
                    if prev_row.get("field_name") == field_name:
                        try:
                            valid_from = _parse_utc(prev_row["event_time"])
                        except Exception:
                            pass
                        break

                edge_type_map = {
                    "email": EdgeType.FORMER_EMAIL,
                    "email_hash": EdgeType.FORMER_EMAIL_HASH,
                    "phone": EdgeType.FORMER_PHONE,
                }
                edge_type = edge_type_map.get(field_name)
                if edge_type is None:
                    continue

                # Normalize email/hash values
                if field_name in ("email", "email_hash"):
                    old_val = old_val.strip().lower()
                    if field_name == "email":
                        old_val = normalize_email(old_val)

                graph.add_edge(IdentityEdge(
                    edge_type=edge_type,
                    from_node=old_val,
                    to_node=uid,
                    source_file=audit_source,
                    source_row_id=row.get("audit_id", ""),
                    valid_from=valid_from,
                    valid_until=valid_until,
                    is_current=False,
                ))

        self._graph = graph
        return graph

    # ------------------------------------------------------------------
    # Public resolution API
    # ------------------------------------------------------------------

    def resolve(
        self,
        email: str,
        audit_at: Optional[datetime] = None,
    ) -> IdentityResolution:
        """
        Resolve an email address to a user_id and full alias set.

        Algorithm:
          1. Normalize email (NFC casefold).
          2. Look up in current email index. If found and unique -> 'current'.
          3. Look up in historical email index:
             a. One user -> 'historical'
             b. Multiple users -> REUSED_EMAIL ambiguity; pick most-recent
          4. Fallback: SHA-256(normalized_email) in hash index -> 'hash'
          5. Build alias list from identities + audit log
          6. Detect contradictory timestamps, cycles, ambiguities
          7. Populate citations

        Parameters
        ----------
        email:
            Raw email address from the deletion request.
        audit_at:
            Evidence cutoff. When provided, historical alias validity is
            checked against this timestamp.

        Returns
        -------
        IdentityResolution
        """
        norm_email = normalize_email(email)
        ambiguities: List[AmbiguityRecord] = []
        citations: List[str] = []
        match_type = "none"
        uid: Optional[str] = None

        # --- Step 2: Current email lookup ---
        current_uids = self._email_to_uids.get(norm_email, set())
        if len(current_uids) > 1:
            return IdentityResolution(
                input_email=email, normalized_email=norm_email, user_id=None,
                match_type="none", aliases=[],
                ambiguities=[AmbiguityRecord(
                    kind=AmbiguityKind.REUSED_EMAIL,
                    description="Current email maps to multiple users",
                    citations=sorted(current_uids),
                )], citations=sorted(current_uids),
            )
        uid = next(iter(current_uids), None)
        if uid is not None:
            match_type = "current"
            id_row = self._identities.get(uid, {})
            citations.append(uid)
            # Validate time: updated_at <= audit_at (current identity is valid at cutoff)
            if audit_at is not None:
                updated_raw = id_row.get("updated_at", "")
                if updated_raw:
                    try:
                        updated_at = _parse_utc(updated_raw)
                        if updated_at > audit_at:
                            # The identity was updated after the audit cutoff — treat as historical
                            match_type = "historical"
                    except Exception:
                        pass

        # --- Step 3: Historical email lookup ---
        if uid is None:
            hist_candidates = self._hist_email_to_uid.get(norm_email, [])
            if hist_candidates:
                # Deduplicate by user_id; track citations
                seen_uids: Dict[str, Dict] = {}
                for cand_uid, audit_row in hist_candidates:
                    if cand_uid not in seen_uids:
                        seen_uids[cand_uid] = audit_row
                    # Keep the audit row with the latest event_time (most recent change)
                    else:
                        try:
                            existing_time = _parse_utc(seen_uids[cand_uid]["event_time"])
                            new_time = _parse_utc(audit_row["event_time"])
                            if new_time > existing_time:
                                seen_uids[cand_uid] = audit_row
                        except Exception:
                            pass

                if len(seen_uids) == 1:
                    uid = next(iter(seen_uids))
                    match_type = "historical"
                    audit_row = seen_uids[uid]
                    citations.append(audit_row.get("audit_id", ""))
                    # Check valid_at: was this email still the user's email at audit_at?
                    if audit_at is not None:
                        try:
                            event_time = _parse_utc(audit_row["event_time"])
                            # valid_until = event_time (when the email was replaced)
                            # The historical email was valid *before* event_time
                            if event_time <= audit_at:
                                # Email was already replaced by audit_at — still a historical match
                                pass
                        except Exception:
                            pass

                elif len(seen_uids) > 1:
                    # REUSED_EMAIL: pick the one with the most recent valid activity
                    best_uid: Optional[str] = None
                    best_time: Optional[datetime] = None
                    for cand_uid, audit_row in seen_uids.items():
                        try:
                            t = _parse_utc(audit_row["event_time"])
                            if best_time is None or t > best_time:
                                best_time = t
                                best_uid = cand_uid
                        except Exception:
                            pass

                    if best_uid is None:
                        best_uid = next(iter(seen_uids))

                    uid = best_uid
                    match_type = "historical"
                    for cand_uid, audit_row in seen_uids.items():
                        aid = audit_row.get("audit_id", "")
                        if aid:
                            citations.append(aid)

                    ambiguities.append(AmbiguityRecord(
                        kind=AmbiguityKind.REUSED_EMAIL,
                        description=(
                            f"Email resolved to {len(seen_uids)} users via historical records; "
                            f"selected user with most recent change"
                        ),
                        citations=list(citations),
                    ))
                    logger.warning(
                        "REUSED_EMAIL: normalized email maps to %d users via history; "
                        "selected user_id=%s (most recent)",
                        len(seen_uids), uid,
                    )

        # --- Step 4: SHA-256 hash fallback ---
        if uid is None:
            # DATA_DISCOVERY.md §2.4 confirms: SHA-256 of lowercase email
            email_hash = hashlib.sha256(norm_email.encode("utf-8")).hexdigest()
            hash_uids = self._hash_to_uids.get(email_hash, set())
            if len(hash_uids) > 1:
                return IdentityResolution(
                    input_email=email, normalized_email=norm_email, user_id=None,
                    match_type="none", aliases=[],
                    ambiguities=[AmbiguityRecord(
                        kind=AmbiguityKind.MULTIPLE_USERS_SAME_HASH,
                        description="Email hash maps to multiple users",
                        citations=sorted(hash_uids),
                    )], citations=sorted(hash_uids),
                )
            uid = next(iter(hash_uids), None)
            if uid is not None:
                match_type = "hash"
                citations.append(uid)
                logger.debug(
                    "Identity matched via SHA-256 hash: user_id=%s match_type=hash", uid
                )

        # --- No match ---
        if uid is None:
            logger.debug(
                "No identity match: match_type=none"
            )
            return IdentityResolution(
                input_email=email,
                normalized_email=norm_email,
                user_id=None,
                match_type="none",
                aliases=[],
                ambiguities=[AmbiguityRecord(
                    kind=AmbiguityKind.NO_MATCH,
                    description="No user found matching the provided email",
                    citations=[],
                )],
                citations=[],
            )

        # --- Step 5: Build aliases ---
        aliases = self._build_aliases(uid, audit_at)

        # --- Step 6: Detect contradictory timestamps ---
        contradictions = self._detect_contradictory_timestamps(uid)
        ambiguities.extend(contradictions)

        # --- Step 7: Cycle detection ---
        graph = self.build_graph()
        cycles = graph.detect_cycles()
        for cycle_path in cycles:
            if uid in cycle_path:
                ambiguities.append(AmbiguityRecord(
                    kind=AmbiguityKind.CYCLE_DETECTED,
                    description=f"Identity graph cycle detected involving {len(cycle_path)} nodes",
                    citations=[],
                ))
                break

        # Collect all citation source_row_ids from aliases
        for alias in aliases:
            if alias.source_row_id and alias.source_row_id not in citations:
                citations.append(alias.source_row_id)

        return IdentityResolution(
            input_email=email,
            normalized_email=norm_email,
            user_id=uid,
            match_type=match_type,
            aliases=aliases,
            ambiguities=ambiguities,
            citations=citations,
        )

    def resolve_by_user_id(self, user_id: str) -> Optional[IdentityResolution]:
        """
        Resolve directly by user_id.

        Used when evidence matching gives a user_id directly (not via email).
        Returns None if the user_id is not in the identities dict.
        """
        if user_id not in self._identities:
            return None

        identity_row = self._identities[user_id]
        aliases = self._build_aliases(user_id, audit_at=None)

        # Use current email as the representative email for provenance
        raw_email = identity_row.get("email", "")
        norm_email = normalize_email(raw_email) if raw_email else ""

        citations = [alias.source_row_id for alias in aliases if alias.source_row_id]

        return IdentityResolution(
            input_email=raw_email,
            normalized_email=norm_email,
            user_id=user_id,
            match_type="direct",
            aliases=aliases,
            ambiguities=[],
            citations=citations,
        )

    def resolve_case(
        self,
        case,            # has .email, .requested_at, .audit_at
        evidence_index,  # optional, may be None
    ) -> IdentityResolution:
        """
        Resolve a RequestCase to a user identity.

        Calls resolve(case.email, case.audit_at) and also links secondary
        records from evidence_index if not None.

        Parameters
        ----------
        case:
            An object with .email (str), .requested_at (datetime), .audit_at (datetime)
        evidence_index:
            Optional index of evidence facts. If provided, any resource_id that
            matches one of the user's identifiers gets its evidence_id recorded
            in citations.
        """
        audit_at: Optional[datetime] = None
        try:
            audit_at = case.audit_at
        except AttributeError:
            pass

        resolution = self.resolve(case.email, audit_at=audit_at)

        # Secondary linking via evidence_index
        if evidence_index is not None and resolution.found:
            all_ids = resolution.all_identifiers
            try:
                # evidence_index may be a dict or object with various structures
                # Handle dict-like: {file_id: [EvidenceFact, ...]}
                if hasattr(evidence_index, "items"):
                    for file_id, facts in evidence_index.items():
                        if not hasattr(facts, "__iter__"):
                            continue
                        for fact in facts:
                            resource_id = getattr(fact, "resource_id", None)
                            subject_email = getattr(fact, "subject_email", None)
                            subject_uid = getattr(fact, "subject_user_id", None)
                            # Check if this fact links to our user
                            if (
                                resource_id in all_ids
                                or subject_uid == resolution.user_id
                                or (subject_email and normalize_email(subject_email) in {
                                    normalize_email(e) for e in resolution.all_emails
                                })
                            ):
                                evidence_file_id = getattr(fact, "file_id", str(file_id))
                                if evidence_file_id and evidence_file_id not in resolution.citations:
                                    resolution.citations.append(evidence_file_id)
                elif hasattr(evidence_index, "__iter__"):
                    # List of facts
                    for fact in evidence_index:
                        resource_id = getattr(fact, "resource_id", None)
                        subject_uid = getattr(fact, "subject_user_id", None)
                        subject_email = getattr(fact, "subject_email", None)
                        if (
                            resource_id in all_ids
                            or subject_uid == resolution.user_id
                            or (subject_email and normalize_email(subject_email) in {
                                normalize_email(e) for e in resolution.all_emails
                            })
                        ):
                            evidence_file_id = getattr(fact, "file_id", None)
                            if evidence_file_id and evidence_file_id not in resolution.citations:
                                resolution.citations.append(evidence_file_id)
            except Exception as exc:
                logger.debug(
                    "evidence_index secondary linking failed for user_id=%s: %s",
                    resolution.user_id, exc,
                )

        return resolution

    # ------------------------------------------------------------------
    # Alias construction
    # ------------------------------------------------------------------

    def _build_aliases(
        self, user_id: str, audit_at: Optional[datetime]
    ) -> List[IdentityAlias]:
        """Build the complete alias list for a user from identities + audit log."""
        aliases: List[IdentityAlias] = []
        identity_row = self._identities.get(user_id)
        if not identity_row:
            return aliases

        source_file = f"{self._dataset_root}/user_identities.csv"

        # Current email
        raw_email = identity_row.get("email", "")
        if raw_email:
            aliases.append(IdentityAlias(
                user_id=user_id,
                identifier_type=IdentifierType.EMAIL,
                value=normalize_email(raw_email),
                is_current=True,
                valid_from=None,
                valid_until=None,
                source_file=source_file,
                source_row_id=user_id,
            ))

        # Current email_hash
        eh = (identity_row.get("email_hash") or "").strip().lower()
        if eh:
            aliases.append(IdentityAlias(
                user_id=user_id,
                identifier_type=IdentifierType.EMAIL_HASH,
                value=eh,
                is_current=True,
                valid_from=None,
                valid_until=None,
                source_file=source_file,
                source_row_id=user_id,
            ))

        # Current phone
        phone = identity_row.get("phone", "")
        if phone:
            aliases.append(IdentityAlias(
                user_id=user_id,
                identifier_type=IdentifierType.PHONE,
                value=phone,
                is_current=True,
                valid_from=None,
                valid_until=None,
                source_file=source_file,
                source_row_id=user_id,
            ))

        # Historical aliases from audit log
        audit_source = f"{self._dataset_root}/user_audit_log.csv"
        audit_rows = self._uid_audit_rows.get(user_id, [])
        # Already sorted ascending by _build_indexes

        # Track the "next event_time" per field for valid_until calculation
        field_next_change: Dict[str, Optional[datetime]] = {}

        # Process in reverse to compute valid_until correctly
        field_rows: Dict[str, List[Dict]] = {}
        for row in audit_rows:
            fn = row.get("field_name", "")
            if fn in ("email", "email_hash", "phone"):
                field_rows.setdefault(fn, []).append(row)

        for field_name, rows in field_rows.items():
            id_type: Optional[IdentifierType] = None
            if field_name == "email":
                id_type = IdentifierType.EMAIL
            elif field_name == "email_hash":
                id_type = IdentifierType.EMAIL_HASH
            elif field_name == "phone":
                id_type = IdentifierType.PHONE

            if id_type is None:
                continue

            for i, row in enumerate(rows):
                old_val = row.get("old_value", "")
                if not old_val:
                    continue

                audit_id = row.get("audit_id", "")
                event_time: Optional[datetime] = None
                try:
                    event_time = _parse_utc(row["event_time"])
                except Exception:
                    pass

                # valid_until for this historical value = when it was replaced
                valid_until = event_time

                # valid_from = previous event_time for same field
                valid_from: Optional[datetime] = None
                if i > 0:
                    try:
                        valid_from = _parse_utc(rows[i - 1]["event_time"])
                    except Exception:
                        pass

                # Normalize the value
                if field_name in ("email", "email_hash"):
                    old_val = old_val.strip().lower()
                    if field_name == "email":
                        old_val = normalize_email(old_val)

                aliases.append(IdentityAlias(
                    user_id=user_id,
                    identifier_type=id_type,
                    value=old_val,
                    is_current=False,
                    valid_from=valid_from,
                    valid_until=valid_until,
                    source_file=audit_source,
                    source_row_id=audit_id,
                ))

        return aliases

    # ------------------------------------------------------------------
    # Ambiguity detection
    # ------------------------------------------------------------------

    def _detect_contradictory_timestamps(
        self, user_id: str
    ) -> List[AmbiguityRecord]:
        """
        Check for contradictory timestamps in the audit log for a user.

        A contradictory timestamp is when the event_time of an old_value
        being set appears *after* the event_time it was replaced.
        In practice: if event[i].event_time >= event[i+1].event_time for
        same field, that is contradictory (events should be monotonically
        increasing).
        """
        ambiguities: List[AmbiguityRecord] = []
        audit_rows = self._uid_audit_rows.get(user_id, [])

        # Group by field_name
        field_rows: Dict[str, List[Dict]] = {}
        for row in audit_rows:
            fn = row.get("field_name", "")
            field_rows.setdefault(fn, []).append(row)

        for field_name, rows in field_rows.items():
            for i in range(len(rows) - 1):
                try:
                    t1 = _parse_utc(rows[i]["event_time"])
                    t2 = _parse_utc(rows[i + 1]["event_time"])
                    if t1 >= t2:
                        citations = [
                            rows[i].get("audit_id", ""),
                            rows[i + 1].get("audit_id", ""),
                        ]
                        ambiguities.append(AmbiguityRecord(
                            kind=AmbiguityKind.CONTRADICTORY_TIMESTAMPS,
                            description=(
                                f"Audit log entries for field '{field_name}' "
                                f"have non-monotonic timestamps"
                            ),
                            citations=[c for c in citations if c],
                        ))
                except Exception:
                    pass

        return ambiguities
