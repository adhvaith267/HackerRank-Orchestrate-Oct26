# Evidence Extraction Prompts

These prompts are used by `llm.py` when calling the LLM provider.
They are stored here for transparency and so the AI interviewer can inspect them.

---

## 1. Request Classification Prompt

**Purpose:** Determine whether `request_text` authorizes deletion of personal data.

**Input variables:**
- `{request_text}` — the raw text from `deletion_requests.csv`

**Expected output:** JSON object with keys `authorized`, `reason`, `confidence`.

```
You are a privacy compliance analyst reviewing a data deletion request.

Determine whether the following message authorizes a deletion of personal data.
A request is authorized if the user is asking to:
- delete their account or personal data
- erase or remove their profile, history, or records
- exercise their right to erasure / right to be forgotten

A request is NOT authorized if the user is asking to:
- access, download, or export their data
- correct or update their data
- opt out of marketing only
- submit a general inquiry or complaint

Respond with a JSON object only, no prose:
{"authorized": true/false, "reason": "brief explanation", "confidence": "high/medium/low"}

Request text:
{request_text}
```

**Notes:**
- Rule-based classification is attempted first (see `llm.py:_classify_by_rules`).
  LLM is only called for ambiguous texts when `llm.mode` is not `off`.
- Multi-language requests (Spanish, French, Japanese observed in dataset) are
  handled natively by the LLM.

---

## 2. Image Evidence Extraction Prompt

**Purpose:** Extract resource states from admin console screenshots.

**Input variables:**
- `{identifiers}` — comma-separated list of known identifiers for the subject
  (email, user_id, etc.)
- `image_b64` — base64-encoded PNG (passed as a vision API image input)

**Expected output:** JSON array of fact objects.

```
You are a privacy auditor examining a screenshot from an internal system.

The subject has the following identifiers: {identifiers}

Extract any records visible in the screenshot that belong to this subject.
For each record found, determine:
- system_id (e.g. account_service, search_service, analytics_platform, support_platform,
  export_service, integration_service, backup_service, security_service,
  identity_service, marketing_platform)
- resource_id (the unique record ID visible in the screenshot)
- state: PRESENT, ABSENT, REDACTED, ANONYMIZED, ACTIVE, DISABLED, or BLOCKED
- data_category: one of USER_PROFILE, SEARCH_INDEX_ENTRY, ANALYTICS_PROFILE,
  SUPPORT_MESSAGE, USER_EXPORT, BACKUP_ARCHIVE, SECURITY_AUDIT_LOG,
  ACCOUNT_TOMBSTONE, MARKETING_PROFILE

Respond with a JSON array only:
[{"system_id":"...","resource_id":"...","state":"...","data_category":"..."}]

If no matching records are found, respond with: []
```

**Notes:**
- Used when `llm.enable_ocr = true` and `llm.mode != "off"`.
- Evidence images observed in the dataset:
  - `account_admin_console_20260926.png` — account_service profile view
  - `deleted_account_reference_20260310.png` — identity_service tombstone / customer reference registry
  - `search_index_inspector_20260901.png` — search_service index entries
  - `backup_restore_console_20260429.png` — backup_service vault entries
  - `analytics_profile_view_20260713.png` — analytics_platform profile (user_20, analytics_7438)
  - `connector_management_console_20260807.png` — integration_service data flows
  - `customer_export_console_20260618.png` — export_service export jobs
  - `object_storage_browser_20260213.png` — support attachments in object storage
  - `security_audit_explorer_20260905.png` — security_service audit events (Sentinel)
  - `marketing_profile_console.png` — marketing_platform audience profile
  - `support_ticket_console_20260524.png` — support_platform conversation

---

## 3. Ambiguous Support Message Classification

**Purpose:** Determine whether a support record should be DELETED (rule_06,
attachment belonging only to the subject) or REDACTED (rule_05, shared context).

**Not yet implemented as a separate LLM call.** Currently handled by the
`data_category` heuristic:
- `support_conversations` → REDACT (shared context)
- `ticket_attachments` → DELETE (attachment belongs to subject)

If this heuristic proves inaccurate on the full dataset, a separate LLM call
will be added here with:
- Input: `message_excerpt`, `subject_reference`, `ticket_id`
- Output: `{"action": "DELETE"|"REDACT", "reason": "..."}`

---

## Versioning

| Prompt | Version | Notes |
|---|---|---|
| Request classification | 1.0 | Derived from sample_output.csv analysis |
| Image extraction | 1.0 | Derived from DATA_DISCOVERY.md §3.4 |
| Support message | n/a | Pending if heuristic is insufficient |
