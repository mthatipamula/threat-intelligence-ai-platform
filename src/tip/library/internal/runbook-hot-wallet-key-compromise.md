---
title: "Runbook: suspected compromise of a hot-wallet API key"
published: 2026-06-15
---
# Runbook: suspected compromise of a hot-wallet API key

**When to use.** Any sign that a credential able to initiate hot-wallet withdrawals was read, copied or used outside
its normal pattern: a human principal reading `prod/hot-wallet/*` secrets, new access keys created for withdrawal
service users, or withdrawals initiated through the internal API outside a release window.

**First 15 minutes.**
1. Freeze outbound withdrawals from the affected hot wallet (Wallet Ops on-call, two-person approval).
2. Revoke the withdrawal API key and every access key of `svc-withdrawals`; rotate the secret.
3. Snapshot cloud audit logs for the principal involved (last 72 hours).
4. Page the Security incident commander and Legal (sanctions exposure if funds moved).

**Within 1 hour.** Identify every withdrawal initiated with the key since the earliest suspicious event. Screen
destination addresses against OFAC and internal blocklists. If any destination is sanctioned, Legal must file a
report with OFAC within 10 business days. Contact blockchain analytics partners to trace and flag the funds.

**Evidence to keep.** Secrets Manager access events, IAM key creation events, withdrawal records, the identity
provider's session history for the principal (look for session reuse from new IP addresses or countries).
