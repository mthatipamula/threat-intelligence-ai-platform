---
title: "IR-2026-014: Customer phishing via lookalike domain"
published: 2026-03-09
---
# IR-2026-014: Customer phishing via lookalike domain (closed)

**Summary.** On 2026-03-02 customers reported emails asking them to "re-verify" their accounts at a site resembling the
Meridian login page. The site was hosted on a lookalike domain registered two days earlier. 41 customers entered
credentials; withdrawals were blocked for 37 of them by the new-device withdrawal hold. Four accounts lost a combined
USD 18,400, reimbursed by Meridian.

**Detection gap.** The domain had a valid TLS certificate for 48 hours before the first phishing email. Certificate
Transparency monitoring would have flagged it before any customer was targeted.

**Actions.** Takedown requests through the registrar and hosting provider (site offline in 9 hours). Added the domain
to the email and web proxy blocklists. Follow-up: build lookalike-domain monitoring on CT logs (owner: Threat Intel).

**Lessons.** Lookalike domains are a leading indicator: registration and certificate issuance precede the attack.
Treat newly registered domains resembling Meridian or its staff-facing services (careers, SSO, support) as high priority.
