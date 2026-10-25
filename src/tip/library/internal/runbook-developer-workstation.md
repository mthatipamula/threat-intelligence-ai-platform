---
title: "Runbook: suspected developer workstation compromise"
published: 2026-05-02
---
# Runbook: suspected developer workstation compromise

**Signals.** A developer laptop running an unusual child process from `node`/`npm` (`curl`, `python3`, a shell), a
process started from a hidden folder in the home directory (for example `~/.n2/`), a non-browser process reading
Chrome's cookie database or wallet extension storage, or a large outbound transfer to an uncategorized IP.

**Contain.** Isolate the host in the EDR console. Revoke all of the user's identity provider sessions and
refresh tokens; this matters because stolen session cookies bypass MFA until revoked. Disable the user's cloud
federation until the investigation clears them.

**Scope.** Pull the user's sign-ins for the previous 7 days and look for the same session ID used from a different
IP address or country. Pull cloud audit events for the user and any keys they created. If the user has access to
wallet infrastructure, follow the hot-wallet key runbook in parallel.

**Recover.** Reimage the laptop. Rotate every credential the user could reach, including browser-stored secrets and
any crypto wallet seed phrases present on the device.
