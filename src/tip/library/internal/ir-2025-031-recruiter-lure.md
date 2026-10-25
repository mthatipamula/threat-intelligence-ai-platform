---
title: "IR-2025-031: Fake recruiter approach to a developer (no compromise)"
published: 2025-11-21
---
# IR-2025-031: Fake recruiter approach to a developer (closed, no compromise)

**Summary.** A backend engineer reported a LinkedIn recruiter offering a well-paid role at a "blockchain startup". The
recruiter sent a technical assessment as a Git repository and asked the engineer to run it locally within 24 hours.
The engineer ran it inside a disposable cloud VM rather than their laptop and noticed a post-install script reaching
an IP address on port 1224.

**Assessment.** Consistent with public FBI and industry reporting on North Korean "Contagious Interview" activity:
fake recruiters, coding tests that install malicious npm packages, a JavaScript downloader followed by a Python
backdoor. No Meridian systems were affected.

**Actions.** Shared the repository URL and IP with industry partners via the sector ISAC. Added guidance to the
engineering handbook: never run take-home assessments on corporate devices.

**Lessons.** Engineers with production or wallet access are deliberately targeted. Any `node` or `npm` process that
spawns `curl`, `python` or a shell and connects to a raw IP on a non-standard port deserves immediate investigation.
