# Demo script

A click-by-click walkthrough of the console, with what to say on each screen. There is a 5-minute version and a
10-minute version; the 10-minute one adds the beats marked **(10 min)**.

## Before the interview (30 minutes ahead)

```bash
./scripts/demo.sh          # starts everything; skips what's already done; ends by serving the console
./tip reset --yes          # in a second terminal: clear earlier investigations, rules, briefs and evaluations
```

Then:

1. Open http://localhost:8000 in a browser window by itself, at about 110% zoom, with other tabs closed.
2. Click through all five screens once, so nothing is loading for the first time while you share.
3. Keep this file and [INTERVIEW.md](INTERVIEW.md) open on another screen, not the one you share.

Everything runs in **mock mode**: free, offline and repeatable. If live mode is set up (`ANTHROPIC_API_KEY` in
`.env`), keep mock for the demo anyway and offer live as an extra: it takes longer and costs money.

---

## Opening (15 seconds)

> "This is an AI-assisted threat intelligence platform for a crypto exchange. It runs the loop the role describes: track
> a threat actor, check whether we're affected, turn that into lasting detections, and brief both engineers and
> executives. The AI never gets the last word: every claim is checked against evidence, and a person approves what
> goes out. The intelligence is real, from MITRE ATT&CK, CISA, the FBI and OFAC; the company and its logs are
> synthetic."

## 1. What's happening in the world (45 seconds)

**Click:** nothing; the screen opens on Contagious Interview.

> "First, who's attacking companies like us. ATT&CK tracks North Korea's fake job-interview campaigns against
> developers as *Contagious Interview*. Its malware, BeaverTail and InvisibleFerret, is what the attack in our logs
> imitates. Here's how they operate, grouped by goal."

**Click:** **Lazarus Group** on the switch.

> "Lazarus is the umbrella group behind the largest crypto thefts; Operation Dream Job is its fake-job campaign."

**Point at the warning signs:**

> "On the right, early warnings, all collected automatically: domains impersonating a big exchange, sanctioned wallet
> addresses we must never pay, government advisories, and vulnerabilities being exploited right now."

**(10 min)** Point at "Found by: new certificate" in the lookalike table:

> "Those come from a Go service that watches Certificate Transparency logs live. Every TLS certificate is published
> there, so a phishing domain shows up before the first phishing email. In testing it found real ones, like
> coinbase-allert.live."

**(10 min)** Hover a dotted term such as *OFAC*:

> "Every term has a plain-English definition, because these screens get shown to non-specialists."

## 2. Are we affected? (2 minutes)

**Click:** **Investigate**, with the first suggested question and **Mock** selected.

> "I'm asking the question in plain English. The agent works like an analyst: it runs reviewed hunts for attacker
> behaviour, matches our logs against the intelligence, builds a timeline for the person involved, and reads
> advisories and our past incidents. It has no free-form access: no raw SQL, only tools, and every row a tool returns
> carries an evidence ID."

**When it finishes, point at the verdict and the score:**

> "Confirmed compromise. Eight of nine findings verified."

**Scroll the timeline:**

> "An engineer opened a fake recruiter site, ran the 'coding test', malware stole their session cookies, and that
> night the attacker replayed the session, read the hot-wallet API key and started withdrawals worth about seven
> million dollars: 3.2 million completed, including 1.85 million to an OFAC-sanctioned Lazarus address, and 3.8
> million still pending."

**Click:** an evidence chip such as `edr-0004439`.

> "Every claim links to the exact log line behind it. This one is curl, started by node, downloading from the
> attacker's server on port 1224."

**Scroll to the red box, "Rejected by the verifier":**

> "This is the part I care most about. The AI claimed cold-wallet keys were exported, but it cited evidence no tool
> ever returned. Plain code, not the AI, checks every citation, so that claim is shown as rejected rather than
> silently trusted. Mock mode plants this on purpose, so you can see the check working."

**(10 min)** Open **How the AI worked**:

> "The full tool trace: which hunt ran, what it returned. An analyst can audit exactly how a conclusion was reached."

## 3. How do we catch this next time? (1 minute)

**Click:** **Draft detection rules**.

> "An investigation explains what happened once; a detection makes sure we catch it next time, even with different
> servers or a different employee. Rules are written in Sigma, the vendor-neutral standard, and converted to Splunk,
> Microsoft Sentinel and our own store."

**Point at a rule's three numbers:**

> "Each rule is replay-tested: did it catch the attack, how many false alarms on this week's normal activity, and how
> many on a fresh week it has never seen? That last one stops a rule from passing just because it was written while
> looking at this week."

**Scroll to "A person reads a production secret", Draft history:**

> "Its first draft failed: 56 false alarms, because people read staging secrets all the time. The revision, limited to
> production secrets, passed. That's the loop a detection engineer goes through, and the test enforces it."

**(10 min)** Click the **Sentinel KQL** tab, then **Approve** on one rule:

> "Approving writes the rule to the repository as detection-as-code, ready for review like any other change."

**Point at the coverage panel:**

> "And here's how much of Contagious Interview's known techniques we can now detect."

## 4. Tell leadership (45 seconds)

**Click:** **Write briefs**.

> "Same facts, two audiences. The executive brief leads with the bottom line, puts the impact in dollars, uses the
> intelligence community's standard words for likelihood ('very likely', not 'maybe'), and says what leadership must
> decide."

**Point at the facts line ("computed from evidence, not by the AI"):**

> "Money, counts and indicators are computed by code from the evidence; the AI only writes the prose. A checker rejects
> any dollar figure that isn't in these facts and any indicator that doesn't appear in its evidence. That's exactly
> the kind of number an executive repeats, so it can't be a hallucination."

**(10 min)** Scroll the technical brief's indicator table, then show the **Download** links:

> "These are the IPs, domains, hashes and the wallet to block. Approved briefs export as Markdown, and the indicators
> export as a MISP event, the format crypto security teams use to share with each other, tagged with ATT&CK and the
> threat group."

## 5. Can we trust the AI? (45 seconds)

**Click:** **Run evaluation**.

> "Instead of asking you to trust it, here's the measurement. It runs the pipeline on cases where we know the answer,
> and scores it against release gates."

**Point at the gates:**

> "It found 10 of the 12 attack steps. The two misses are shown in red, the git clone and the npm install script, so
> this scorecard isn't flattering me. All accepted findings were real. On a normal week with no attack it correctly
> found nothing; an AI that always finds something is useless."

**Point at the injection table:**

> "Attackers increasingly target the AI itself. The evaluation plants two prompt injections: an instruction hidden in
> a malware command line, and a fake vendor report calling it all a red-team exercise. Both were flagged. Whether
> the model would have been steered can only be measured live, so that gate says 'needs live mode' rather than
> pretending."

## Close (15 seconds)

> "So: real intelligence, an agent that has to show its evidence, detections tested against data, briefs where the
> numbers come from code, and an evaluation that measures all of it. Happy to go deeper on any piece, or run it live
> against Claude."

---

## If something breaks

| Symptom | Fix |
|---|---|
| The page doesn't load | Is `./scripts/demo.sh` still running? Rerun it. If it says the port is in use: `./scripts/demo.sh 8001` |
| "Could not load intelligence" on screen 1 | Postgres is down: `docker compose up -d --wait`, then reload |
| "uv not found" | `export PATH="$HOME/.local/bin:$PATH"` (the `./tip` launcher also searches common locations) |
| Screen 3, 4 or 5 says to run an investigation first | Go to screen 2 and click **Investigate** (about 2 seconds in mock mode) |
| Too many old runs in the dropdowns | `./tip reset --yes`, then reload |
| Anything else | `./tip doctor` lists what's missing and the command to fix it |

If the console won't come up at all, show the README's architecture and the terminal versions:
`./tip investigate "Are we affected?"`, `./tip detections draft`, `./tip brief`, `./tip eval`.

## Things to say before you're asked

- **"The company and logs are synthetic; the threat intelligence is real."** The attack follows public FBI and CISA
  reporting.
- **"Synthetic normal activity is cleaner than a real company's."** That's why the detections score so well; in
  production you'd deploy them in test mode first.
- **"Mock mode is a scripted playbook over real tool results."** It shows the architecture and every check working,
  for free. Live mode with Claude is built in; its injection-resistance gate is the one number mock mode can't produce.
