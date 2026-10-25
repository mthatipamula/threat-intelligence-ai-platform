# Interview questions and answers

Short, honest answers grounded in this project. Say them in your own words; the point is the reasoning, not the
script. Answers marked **(honest gap)** say what the project does *not* do. Volunteering those builds more trust than
having them discovered.

## The project

**What is it, in one breath?**
An AI-assisted threat intelligence platform for a crypto exchange: it collects intelligence on threat actors, checks
our logs for their behaviour, turns findings into tested detections, and writes briefs for engineers and executives.
Every AI claim is checked against evidence, and a person approves what goes out.

**Why did you build it?**
To show the loop this role describes, end to end, with the AI engineering done carefully: tools instead of free-form
access, citations checked by code, and an evaluation that measures quality instead of asserting it. My background is
backend and AI engineering; building it is how I learned the threat-intel side properly.

**What's real and what's synthetic?**
The intelligence is real: MITRE ATT&CK, CISA's exploited-vulnerability list, FBI and CISA advisories on North Korean
crypto theft, and OFAC's sanctioned wallets. The company, "Meridian Exchange", and its logs are synthetic, with one
attack modelled on public reporting about North Korea's fake job-interview campaigns.

## Threat intelligence basics

**What's the difference between an IOC and a TTP?**
An IOC (indicator of compromise) is a specific artefact: an IP, a domain, a file hash, a wallet. A TTP (tactics,
techniques and procedures) is *how* an attacker operates, like "a malicious npm package spawns curl". Attackers change
IOCs cheaply and TTPs expensively, so my detections target behaviour: none of them hard-code this attacker's
addresses.

**Why MITRE ATT&CK?**
It's the shared vocabulary for attacker behaviour: every technique has an ID (T1550.004 is "use a stolen session
cookie"). It lets findings, detections and coverage be compared across tools and teams. I use it for tagging
findings, mapping detection coverage per threat group, and even the prompt-injection tests (T1698).

**Why STIX?**
It's the standard format for threat intelligence: objects (actor, malware, indicator) and relationships ("Lazarus uses
T1566"). Storing everything as STIX 2.1 means it can be shared with MISP or OpenCTI and linked together, and every
object keeps its source, which is what lets the AI cite where a fact came from.

**How do you handle attribution?**
As an assessment, never a fact. The briefs say the activity is "very likely" North Korean and explain why: the lure,
the malware behaviour, and a sanctioned Lazarus-linked wallet all match public reporting. They also say it rests on
that match, not on proof of who was at the keyboard. "Very likely" is one of the ICD 203 standard likelihood words
the intelligence community uses so readers know exactly how sure we are.

**What's OSINT here?**
Public sources collected automatically: ATT&CK, CISA's exploited-vulnerability list, OFAC's sanctioned crypto
addresses, abuse.ch ThreatFox (with a free key), and lookalike domains found by generating typo variants of the brand
and checking which resolve in DNS.

## The AI engineering

**Why an agent with tools rather than giving the model the data?**
Two reasons. Control: the model can only call reviewed tools (hunts, filtered searches, lookups); it can't write SQL
or see data it shouldn't. Evidence: every row a tool returns carries an ID, and those IDs are logged per
investigation, which is what makes citations checkable.

**How do you stop hallucinations?**
I don't trust the model to police itself. Plain code checks every finding:
1. it cites evidence;
2. every cited ID was actually returned by a tool in this run;
3. its ATT&CK IDs exist;
4. the people it names appear in the cited events;
5. its timestamp falls within them.

Failing findings stay visible, marked rejected. For briefs, the numbers an executive would repeat (dollars, counts,
indicators) are computed by code from the evidence, and any dollar figure the model writes that isn't in those facts
is rejected.

**How does the RAG work?**
The library is government advisories, ATT&CK write-ups and our own past incidents and runbooks, split into passages.
Search is hybrid: semantic (local embeddings, so no API cost) and keyword, merged with reciprocal rank fusion. The
keyword half matters for exact terms like "T1550.004" or "port 1224" that embeddings blur. Passages come back with IDs
the agent must cite.

**What about prompt injection?**
Logs and reports contain attacker-written text, and attackers are starting to aim it at AI analysts. There are three
layers:
1. The prompts say tool output is data, never instructions.
2. A scanner flags instruction-like text in every tool result, warns the model, and shows the analyst. It never edits
   the evidence.
3. The citation checker rejects anything the evidence doesn't support, whatever prompted it.

The evaluation plants two injections and checks they're flagged. **(honest gap)** The scanner is pattern-based, so it
won't catch every phrasing. That's why it's one layer of three, and why the "was the model steered?" gate needs a live
run.

**How do you know it works? (evals)**
The evaluation run scores the whole pipeline against known answers and turns it into release gates:
- attack steps found against the answer key: 10 of 12;
- accepted findings that are real: 100%;
- a normal week where the right answer is "nothing";
- planted prompt injections flagged;
- detection pass rate and attack events caught;
- valid brief citations.

The two missed steps are shown, not hidden.

**Why mock mode?**
Demos and CI need to be free, fast and repeatable. Mock mode is a scripted analyst playbook over the same real tools,
so every check and screen works without an API key. Live mode swaps in Claude for the decisions and the writing.
**(honest gap)** Live mode is built but I've run the demo in mock; a live evaluation costs a few dollars.

**Which model, and why?**
Claude through the official Anthropic SDK, behind one brain interface, so another provider could plug in. It uses
strict tool schemas, structured JSON output for reports, and a server-side refusal fallback: security content can
trip safety classifiers, and the fallback reruns the request on a model suited to that category instead of failing.

**What does it cost?**
Mock mode costs nothing. A live investigation is roughly a dollar or less on Opus-class pricing, and the token usage
is shown per run. To cut cost, I'd cache the stable system prompt and tool definitions, and use a smaller model for
the bulk steps once the evaluation shows quality holds.

## Detection engineering

**Why Sigma?**
Write the logic once, convert it to whatever SIEM a company runs. The same rule becomes Splunk SPL, Sentinel KQL
(mapped onto Sentinel's normalised ASIM tables) and SQL for this demo's store, via pySigma.

**How do you test a rule?**
By replaying it over logs where the answer is known. It must catch the attack and stay at or under two false alarms a
week, both on this week's normal activity and on a fresh normal week it has never seen. The second check stops
overfitting. A failing draft goes back once with the reasons.

**Your rules have zero false alarms. Isn't that suspicious?**
Yes. Synthetic normal activity is cleaner than a real company's. A pass here means "deploy in test mode and watch",
which is why approved rules are saved with `status: test`. In production I'd measure alert volume over a few weeks
before promoting a rule.

**What does coverage mean?**
Which of a threat group's known ATT&CK techniques we have a tested rule for. It's a planning tool for finding gaps,
not a score. Some of our rules also cover techniques ATT&CK doesn't yet list for that group, because they come from
our own incident.

## Crypto-specific

**Why does OFAC matter for an exchange?**
Sending funds to a sanctioned address is illegal for US companies. Here the attacker routed $1.85M to a real
sanctioned Lazarus address, which creates a reporting obligation. That's why every withdrawal should be screened
against the list and why the brief flags it to Legal.

**What's the threat model for a hot wallet?**
A hot wallet's keys are online so withdrawals can be automated, which makes the withdrawal credential the prize. The
attack here never touches the wallet's private keys: it steals an engineer's session, reads the withdrawal API key
from the secrets store, and creates a backdoor key. The detections watch exactly those steps.

**What real incidents is this based on?**
FBI and CISA reporting on North Korean operations against crypto companies, such as TraderTraitor and the fake
job-interview campaigns ATT&CK tracks as Contagious Interview. The FBI attributed the $1.5B Bybit theft in 2025 to
North Korea. Those advisories are in the report library.

## Production and judgment

**What would you change for production?**
- **Data:** connect to the real SIEM (Splunk, Sentinel or Chronicle) through its API instead of DuckDB.
- **Sharing:** sync intelligence with MISP or OpenCTI to share it with industry partners.
- **Access:** single sign-on and role-based access, and audit logging of who approved what.
- **CI and model checks:** run the evaluation in CI on every change, track model quality and cost over time, and
  alert when a gate regresses.
- **Detection lifecycle:** deploy rules through the SIEM's detection-as-code pipeline in test mode, and promote them
  after measuring real alert volume.
- **Live usage:** use prompt caching and a smaller model where the evaluation shows quality holds.

**What are the limitations?**
- One synthetic attack and cleaner-than-real normal activity.
- A pattern-based injection scanner.
- Mock mode is scripted.
- Single-user, with no authentication.
- The lookalike-domain check is DNS-based rather than streaming certificate-transparency logs (planned in Go).

**How would you brief an executive differently from an engineer?**
Executives get the bottom line in the first sentence, impact in dollars and legal exposure, a stated confidence with
its reason, and the decisions they need to make, with no jargon. Engineers get the timeline, indicators, techniques
and detections. Both trace to the same evidence.

**How do you work solo on an investigation?**
Start broad (hunt for behaviour, match logs to intelligence), follow the strongest lead, build a timeline, check it
against reporting, then write it up with evidence for every claim. The platform encodes that sequence, and its
checkpoints (citations, replay tests, approvals) are the discipline I'd apply working alone.

**How do you use generative AI day to day?**
For the reading-heavy work: extracting indicators and techniques from long reports, drafting detections and briefs,
summarising timelines. Always with the output tied to evidence I can check, and never as the final decision maker.
