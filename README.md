# ScamSlyce

ScamSlyce is a paused research prototype that explored safe passive checks for suspicious scam/phishing links.

The original goal was to build a simple public-facing tool for non-technical users: paste a suspicious link, receive plain-English warning signs, and generate an abuse report for easier reporting.

During testing, I found that passive heuristic URL analysis alone is not reliable enough to provide accurate safety guidance for a non-technical public tool. Many suspicious pages rely on JavaScript rendering, Cloudflare/security interstitials, geo/IP differences, hidden embedded destinations, changing content, or rapid takedowns. Making the tool more accurate would require a more technical investigation workflow, reputation checks, browser-based analysis, or analyst-led evidence handling, which moves it away from the original goal of a simple public app.

I am keeping this repository as a learning and research prototype.

## Project status

**Paused / research prototype**

ScamSlyce should not be treated as a definitive phishing, malware, or scam verdict system.

A low-risk result does not guarantee that a link is safe. A high-risk result should still be reviewed in context.

The project demonstrated useful ideas, but the current concept is not being developed further as a public non-technical link-checking app.

## What this prototype explored

ScamSlyce explored:

- Safe passive URL checks
- Domain and registered-domain analysis
- Redirect inspection
- Embedded link discovery
- Chain-aware analysis for landing pages that lead to suspicious destinations
- Form and sensitive-input detection
- Brand impersonation clues
- JavaScript/session indicators
- Inspection confidence for blocked, dead, or limited pages
- Plain-English user guidance
- Abuse-report text generation
- Suggested reporting actions
- Regression testing with known-safe, noisy, benign, and suspicious URLs

## What ScamSlyce does

- Checks submitted links using passive requests
- Looks for domain, redirect, form, brand, embedded-link, and JavaScript/session indicators
- Separates plain-English guidance from technical evidence
- Attempts to identify when inspection is limited or inconclusive
- Generates copy-paste abuse-report text
- Suggests reporting actions based on detected indicators
- Includes a regression test harness for scoring and behaviour checks

## What ScamSlyce does not do

- It does not prove that a site is safe or malicious
- It does not submit forms
- It does not test credentials
- It does not log in
- It does not brute force or fuzz directories
- It does not scan ports
- It does not bypass protections
- It does not solve CAPTCHAs
- It does not attempt to bypass Cloudflare or other security interstitials
- It does not execute browser-based JavaScript rendering
- It does not replace manual investigation or professional threat intelligence tools

## Key lesson learned

The main conclusion from this prototype is:

> Passive heuristic URL checks can highlight useful warning signs, but they are not accurate or complete enough to act as a reliable public-facing malicious-link verdict system.

To make the idea significantly more accurate, ScamSlyce would need to become more like an analyst investigation system, using additional evidence sources such as reputation feeds, rendered-page analysis, controlled sandboxing, and manual evidence handling. That would make it less suitable for the original target audience of non-technical users.

## Safety note

Do not submit private links, password reset links, magic login links, banking session links, internal company URLs, invite links, or any URL containing personal tokens or sensitive information.

This prototype performs passive requests to submitted URLs. Only test URLs you are comfortable sending to the tool.

## Running locally

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the Streamlit app:

```bash
streamlit run scamslyce.py
```

## Running URL regression tests

ScamSlyce includes a simple URL regression harness for checking behaviour against a fixed list of known-safe, noisy, benign test, and known suspicious sample URLs.

Run the stable regression suite with:

```bash
python3 tests/run_url_tests.py
```

The runner loads `tests/test_urls.json`, calls the analysis logic for each listed URL, prints a PASS/FAIL table, and writes:

- `tests/latest_results.md`
- `tests/latest_results.csv`

Empty URLs and URLs containing `PASTE_YOUR_STREAMLIT_URL_HERE` are skipped.

## Running candidate phishing tests

Candidate phishing URLs are kept separate from the stable regression suite because live phishing links are volatile and may go offline, change behaviour, block automated requests, or return security interstitials.

Run candidate tests with:

```bash
python3 tests/run_url_tests.py tests/candidate_urls.json
```

This writes:

- `tests/candidate_results.md`
- `tests/candidate_results.csv`

Candidate test failures should be reviewed carefully. A low score on a candidate phishing URL may mean the page was unavailable, blocked, JavaScript-rendered, changed, or not inspectable through passive requests.

## Repository note

This repository remains available as a record of the prototype and the lessons learned from building it.

The next project direction is separate: a local-first bug bounty recon triage assistant focused on authorised recon outputs, evidence organisation, and manual testing prioritisation rather than public suspicious-link verdicts.

## Feedback

Feedback is still welcome, especially around:

- passive-analysis limitations
- false positives
- missed phishing/scam indicators
- confusing wording
- chain-analysis edge cases
- reporting-action logic
- lessons that could inform future investigation tools
