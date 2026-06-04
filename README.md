# ScamSlyce

ScamSlyce is an early-stage prototype for checking suspicious links, explaining warning signs in plain English, and preparing abuse reports for easier reporting.

It performs safe passive checks such as domain analysis, redirects, embedded links, form detection, brand impersonation clues, and JavaScript/session indicators.

## Status

This project is still in development. ScamSlyce should not be treated as a definitive phishing, malware, or scam verdict system. A low-risk result does not guarantee a link is safe, and a high-risk result should be reviewed in context.

## What ScamSlyce does

- Checks suspicious links using passive requests
- Explains warning signs in plain English
- Separates user guidance from technical evidence
- Generates abuse-report text
- Suggests reporting actions based on detected indicators

## What ScamSlyce does not do

- It does not submit forms
- It does not test credentials
- It does not brute force or fuzz directories
- It does not scan ports
- It does not bypass protections
- It does not prove that a site is safe or malicious

## Safety note

Do not submit private links, password reset links, magic login links, banking session links, internal company URLs, or any URL containing personal tokens or sensitive information.

## Running locally

    pip install -r requirements.txt
    streamlit run scamslyce.py

## Running URL regression tests

ScamSlyce includes a simple URL regression harness for checking scoring changes against a fixed list of known-safe, noisy, benign test, and known phishing sample URLs.

Run it with:

    python3 tests/run_url_tests.py

The runner loads `tests/test_urls.json`, calls `analyse_url(url, message_text="")` for each listed URL, prints a PASS/FAIL table, and writes:

- `tests/latest_results.md`
- `tests/latest_results.csv`

Empty URLs and URLs containing `PASTE_YOUR_STREAMLIT_URL_HERE` are skipped.

## Feedback

Feedback is welcome, especially:

- false positives
- missed scam/phishing pages
- confusing wording
- mobile layout issues
- reporting-action suggestions
