# ScamSlyce URL Regression Results

Generated: 2026-06-05T09:51:37
Input file: /home/rayza/projects/phishcheck/tests/test_urls.json

Passed: 18
Failed: 0
Skipped: 0

| Status | Name | Category | Expected Level | Min Score | Max Score | Expected Overall Level | Min Overall Score | Max Overall Score | Direct Level | Direct Score | Overall Level | Overall Score | Embedded High Risk Found | Embedded Highest Risk Level | Embedded Highest Risk Score | Inspection Status | Inspection Notes | Error | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| PASS | Google | known_safe | Low |  | 20 |  |  |  | Low | 0 | Low | 0 | False |  | 0 | complete |  |  | Major safe site, redirects to www.google.com. |
| PASS | YouTube | known_safe | Low |  | 20 |  |  |  | Low | 0 | Low | 0 | False | Low | 5 | complete |  |  | Google-owned site with many Google links and JavaScript. |
| PASS | Netflix | known_safe | Low |  | 20 |  |  |  | Low | 0 | Low | 0 | False |  | 0 | limited | The visible HTML text was very short, so ScamSlyce had little page content to inspect. |  | Large consumer site with login and JavaScript. |
| PASS | GitHub | known_safe | Low |  | 20 |  |  |  | Low | 0 | Low | 0 | False | Low | 0 | complete |  |  | Developer platform with redirects, forms, and JavaScript. |
| PASS | GOV.UK | known_safe | Low |  | 20 |  |  |  | Low | 0 | Low | 0 | False | Low | 0 | complete |  |  | Official UK government site. |
| PASS | BBC | known_safe | Low |  | 25 |  |  |  | Low | 0 | Low | 0 | False |  | 0 | complete |  |  | Large media site with scripts and external resources. |
| PASS | Amazon UK | known_safe_noisy | Low |  | 25 |  |  |  | Low | 0 | Low | 0 | False |  | 0 | complete |  |  | Large ecommerce site with login, redirects, forms, and scripts. |
| PASS | PayPal UK | known_safe_noisy | Low |  | 25 |  |  |  | Low | 0 | Low | 0 | False |  | 0 | complete |  |  | Financial/login-heavy official site. |
| PASS | Microsoft | known_safe | Low |  | 25 |  |  |  | Low | 0 | Low | 0 | False |  | 0 | complete |  |  | Official Microsoft site. |
| PASS | Outlook | known_safe_noisy | Low |  | 25 |  |  |  | Low | 0 | Low | 0 | False |  | 0 | limited | The visible HTML text was very short, so ScamSlyce had little page content to inspect. |  | Microsoft-owned login-related domain. |
| PASS | Apple | known_safe | Low |  | 20 |  |  |  | Low | 0 | Low | 0 | False |  | 0 | complete |  |  | Official Apple site. |
| PASS | Facebook | known_safe_noisy | Low |  | 25 |  |  |  | Low | 0 | Low | 0 | False |  | 0 | limited | The visible HTML text was very short, so ScamSlyce had little page content to inspect. |  | Official Meta/Facebook domain with login elements. |
| PASS | Instagram | known_safe_noisy | Low |  | 25 |  |  |  | Low | 0 | Low | 0 | False | Suspicious | 35 | complete |  |  | Official Instagram domain with login elements. |
| PASS | JD Sports | known_safe_noisy | Low |  | 30 |  |  |  | Low | 0 | Low | 0 | False |  | 0 | complete |  |  | Noisy ecommerce site that previously false-positive matched Microsoft. |
| PASS | ScamSlyce live app | known_safe_self | Low |  | 25 |  |  |  | Low | 0 | Low | 0 | False |  | 0 | limited | The visible HTML text was very short, so ScamSlyce had little page content to inspect. |  | Self-test for the deployed app. |
| PASS | AMTSO phishing test page | benign_security_test | Low |  | 20 |  |  |  | Low | 0 | Low | 0 | False |  | 0 | complete |  |  | Benign security test page. Not malicious, but designed to exercise anti-phishing detection. |
| PASS | Meta phishing sample | known_phishing_sample | Very High | 70 |  |  |  |  | Very High | 100 | Very High | 100 | True | Very High | 100 | limited | The visible HTML text was very short, so ScamSlyce had little page content to inspect. |  | Known Meta/Facebook impersonation sample used during development. |
| PASS | Google Sites Meta phishing chain | known_phishing_chain |  |  |  |  | 50 |  | Low | 0 | Very High | 100 | True | Very High | 100 | complete |  |  | Known chain pattern: Google Sites landing page leading to a higher-risk embedded destination. |
