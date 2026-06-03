import ipaddress
import re
import socket
from urllib.parse import quote_plus, urljoin, urlparse

import requests
import streamlit as st
import tldextract
from bs4 import BeautifulSoup


# -----------------------------
# Config / simple intelligence
# -----------------------------

KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly",
    "rebrand.ly", "cutt.ly", "is.gd", "s.id", "shorturl.at", "rb.gy", "lnkd.in",
}

HOSTING_PLATFORMS = {
    "bolt.host", "supabase.co", "vercel.app", "netlify.app", "github.io",
    "pages.dev", "workers.dev", "web.app", "firebaseapp.com", "sites.google.com",
    "replit.app", "glitch.me", "wixsite.com", "weebly.com",
}

SUSPICIOUS_WORDS = {
    "verify", "verification", "login", "account", "password", "secure", "security",
    "appeal", "suspended", "disabled", "bonus", "reward", "urgent", "confirm",
    "update", "support", "wallet", "bank", "payment", "invoice", "limited",
    "warning", "unusual", "activity", "locked", "review", "violation",
    "copyright", "business", "manager", "credentials", "authenticate",
    "authentication",
}

BRAND_KEYWORDS = {
    "Meta/Facebook": ["meta", "facebook", "fb", "business manager", "meta business"],
    "Instagram": ["instagram", "insta"],
    "PayPal": ["paypal"],
    "Microsoft": ["microsoft", "office365", "outlook", "office 365", "microsoft account"],
    "Google": ["google", "gmail"],
    "Apple": ["apple", "icloud"],
    "Amazon": ["amazon"],
    "HMRC/GOV.UK": ["hmrc", "govuk", "gov.uk", "tax rebate", "tax refund"],
    "Banking": ["bank", "onlinebanking", "securebank"],
}

LEGIT_BRAND_DOMAINS = {
    "Meta/Facebook": ["meta.com", "facebook.com", "fb.com", "messenger.com"],
    "Instagram": ["instagram.com", "meta.com"],
    "PayPal": ["paypal.com", "paypal.co.uk"],
    "Microsoft": ["microsoft.com", "live.com", "office.com", "outlook.com"],
    "Google": ["google.com", "gmail.com"],
    "Apple": ["apple.com", "icloud.com"],
    "Amazon": ["amazon.com", "amazon.co.uk"],
    "HMRC/GOV.UK": ["gov.uk"],
}

BRAND_REPORTING = {
    "Meta/Facebook": {
        "title": "Report impersonation to Meta/Facebook",
        "email": "phish@fb.com",
        "url": "https://www.facebook.com/help/225602007465207/",
        "subject_prefix": "Suspected Meta/Facebook phishing page",
    },
    "Instagram": {
        "title": "Report impersonation to Instagram/Meta",
        "email": "phish@fb.com",
        "url": "https://help.instagram.com/",
        "subject_prefix": "Suspected Instagram phishing page",
    },
    "PayPal": {
        "title": "Report impersonation to PayPal",
        "email": "phishing@paypal.com",
        "url": "https://www.paypal.com/uk/security/report-suspicious-messages",
        "subject_prefix": "Suspected PayPal phishing page",
    },
    "Microsoft": {
        "title": "Report impersonation to Microsoft",
        "email": "phish@office365.microsoft.com",
        "url": "https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site",
        "subject_prefix": "Suspected Microsoft phishing page",
    },
    "Google": {
        "title": "Report impersonation to Google Safe Browsing",
        "email": "",
        "url": "https://www.google.com/safebrowsing/report_phish/",
        "subject_prefix": "Suspected Google phishing page",
    },
    "Apple": {
        "title": "Report impersonation to Apple",
        "email": "reportphishing@apple.com",
        "url": "https://support.apple.com/102568",
        "subject_prefix": "Suspected Apple phishing page",
    },
    "Amazon": {
        "title": "Report impersonation to Amazon",
        "email": "reportascam@amazon.com",
        "url": "https://www.amazon.co.uk/reportascam",
        "subject_prefix": "Suspected Amazon phishing page",
    },
    "HMRC/GOV.UK": {
        "title": "Report GOV.UK/HMRC impersonation",
        "email": "report@phishing.gov.uk",
        "url": "https://www.ncsc.gov.uk/collection/phishing-scams/report-scam-email",
        "subject_prefix": "Suspected HMRC/GOV.UK phishing page",
    },
}

PLATFORM_REPORTING = {
    "supabase.co": {
        "title": "Report backend/API abuse to Supabase",
        "email": "abuse@supabase.io",
        "fallback_email": "legal@supabase.io",
        "url": "https://supabase.com/aup",
        "subject_prefix": "Suspected phishing use of Supabase infrastructure",
    },
    "rebrand.ly": {
        "title": "Report URL shortener abuse to Rebrandly",
        "email": "",
        "url": "https://support.rebrandly.com/hc/en-us/requests/new",
        "subject_prefix": "Suspected malicious Rebrandly short link",
    },
    "sites.google.com": {
        "title": "Report abuse to Google",
        "email": "",
        "url": "https://www.google.com/safebrowsing/report_phish/",
        "subject_prefix": "Suspected phishing page hosted on Google Sites",
    },
    "vercel.app": {
        "title": "Report hosting abuse to Vercel",
        "email": "",
        "url": "https://vercel.com/abuse",
        "subject_prefix": "Suspected phishing page hosted on Vercel",
    },
    "netlify.app": {
        "title": "Report hosting abuse to Netlify",
        "email": "abuse@netlify.com",
        "url": "https://www.netlify.com/abuse/",
        "subject_prefix": "Suspected phishing page hosted on Netlify",
    },
    "pages.dev": {
        "title": "Report hosting abuse to Cloudflare",
        "email": "",
        "url": "https://abuse.cloudflare.com/",
        "subject_prefix": "Suspected phishing page hosted on Cloudflare Pages",
    },
    "workers.dev": {
        "title": "Report hosting abuse to Cloudflare",
        "email": "",
        "url": "https://abuse.cloudflare.com/",
        "subject_prefix": "Suspected phishing page hosted on Cloudflare Workers",
    },
}

SUSPICIOUS_JS_TERMS = {
    "fetch(", "axios.", "session_id", "sessionid", "qr_link", "qr_code_login",
    "encrypted_blob", "poll", "create", "bearer", "authorization", "supabase.co",
    "functions/v1", "window.location", "location.replace", "location.href",
    "telegram", "whatsapp", "m.me/", "setinterval", "settimeout", "localstorage",
    "document.cookie",
}

URL_REGEX = re.compile(r"""https?://[^\s"'<>\\)]+""", re.IGNORECASE)

MAX_EXTERNAL_JS_FILES = 5
MAX_EXTERNAL_JS_BYTES = 250_000


# -----------------------------
# URL / domain helpers
# -----------------------------

def normalise_url(raw_url: str) -> str:
    raw_url = raw_url.strip()

    if not raw_url:
        raise ValueError("Please enter a URL.")

    if not raw_url.startswith(("http://", "https://")):
        raw_url = "https://" + raw_url

    parsed = urlparse(raw_url)

    if not parsed.netloc:
        raise ValueError("That does not look like a valid URL.")

    return raw_url


def get_hostname(url: str) -> str:
    parsed = urlparse(url)
    return parsed.hostname.lower() if parsed.hostname else ""


def get_registered_domain(url_or_hostname: str) -> str:
    if url_or_hostname.startswith(("http://", "https://")):
        hostname = get_hostname(url_or_hostname)
    else:
        hostname = url_or_hostname.lower()

    extracted = tldextract.extract(hostname)

    if not extracted.domain or not extracted.suffix:
        return hostname

    return f"{extracted.domain}.{extracted.suffix}".lower()


def get_subdomain(url: str) -> str:
    hostname = get_hostname(url)
    extracted = tldextract.extract(hostname)
    return extracted.subdomain.lower()


def is_private_or_local_host(hostname: str) -> bool:
    if not hostname:
        return True

    lowered = hostname.lower()

    if lowered in {"localhost", "local", "0.0.0.0"}:
        return True

    try:
        ip = ipaddress.ip_address(lowered)
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
        )
    except ValueError:
        pass

    try:
        resolved_ips = socket.gethostbyname_ex(lowered)[2]
    except socket.gaierror:
        return False

    for ip in resolved_ips:
        ip_obj = ipaddress.ip_address(ip)
        if (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_reserved
            or ip_obj.is_multicast
        ):
            return True

    return False


def is_legit_brand_domain(registered_domain: str, brand: str) -> bool:
    legit_domains = LEGIT_BRAND_DOMAINS.get(brand, [])
    return any(
        registered_domain == legit_domain
        or registered_domain.endswith("." + legit_domain)
        for legit_domain in legit_domains
    )


def is_hosting_platform(registered_domain: str) -> bool:
    return registered_domain in HOSTING_PLATFORMS


def is_official_brand_domain(registered_domain: str) -> list[str]:
    official_for = []

    for brand, domains in LEGIT_BRAND_DOMAINS.items():
        if registered_domain in domains:
            official_for.append(brand)

    return official_for


# -----------------------------
# Fetching
# -----------------------------

def fetch_url(url: str):
    headers = {"User-Agent": "ScamSlyce/0.6 Safe Link Checker"}

    response = requests.get(
        url,
        headers=headers,
        allow_redirects=True,
        timeout=12,
    )

    return response


def fetch_text_limited(url: str, max_bytes: int = MAX_EXTERNAL_JS_BYTES) -> tuple[str, str]:
    headers = {"User-Agent": "ScamSlyce/0.6 Safe JS Inspector"}

    try:
        with requests.get(url, headers=headers, stream=True, timeout=12, allow_redirects=True) as response:
            content_type = response.headers.get("Content-Type", "")
            chunks = []
            total = 0

            for chunk in response.iter_content(chunk_size=8192):
                if not chunk:
                    continue

                total += len(chunk)

                if total > max_bytes:
                    break

                chunks.append(chunk)

            raw = b"".join(chunks)

            try:
                text = raw.decode(response.encoding or "utf-8", errors="replace")
            except LookupError:
                text = raw.decode("utf-8", errors="replace")

            return text, content_type

    except Exception:
        return "", ""


# -----------------------------
# HTML parsing
# -----------------------------

def extract_visible_text(html: str) -> str:
    soup = BeautifulSoup(html, "html.parser")

    for tag in soup(["script", "style", "meta", "noscript", "svg"]):
        tag.decompose()

    return soup.get_text(separator=" ", strip=True)


def extract_page_title(html: str) -> str:
    soup = BeautifulSoup(html, "html.parser")
    title = soup.find("title")

    if title and title.get_text(strip=True):
        return title.get_text(strip=True)

    return ""


def detect_forms(html: str) -> dict:
    soup = BeautifulSoup(html, "html.parser")

    forms = soup.find_all("form")
    inputs = soup.find_all("input")
    textareas = soup.find_all("textarea")
    buttons = soup.find_all("button")
    password_fields = soup.find_all("input", {"type": "password"})

    input_types = []
    for item in inputs:
        input_types.append(item.get("type", "text").lower())

    form_actions = []
    for form in forms:
        action = form.get("action")
        if action:
            form_actions.append(action)

    return {
        "form_count": len(forms),
        "input_count": len(inputs),
        "textarea_count": len(textareas),
        "button_count": len(buttons),
        "password_field_detected": len(password_fields) > 0,
        "input_types": sorted(set(input_types)),
        "form_actions": form_actions,
    }


def extract_embedded_links(html: str, base_url: str) -> dict:
    soup = BeautifulSoup(html, "html.parser")

    anchors = []
    scripts = []
    iframes = []
    forms = []

    for tag in soup.find_all("a", href=True):
        absolute = urljoin(base_url, tag.get("href"))
        label = tag.get_text(separator=" ", strip=True)
        anchors.append({"url": absolute, "label": label[:120]})

    for tag in soup.find_all("script", src=True):
        scripts.append(urljoin(base_url, tag.get("src")))

    for tag in soup.find_all("iframe", src=True):
        iframes.append(urljoin(base_url, tag.get("src")))

    for tag in soup.find_all("form", action=True):
        forms.append(urljoin(base_url, tag.get("action")))

    return {
        "anchors": unique_dicts_by_url(anchors),
        "scripts": unique_strings(scripts),
        "iframes": unique_strings(iframes),
        "forms": unique_strings(forms),
    }


def unique_strings(items: list[str], limit: int = 50) -> list[str]:
    seen = []
    for item in items:
        if item and item not in seen:
            seen.append(item)

    return seen[:limit]


def unique_dicts_by_url(items: list[dict], limit: int = 50) -> list[dict]:
    seen_urls = set()
    results = []

    for item in items:
        url = item.get("url")
        if url and url not in seen_urls:
            seen_urls.add(url)
            results.append(item)

    return results[:limit]


# -----------------------------
# JavaScript analysis
# -----------------------------

def analyse_javascript_text(js_text: str) -> dict:
    js_urls = unique_strings(URL_REGEX.findall(js_text), limit=80)

    found_terms = []
    lower_js = js_text.lower()

    for term in SUSPICIOUS_JS_TERMS:
        if term.lower() in lower_js:
            found_terms.append(term)

    return {
        "js_url_count": len(js_urls),
        "js_urls": js_urls,
        "suspicious_js_terms": sorted(found_terms),
    }


def extract_inline_js(html: str) -> str:
    soup = BeautifulSoup(html, "html.parser")

    script_texts = []
    for script in soup.find_all("script"):
        if script.string:
            script_texts.append(script.string)

    return "\n".join(script_texts)


def fetch_and_analyse_external_js(script_urls: list[str], page_url: str) -> dict:
    fetched_scripts = []
    combined_external_js = ""
    page_registered_domain = get_registered_domain(page_url)

    safe_script_urls = []

    for script_url in script_urls:
        if not script_url.startswith(("http://", "https://")):
            continue

        if get_registered_domain(script_url) != page_registered_domain:
            continue

        script_hostname = get_hostname(script_url)

        if is_private_or_local_host(script_hostname):
            continue

        safe_script_urls.append(script_url)

    for script_url in unique_strings(safe_script_urls, limit=MAX_EXTERNAL_JS_FILES):
        text, content_type = fetch_text_limited(script_url)

        fetched_scripts.append({
            "url": script_url,
            "content_type": content_type,
            "bytes_read": len(text.encode("utf-8", errors="replace")),
            "fetched": bool(text),
        })

        if text:
            combined_external_js += "\n" + text

    analysis = analyse_javascript_text(combined_external_js)

    return {
        "fetched_scripts": fetched_scripts,
        "combined_external_js_length": len(combined_external_js),
        "external_js_url_count": analysis["js_url_count"],
        "external_js_urls": analysis["js_urls"],
        "external_js_suspicious_terms": analysis["suspicious_js_terms"],
    }


def combine_js_analysis(inline_analysis: dict, external_analysis: dict) -> dict:
    all_urls = unique_strings(
        inline_analysis["js_urls"] + external_analysis["external_js_urls"],
        limit=100,
    )

    all_terms = sorted(
        set(inline_analysis["suspicious_js_terms"])
        | set(external_analysis["external_js_suspicious_terms"])
    )

    return {
        "js_url_count": len(all_urls),
        "js_urls": all_urls,
        "suspicious_js_terms": all_terms,
        "inline_js_url_count": inline_analysis["js_url_count"],
        "inline_js_urls": inline_analysis["js_urls"],
        "inline_suspicious_js_terms": inline_analysis["suspicious_js_terms"],
        "external_js": external_analysis,
    }


# -----------------------------
# Signal detection
# -----------------------------

def detect_suspicious_words(url: str, html: str, message_text: str) -> list[str]:
    visible_text = extract_visible_text(html)
    combined = f"{url} {message_text} {visible_text[:5000]}".lower()

    found = []

    for word in SUSPICIOUS_WORDS:
        if word in combined:
            found.append(word)

    return sorted(found)


def detect_brand_impersonation(url: str, html: str, message_text: str) -> list[dict]:
    hostname = get_hostname(url)
    path = urlparse(url).path.lower()
    registered_domain = get_registered_domain(url)
    visible_text = extract_visible_text(html)
    title = extract_page_title(html)

    combined = f"{hostname} {path} {message_text} {title} {visible_text[:3000]}".lower()

    matches = []

    for brand, keywords in BRAND_KEYWORDS.items():
        for keyword in keywords:
            if keyword.lower() in combined:
                if not is_legit_brand_domain(registered_domain, brand):
                    matches.append({
                        "brand": brand,
                        "keyword": keyword,
                        "registered_domain": registered_domain,
                        "hostname": hostname,
                    })
                break

    return matches


def classify_embedded_links(links: dict, original_registered_domain: str) -> dict:
    all_urls = []

    for item in links["anchors"]:
        all_urls.append(item["url"])

    all_urls.extend(links["scripts"])
    all_urls.extend(links["iframes"])
    all_urls.extend(links["forms"])

    external_links = []
    official_brand_links = []
    hosting_platform_links = []

    for link in unique_strings(all_urls, limit=120):
        parsed = urlparse(link)

        if not parsed.scheme.startswith("http"):
            continue

        link_domain = get_registered_domain(link)

        if link_domain != original_registered_domain:
            external_links.append(link)

        official_brands = is_official_brand_domain(link_domain)

        if official_brands:
            official_brand_links.append({
                "url": link,
                "domain": link_domain,
                "brands": official_brands,
            })

        if is_hosting_platform(link_domain):
            hosting_platform_links.append(link)

    return {
        "external_links": unique_strings(external_links, limit=60),
        "official_brand_links": official_brand_links[:30],
        "hosting_platform_links": unique_strings(hosting_platform_links, limit=30),
    }


def classify_js_urls(js_urls: list[str], original_registered_domain: str) -> dict:
    external_js_urls = []
    official_brand_js_urls = []
    hosting_platform_js_urls = []
    api_like_urls = []

    for url in js_urls:
        parsed = urlparse(url)

        if not parsed.scheme.startswith("http"):
            continue

        registered_domain = get_registered_domain(url)

        if registered_domain != original_registered_domain:
            external_js_urls.append(url)

        official_brands = is_official_brand_domain(registered_domain)

        if official_brands:
            official_brand_js_urls.append({
                "url": url,
                "domain": registered_domain,
                "brands": official_brands,
            })

        if is_hosting_platform(registered_domain):
            hosting_platform_js_urls.append(url)

        if any(marker in url.lower() for marker in ["/api/", "/functions/", "functions/v1", "session", "poll", "create"]):
            api_like_urls.append(url)

    return {
        "external_js_urls": unique_strings(external_js_urls, limit=60),
        "official_brand_js_urls": official_brand_js_urls[:30],
        "hosting_platform_js_urls": unique_strings(hosting_platform_js_urls, limit=30),
        "api_like_urls": unique_strings(api_like_urls, limit=40),
    }


def detect_qr_session_pattern(result: dict) -> bool:
    suspicious_terms = set(result["js_analysis"]["suspicious_js_terms"])

    qr_terms = {"qr_link", "qr_code_login", "encrypted_blob"}
    session_terms = {"session_id", "sessionid", "poll", "create"}
    backend_terms = {"supabase.co", "functions/v1"}

    has_qr = bool(qr_terms.intersection(suspicious_terms))
    has_session = bool(session_terms.intersection(suspicious_terms))
    has_backend = bool(backend_terms.intersection(suspicious_terms))

    official_qr_link_in_page = any(
        "facebook.com/qr_code_login" in item["url"]
        for item in result["link_classification"]["official_brand_links"]
    )

    official_qr_link_in_js = any(
        "facebook.com/qr_code_login" in item["url"]
        for item in result["js_url_classification"]["official_brand_js_urls"]
    )

    return (
        (has_qr and has_session)
        or (has_qr and has_backend)
        or ((official_qr_link_in_page or official_qr_link_in_js) and (has_session or has_backend))
    )



def get_high_risk_js_terms(result: dict) -> list[str]:
    high_risk_terms = {
        "qr_link",
        "qr_code_login",
        "encrypted_blob",
        "session_id",
        "sessionid",
        "bearer",
        "authorization",
        "supabase.co",
        "functions/v1",
        "document.cookie",
        "localstorage",
    }

    found = []
    for term in result["js_analysis"]["suspicious_js_terms"]:
        if term.lower() in high_risk_terms:
            found.append(term)

    return sorted(found)


def has_meaningful_js_signal(result: dict) -> bool:
    high_risk_terms = get_high_risk_js_terms(result)

    return bool(
        high_risk_terms
        or result["qr_session_pattern_detected"]
        or result["js_url_classification"]["api_like_urls"]
        or result["js_url_classification"]["hosting_platform_js_urls"]
    )


def has_suspicious_context(result: dict) -> bool:
    return bool(
        result["brand_impersonation"]
        or result["is_shortener"]
        or result["final_domain"] != result["original_domain"]
        or result["qr_session_pattern_detected"]
        or result["hosted_platform_detected"]
    )


# -----------------------------
# Scoring
# -----------------------------

def score_result(findings: dict) -> tuple[int, str]:
    score = 0

    suspicious_context = has_suspicious_context(findings)
    meaningful_js = has_meaningful_js_signal(findings)
    high_risk_js_terms = get_high_risk_js_terms(findings)

    # Strong URL/domain indicators
    if findings["is_shortener"]:
        score += 20

    if findings["final_domain"] != findings["original_domain"]:
        score += 20

    if findings["brand_impersonation"]:
        score += 35

    if findings["hosted_platform_detected"] and findings["brand_impersonation"]:
        score += 10

    if findings["subdomain"] and findings["brand_impersonation"]:
        if any(
            word in findings["subdomain"]
            for word in ["login", "verify", "secure", "account", "support", "status", "center", "centre"]
        ):
            score += 10

    # Redirects are only meaningful if they hide/change destination or happen in suspicious context.
    if findings["redirect_count"] > 0:
        if findings["final_domain"] != findings["original_domain"] or findings["is_shortener"]:
            score += 15
        elif suspicious_context:
            score += 5

    if findings["redirect_count"] >= 3 and suspicious_context:
        score += 10

    # Forms are normal on many sites. Score only when they collect credentials or appear in suspicious context.
    if findings["forms"]["password_field_detected"]:
        score += 30
    elif findings["forms"]["form_count"] > 0 and suspicious_context:
        score += 10

    # HTTP is a weak signal by itself, stronger in suspicious context.
    if findings["uses_http"]:
        score += 10 if suspicious_context else 5

    # Suspicious wording is only weak evidence. It needs multiple terms or suspicious context.
    if len(findings["suspicious_words"]) >= 3 and suspicious_context:
        score += 10
    elif len(findings["suspicious_words"]) >= 5:
        score += 5

    # External links/CDNs are normal. Score only with suspicious context.
    if findings["link_classification"]["external_links"] and suspicious_context:
        score += 5

    if findings["link_classification"]["official_brand_links"] and findings["brand_impersonation"]:
        score += 15

    # JavaScript is noisy. Generic terms like create/location.href/setTimeout are normal.
    # Score only high-risk JS indicators or backend/session URLs.
    if meaningful_js:
        if high_risk_js_terms:
            score += 15

        if findings["js_url_classification"]["api_like_urls"]:
            score += 15

        if findings["js_url_classification"]["hosting_platform_js_urls"] and suspicious_context:
            score += 10

        if findings["js_analysis"]["external_js"]["fetched_scripts"] and suspicious_context:
            score += 5

    if findings["qr_session_pattern_detected"]:
        score += 35

    score = min(score, 100)

    if score <= 20:
        level = "Low"
    elif score <= 45:
        level = "Suspicious"
    elif score <= 70:
        level = "High"
    else:
        level = "Very High"

    return score, level


# -----------------------------
# Main analysis
# -----------------------------

def analyse_url(raw_url: str, message_text: str = "") -> dict:
    url = normalise_url(raw_url)
    parsed = urlparse(url)

    if is_private_or_local_host(parsed.hostname):
        raise ValueError("This URL points to a private, local, or internal address. ScamSlyce will not scan it.")

    original_domain = get_registered_domain(url)
    hostname = get_hostname(url)
    subdomain = get_subdomain(url)
    uses_http = parsed.scheme == "http"

    response = fetch_url(url)

    final_url = response.url
    final_domain = get_registered_domain(final_url)
    redirect_chain = [r.url for r in response.history]
    redirect_count = len(redirect_chain)

    content_type = response.headers.get("Content-Type", "")
    html = response.text if "text/html" in content_type else ""

    forms = detect_forms(html)
    embedded_links = extract_embedded_links(html, final_url)

    inline_js = extract_inline_js(html)
    inline_js_analysis = analyse_javascript_text(inline_js)

    external_js_analysis = fetch_and_analyse_external_js(
        embedded_links["scripts"],
        final_url,
    )

    js_analysis = combine_js_analysis(
        inline_js_analysis,
        external_js_analysis,
    )

    link_classification = classify_embedded_links(embedded_links, final_domain)
    js_url_classification = classify_js_urls(js_analysis["js_urls"], final_domain)

    findings = {
        "input_url": raw_url,
        "message_text": message_text.strip(),
        "normalised_url": url,
        "final_url": final_url,
        "original_domain": original_domain,
        "final_domain": final_domain,
        "hostname": hostname,
        "subdomain": subdomain,
        "status_code": response.status_code,
        "content_type": content_type,
        "page_title": extract_page_title(html),
        "redirect_chain": redirect_chain,
        "redirect_count": redirect_count,
        "is_shortener": original_domain in KNOWN_SHORTENERS,
        "uses_http": uses_http,
        "hosted_platform_detected": is_hosting_platform(original_domain),
        "forms": forms,
        "embedded_links": embedded_links,
        "link_classification": link_classification,
        "js_analysis": js_analysis,
        "js_url_classification": js_url_classification,
        "brand_impersonation": detect_brand_impersonation(url, html, message_text),
        "suspicious_words": detect_suspicious_words(url, html, message_text),
    }

    findings["qr_session_pattern_detected"] = detect_qr_session_pattern(findings)

    score, level = score_result(findings)
    findings["risk_score"] = score
    findings["risk_level"] = level

    return findings


# -----------------------------
# User action guidance
# -----------------------------

def identify_likely_brands(result: dict) -> list[str]:
    return sorted({item["brand"] for item in result["brand_impersonation"]})


def build_action_plan(result: dict, user_situation: str) -> list[str]:
    low_risk = result["risk_level"] == "Low"

    if low_risk:
        actions = [
            "No major warning signs were detected by ScamSlyce's basic passive checks.",
            "Reporting is probably not necessary unless you still have a specific reason to be concerned.",
        ]

        if user_situation == "I only received the link/message":
            actions.append("If the message was unexpected, verify through the official website or app rather than relying only on the supplied link.")
        elif user_situation == "I clicked the link but did not enter details":
            actions.append("Because you clicked but did not enter details, no account recovery action is usually needed. Close the page if you are unsure.")
        elif user_situation == "I entered login details":
            actions.append("Because you entered login details, change the password through the official website or app if you have any doubt about the page.")
            actions.append("Check recent login activity and enable two-factor authentication if available.")
        elif user_situation == "I entered payment/card details":
            actions.append("Because you entered payment/card details, contact your bank/card provider if you have any doubt about the page.")
        elif user_situation == "I downloaded or opened a file":
            actions.append("Because you downloaded or opened a file, scan it with your security software and avoid opening it again if unsure.")
        elif user_situation == "I am reporting this on behalf of someone else":
            actions.append("Ask the affected person what they did with the link before deciding whether account recovery or reporting is needed.")

        return actions

    if user_situation == "I only received the link/message":
        actions = [
            "Do not click the link.",
            "Do not enter login details, payment information, or personal data on the page.",
            "Report the message through the platform where you received it, then delete it.",
            "Use the official website or app directly if you need to check the account or offer.",
        ]

    elif user_situation == "I clicked the link but did not enter details":
        actions = [
            "Close the page and do not interact with it further.",
            "Do not press buttons, scan QR codes, approve login prompts, download files, or submit forms.",
            "Use the official website or app directly if you need to check the account or offer.",
            "Report the link using the priority reporting actions below.",
        ]

    elif user_situation == "I entered login details":
        actions = [
            "Change the affected account password immediately using the official website or app, not the suspicious link.",
            "Log out of other sessions/devices if the official account settings allow it.",
            "Enable two-factor authentication if it is available.",
            "Check account recovery email addresses, phone numbers, connected devices, and recent login activity.",
            "If the same password is used anywhere else, change it on those accounts too.",
            "Report the phishing page using the priority reporting actions below.",
        ]

    elif user_situation == "I entered payment/card details":
        actions = [
            "Contact your bank/card provider immediately using the number on the back of your card or the official banking app.",
            "Ask whether the card should be frozen, replaced, or monitored for fraud.",
            "Do not communicate with anyone through the suspicious site about refunds, verification, or cancellation.",
            "Keep screenshots, the URL, and any messages as evidence.",
            "Report the page using the priority reporting actions below.",
        ]

    elif user_situation == "I downloaded or opened a file":
        actions = [
            "Do not open the file again.",
            "If the file was opened, disconnect from the network if you suspect infection.",
            "Run a security scan and consider getting help from someone technical if you are unsure.",
            "Preserve the file/link as evidence if safe to do so, but do not share it casually.",
            "Report the page using the priority reporting actions below.",
        ]

    elif user_situation == "I am reporting this on behalf of someone else":
        actions = [
            "Tell the affected person not to use the link.",
            "Ask whether they clicked it, entered credentials, entered payment details, downloaded a file, scanned a QR code, or approved a login prompt.",
            "If they entered credentials or payment details, help them take the relevant account or bank recovery steps.",
            "Use the copy-paste report below when contacting platforms, hosts, or abuse teams.",
        ]

    else:
        actions = [
            "Use the official website or app directly instead of using the supplied link.",
            "Report the link using the priority reporting actions below.",
        ]

    if result["qr_session_pattern_detected"] and user_situation not in {
        "I entered login details",
        "I entered payment/card details",
    }:
        actions.append("Do not scan any QR code or approve any login/session prompt connected to this page.")

    if result["qr_session_pattern_detected"] and user_situation == "I entered login details":
        actions.append("If you scanned a QR code or approved a login prompt, check active sessions/devices urgently and revoke anything unfamiliar.")

    return actions

def get_main_and_supporting_urls(result: dict) -> dict:
    supporting = []

    supporting.extend(result["link_classification"]["external_links"])
    supporting.extend(result["js_url_classification"]["api_like_urls"])
    supporting.extend(result["js_url_classification"]["hosting_platform_js_urls"])
    supporting.extend(result["js_url_classification"]["official_brand_js_urls"])

    supporting = [
        url for url in unique_strings(supporting, limit=30)
        if url != result["normalised_url"] and url != result["final_url"]
    ]

    return {
        "main_url": result["final_url"],
        "submitted_url": result["normalised_url"],
        "supporting_urls": supporting,
    }


def build_simple_summary(result: dict, user_situation: str = "") -> str:
    brands = identify_likely_brands(result)
    brand_text = ", ".join(brands) if brands else "a known brand or service"

    if result["risk_level"] == "Low":
        summary = "This link did not show major warning signs in this basic passive check.\n\n"

        if user_situation == "I only received the link/message":
            summary += "If the message was unexpected, it is still sensible to verify through the official website or app rather than relying only on the supplied link."
        elif user_situation == "I clicked the link but did not enter details":
            summary += "Because no details were entered, no account recovery action is usually needed. Close the page if you are unsure."
        elif user_situation == "I entered login details":
            summary += "Because login details were entered, change the password through the official website or app if you have any doubt about the page."
        elif user_situation == "I entered payment/card details":
            summary += "Because payment/card details were entered, contact your bank/card provider if you have any doubt about the page."
        elif user_situation == "I downloaded or opened a file":
            summary += "Because a file was downloaded or opened, scan it with security software if you are unsure."
        else:
            summary += "Use normal caution with unexpected links and verify through official channels if unsure."

        return summary

    if result["risk_level"] in {"High", "Very High"}:
        opening = "This link shows strong warning signs."
    else:
        opening = "This link shows some suspicious signs."

    summary = f"{opening}\n\n"

    if brands:
        summary += (
            f"It appears to reference {brand_text}, but it is hosted on "
            f"{result['original_domain']}, not an official domain for that brand.\n\n"
        )

    if result["qr_session_pattern_detected"]:
        summary += (
            "The page also appears to contain QR/session-based login behaviour, "
            "which is a strong warning sign in a brand-impersonation context.\n\n"
        )

    if result["js_url_classification"]["api_like_urls"]:
        summary += (
            "JavaScript on the page contains API/session-like URLs, suggesting the page may be "
            "communicating with a backend service.\n\n"
        )

    if user_situation == "I entered login details":
        summary += (
            "Because login details were entered, change the affected password through the official website or app, "
            "check active sessions, and enable two-factor authentication if available."
        )
    elif user_situation == "I entered payment/card details":
        summary += (
            "Because payment/card details were entered, contact the bank/card provider immediately using official contact details."
        )
    elif user_situation == "I downloaded or opened a file":
        summary += (
            "Because a file was downloaded or opened, do not open it again and run a security check."
        )
    else:
        summary += (
            "Do not enter personal details, passwords, card details, or scan QR codes from this page. "
            "Use the official website or app directly instead."
        )

    return summary

def build_targeted_abuse_report(result: dict, user_situation: str, target_name: str = "abuse team") -> str:
    url_context = get_main_and_supporting_urls(result)
    brands = identify_likely_brands(result)
    brand_text = ", ".join(brands) if brands else "Not clearly identified"

    supporting_text = "None detected"
    if url_context["supporting_urls"]:
        supporting_text = "\n".join(f"- {url}" for url in url_context["supporting_urls"][:15])

    js_terms = "None detected"
    high_risk_js_terms = get_high_risk_js_terms(result)
    if high_risk_js_terms:
        js_terms = ", ".join(high_risk_js_terms[:15])
    elif has_meaningful_js_signal(result):
        js_terms = "Meaningful backend/session indicators detected, but no high-risk JS terms were isolated."

    api_urls = "None detected"
    if result["js_url_classification"]["api_like_urls"]:
        api_urls = "\n".join(f"- {url}" for url in result["js_url_classification"]["api_like_urls"][:10])

    reasons = []

    if result["brand_impersonation"]:
        reasons.append(
            f"The page appears to reference {brand_text}, but the registered domain is "
            f"{result['original_domain']}, not an official domain for that brand."
        )

    if result["hosted_platform_detected"]:
        reasons.append(
            f"The page is hosted on a general-purpose hosting platform/domain: {result['original_domain']}."
        )

    if result["qr_session_pattern_detected"]:
        reasons.append(
            "The page appears to contain QR/session-based login behaviour, which is suspicious in a brand-impersonation context."
        )

    if result["js_url_classification"]["api_like_urls"]:
        reasons.append(
            "JavaScript on the page contains API/session-like URLs, suggesting backend communication."
        )

    if result["js_analysis"]["suspicious_js_terms"]:
        reasons.append(
            "Suspicious JavaScript/session indicators were detected."
        )

    if not reasons:
        reasons.append("The URL was flagged by the reporter as suspicious and has been passively inspected.")

    reasons_text = "\n".join(f"- {reason}" for reason in reasons)

    return f"""Suspected scam/phishing/brand impersonation report

Main suspicious URL:
{url_context['main_url']}

Submitted URL:
{url_context['submitted_url']}

Risk level from ScamSlyce:
{result['risk_level']} ({result['risk_score']}/100)

Suspected impersonated brand:
{brand_text}

Page title:
{result['page_title'] or 'Not detected'}

User situation:
{user_situation}

Reason for report:
{reasons_text}

Technical indicators:
- Original registered domain: {result['original_domain']}
- Final registered domain: {result['final_domain']}
- Hostname: {result['hostname']}
- Subdomain: {result['subdomain'] or 'None'}
- HTTP status: {result['status_code']}
- Content-Type: {result['content_type'] or 'Unknown'}
- Redirect count: {result['redirect_count']}
- External embedded links found: {len(result['link_classification']['external_links'])}
- Script URLs found on page: {len(result['embedded_links']['scripts'])}
- Same-domain script files fetched and inspected: {len(result['js_analysis']['external_js']['fetched_scripts'])}
- JavaScript URLs found: {result['js_analysis']['js_url_count']}
- API/session-like JavaScript URLs found: {len(result['js_url_classification']['api_like_urls'])}
- Possible QR/session login flow detected: {result['qr_session_pattern_detected']}

Suspicious JavaScript/session terms:
{js_terms}

API/session-like URLs found:
{api_urls}

Supporting infrastructure / URLs found:
{supporting_text}

Requested action:
Please review this URL and associated infrastructure. If confirmed malicious or abusive, please suspend, remove, block, or otherwise mitigate the content.

Passive inspection note:
This report is based on passive inspection only. No login attempts, form submissions, brute forcing, vulnerability scanning, directory fuzzing, port scanning, or bypass activity were performed.
"""


def build_email_body(result: dict, user_situation: str, focus: str = "general") -> str:
    url_context = get_main_and_supporting_urls(result)
    summary = build_simple_summary(result, user_situation)

    supporting_text = "None detected"
    if url_context["supporting_urls"]:
        supporting_text = "\n".join(f"- {url}" for url in url_context["supporting_urls"][:15])

    indicators = []

    if result["brand_impersonation"]:
        brands = ", ".join(identify_likely_brands(result))
        indicators.append(f"Possible brand impersonation: {brands}")

    if result["hosted_platform_detected"]:
        indicators.append(f"Hosted on general-purpose platform: {result['original_domain']}")

    if result["js_analysis"]["external_js"]["fetched_scripts"]:
        indicators.append("Same-domain JavaScript was fetched and inspected passively")

    high_risk_js_terms = get_high_risk_js_terms(result)
    if high_risk_js_terms:
        indicators.append("High-risk JavaScript/session terms: " + ", ".join(high_risk_js_terms[:15]))
    elif has_meaningful_js_signal(result):
        indicators.append("JavaScript/backend indicators were found in a suspicious context")

    if result["js_url_classification"]["api_like_urls"]:
        indicators.append("API/session-like URLs found inside JavaScript")

    if result["qr_session_pattern_detected"]:
        indicators.append("Possible QR/session-based login flow detected")

    indicator_text = "\n".join(f"- {item}" for item in indicators) if indicators else "- No major indicators detected by basic analysis"

    body = f"""Hello,

I am reporting a suspected scam/phishing/brand impersonation page.

Main suspicious URL:
{url_context['main_url']}

Submitted URL:
{url_context['submitted_url']}

Risk level from ScamSlyce:
{result['risk_level']} ({result['risk_score']}/100)

Page title:
{result['page_title'] or 'Not detected'}

User situation:
{user_situation}

Plain-English summary:
{summary}

Observed indicators:
{indicator_text}

Supporting infrastructure / URLs found:
{supporting_text}

Technical evidence:
- Original registered domain: {result['original_domain']}
- Final registered domain: {result['final_domain']}
- Hostname: {result['hostname']}
- Subdomain: {result['subdomain'] or 'None'}
- HTTP status: {result['status_code']}
- Content-Type: {result['content_type'] or 'Unknown'}
- Redirect count: {result['redirect_count']}
- External embedded links found: {len(result['link_classification']['external_links'])}
- Official brand links found in HTML: {len(result['link_classification']['official_brand_links'])}
- Official brand URLs found in JavaScript: {len(result['js_url_classification']['official_brand_js_urls'])}
- Script URLs found on page: {len(result['embedded_links']['scripts'])}
- Same-domain script files fetched: {len(result['js_analysis']['external_js']['fetched_scripts'])}
- JavaScript URLs found: {result['js_analysis']['js_url_count']}
- API/session-like JavaScript URLs found: {len(result['js_url_classification']['api_like_urls'])}

This report is based on passive inspection only. No login attempts, form submissions, brute forcing, vulnerability scanning, directory fuzzing, port scanning, or bypass activity were performed.

Regards
"""

    if result["message_text"]:
        body += f"""

Message text supplied by reporter:
{result['message_text']}
"""

    return body


def build_mailto(to_email: str, subject: str, body: str) -> str:
    return f"mailto:{to_email}?subject={quote_plus(subject)}&body={quote_plus(body)}"


def build_priority_reporting_actions(result: dict, user_situation: str) -> list[dict]:
    url_context = get_main_and_supporting_urls(result)
    main_url = url_context["main_url"]
    actions = []

    netcraft_body = build_email_body(result, user_situation, focus="netcraft")
    actions.append({
        "priority": 1,
        "title": "Report the main suspicious URL to Netcraft",
        "why": "Good first reporting route for phishing, malware, fake shops, and suspicious URLs. Report the main page first and include supporting infrastructure as evidence.",
        "url": "https://report.netcraft.com/",
        "email": "scam@netcraft.com",
        "subject": f"Suspected malicious URL - {get_hostname(main_url)}",
        "body": netcraft_body,
        "paste": build_targeted_abuse_report(result, user_situation, target_name="Netcraft"),
    })

    brands = identify_likely_brands(result)
    next_priority = 2

    for brand in brands:
        config = BRAND_REPORTING.get(brand)
        if not config:
            continue

        subject = f"{config['subject_prefix']} - {get_hostname(main_url)}"
        body = build_email_body(result, user_situation, focus=brand)

        actions.append({
            "priority": next_priority,
            "title": config["title"],
            "why": f"ScamSlyce detected possible {brand} impersonation.",
            "url": config.get("url", ""),
            "email": config.get("email", ""),
            "subject": subject,
            "body": body,
            "paste": body,
        })
        next_priority += 1

    platform_domains = set()

    if result["hosted_platform_detected"]:
        platform_domains.add(result["original_domain"])

    for url in result["js_url_classification"]["hosting_platform_js_urls"]:
        platform_domains.add(get_registered_domain(url))

    if result["is_shortener"]:
        platform_domains.add(result["original_domain"])

    for domain in sorted(platform_domains):
        config = PLATFORM_REPORTING.get(domain)

        if not config:
            continue

        subject = f"{config['subject_prefix']} - {get_hostname(main_url)}"
        body = build_email_body(result, user_situation, focus=domain)

        if config.get("fallback_email"):
            body += f"\nFallback reporting contact if needed: {config['fallback_email']}\n"

        actions.append({
            "priority": next_priority,
            "title": config["title"],
            "why": f"ScamSlyce detected infrastructure connected to {domain}. Report the main URL and include supporting URLs as evidence.",
            "url": config.get("url", ""),
            "email": config.get("email", ""),
            "subject": subject,
            "body": body,
            "paste": body,
        })
        next_priority += 1

    actions.append({
        "priority": next_priority,
        "title": "Report the message where you received it",
        "why": "This helps stop the scam spreading through the original delivery route.",
        "url": "",
        "email": "",
        "subject": "",
        "body": "",
        "paste": "Use the in-app report option where the message appeared, such as Facebook, Messenger, Instagram, TikTok, X, WhatsApp, email, or SMS.",
    })
    next_priority += 1

    actions.append({
        "priority": next_priority,
        "title": "Optional: report the URL to Google Safe Browsing",
        "why": "This may help browsers and search results warn other users if the page is classified as unsafe.",
        "url": "https://www.google.com/safebrowsing/report_phish/",
        "email": "",
        "subject": "",
        "body": "",
        "paste": f"URL to report:\n{main_url}",
    })

    return actions


def build_report(result: dict, user_situation: str) -> str:
    return build_email_body(result, user_situation, focus="general")


# -----------------------------
# UI helpers / styling
# -----------------------------

def inject_rayza_theme():
    st.markdown(
        """
<style>
:root {
    --rayza-bg: #071111;
    --rayza-card: #101B1B;
    --rayza-card-2: #0D1717;
    --rayza-border: #1F3A3A;
    --rayza-text: #EAFDFD;
    --rayza-muted: #9FB8B8;
    --rayza-accent: #48F5E8;
    --rayza-accent-2: #8FFFEA;
    --rayza-danger: #FF5C7A;
    --rayza-warning: #FFC857;
    --rayza-success: #4ADE80;
}

html, body, [data-testid="stAppViewContainer"] {
    background: radial-gradient(circle at top, #0B2525 0%, #071111 42%, #030707 100%) !important;
    color: var(--rayza-text) !important;
}

[data-testid="stHeader"] {
    background: rgba(7, 17, 17, 0.85) !important;
}

[data-testid="stSidebar"] {
    background: #061010 !important;
}

.block-container {
    max-width: 1040px;
    padding-top: 2.5rem;
}

h1, h2, h3, h4, h5, h6, p, li, label, span, div {
    color: var(--rayza-text);
}

.stCaptionContainer, .caption, small {
    color: var(--rayza-muted) !important;
}

a {
    color: var(--rayza-accent) !important;
}

div[data-testid="stTextInput"] input,
textarea,
div[data-baseweb="select"] > div {
    background-color: #0B1515 !important;
    color: var(--rayza-text) !important;
    border: 1px solid var(--rayza-border) !important;
    border-radius: 12px !important;
}

textarea {
    font-family: "Inter", sans-serif !important;
}

.stButton button {
    background: linear-gradient(135deg, #1EDFD2, #48F5E8) !important;
    color: #031010 !important;
    border: none !important;
    border-radius: 12px !important;
    font-weight: 700 !important;
    padding: 0.65rem 1.2rem !important;
    box-shadow: 0 0 20px rgba(72,245,232,0.18);
}

.stButton button:hover {
    box-shadow: 0 0 30px rgba(72,245,232,0.35);
    transform: translateY(-1px);
}

[data-testid="stMetric"] {
    background: linear-gradient(180deg, rgba(16,27,27,0.96), rgba(9,18,18,0.96));
    border: 1px solid var(--rayza-border);
    border-radius: 16px;
    padding: 1rem;
    box-shadow: 0 0 22px rgba(72,245,232,0.06);
}

[data-testid="stMetricValue"] {
    color: var(--rayza-accent) !important;
}

div[data-testid="stExpander"] {
    background: rgba(16,27,27,0.88) !important;
    border: 1px solid var(--rayza-border) !important;
    border-radius: 14px !important;
}

div[data-testid="stExpander"] details summary {
    color: var(--rayza-text) !important;
}

.stTabs [data-baseweb="tab-list"] {
    gap: 0.4rem;
}

.stTabs [data-baseweb="tab"] {
    background: #0B1515;
    border: 1px solid var(--rayza-border);
    border-radius: 12px 12px 0 0;
    color: var(--rayza-muted);
    padding: 0.6rem 1rem;
}

.stTabs [aria-selected="true"] {
    background: #102323 !important;
    color: var(--rayza-accent) !important;
    border-bottom: 1px solid var(--rayza-accent) !important;
}

pre, code {
    background-color: #081313 !important;
    color: #BFFDF8 !important;
    border: 1px solid #183030 !important;
    border-radius: 10px !important;
}

.rayza-hero {
    background: linear-gradient(135deg, rgba(16,27,27,0.94), rgba(8,18,18,0.94));
    border: 1px solid rgba(72,245,232,0.25);
    border-radius: 22px;
    padding: 1.4rem 1.6rem;
    margin-bottom: 1.2rem;
    box-shadow: 0 0 36px rgba(72,245,232,0.08);
}

.rayza-title {
    font-size: 2.4rem;
    font-weight: 800;
    letter-spacing: -0.03em;
    margin-bottom: 0.25rem;
}

.rayza-accent {
    color: var(--rayza-accent);
}

.rayza-subtitle {
    color: var(--rayza-muted);
    font-size: 1rem;
    margin-bottom: 0;
}

.result-card {
    background: rgba(16,27,27,0.92);
    border: 1px solid rgba(72,245,232,0.18);
    border-radius: 18px;
    padding: 1rem 1.1rem;
    margin: 0.7rem 0 1rem 0;
    box-shadow: 0 0 24px rgba(72,245,232,0.05);
}

.risk-low {
    border-color: rgba(74,222,128,0.65);
    box-shadow: 0 0 28px rgba(74,222,128,0.08);
}

.risk-suspicious {
    border-color: rgba(255,200,87,0.65);
    box-shadow: 0 0 28px rgba(255,200,87,0.08);
}

.risk-high, .risk-very-high {
    border-color: rgba(255,92,122,0.72);
    box-shadow: 0 0 30px rgba(255,92,122,0.12);
}

.risk-label {
    font-size: 1.15rem;
    font-weight: 800;
}

.risk-low .risk-label {
    color: var(--rayza-success);
}

.risk-suspicious .risk-label {
    color: var(--rayza-warning);
}

.risk-high .risk-label,
.risk-very-high .risk-label {
    color: var(--rayza-danger);
}

.muted {
    color: var(--rayza-muted);
}

.url-chip {
    display: inline-block;
    background: #071313;
    border: 1px solid var(--rayza-border);
    color: #BFFDF8;
    border-radius: 999px;
    padding: 0.3rem 0.65rem;
    margin-top: 0.3rem;
    font-family: monospace;
    font-size: 0.85rem;
}

/* Fix Streamlit dark-mode clashes for dropdowns, popovers and expander headers */
div[data-baseweb="popover"],
div[data-baseweb="popover"] > div,
div[data-baseweb="menu"],
ul[role="listbox"],
div[role="listbox"] {
    background-color: #0B1515 !important;
    color: #EAFDFD !important;
    border: 1px solid #1F3A3A !important;
}

li[role="option"],
div[role="option"] {
    background-color: #0B1515 !important;
    color: #EAFDFD !important;
}

li[role="option"]:hover,
div[role="option"]:hover,
li[aria-selected="true"],
div[aria-selected="true"] {
    background-color: #102323 !important;
    color: #48F5E8 !important;
}

div[data-baseweb="select"] span,
div[data-baseweb="select"] div {
    color: #EAFDFD !important;
}

div[data-testid="stExpander"] details summary,
div[data-testid="stExpander"] details summary:hover {
    background-color: #102323 !important;
    color: #EAFDFD !important;
    border-radius: 12px !important;
}

div[data-testid="stExpander"] details summary * {
    color: #EAFDFD !important;
}

div[data-testid="stExpander"] {
    overflow: hidden !important;
}

/* Text areas and generated report boxes */
textarea,
textarea:focus {
    background-color: #071313 !important;
    color: #EAFDFD !important;
    border: 1px solid #48F5E8 !important;
    caret-color: #48F5E8 !important;
}

/* Browser autofill / selected text weirdness */
input:-webkit-autofill,
textarea:-webkit-autofill {
    -webkit-text-fill-color: #EAFDFD !important;
    box-shadow: 0 0 0px 1000px #071313 inset !important;
}

</style>
        """,
        unsafe_allow_html=True,
    )


def risk_class(level: str) -> str:
    return {
        "Low": "risk-low",
        "Suspicious": "risk-suspicious",
        "High": "risk-high",
        "Very High": "risk-very-high",
    }.get(level, "risk-suspicious")


def render_result_card(result: dict):
    css_class = risk_class(result["risk_level"])
    brands = ", ".join(identify_likely_brands(result)) or "No specific brand detected"
    key_concern = "No major concern detected"

    if result["brand_impersonation"] and result["qr_session_pattern_detected"]:
        key_concern = "Brand impersonation with QR/session login behaviour"
    elif result["brand_impersonation"]:
        key_concern = "Possible brand impersonation"
    elif result["qr_session_pattern_detected"]:
        key_concern = "Possible QR/session login behaviour"
    elif result["js_analysis"]["suspicious_js_terms"]:
        key_concern = "Suspicious JavaScript/session indicators"

    st.markdown(
        f"""
<div class="result-card {css_class}">
    <div class="risk-label">Risk level: {result['risk_level']} · {result['risk_score']}/100</div>
    <div class="muted">Main concern: {key_concern}</div>
    <div class="muted">Likely brand: {brands}</div>
    <div class="url-chip">{result['final_url']}</div>
</div>
        """,
        unsafe_allow_html=True,
    )


# -----------------------------
# Streamlit UI
# -----------------------------

st.set_page_config(
    page_title="ScamSlyce",
    page_icon="🛡️",
    layout="centered",
)

inject_rayza_theme()

st.image("scamslyce_banner.png", use_container_width=True)

st.write(
    "Paste a suspicious link below. ScamSlyce performs safe passive checks, explains any warning signs in plain English, and prepares an abuse report for easy reporting."
)

st.caption("No logins, form submissions, or intrusive scans are performed.")

st.warning(
    "Do not submit private links, password reset links, magic login links, banking session links, "
    "internal company URLs, or any URL containing personal tokens or sensitive information."
)

with st.expander("What ScamSlyce does and does not do"):
    st.write(
        """
        ScamSlyce checks visible warning signs such as suspicious domains, redirects, embedded links,
        forms, brand impersonation clues, and basic JavaScript/session indicators.

        It can fetch and inspect a small number of same-domain JavaScript files because many scam pages
        hide important behaviour in bundled JavaScript.

        It does **not** prove a page is safe or malicious. It does not submit forms, test credentials,
        brute force, fuzz directories, scan ports, or bypass protections.
        """
    )

url_input = st.text_input("Suspicious URL", placeholder="https://example.com")

message_text = st.text_area(
    "Optional: paste the message that came with the link",
    placeholder="Example: Your Facebook page will be disabled. Appeal here...",
    height=120,
)

user_situation = st.selectbox(
    "What happened?",
    [
        "I only received the link/message",
        "I clicked the link but did not enter details",
        "I entered login details",
        "I entered payment/card details",
        "I downloaded or opened a file",
        "I am reporting this on behalf of someone else",
    ],
)

analyse_button = st.button("Analyse Link")

if analyse_button:
    try:
        with st.spinner("Checking link safely..."):
            result = analyse_url(url_input, message_text)

        render_result_card(result)

        col1, col2, col3 = st.columns(3)
        col1.metric("Risk score", f"{result['risk_score']} / 100")
        col2.metric("Registered domain", result["original_domain"])
        col3.metric("HTTP status", result["status_code"])

        tab_summary, tab_actions, tab_report, tab_evidence = st.tabs(
            ["Summary", "What to do", "Report it", "Technical evidence"]
        )

        with tab_summary:
            st.subheader("Plain-English Summary")

            summary_points = []

            if result["page_title"]:
                summary_points.append(f"The page title is: '{result['page_title']}'.")

            if result["is_shortener"]:
                summary_points.append("This URL uses a known link shortener. That does not prove it is malicious, but it hides the final destination.")

            if result["hosted_platform_detected"]:
                summary_points.append(
                    f"This appears to be hosted on a general-purpose app/site hosting platform: {result['original_domain']}. "
                    "That does not prove abuse, but it can be relevant when combined with brand impersonation."
                )

            if result["redirect_count"] > 0:
                summary_points.append(f"This link redirects {result['redirect_count']} time(s) before reaching the final page.")

            if result["final_domain"] != result["original_domain"]:
                summary_points.append("The final registered domain is different from the original registered domain. This can be common in scam or phishing chains.")

            if result["brand_impersonation"]:
                brands = ", ".join(identify_likely_brands(result))
                summary_points.append(
                    f"The URL/page/message appears to reference {brands}, but the registered domain is {result['original_domain']}. "
                    "This can indicate brand impersonation."
                )

            if result["subdomain"]:
                summary_points.append(
                    f"The URL uses the subdomain '{result['subdomain']}'. Attackers often use convincing subdomains to make a link look official."
                )

            if result["forms"]["password_field_detected"]:
                summary_points.append("The page appears to contain a password field. Be very cautious before entering credentials.")
            elif result["forms"]["form_count"] > 0 and result["risk_level"] != "Low":
                summary_points.append(
                    f"The page contains {result['forms']['form_count']} form(s) and {result['forms']['input_count']} input field(s). "
                    "Forms are common on normal sites, but they are more relevant when combined with other warning signs."
                )

            fetched_scripts = result["js_analysis"]["external_js"]["fetched_scripts"]
            if fetched_scripts:
                summary_points.append(
                    f"ScamSlyce fetched and inspected {len(fetched_scripts)} same-domain JavaScript file(s). "
                    "This is useful because scam pages often hide behaviour in bundled JavaScript."
                )

            if has_meaningful_js_signal(result):
                high_risk_terms = get_high_risk_js_terms(result)
                if high_risk_terms:
                    terms = ", ".join(high_risk_terms[:12])
                    summary_points.append(f"High-risk JavaScript/session indicators were detected: {terms}.")
                elif result["risk_level"] != "Low":
                    summary_points.append("JavaScript/backend indicators were detected in a suspicious context.")

            if result["js_url_classification"]["api_like_urls"]:
                summary_points.append("API/session-like URLs were found inside JavaScript. This can indicate that the page is communicating with a backend service.")

            if result["qr_session_pattern_detected"]:
                summary_points.append("Possible QR/session-based login behaviour was detected. In a brand-impersonation context, this is a strong warning sign.")

            if result["uses_http"]:
                summary_points.append("The original link uses HTTP instead of HTTPS.")

            if result["suspicious_words"]:
                words = ", ".join(result["suspicious_words"][:10])
                summary_points.append(f"Suspicious or scam-related wording was detected: {words}.")

            if not summary_points:
                summary_points.append("No major warning signs were detected by this basic version. This does not guarantee the link is safe.")

            for point in summary_points:
                st.write(f"- {point}")

            st.subheader("Simple Summary to Share")
            simple_summary = build_simple_summary(result, user_situation)
            st.text_area("Simple summary", simple_summary, height=180)

        with tab_actions:
            st.subheader("What You Should Do Next")
            for action in build_action_plan(result, user_situation):
                st.write(f"- {action}")

            st.subheader("Main URL and Supporting Infrastructure")
            url_context = get_main_and_supporting_urls(result)

            if result["risk_level"] == "Low":
                st.write("**Checked URL:**")
                st.code(url_context["main_url"])

                if url_context["supporting_urls"]:
                    st.write("**Additional linked/resource URLs observed:**")
                    st.caption("These are not automatically suspicious. Many normal websites link to external resources.")
                    for supporting_url in url_context["supporting_urls"][:15]:
                        st.code(supporting_url)
                else:
                    st.write("No separate supporting infrastructure URLs were detected.")
            else:
                st.write("**Main suspicious URL to report first:**")
                st.code(url_context["main_url"])

                if url_context["supporting_urls"]:
                    st.write("**Supporting infrastructure found. Include these as evidence where useful:**")
                    for supporting_url in url_context["supporting_urls"][:15]:
                        st.code(supporting_url)
                else:
                    st.write("No separate supporting infrastructure URLs were detected.")

        with tab_report:
            if result["risk_level"] == "Low":
                st.subheader("Reporting Not Usually Needed")
                st.write(
                    "ScamSlyce did not detect major warning signs in this basic passive check. "
                    "For a normal low-risk result, reporting is probably not necessary."
                )
                st.write(
                    "If you still believe the link is suspicious because of the message context, sender behaviour, "
                    "or something ScamSlyce cannot see, you can still use the optional report below."
                )

                with st.expander("Optional: show reporting actions anyway"):
                    reporting_actions = build_priority_reporting_actions(result, user_situation)

                    for action in reporting_actions:
                        with st.expander(f"{action['priority']}. {action['title']}", expanded=False):
                            st.write(action["why"])

                            if action["url"]:
                                st.markdown(f"**Open report page:** {action['url']}")

                            if action["email"]:
                                st.write(f"**Email:** {action['email']}")
                                st.write(f"**Subject:** {action['subject']}")
                                st.caption("Copy the email address, subject, and message manually. ScamSlyce does not open email apps automatically.")

                            st.text_area(
                                f"Text to paste for action {action['priority']}",
                                action["paste"],
                                height=220,
                                key=f"report_action_{action['priority']}",
                            )

                st.subheader("Optional Copy-Paste Report")
                report = build_report(result, user_situation)
                st.text_area("Optional report text", report, height=420)

            else:
                st.subheader("Priority Reporting Actions")
                st.write("Start with the first action. Use the generated text boxes below so the user is not left guessing what to send.")

                reporting_actions = build_priority_reporting_actions(result, user_situation)

                for action in reporting_actions:
                    with st.expander(f"{action['priority']}. {action['title']}", expanded=action["priority"] <= 2):
                        st.write(action["why"])

                        if action["url"]:
                            st.markdown(f"**Open report page:** {action['url']}")

                        if action["email"]:
                            st.write(f"**Email:** {action['email']}")
                            st.write(f"**Subject:** {action['subject']}")
                            st.caption("Copy the email address, subject, and message manually. ScamSlyce does not open email apps automatically.")

                        st.text_area(
                            f"Text to paste for action {action['priority']}",
                            action["paste"],
                            height=220,
                            key=f"report_action_{action['priority']}",
                        )

                st.subheader("Full Copy-Paste Abuse Report")
                report = build_report(result, user_situation)
                st.text_area("Full report text", report, height=520)

        with tab_evidence:
            st.subheader("Technical Evidence")

            st.write(f"**Original URL:** {result['normalised_url']}")
            st.write(f"**Final URL:** {result['final_url']}")
            st.write(f"**Original registered domain:** {result['original_domain']}")
            st.write(f"**Final registered domain:** {result['final_domain']}")
            st.write(f"**Hostname:** {result['hostname']}")
            st.write(f"**Subdomain:** {result['subdomain'] or 'None'}")
            st.write(f"**HTTP status:** {result['status_code']}")
            st.write(f"**Content-Type:** {result['content_type'] or 'Unknown'}")
            st.write(f"**Page title:** {result['page_title'] or 'Not detected'}")
            st.write(f"**Redirect count:** {result['redirect_count']}")

            if result["redirect_chain"]:
                st.write("**Redirect chain:**")
                for redirect in result["redirect_chain"]:
                    st.code(redirect)

            if result["brand_impersonation"]:
                st.write("**Possible brand impersonation:**")
                for item in result["brand_impersonation"]:
                    st.write(
                        f"- Keyword `{item['keyword']}` suggests `{item['brand']}`, "
                        f"but the registered domain is `{item['registered_domain']}`."
                    )

            st.write("**Forms and inputs:**")
            st.write(f"- Forms: {result['forms']['form_count']}")
            st.write(f"- Inputs: {result['forms']['input_count']}")
            st.write(f"- Textareas: {result['forms']['textarea_count']}")
            st.write(f"- Buttons: {result['forms']['button_count']}")
            st.write(f"- Password field detected: {result['forms']['password_field_detected']}")
            st.write(f"- Input types: {', '.join(result['forms']['input_types']) or 'None detected'}")

            if result["embedded_links"]["anchors"]:
                st.write("**Page links found:**")
                for item in result["embedded_links"]["anchors"][:20]:
                    label = f" — {item['label']}" if item["label"] else ""
                    st.code(f"{item['url']}{label}")

            if result["embedded_links"]["scripts"]:
                st.write("**Script sources found:**")
                for script in result["embedded_links"]["scripts"][:20]:
                    st.code(script)

            if result["js_analysis"]["external_js"]["fetched_scripts"]:
                st.write("**Same-domain JavaScript files fetched and inspected:**")
                for script in result["js_analysis"]["external_js"]["fetched_scripts"]:
                    status = "fetched" if script["fetched"] else "not fetched"
                    st.code(
                        f"{script['url']}\nStatus: {status}\nBytes read: {script['bytes_read']}\nContent-Type: {script['content_type'] or 'Unknown'}"
                    )

            if result["embedded_links"]["iframes"]:
                st.write("**Iframes found:**")
                for iframe in result["embedded_links"]["iframes"][:10]:
                    st.code(iframe)

            if result["embedded_links"]["forms"]:
                st.write("**Form action URLs found:**")
                for form_url in result["embedded_links"]["forms"][:10]:
                    st.code(form_url)

            if result["link_classification"]["external_links"]:
                st.write("**External embedded links:**")
                for link in result["link_classification"]["external_links"][:25]:
                    st.code(link)

            if result["link_classification"]["official_brand_links"]:
                st.write("**Official brand links embedded in page HTML:**")
                for item in result["link_classification"]["official_brand_links"][:15]:
                    brands = ", ".join(item["brands"])
                    st.code(f"{item['url']}  [{brands}]")

            if result["js_analysis"]["js_urls"]:
                st.write("**URLs found inside JavaScript:**")
                for js_url in result["js_analysis"]["js_urls"][:30]:
                    st.code(js_url)

            if result["js_url_classification"]["api_like_urls"]:
                st.write("**API/session-like URLs found inside JavaScript:**")
                for api_url in result["js_url_classification"]["api_like_urls"][:20]:
                    st.code(api_url)

            if result["js_url_classification"]["hosting_platform_js_urls"]:
                st.write("**Hosted-platform URLs found inside JavaScript:**")
                for hosted_url in result["js_url_classification"]["hosting_platform_js_urls"][:20]:
                    st.code(hosted_url)

            if result["js_url_classification"]["official_brand_js_urls"]:
                st.write("**Official brand URLs found inside JavaScript:**")
                for item in result["js_url_classification"]["official_brand_js_urls"][:15]:
                    brands = ", ".join(item["brands"])
                    st.code(f"{item['url']}  [{brands}]")

            if result["js_analysis"]["suspicious_js_terms"]:
                st.write("**JavaScript/session terms observed:**")
                st.caption("Some of these are common on normal websites. They only become meaningful when combined with stronger indicators.")
                st.write(", ".join(result["js_analysis"]["suspicious_js_terms"]))

        st.divider()
        st.subheader("Feedback / Report an Issue")
        st.write(
            "ScamSlyce is still a prototype. Feedback is useful, especially false positives, missed scams, "
            "confusing wording, mobile layout problems, or reporting-action suggestions."
        )

        with st.expander("What to include in feedback"):
            st.write("- The URL you tested, unless it contains private tokens or sensitive data.")
            st.write("- Whether the result felt right or wrong.")
            st.write("- What ScamSlyce scored it.")
            st.write("- What device/browser you used.")
            st.write("- Any wording or advice that confused you.")

        st.info(
            "For now, send feedback manually or open an issue in the GitHub repo once it is published. "
            "Do not include passwords, private links, account recovery links, or personal tokens."
        )

    except Exception as e:
        st.error(str(e))
