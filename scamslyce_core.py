import ipaddress
import re
import socket
from urllib.parse import quote_plus, urljoin, urlparse

import requests
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

KNOWN_SAFE_DOMAINS = {
    "google.com",
    "youtube.com",
    "youtu.be",
    "github.com",
    "microsoft.com",
    "office.com",
    "live.com",
    "outlook.com",
    "apple.com",
    "icloud.com",
    "amazon.com",
    "amazon.co.uk",
    "paypal.com",
    "paypal.co.uk",
    "facebook.com",
    "meta.com",
    "instagram.com",
    "gov.uk",
    "jdsports.co.uk",
    "streamlit.app",
}

STRONG_SUSPICIOUS_WORDS = {
    "password",
    "credentials",
    "verify",
    "verification",
    "suspended",
    "disabled",
    "locked",
    "appeal",
    "urgent",
    "unusual activity",
    "copyright violation",
    "security warning",
    "account disabled",
    "account suspended",
    "login attempt",
}

MEDIUM_SUSPICIOUS_WORDS = {
    "login",
    "account",
    "secure",
    "security",
    "confirm",
    "payment",
    "wallet",
    "invoice",
    "authenticate",
    "authentication",
    "support",
    "review",
}

WEAK_SUSPICIOUS_WORDS = {
    "business",
    "manager",
    "limited",
    "update",
    "activity",
    "bonus",
    "reward",
}

SUSPICIOUS_WORDS = (
    STRONG_SUSPICIOUS_WORDS
    | MEDIUM_SUSPICIOUS_WORDS
    | WEAK_SUSPICIOUS_WORDS
)


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
    "Google": ["google.com", "gmail.com", "youtube.com", "youtu.be"],
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

SENSITIVE_INPUT_TERMS = {
    "email",
    "password",
    "pass",
    "passwd",
    "card",
    "cardnumber",
    "cvv",
    "cvc",
    "otp",
    "2fa",
    "token",
    "recovery",
    "phone",
    "business_id",
    "page_name",
}

SUSPICIOUS_PATH_INTENT_WORDS = {
    "login",
    "verify",
    "verification",
    "appeal",
    "security-check",
    "account-disabled",
    "account-suspended",
    "qr-session",
    "support",
    "copyright",
    "business",
    "recover",
    "reset",
    "unlock",
}

BRAND_LOOKALIKE_TARGETS = {
    "Meta/Facebook": ["facebook"],
    "Instagram": ["instagram"],
    "PayPal": ["paypal"],
    "Microsoft": ["microsoft"],
    "Google": ["google"],
    "Apple": ["apple"],
    "Amazon": ["amazon"],
}

LOOKALIKE_TRANSLATION = str.maketrans({
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "8": "b",
})

STRONG_JS_ENDPOINT_MARKERS = {
    "functions/v1",
    "session_id",
    "sessionid",
    "qr_link",
    "encrypted_blob",
    "webhook",
    "api.telegram.org/bot",
    "t.me/",
    "wa.me/",
    "api.whatsapp.com",
    "m.me/",
}

URL_REGEX = re.compile(r"""https?://[^\s"'<>\\)]+""", re.IGNORECASE)

MAX_EXTERNAL_JS_FILES = 5
MAX_EXTERNAL_JS_BYTES = 250_000
MAX_MAIN_RESPONSE_BYTES = 1_000_000
MAX_REDIRECTS = 5
ALLOWED_SCHEMES = {"http", "https"}


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


def is_expected_brand_relationship(registered_domain: str, brand: str) -> bool:
    """
    Some brands legitimately operate across multiple related domains.
    Example: YouTube pages commonly reference Google accounts, APIs, policies,
    and support pages. That should not count as Google impersonation.
    """
    trusted_relationships = {
        "Google": {"youtube.com", "youtu.be", "google.com", "gmail.com"},
        "Meta/Facebook": {"facebook.com", "fb.com", "messenger.com", "meta.com", "instagram.com"},
        "Instagram": {"instagram.com", "facebook.com", "meta.com"},
        "Microsoft": {"microsoft.com", "office.com", "outlook.com", "live.com"},
    }

    trusted_domains = trusted_relationships.get(brand, set())

    return any(
        registered_domain == trusted_domain
        or registered_domain.endswith("." + trusted_domain)
        for trusted_domain in trusted_domains
    )


def domains_share_known_organisation(domain_a: str, domain_b: str) -> bool:
    if domain_a == domain_b:
        return True

    for domains in LEGIT_BRAND_DOMAINS.values():
        if domain_a in domains and domain_b in domains:
            return True

    trusted_groups = [
        {"google.com", "gmail.com", "youtube.com", "youtu.be"},
        {"facebook.com", "fb.com", "messenger.com", "meta.com", "instagram.com"},
        {"microsoft.com", "office.com", "outlook.com", "live.com"},
        {"paypal.com", "paypal.co.uk"},
        {"amazon.com", "amazon.co.uk"},
        {"apple.com", "icloud.com"},
    ]

    return any(domain_a in group and domain_b in group for group in trusted_groups)


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

def validate_public_url(url: str) -> str:
    parsed = urlparse(url)

    if parsed.scheme not in ALLOWED_SCHEMES:
        raise ValueError("Only http and https URLs can be checked.")

    if not parsed.hostname:
        raise ValueError("URL does not contain a valid hostname.")

    if is_private_or_local_host(parsed.hostname):
        raise ValueError(
            "This URL points to a private, local, internal, reserved, or otherwise unsafe address. "
            "ScamSlyce will not scan it."
        )

    return url


def read_response_limited(response, max_bytes: int) -> bytes:
    chunks = []
    total = 0
    truncated = False

    for chunk in response.iter_content(chunk_size=8192):
        if not chunk:
            continue

        remaining = max_bytes - total

        if remaining <= 0:
            truncated = True
            break

        if len(chunk) > remaining:
            chunks.append(chunk[:remaining])
            total += remaining
            truncated = True
            break

        chunks.append(chunk)
        total += len(chunk)

    response.scamslyce_truncated = truncated
    return b"".join(chunks)


def safe_fetch_response(url: str, max_bytes: int, user_agent: str):
    current_url = validate_public_url(url)
    history = []

    session = requests.Session()
    session.trust_env = False

    headers = {
        "User-Agent": user_agent,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }

    for _ in range(MAX_REDIRECTS + 1):
        current_url = validate_public_url(current_url)

        response = session.get(
            current_url,
            headers=headers,
            allow_redirects=False,
            timeout=(5, 12),
            stream=True,
        )

        response._content = read_response_limited(response, max_bytes)
        response._content_consumed = True

        if response.is_redirect or response.is_permanent_redirect:
            location = response.headers.get("Location")

            if not location:
                response.history = history
                return response

            next_url = urljoin(current_url, location)
            validate_public_url(next_url)

            history.append(response)
            current_url = next_url
            continue

        response.history = history
        return response

    raise ValueError(f"Too many redirects. ScamSlyce stops after {MAX_REDIRECTS} redirects for safety.")


def fetch_url(url: str):
    return safe_fetch_response(
        url=url,
        max_bytes=MAX_MAIN_RESPONSE_BYTES,
        user_agent="ScamSlyce/0.7 Safe Link Checker",
    )


def fetch_text_limited(url: str, max_bytes: int = MAX_EXTERNAL_JS_BYTES) -> tuple[str, str]:
    try:
        response = safe_fetch_response(
            url=url,
            max_bytes=max_bytes,
            user_agent="ScamSlyce/0.7 Safe JS Inspector",
        )

        content_type = response.headers.get("Content-Type", "")

        try:
            text = response.content.decode(response.encoding or "utf-8", errors="replace")
        except LookupError:
            text = response.content.decode("utf-8", errors="replace")

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
    sensitive_input_fields = []
    for item in inputs:
        input_type = item.get("type", "text").lower()
        input_types.append(input_type)

        searchable_values = [
            input_type,
            item.get("name", ""),
            item.get("id", ""),
            item.get("placeholder", ""),
            item.get("aria-label", ""),
            item.get("autocomplete", ""),
        ]
        searchable = " ".join(searchable_values).lower()

        matched_terms = sorted(
            term for term in SENSITIVE_INPUT_TERMS
            if term in searchable
        )

        if matched_terms:
            sensitive_input_fields.append({
                "type": input_type,
                "name": item.get("name", ""),
                "id": item.get("id", ""),
                "matched_terms": matched_terms,
            })

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
        "sensitive_input_fields": sensitive_input_fields[:30],
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


def contains_brand_keyword(text: str, keyword: str) -> bool:
    keyword = keyword.lower()

    if not keyword:
        return False

    if " " in keyword or "." in keyword:
        return keyword in text

    return re.search(rf"(?<![a-z0-9]){re.escape(keyword)}(?![a-z0-9])", text) is not None


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
            if contains_brand_keyword(combined, keyword):
                if (
                    not is_legit_brand_domain(registered_domain, brand)
                    and not is_expected_brand_relationship(registered_domain, brand)
                ):
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


def classify_form_actions(form_urls: list[str], page_registered_domain: str) -> dict:
    external_form_actions = []

    for form_url in unique_strings(form_urls, limit=50):
        parsed = urlparse(form_url)

        if not parsed.scheme.startswith("http"):
            continue

        form_domain = get_registered_domain(form_url)

        if (
            form_domain != page_registered_domain
            and not domains_share_known_organisation(form_domain, page_registered_domain)
        ):
            external_form_actions.append(form_url)

    return {
        "external_form_actions": unique_strings(external_form_actions, limit=20),
    }


def detect_punycode_hostname(hostname: str) -> dict:
    labels = hostname.lower().split(".")
    punycode_labels = [label for label in labels if label.startswith("xn--")]

    return {
        "detected": bool(punycode_labels),
        "labels": punycode_labels,
    }


def detect_brand_digit_lookalikes(registered_domain: str) -> list[dict]:
    domain_name = registered_domain.split(".", 1)[0].lower()
    translated_domain_name = domain_name.translate(LOOKALIKE_TRANSLATION)
    matches = []

    if translated_domain_name == domain_name:
        return matches

    for brand, targets in BRAND_LOOKALIKE_TARGETS.items():
        if is_legit_brand_domain(registered_domain, brand):
            continue

        for target in targets:
            if target in translated_domain_name and target not in domain_name:
                matches.append({
                    "brand": brand,
                    "domain_text": domain_name,
                    "normalised_text": translated_domain_name,
                    "matched": target,
                })
                break

    return matches


def detect_path_intent(url: str) -> list[str]:
    path = urlparse(url).path.lower()
    normalised_path = path.replace("_", "-")

    found = []
    for word in SUSPICIOUS_PATH_INTENT_WORDS:
        if word in normalised_path:
            found.append(word)

    return sorted(found)


def classify_js_urls(js_urls: list[str], original_registered_domain: str) -> dict:
    external_js_urls = []
    official_brand_js_urls = []
    hosting_platform_js_urls = []
    api_like_urls = []
    strong_endpoint_urls = []

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

        lower_url = url.lower()

        if any(marker in lower_url for marker in ["/api/", "/functions/", "functions/v1", "session", "poll"]):
            api_like_urls.append(url)

        if any(marker in lower_url for marker in STRONG_JS_ENDPOINT_MARKERS):
            strong_endpoint_urls.append(url)

    return {
        "external_js_urls": unique_strings(external_js_urls, limit=60),
        "official_brand_js_urls": official_brand_js_urls[:30],
        "hosting_platform_js_urls": unique_strings(hosting_platform_js_urls, limit=30),
        "api_like_urls": unique_strings(api_like_urls, limit=40),
        "strong_endpoint_urls": unique_strings(strong_endpoint_urls, limit=40),
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

    if is_known_safe_domain(result) and not result["brand_impersonation"]:
        return False

    return (
        (has_qr and has_session)
        or (has_qr and has_backend)
        or ((official_qr_link_in_page or official_qr_link_in_js) and (has_session or has_backend))
    )




def is_known_safe_domain(result: dict) -> bool:
    domains = {
        result.get("original_domain", ""),
        result.get("final_domain", ""),
    }

    return any(domain in KNOWN_SAFE_DOMAINS for domain in domains)


def get_suspicious_word_categories(result: dict) -> dict:
    found = set(result.get("suspicious_words", []))

    return {
        "strong": sorted(found.intersection(STRONG_SUSPICIOUS_WORDS)),
        "medium": sorted(found.intersection(MEDIUM_SUSPICIOUS_WORDS)),
        "weak": sorted(found.intersection(WEAK_SUSPICIOUS_WORDS)),
    }


def get_high_risk_js_terms(result: dict) -> list[str]:
    # These are higher-value indicators. Generic JS terms like create,
    # setTimeout, location.href, and window.location are too common to score alone.
    high_risk_terms = {
        "qr_link",
        "qr_code_login",
        "encrypted_blob",
        "session_id",
        "sessionid",
        "bearer",
        "supabase.co",
        "functions/v1",
        "telegram",
        "whatsapp",
        "m.me/",
    }

    found = []
    for term in result["js_analysis"]["suspicious_js_terms"]:
        if term.lower() in high_risk_terms:
            found.append(term)

    return sorted(found)


def has_meaningful_js_signal(result: dict) -> bool:
    return bool(
        get_high_risk_js_terms(result)
        or result["qr_session_pattern_detected"]
        or result["js_url_classification"]["strong_endpoint_urls"]
        or result["js_url_classification"]["api_like_urls"]
        or result["js_url_classification"]["hosting_platform_js_urls"]
    )


def has_unexpected_final_domain_change(result: dict) -> bool:
    if result["final_domain"] == result["original_domain"]:
        return False

    return not domains_share_known_organisation(
        result["original_domain"],
        result["final_domain"],
    )


def has_suspicious_context(result: dict) -> bool:
    return bool(
        result["brand_impersonation"]
        or result["is_shortener"]
        or has_unexpected_final_domain_change(result)
        or result["punycode_hostname"]["detected"]
        or result["brand_digit_lookalikes"]
        or result["qr_session_pattern_detected"]
        or (
            result["hosted_platform_detected"]
            and bool(result["brand_impersonation"])
        )
    )


def has_strong_danger_indicator(result: dict) -> bool:
    return has_hard_danger_indicator(result)


def has_hard_danger_indicator(result: dict) -> bool:
    suspicious_context = has_suspicious_context(result)

    return bool(
        result["brand_impersonation"]
        or (result["is_shortener"] and has_unexpected_final_domain_change(result))
        or (
            result["hosted_platform_detected"]
            and bool(result["brand_impersonation"])
        )
        or result["punycode_hostname"]["detected"]
        or result["brand_digit_lookalikes"]
        or (result["qr_session_pattern_detected"] and suspicious_context)
        or (
            result["forms"]["password_field_detected"]
            and suspicious_context
        )
        or (
            result["forms"]["sensitive_input_fields"]
            and suspicious_context
        )
        or (
            result["form_action_classification"]["external_form_actions"]
            and suspicious_context
        )
        or (
            result["js_url_classification"]["api_like_urls"]
            and suspicious_context
        )
        or (
            result["js_url_classification"]["strong_endpoint_urls"]
            and suspicious_context
        )
        or (
            result["js_url_classification"]["hosting_platform_js_urls"]
            and suspicious_context
        )
    )


# -----------------------------
# Scoring
# -----------------------------

def score_result(findings: dict) -> tuple[int, str]:
    score = 0

    suspicious_context = has_suspicious_context(findings)
    unexpected_final_domain_change = has_unexpected_final_domain_change(findings)
    meaningful_js = has_meaningful_js_signal(findings)
    high_risk_js_terms = get_high_risk_js_terms(findings)
    word_categories = get_suspicious_word_categories(findings)

    # Strong URL/domain indicators
    if findings["is_shortener"]:
        score += 20

    if unexpected_final_domain_change:
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

    # Redirects are common. Score only if they change registered domain,
    # come from shorteners, or appear with other suspicious context.
    if findings["redirect_count"] > 0:
        if unexpected_final_domain_change or findings["is_shortener"]:
            score += 15
        elif suspicious_context:
            score += 5

    if findings["redirect_count"] >= 3 and suspicious_context:
        score += 10

    if findings["punycode_hostname"]["detected"]:
        score += 25

    if findings["brand_digit_lookalikes"]:
        score += 25

    if findings["path_intent_words"] and suspicious_context:
        score += 8
    elif len(findings["path_intent_words"]) >= 3:
        score += 3

    # Forms are normal on search/ecommerce/login sites. They become important
    # when paired with brand mismatch, hosted-platform abuse, or other context.
    if findings["forms"]["password_field_detected"] and suspicious_context:
        score += 30
    elif findings["forms"]["form_count"] > 0 and suspicious_context:
        score += 10

    if findings["forms"]["sensitive_input_fields"] and suspicious_context:
        score += 15
    elif len(findings["forms"]["sensitive_input_fields"]) >= 3 and not is_known_safe_domain(findings):
        score += 5

    if findings["form_action_classification"]["external_form_actions"] and suspicious_context:
        score += 15

    # HTTP is weak by itself.
    if findings["uses_http"]:
        score += 10 if suspicious_context else 5

    # Weighted suspicious wording.
    if suspicious_context:
        if len(word_categories["strong"]) >= 1:
            score += 10
        elif len(word_categories["medium"]) >= 3:
            score += 5
    else:
        if len(word_categories["strong"]) >= 3:
            score += 5

    # External links/CDNs are normal. Only score in suspicious context.
    if findings["link_classification"]["external_links"] and suspicious_context:
        score += 5

    if findings["link_classification"]["official_brand_links"] and findings["brand_impersonation"]:
        score += 15

    # JavaScript is noisy. Score only meaningful/high-risk JS signals.
    if meaningful_js:
        if high_risk_js_terms and suspicious_context:
            score += 15

        if findings["js_url_classification"]["api_like_urls"] and suspicious_context:
            score += 10

        if findings["js_url_classification"]["strong_endpoint_urls"] and suspicious_context:
            score += 15

        if findings["js_url_classification"]["hosting_platform_js_urls"] and suspicious_context:
            score += 10

        if findings["js_analysis"]["external_js"]["fetched_scripts"] and suspicious_context:
            score += 5

    if findings["qr_session_pattern_detected"] and suspicious_context:
        score += 35

    # Known safe / official domains should not be punished for normal web behaviour.
    # This is not a full whitelist. Hard danger indicators still override it.
    if is_known_safe_domain(findings) and not has_hard_danger_indicator(findings):
        score = min(score, 20)

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

    validate_public_url(url)

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
    form_action_classification = classify_form_actions(embedded_links["forms"], final_domain)
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
        "form_action_classification": form_action_classification,
        "js_analysis": js_analysis,
        "js_url_classification": js_url_classification,
        "brand_impersonation": detect_brand_impersonation(final_url, html, message_text),
        "suspicious_words": detect_suspicious_words(final_url, html, message_text),
        "punycode_hostname": detect_punycode_hostname(get_hostname(final_url)),
        "brand_digit_lookalikes": detect_brand_digit_lookalikes(final_domain),
        "path_intent_words": unique_strings(
            detect_path_intent(url) + detect_path_intent(final_url),
            limit=20,
        ),
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

    # Plain URL lists
    supporting.extend(result["link_classification"]["external_links"])
    supporting.extend(result["js_url_classification"]["api_like_urls"])
    supporting.extend(result["js_url_classification"]["hosting_platform_js_urls"])

    # official_brand_js_urls is a list of dicts, so extract the url value
    for item in result["js_url_classification"].get("official_brand_js_urls", []):
        if isinstance(item, dict) and item.get("url"):
            supporting.append(item["url"])

    # official_brand_links is also a list of dicts
    for item in result["link_classification"].get("official_brand_links", []):
        if isinstance(item, dict) and item.get("url"):
            supporting.append(item["url"])

    clean_supporting = []
    for item in supporting:
        if not isinstance(item, str):
            continue

        if item in {result["normalised_url"], result["final_url"]}:
            continue

        clean_supporting.append(item)

    return {
        "main_url": result["final_url"],
        "submitted_url": result["normalised_url"],
        "supporting_urls": unique_strings(clean_supporting, limit=30),
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
