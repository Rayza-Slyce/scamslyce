import ipaddress
import html as html_lib
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
    "google.co.uk",
    "youtube.com",
    "youtu.be",
    "github.com",
    "microsoft.com",
    "xbox.com",
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
    "bbc.co.uk",
    "bbc.com",
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
    "Microsoft": ["microsoft.com", "live.com", "office.com", "outlook.com", "xbox.com"],
    "Google": ["google.com", "google.co.uk", "gmail.com", "youtube.com", "youtu.be"],
    "Apple": ["apple.com", "icloud.com", "applecard.apple"],
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

EMBEDDED_LINK_ACTION_WORDS = {
    "continue",
    "login",
    "log in",
    "get verified",
    "verify",
    "appeal",
    "confirm",
    "secure",
    "review",
    "open",
    "start",
    "proceed",
}

EMBEDDED_LINK_INTENT_WORDS = {
    "login",
    "verify",
    "verification",
    "appeal",
    "security",
    "account",
    "business",
    "support",
    "copyright",
    "reset",
    "recover",
    "unlock",
    "qr",
    "qr-session",
    "session",
    "auth",
}

LOW_VALUE_LINK_TERMS = {
    "privacy",
    "terms",
    "cookie",
    "cookies",
    "legal",
    "policy",
    "help",
    "docs",
    "documentation",
    "schema.org",
    "w3.org",
}

STATIC_RESOURCE_EXTENSIONS = {
    ".css",
    ".js",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".webp",
    ".woff",
    ".woff2",
    ".ttf",
    ".map",
}

ANALYTICS_OR_STATIC_HOST_TERMS = {
    "analytics",
    "googletagmanager",
    "google-analytics",
    "doubleclick",
    "stats",
    "tracking",
    "cdn",
    "static",
    "assets",
}

LOW_VALUE_HOSTS = {
    "schema.org",
    "www.schema.org",
    "w3.org",
    "www.w3.org",
    "s.w.org",
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
        "Microsoft": {"microsoft.com", "office.com", "outlook.com", "live.com", "xbox.com"},
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
        {"google.com", "google.co.uk", "gmail.com", "youtube.com", "youtu.be"},
        {"facebook.com", "fb.com", "messenger.com", "meta.com", "instagram.com"},
        {"microsoft.com", "office.com", "outlook.com", "live.com", "xbox.com"},
        {"paypal.com", "paypal.co.uk"},
        {"amazon.com", "amazon.co.uk"},
        {"apple.com", "icloud.com", "applecard.apple"},
        {"bbc.co.uk", "bbc.com"},
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


def assess_inspection_status(
    status_code: int,
    content_type: str,
    html: str,
    page_title: str,
) -> dict:
    notes = []
    lower_content_type = content_type.lower()
    visible_text = extract_visible_text(html) if html else ""
    combined_text = f"{page_title} {visible_text[:1000]}".lower()

    if status_code in {401, 403}:
        notes.append(
            f"The server returned HTTP {status_code}, so ScamSlyce may have seen an access-control or security page instead of the real page."
        )

    if status_code in {404, 410}:
        notes.append(
            f"The server returned HTTP {status_code}, so the page may be unavailable, removed, or already taken down."
        )

    if "text/html" not in lower_content_type:
        notes.append(
            f"The response was not HTML ({content_type or 'unknown content type'}), so page content inspection was limited."
        )

    interstitial_markers = [
        "attention required",
        "cloudflare",
        "just a moment",
        "access denied",
        "checking your browser",
    ]
    if any(marker in combined_text for marker in interstitial_markers):
        notes.append(
            "The page appears to be a security, anti-bot, or access-denied interstitial rather than the real destination content."
        )

    placeholder_markers = [
        "my framer site",
        "not found",
        "access denied",
        "page not found",
        "404",
        "coming soon",
    ]
    if any(marker in combined_text for marker in placeholder_markers):
        notes.append(
            "The page title or body looks like a generic placeholder, holding page, or error page."
        )

    if html and len(visible_text.strip()) < 80:
        notes.append(
            "The visible HTML text was very short, so ScamSlyce had little page content to inspect."
        )

    if not html:
        notes.append(
            "No inspectable HTML body was available for page, form, link, or JavaScript context checks."
        )

    notes = unique_strings(notes, limit=10)

    if not notes:
        status = "complete"
    elif status_code in {404, 410} or not html:
        status = "inconclusive"
    else:
        status = "limited"

    return {
        "inspection_status": status,
        "inspection_notes": notes,
    }


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


def clean_extracted_url(url: str) -> str:
    for marker in ["&quot;", "&#34;", "&apos;", "&#39;", "&lt;", "&gt;"]:
        if marker in url:
            url = url.split(marker, 1)[0]

    return url.rstrip(".,;]")


# -----------------------------
# JavaScript analysis
# -----------------------------

def analyse_javascript_text(js_text: str) -> dict:
    normalised_js_text = html_lib.unescape(js_text).replace("\\/", "/")
    js_urls = unique_strings(
        [
            clean_extracted_url(url)
            for url in URL_REGEX.findall(js_text) + URL_REGEX.findall(normalised_js_text)
        ],
        limit=80,
    )

    found_terms = []
    lower_js = normalised_js_text.lower()

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


def is_static_resource_url(url: str) -> bool:
    path = urlparse(url).path.lower()
    return any(path.endswith(extension) for extension in STATIC_RESOURCE_EXTENSIONS)


def is_low_value_embedded_url(url: str, link_text: str = "") -> bool:
    lower_url = url.lower()
    lower_text = link_text.lower()
    hostname = get_hostname(url)

    if hostname in LOW_VALUE_HOSTS:
        return True

    if hostname.endswith(".github.io"):
        has_intent = any(word in lower_url or word in lower_text for word in EMBEDDED_LINK_INTENT_WORDS)
        has_endpoint = any(marker in lower_url for marker in STRONG_JS_ENDPOINT_MARKERS)
        if not has_intent and not has_endpoint:
            return True

    if is_static_resource_url(url):
        return True

    if any(term in hostname for term in ANALYTICS_OR_STATIC_HOST_TERMS):
        return not any(marker in lower_url for marker in STRONG_JS_ENDPOINT_MARKERS)

    if any(term in lower_url or term in lower_text for term in LOW_VALUE_LINK_TERMS):
        return not any(
            word in lower_url or word in lower_text
            for word in EMBEDDED_LINK_INTENT_WORDS
        )

    social_domains = {
        "facebook.com",
        "instagram.com",
        "x.com",
        "twitter.com",
        "linkedin.com",
        "youtube.com",
        "youtu.be",
        "tiktok.com",
    }
    registered_domain = get_registered_domain(url)
    if registered_domain in social_domains:
        return not any(
            word in lower_url or word in lower_text
            for word in EMBEDDED_LINK_INTENT_WORDS
        )

    return False


def collect_embedded_link_candidates(result: dict) -> list[dict]:
    candidates = []

    for item in result["embedded_links"]["anchors"]:
        candidates.append({
            "url": item["url"],
            "source": "anchor",
            "link_text": item.get("label", ""),
        })

    for form_url in result["embedded_links"]["forms"]:
        candidates.append({
            "url": form_url,
            "source": "form_action",
            "link_text": "",
        })

    for iframe_url in result["embedded_links"]["iframes"]:
        candidates.append({
            "url": iframe_url,
            "source": "iframe",
            "link_text": "",
        })

    for api_url in result["js_url_classification"]["api_like_urls"]:
        candidates.append({
            "url": api_url,
            "source": "api_like_url",
            "link_text": "",
        })

    for hosted_url in result["js_url_classification"]["hosting_platform_js_urls"]:
        candidates.append({
            "url": hosted_url,
            "source": "hosted_platform_url",
            "link_text": "",
        })

    for strong_url in result["js_url_classification"].get("strong_endpoint_urls", []):
        candidates.append({
            "url": strong_url,
            "source": "strong_endpoint_url",
            "link_text": "",
        })

    unique_candidates = []
    seen = set()
    for candidate in candidates:
        url = candidate.get("url", "")

        if not url.startswith(("http://", "https://")):
            continue

        if url in {result["normalised_url"], result["final_url"]}:
            continue

        if is_private_or_local_host(get_hostname(url)):
            continue

        key = url.rstrip("/")
        if key in seen:
            continue

        seen.add(key)
        candidate["registered_domain"] = get_registered_domain(url)
        unique_candidates.append(candidate)

    return unique_candidates


def score_embedded_link_candidate(candidate: dict, parent_result: dict) -> dict:
    url = candidate["url"]
    link_text = candidate.get("link_text", "")
    registered_domain = candidate["registered_domain"]
    parent_domain = parent_result["final_domain"]
    lower_url = url.lower()
    lower_text = link_text.lower()
    hostname = get_hostname(url)
    score = 0
    reasons = []

    strong_endpoint = any(marker in lower_url for marker in STRONG_JS_ENDPOINT_MARKERS)

    if is_low_value_embedded_url(url, link_text) and not strong_endpoint:
        candidate["selection_score"] = 0
        candidate["reason_selected"] = "Low-value static, policy, analytics, or social/profile link."
        return candidate

    same_organisation = domains_share_known_organisation(registered_domain, parent_domain)

    if registered_domain != parent_domain and not same_organisation:
        score += 25
        reasons.append("different registered domain from submitted page")

    if is_hosting_platform(registered_domain):
        score += 25
        reasons.append("hosted on a general-purpose platform")

    if any(word in lower_url or word in hostname for word in EMBEDDED_LINK_INTENT_WORDS):
        score += 15
        reasons.append("URL contains login, verification, account, session, or support intent")

    if any(action in lower_text for action in EMBEDDED_LINK_ACTION_WORDS):
        score += 15
        reasons.append("link text is an action prompt")

    parent_brands = identify_likely_brands(parent_result)
    for brand in parent_brands:
        if not is_legit_brand_domain(registered_domain, brand) and not is_expected_brand_relationship(registered_domain, brand):
            score += 20
            reasons.append(f"parent page references {brand}, but destination is not an official related domain")
            break

    if candidate["source"] == "form_action" and registered_domain != parent_domain:
        score += 20
        reasons.append("form action submits to a different registered domain")

    if strong_endpoint:
        score += 25
        reasons.append("URL contains strong JavaScript endpoint/session/messaging indicators")

    if registered_domain in KNOWN_SHORTENERS:
        score += 20
        reasons.append("destination uses a known URL shortener")

    if detect_punycode_hostname(hostname)["detected"]:
        score += 20
        reasons.append("destination hostname contains punycode labels")

    if detect_brand_digit_lookalikes(registered_domain):
        score += 20
        reasons.append("destination resembles a known brand using digit substitution")

    if same_organisation and not strong_endpoint:
        candidate["selection_score"] = 0
        candidate["reason_selected"] = "Same-organisation navigation or resource link."
        return candidate

    candidate["selection_score"] = score
    candidate["reason_selected"] = "; ".join(unique_strings(reasons, limit=8)) or "No strong embedded-link selection reason."
    return candidate


def select_embedded_links_for_analysis(result: dict, max_links: int = 3) -> list[dict]:
    scored = [
        score_embedded_link_candidate(candidate, result)
        for candidate in collect_embedded_link_candidates(result)
    ]

    selected = [
        candidate for candidate in scored
        if candidate["selection_score"] >= 25
    ]

    selected.sort(
        key=lambda item: (
            item["selection_score"],
            item["source"] in {"form_action", "anchor"},
        ),
        reverse=True,
    )

    return selected[:max_links]


def describe_main_concern(result: dict) -> str:
    if result["brand_impersonation"] and result["qr_session_pattern_detected"]:
        return "Brand impersonation with QR/session login behaviour"
    if result["brand_impersonation"]:
        return "Possible brand impersonation"
    if result["qr_session_pattern_detected"]:
        return "Possible QR/session login behaviour"
    if result["js_url_classification"]["strong_endpoint_urls"]:
        return "Strong JavaScript endpoint/session indicators"
    if result["js_url_classification"]["api_like_urls"]:
        return "API/session-like JavaScript URLs"
    if result["forms"]["password_field_detected"]:
        return "Password field detected"
    return "No major concern detected"


def summarise_embedded_result(candidate: dict, result: dict) -> dict:
    brands = identify_likely_brands(result)
    high_risk_js_terms = get_high_risk_js_terms(result)
    api_like_urls = result["js_url_classification"]["api_like_urls"]
    hosting_platform_js_urls = result["js_url_classification"]["hosting_platform_js_urls"]

    return {
        "url": candidate["url"],
        "source": candidate["source"],
        "link_text": candidate.get("link_text", ""),
        "registered_domain": candidate["registered_domain"],
        "reason_selected": candidate["reason_selected"],
        "selection_score": candidate["selection_score"],
        "risk_score": result["risk_score"],
        "risk_level": result["risk_level"],
        "page_title": result["page_title"],
        "final_url": result["final_url"],
        "original_domain": result["original_domain"],
        "final_domain": result["final_domain"],
        "hostname": result["hostname"],
        "subdomain": result["subdomain"],
        "http_status": result["status_code"],
        "content_type": result["content_type"],
        "inspection_status": result["inspection_status"],
        "inspection_notes": result["inspection_notes"],
        "main_concern": describe_main_concern(result),
        "brand_impersonation": result["brand_impersonation"],
        "likely_brands": brands,
        "hosted_platform_detected": result["hosted_platform_detected"],
        "forms_summary": {
            "form_count": result["forms"]["form_count"],
            "input_count": result["forms"]["input_count"],
            "password_field_detected": result["forms"]["password_field_detected"],
            "sensitive_input_count": len(result["forms"].get("sensitive_input_fields", [])),
        },
        "high_risk_js_terms": high_risk_js_terms,
        "suspicious_js_terms": result["js_analysis"]["suspicious_js_terms"][:20],
        "api_like_urls_count": len(api_like_urls),
        "api_like_urls_sample": api_like_urls[:5],
        "hosting_platform_js_urls_count": len(hosting_platform_js_urls),
        "hosting_platform_js_urls_sample": hosting_platform_js_urls[:5],
        "qr_session_pattern_detected": result["qr_session_pattern_detected"],
        "overall_risk_score": result.get("overall_risk_score", result["risk_score"]),
        "overall_risk_level": result.get("overall_risk_level", result["risk_level"]),
        "error": "",
    }


def analyse_embedded_links(parent_result: dict, max_links: int = 3) -> list[dict]:
    embedded_results = []

    for candidate in select_embedded_links_for_analysis(parent_result, max_links=max_links):
        try:
            embedded_result = analyse_url(
                candidate["url"],
                message_text=parent_result.get("message_text", ""),
                analyse_embedded=False,
                depth=1,
            )
            embedded_results.append(summarise_embedded_result(candidate, embedded_result))
        except Exception as error:
            embedded_results.append({
                "url": candidate["url"],
                "source": candidate["source"],
                "link_text": candidate.get("link_text", ""),
                "registered_domain": candidate["registered_domain"],
                "reason_selected": candidate["reason_selected"],
                "selection_score": candidate["selection_score"],
                "risk_score": "",
                "risk_level": "",
                "page_title": "",
                "final_url": "",
                "original_domain": "",
                "final_domain": "",
                "hostname": "",
                "subdomain": "",
                "http_status": "",
                "content_type": "",
                "inspection_status": "inconclusive",
                "inspection_notes": ["Embedded destination analysis failed."],
                "main_concern": "",
                "brand_impersonation": [],
                "likely_brands": [],
                "hosted_platform_detected": False,
                "forms_summary": {},
                "high_risk_js_terms": [],
                "suspicious_js_terms": [],
                "api_like_urls_count": 0,
                "api_like_urls_sample": [],
                "hosting_platform_js_urls_count": 0,
                "hosting_platform_js_urls_sample": [],
                "qr_session_pattern_detected": False,
                "overall_risk_score": "",
                "overall_risk_level": "",
                "error": str(error),
            })

    return embedded_results


def apply_overall_risk_from_embedded(result: dict) -> dict:
    embedded_results = result.get("embedded_analysis", [])
    scored_results = [
        item for item in embedded_results
        if isinstance(item.get("risk_score"), int)
    ]

    highest = max(scored_results, key=lambda item: item["risk_score"], default=None)

    result["embedded_highest_risk_score"] = highest["risk_score"] if highest else 0
    result["embedded_highest_risk_level"] = highest["risk_level"] if highest else ""
    result["embedded_high_risk_found"] = bool(
        highest and highest["risk_level"] in {"High", "Very High"}
    )

    result["overall_risk_score"] = result["risk_score"]
    result["overall_risk_level"] = result["risk_level"]
    result["overall_risk_reason"] = "Overall risk is based on the submitted URL's direct analysis."

    if result["embedded_high_risk_found"]:
        result["overall_risk_score"] = max(result["risk_score"], highest["risk_score"])
        result["overall_risk_level"] = highest["risk_level"]
        result["overall_risk_reason"] = (
            "The submitted URL contains or leads to an embedded destination "
            f"that scored {highest['risk_level']} ({highest['risk_score']}/100)."
        )

    return result


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

def analyse_url(raw_url: str, message_text: str = "", analyse_embedded: bool = True, depth: int = 0) -> dict:
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
    page_title = extract_page_title(html)
    inspection = assess_inspection_status(
        response.status_code,
        content_type,
        html,
        page_title,
    )

    forms = detect_forms(html)
    embedded_links = extract_embedded_links(html, final_url)

    inline_js = extract_inline_js(html)
    if html:
        inline_js += "\n" + html
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
        "page_title": page_title,
        "inspection_status": inspection["inspection_status"],
        "inspection_notes": inspection["inspection_notes"],
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
    findings["embedded_analysis"] = []

    if analyse_embedded and depth == 0:
        findings["embedded_analysis"] = analyse_embedded_links(findings, max_links=3)

    apply_overall_risk_from_embedded(findings)

    return findings


# -----------------------------
# User action guidance
# -----------------------------

def identify_likely_brands(result: dict) -> list[str]:
    return sorted({item["brand"] for item in result["brand_impersonation"]})


def build_action_plan(result: dict, user_situation: str) -> list[str]:
    low_risk = result["risk_level"] == "Low"

    if result.get("embedded_high_risk_found"):
        highest = get_highest_risk_embedded_result(result)
        destination = highest.get("final_url") or highest["url"] if highest else "the embedded destination"
        actions = [
            f"Do not follow the embedded destination: {destination}",
            "Treat the link chain as risky even if the submitted page itself looks mild.",
            "Do not enter login details, payment information, personal data, or scan QR codes on the embedded destination.",
            "Use the official website or app directly if you need to check the account, page, or offer.",
            "Report the embedded destination as the primary suspicious URL.",
            "Optionally report the landing page to its hosting/platform provider as a page that leads to a phishing destination.",
        ]
        return actions

    if low_risk:
        if result.get("inspection_status") in {"limited", "inconclusive"}:
            actions = [
                "ScamSlyce could not inspect enough of the real page to make a strong judgement.",
                "Do not treat the low score as proof that the link is safe.",
                "Use the official website or app directly if the link was unexpected or asks for sensitive information.",
            ]
        else:
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

def get_highest_risk_embedded_result(result: dict) -> dict | None:
    scored = [
        item for item in result.get("embedded_analysis", [])
        if isinstance(item.get("risk_score"), int)
    ]

    return max(scored, key=lambda item: item["risk_score"], default=None)


def get_primary_report_context(result: dict) -> dict:
    highest_embedded = get_highest_risk_embedded_result(result)
    direct_high = result["risk_level"] in {"High", "Very High"}
    embedded_high = bool(highest_embedded and highest_embedded["risk_level"] in {"High", "Very High"})

    if embedded_high and not direct_high:
        primary_url = highest_embedded.get("final_url") or highest_embedded["url"]
        primary_type = "embedded_destination"
        supporting_urls = [
            result["final_url"],
            result["normalised_url"],
        ]
        primary_title = "high-risk embedded destination"
        reason = (
            "The submitted landing page scored lower directly, but it contains or leads to "
            "an embedded destination that shows strong phishing/scam indicators."
        )
    else:
        primary_url = result["final_url"]
        primary_type = "submitted_url"
        supporting_urls = []
        primary_title = "submitted URL"
        reason = "The submitted URL itself has the strongest direct evidence."

    return {
        "primary_report_url": primary_url,
        "primary_report_type": primary_type,
        "primary_report_title": primary_title,
        "primary_report_reason": reason,
        "highest_embedded": highest_embedded,
        "supporting_report_urls": unique_strings(supporting_urls, limit=30),
    }


def get_main_and_supporting_urls(result: dict) -> dict:
    report_context = get_primary_report_context(result)
    supporting = []

    if report_context["primary_report_type"] == "embedded_destination":
        supporting.extend(report_context["supporting_report_urls"])
        highest = report_context["highest_embedded"]
        if highest:
            supporting.extend(highest.get("api_like_urls_sample", []))
            supporting.extend(highest.get("hosting_platform_js_urls_sample", []))
    else:
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

        supporting.extend(report_context["supporting_report_urls"])

    clean_supporting = []
    for item in supporting:
        if not isinstance(item, str):
            continue

        if item == report_context["primary_report_url"]:
            continue

        clean_supporting.append(item)

    return {
        "main_url": report_context["primary_report_url"],
        "submitted_url": result["normalised_url"],
        "supporting_urls": unique_strings(clean_supporting, limit=30),
        "primary_report_type": report_context["primary_report_type"],
        "primary_report_reason": report_context["primary_report_reason"],
    }


def format_forms_summary(forms_summary: dict) -> str:
    if not forms_summary:
        return "Not available"

    return (
        f"{forms_summary.get('form_count', 0)} form(s), "
        f"{forms_summary.get('input_count', 0)} input(s), "
        f"password field detected: {forms_summary.get('password_field_detected', False)}, "
        f"sensitive input indicators: {forms_summary.get('sensitive_input_count', 0)}"
    )


def format_embedded_destination_evidence(embedded: dict | None) -> str:
    if not embedded:
        return "No embedded destination evidence available."

    brands = ", ".join(embedded.get("likely_brands", [])) or "None detected"
    high_risk_terms = ", ".join(embedded.get("high_risk_js_terms", [])) or "None detected"
    api_sample = embedded.get("api_like_urls_sample", [])
    api_text = "None detected"
    if api_sample:
        api_text = "\n".join(f"  - {url}" for url in api_sample)

    hosted_platform = embedded.get("final_domain") if embedded.get("hosted_platform_detected") else "No"

    return f"""- Page title: {embedded.get('page_title') or 'Not detected'}
- Registered domain: {embedded.get('final_domain') or 'Not available'}
- Hostname: {embedded.get('hostname') or 'Not available'}
- Subdomain: {embedded.get('subdomain') or 'None'}
- HTTP status: {embedded.get('http_status') or 'Not available'}
- Content-Type: {embedded.get('content_type') or 'Unknown'}
- Inspection status: {embedded.get('inspection_status') or 'unknown'}
- Possible brand impersonation: {brands}
- Hosted platform detected: {hosted_platform}
- QR/session behaviour detected: {embedded.get('qr_session_pattern_detected', False)}
- API/session-like JavaScript URLs found: {embedded.get('api_like_urls_count', 0)}
{api_text}
- High-risk JavaScript/session indicators: {high_risk_terms}
- Forms/inputs summary: {format_forms_summary(embedded.get('forms_summary', {}))}
- Main concern: {embedded.get('main_concern') or 'Not available'}"""


def format_landing_page_supporting_evidence(result: dict, embedded: dict | None) -> str:
    reason = embedded.get("reason_selected") if embedded else "Not available"
    return f"""- Submitted URL: {result['normalised_url']}
- Landing page final URL: {result['final_url']}
- Landing page title: {result['page_title'] or 'Not detected'}
- Landing page registered domain: {result['final_domain']}
- Landing page direct risk: {result['risk_level']} ({result['risk_score']}/100)
- The landing page linked to the suspicious embedded destination.
- Reason embedded destination was selected: {reason}"""


def build_simple_summary(result: dict, user_situation: str = "") -> str:
    brands = identify_likely_brands(result)
    brand_text = ", ".join(brands) if brands else "a known brand or service"

    if result.get("embedded_high_risk_found"):
        highest = get_highest_risk_embedded_result(result)
        destination = highest.get("final_url") or highest["url"] if highest else "the embedded destination"
        destination_domain = get_registered_domain(destination) if highest else "unknown domain"
        return (
            f"The submitted page itself scored {result['risk_level']}, but it links to an embedded destination "
            f"that scored {highest['risk_level']}.\n\n"
            f"Embedded destination: {destination}\n"
            f"Embedded destination domain: {destination_domain}\n\n"
            f"Direct submitted-page risk: {result['risk_level']} ({result['risk_score']}/100).\n"
            f"Embedded destination risk: {highest['risk_level']} ({highest['risk_score']}/100).\n"
            f"Overall chain risk: {result.get('overall_risk_level', result['risk_level'])} "
            f"({result.get('overall_risk_score', result['risk_score'])}/100).\n\n"
            "The evidence mainly shows that the landing page leads users to a higher-risk destination."
        )

    if result["risk_level"] == "Low":
        if result.get("inspection_status") in {"limited", "inconclusive"}:
            inspection_notes = result.get("inspection_notes", [])
            summary = (
                "This link scored Low, but ScamSlyce could not inspect enough of the real page "
                "to make a strong judgement.\n\n"
            )

            if inspection_notes:
                summary += "Inspection limits observed: " + " ".join(inspection_notes[:3]) + "\n\n"

            summary += (
                "Do not treat this as proof that the link is safe. Verify through the official website "
                "or app if the message was unexpected or asks for sensitive information."
            )

            return summary

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


def build_chain_abuse_report(result: dict, user_situation: str) -> str:
    report_context = get_primary_report_context(result)
    embedded = report_context["highest_embedded"]
    primary_url = report_context["primary_report_url"]
    supporting_text = "\n".join(
        f"- {url}" for url in get_main_and_supporting_urls(result)["supporting_urls"][:15]
    ) or "None detected"

    embedded_risk = "None selected"
    if embedded:
        embedded_risk = f"{embedded['risk_level']} ({embedded['risk_score']}/100)"

    return f"""Hello,

I am reporting a suspected scam/phishing/brand impersonation destination found through a landing page.

Primary suspicious URL:
{primary_url}

Primary report target type:
High-risk embedded destination

Submitted landing page:
{result['normalised_url']}

Reason for report:
The submitted landing page contains or leads to an embedded destination that shows strong phishing/scam indicators.

Risk level from ScamSlyce:
Submitted page direct risk: {result['risk_level']} ({result['risk_score']}/100)
Embedded destination risk: {embedded_risk}
Overall chain concern: {result.get('overall_risk_level', result['risk_level'])} ({result.get('overall_risk_score', result['risk_score'])}/100)

Embedded destination evidence:
{format_embedded_destination_evidence(embedded)}

Landing page/supporting evidence:
{format_landing_page_supporting_evidence(result, embedded)}

Supporting URLs:
{supporting_text}

User situation:
{user_situation}

Recommended action:
Please review and, if confirmed abusive, suspend/remove/mitigate the primary suspicious URL and associated infrastructure.

Passive inspection note:
This report is based on passive inspection only. No login attempts, form submissions, brute forcing, vulnerability scanning, directory fuzzing, port scanning, or bypass activity were performed.
"""


def build_targeted_abuse_report(result: dict, user_situation: str, target_name: str = "abuse team") -> str:
    url_context = get_main_and_supporting_urls(result)
    report_context = get_primary_report_context(result)

    if report_context["primary_report_type"] == "embedded_destination":
        return build_chain_abuse_report(result, user_situation)

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

    inspection_notes = "None"
    if result.get("inspection_notes"):
        inspection_notes = "\n".join(f"- {note}" for note in result["inspection_notes"])

    embedded_text = "None selected for depth-1 analysis"
    if result.get("embedded_analysis"):
        embedded_lines = []
        for item in result["embedded_analysis"]:
            embedded_lines.append(
                f"- URL: {item['url']}\n"
                f"  Final URL: {item.get('final_url') or 'Not available'}\n"
                f"  Source: {item['source']}\n"
                f"  Selection reason: {item['reason_selected']}\n"
                f"  Selection score: {item['selection_score']}\n"
                f"  Risk: {item.get('risk_level') or 'Not available'} ({item.get('risk_score') or 'N/A'}/100)\n"
                f"  Inspection status: {item.get('inspection_status') or 'unknown'}\n"
                f"  Main concern: {item.get('main_concern') or item.get('error') or 'Not available'}"
            )
        embedded_text = "\n".join(embedded_lines)

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

    if result.get("embedded_high_risk_found"):
        reasons.append(
            "The submitted URL contains or leads to an embedded destination that shows strong phishing/scam indicators."
        )

    if not reasons:
        reasons.append("The URL was flagged by the reporter as suspicious and has been passively inspected.")

    reasons_text = "\n".join(f"- {reason}" for reason in reasons)

    return f"""Suspected scam/phishing/brand impersonation report

Main suspicious URL:
{url_context['main_url']}

Primary report target:
{report_context['primary_report_title']}

Submitted landing page URL:
{url_context['submitted_url']}

Primary suspicious embedded destination URL:
{report_context['primary_report_url'] if report_context['primary_report_type'] == 'embedded_destination' else 'Not applicable'}

Risk level from ScamSlyce:
Direct submitted URL: {result['risk_level']} ({result['risk_score']}/100)
Embedded destination risk: {report_context['highest_embedded']['risk_level'] + ' (' + str(report_context['highest_embedded']['risk_score']) + '/100)' if report_context['highest_embedded'] else 'None selected'}
Overall chain concern: {result.get('overall_risk_level', result['risk_level'])} ({result.get('overall_risk_score', result['risk_score'])}/100)
Overall reason: {result.get('overall_risk_reason', 'Overall risk is based on the submitted URL direct analysis.')}

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
- Inspection status: {result.get('inspection_status', 'complete')}
- External embedded links found: {len(result['link_classification']['external_links'])}
- Script URLs found on page: {len(result['embedded_links']['scripts'])}
- Same-domain script files fetched and inspected: {len(result['js_analysis']['external_js']['fetched_scripts'])}
- JavaScript URLs found: {result['js_analysis']['js_url_count']}
- API/session-like JavaScript URLs found: {len(result['js_url_classification']['api_like_urls'])}
- Possible QR/session login flow detected: {result['qr_session_pattern_detected']}

Inspection notes:
{inspection_notes}

Embedded destinations analysed:
{embedded_text}

Suspicious JavaScript/session terms:
{js_terms}

API/session-like URLs found:
{api_urls}

Supporting infrastructure / URLs found:
{supporting_text}

Requested action:
Please review the primary report target and associated supporting infrastructure. If confirmed malicious or abusive, please suspend, remove, block, or otherwise mitigate the content.

Passive inspection note:
This report is based on passive inspection only. No login attempts, form submissions, brute forcing, vulnerability scanning, directory fuzzing, port scanning, or bypass activity were performed.
"""


def build_email_body(result: dict, user_situation: str, focus: str = "general") -> str:
    url_context = get_main_and_supporting_urls(result)
    report_context = get_primary_report_context(result)

    if report_context["primary_report_type"] == "embedded_destination":
        return build_chain_abuse_report(result, user_situation)

    summary = build_simple_summary(result, user_situation)

    supporting_text = "None detected"
    if url_context["supporting_urls"]:
        supporting_text = "\n".join(f"- {url}" for url in url_context["supporting_urls"][:15])

    inspection_notes = "None"
    if result.get("inspection_notes"):
        inspection_notes = "\n".join(f"- {note}" for note in result["inspection_notes"])

    embedded_text = "None selected for depth-1 analysis"
    if result.get("embedded_analysis"):
        embedded_lines = []
        for item in result["embedded_analysis"]:
            embedded_lines.append(
                f"- URL: {item['url']}\n"
                f"  Final URL: {item.get('final_url') or 'Not available'}\n"
                f"  Source: {item['source']}\n"
                f"  Selection reason: {item['reason_selected']}\n"
                f"  Risk: {item.get('risk_level') or 'Not available'} ({item.get('risk_score') or 'N/A'}/100)\n"
                f"  Inspection status: {item.get('inspection_status') or 'unknown'}"
            )
        embedded_text = "\n".join(embedded_lines)

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

    if result.get("embedded_high_risk_found"):
        indicators.append("A linked embedded destination scored High or Very High")

    indicator_text = "\n".join(f"- {item}" for item in indicators) if indicators else "- No major indicators detected by basic analysis"

    body = f"""Hello,

I am reporting a suspected scam/phishing/brand impersonation page.

Main suspicious URL:
{url_context['main_url']}

Primary report target:
{report_context['primary_report_title']}

Submitted landing page URL:
{url_context['submitted_url']}

Primary suspicious embedded destination URL:
{report_context['primary_report_url'] if report_context['primary_report_type'] == 'embedded_destination' else 'Not applicable'}

Risk level from ScamSlyce:
Direct submitted URL: {result['risk_level']} ({result['risk_score']}/100)
Embedded destination risk: {report_context['highest_embedded']['risk_level'] + ' (' + str(report_context['highest_embedded']['risk_score']) + '/100)' if report_context['highest_embedded'] else 'None selected'}
Overall chain concern: {result.get('overall_risk_level', result['risk_level'])} ({result.get('overall_risk_score', result['risk_score'])}/100)
Overall reason: {result.get('overall_risk_reason', 'Overall risk is based on the submitted URL direct analysis.')}

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
- Inspection status: {result.get('inspection_status', 'complete')}
- External embedded links found: {len(result['link_classification']['external_links'])}
- Official brand links found in HTML: {len(result['link_classification']['official_brand_links'])}
- Official brand URLs found in JavaScript: {len(result['js_url_classification']['official_brand_js_urls'])}
- Script URLs found on page: {len(result['embedded_links']['scripts'])}
- Same-domain script files fetched: {len(result['js_analysis']['external_js']['fetched_scripts'])}
- JavaScript URLs found: {result['js_analysis']['js_url_count']}
- API/session-like JavaScript URLs found: {len(result['js_url_classification']['api_like_urls'])}

Inspection notes:
{inspection_notes}

Embedded destinations analysed:
{embedded_text}

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
    report_context = get_primary_report_context(result)
    main_url = url_context["main_url"]
    actions = []

    netcraft_body = build_email_body(result, user_situation, focus="netcraft")
    netcraft_title = "Report the main suspicious URL to Netcraft"
    netcraft_why = "Good first reporting route for phishing, malware, fake shops, and suspicious URLs. Report the main page first and include supporting infrastructure as evidence."

    if report_context["primary_report_type"] == "embedded_destination":
        netcraft_title = "Report the high-risk embedded destination to Netcraft"
        netcraft_why = (
            "ScamSlyce found that the submitted landing page leads to a higher-risk embedded destination. "
            "Report the embedded destination first and include the submitted landing page as supporting evidence."
        )

    actions.append({
        "priority": 1,
        "title": netcraft_title,
        "why": netcraft_why,
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

    if result["hosted_platform_detected"] and report_context["primary_report_type"] != "embedded_destination":
        platform_domains.add(result["original_domain"])

    if report_context["primary_report_type"] == "embedded_destination":
        primary_domain = get_registered_domain(report_context["primary_report_url"])
        if is_hosting_platform(primary_domain):
            platform_domains.add(primary_domain)

        landing_domain = result["final_domain"]
        landing_hostname = result["hostname"]
        if is_hosting_platform(landing_domain):
            platform_domains.add(landing_domain)
        if landing_hostname in PLATFORM_REPORTING:
            platform_domains.add(landing_hostname)

    for url in result["js_url_classification"]["hosting_platform_js_urls"]:
        platform_domains.add(get_registered_domain(url))

    if result["is_shortener"]:
        platform_domains.add(result["original_domain"])

    for domain in sorted(platform_domains):
        config = PLATFORM_REPORTING.get(domain)

        if not config:
            continue

        action_title = config["title"]
        if (
            report_context["primary_report_type"] == "embedded_destination"
            and domain == result["hostname"]
        ):
            action_title = "Optional: report the landing page to the hosting/platform provider"

        subject = f"{config['subject_prefix']} - {get_hostname(main_url)}"
        body = build_email_body(result, user_situation, focus=domain)

        if config.get("fallback_email"):
            body += f"\nFallback reporting contact if needed: {config['fallback_email']}\n"

        actions.append({
            "priority": next_priority,
            "title": action_title,
            "why": (
                f"ScamSlyce detected infrastructure connected to {domain}. "
                "If this is the landing-page host, report it as a page that leads to a phishing destination. "
                "If this is the embedded destination host, report the embedded URL as the primary suspicious URL."
            ),
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
