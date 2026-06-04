import streamlit as st

from scamslyce_core import (
    analyse_url,
    build_action_plan,
    build_priority_reporting_actions,
    build_report,
    get_high_risk_js_terms,
    get_main_and_supporting_urls,
    get_suspicious_word_categories,
    has_meaningful_js_signal,
    identify_likely_brands,
)

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

st.caption(
    "A low score does not guarantee a link is safe. ScamSlyce only reports warning signs found during basic passive checks."
)

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

            if result["redirect_count"] > 0 and result["final_domain"] != result["original_domain"]:
                summary_points.append(f"This link redirects {result['redirect_count']} time(s) before reaching a different registered domain.")
            elif result["redirect_count"] > 0 and result["risk_level"] != "Low":
                summary_points.append(
                    f"This link redirects {result['redirect_count']} time(s), but remains on the same registered domain."
                )

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

            word_categories = get_suspicious_word_categories(result)
            if result["risk_level"] != "Low" and word_categories["strong"]:
                words = ", ".join(word_categories["strong"][:10])
                summary_points.append(f"Strong scam/phishing wording was detected: {words}.")

            if not summary_points:
                summary_points.append("No major warning signs were detected by this basic version. This does not guarantee the link is safe.")

            for point in summary_points:
                st.write(f"- {point}")

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

                            st.caption("Use the full copy-paste abuse report below when submitting this report.")
                st.subheader("Optional Copy-Paste Report")
                st.write("Only use this if you still have a reason to report the link despite the low-risk result.")
                report = build_report(result, user_situation)
                st.text_area("Optional report text", report, height=420)

            else:
                st.subheader("Priority Reporting Actions")
                st.write("Start with the first action. These are the places to report the link. Use the full copy-paste abuse report below for each report.")

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

                        st.caption("Use the full copy-paste abuse report below when submitting this report.")
                st.subheader("Full Copy-Paste Abuse Report")
                st.write(
                    "Copy this report and paste it into Netcraft, the impersonated brand report, hosting/backend abuse reports, "
                    "or the platform where the message was received."
                )
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

        st.warning(
            "Do not include passwords, private links, account recovery links, magic login links, banking links, "
            "internal company URLs, or personal tokens in GitHub issues."
        )

        col_a, col_b = st.columns(2)

        with col_a:
            st.markdown(
                "[Report a false positive](https://github.com/Rayza-Slyce/scamslyce/issues/new?template=false_positive.md)"
            )
            st.markdown(
                "[Report a missed scam](https://github.com/Rayza-Slyce/scamslyce/issues/new?template=missed_scam.md)"
            )
            st.markdown(
                "[Report confusing wording/advice](https://github.com/Rayza-Slyce/scamslyce/issues/new?template=wording_or_advice.md)"
            )

        with col_b:
            st.markdown(
                "[Report mobile/layout issue](https://github.com/Rayza-Slyce/scamslyce/issues/new?template=mobile_layout.md)"
            )
            st.markdown(
                "[Suggest a feature](https://github.com/Rayza-Slyce/scamslyce/issues/new?template=feature_request.md)"
            )
            st.markdown(
                "[View project on GitHub](https://github.com/Rayza-Slyce/scamslyce)"
            )

        with st.expander("What to include in feedback"):
            st.write("- The URL you tested, unless it contains private tokens or sensitive data.")
            st.write("- Whether the result felt right or wrong.")
            st.write("- What ScamSlyce scored it.")
            st.write("- What device/browser you used.")
            st.write("- Any wording or advice that confused you.")

    except Exception as e:
        st.error(str(e))
