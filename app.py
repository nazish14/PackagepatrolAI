import os
import json
import sqlite3
from datetime import datetime, timezone

import pandas as pd
import streamlit as st

from ai_analyzer import generate_ai_explanation
from analyzer import full_scan
from risk_engine import risk_summary
from utils import clean_package_name, package_url, valid_package_name

DB_FILE = "packagepatrol.db"

st.set_page_config(
    page_title="PackagePatrol AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# -----------------------------
# Styling
# -----------------------------


def inject_css():
    st.markdown(
        """
        <style>

        /* =====================================================
           PACKAGEPATROL AI — CYBERGUARD BLACK & GOLD UI
           ===================================================== */

        :root {
            --pp-bg: #050505;
            --pp-panel: #11100C;
            --pp-panel2: #19170F;
            --pp-border: #39301A;

            --pp-gold: #FFD23F;
            --pp-gold-light: #FFE58A;
            --pp-gold-dark: #B8860B;

            --pp-text: #FFFDF5;
            --pp-muted: #AAA597;
        }

        /* ================= APP BACKGROUND ================= */

        .stApp {
            background:
                radial-gradient(
                    circle at 50% -10%,
                    rgba(255, 210, 63, 0.14),
                    transparent 42%
                ),
                linear-gradient(
                    135deg,
                    #050505 0%,
                    #0A0906 55%,
                    #050505 100%
                ) !important;

            color: var(--pp-text);
        }

        [data-testid="stHeader"] {
            background: transparent !important;
        }

        /* =====================================================
           SECURITY BACKGROUND LAYER
           ===================================================== */

        .pp-security-bg {
            position: fixed;
            inset: 0;
            width: 100%;
            height: 100%;

            pointer-events: none;
            overflow: hidden;

            z-index: 0;
        }

        /* Code pattern */

        .pp-code-pattern {
            position: absolute;
            inset: 0;

            color: #FFD23F;
            font-family: "Courier New", monospace;
            font-size: 12px;
            line-height: 2.1;
            letter-spacing: 4px;

            opacity: 0.055;
            word-break: break-all;
            overflow: hidden;

            mask-image: radial-gradient(
                ellipse at center,
                black 0%,
                transparent 76%
            );

            -webkit-mask-image: radial-gradient(
                ellipse at center,
                black 0%,
                transparent 76%
            );
        }

        /* Lock position */

        .pp-lock-wrapper {
            position: absolute;

            top: 48%;
            left: 58%;

            width: min(430px, 45vw);
            min-width: 220px;

            transform: translate(-50%, -50%);

            opacity: 0.14;

            filter:
                drop-shadow(
                    0 0 30px rgba(255, 210, 63, 0.25)
                )
                drop-shadow(
                    0 0 90px rgba(255, 210, 63, 0.08)
                );
        }

        .pp-lock-wrapper svg {
            display: block;
            width: 100%;
            height: auto;
        }

        /* Keep Streamlit content above background */

        [data-testid="stAppViewContainer"] {
            position: relative;
            z-index: 1;
        }

        [data-testid="stAppViewContainer"] > .main {
            position: relative;
            z-index: 2;
        }

        /* ================= SIDEBAR ================= */

        [data-testid="stSidebar"] {
            background:
                linear-gradient(
                    180deg,
                    #171208 0%,
                    #0A0906 45%,
                    #050505 100%
                ) !important;

            border-right: 1px solid #5C4817 !important;
        }

        [data-testid="stSidebar"] > div:first-child {
            background: transparent !important;
        }

        [data-testid="stSidebar"] h1,
        [data-testid="stSidebar"] h2,
        [data-testid="stSidebar"] h3 {
            color: var(--pp-gold) !important;
        }

        [data-testid="stSidebar"] p,
        [data-testid="stSidebar"] .stCaption {
            color: #BEB6A3 !important;
        }

        /* Sidebar navigation */

        [data-testid="stSidebar"] [role="radiogroup"] {
            gap: 8px !important;
        }

        [data-testid="stSidebar"] [role="radiogroup"] label {
            display: flex !important;
            align-items: center !important;

            padding: 12px 14px !important;
            margin: 4px 0 !important;

            border: 1px solid transparent !important;
            border-radius: 12px !important;

            background: transparent !important;
            color: #C8C0AD !important;

            font-weight: 600 !important;
            transition: all 0.2s ease;
        }

        [data-testid="stSidebar"] [role="radiogroup"] label p {
            color: #C8C0AD !important;
            font-size: 0.95rem !important;
        }

        [data-testid="stSidebar"] [role="radiogroup"] label:hover {
            background: #211B0C !important;
            border-color: #6B541A !important;
        }

        [data-testid="stSidebar"] [role="radiogroup"] label:hover p {
            color: var(--pp-gold) !important;
        }

        [data-testid="stSidebar"] [role="radiogroup"]
        label:has(input:checked) {
            background:
                linear-gradient(
                    90deg,
                    #4A350D 0%,
                    #211A0B 100%
                ) !important;

            border: 1px solid #B8860B !important;

            box-shadow:
                inset 3px 0 0 var(--pp-gold),
                0 0 15px rgba(255, 210, 63, 0.08);
        }

        [data-testid="stSidebar"] [role="radiogroup"]
        label:has(input:checked) p {
            color: var(--pp-gold) !important;
            font-weight: 800 !important;
        }

        [data-testid="stSidebar"] input[type="radio"] {
            accent-color: var(--pp-gold) !important;
        }

        [data-testid="stSidebar"] hr {
            border-color: #39301A !important;
        }

        /* ================= TYPOGRAPHY ================= */

        h1, h2, h3, h4 {
            color: var(--pp-text);
            letter-spacing: -0.025em;
        }

        .pp-muted {
            color: var(--pp-muted);
        }

        .pp-eyebrow {
            color: var(--pp-gold);
            text-transform: uppercase;
            font-size: 0.72rem;
            font-weight: 800;
            letter-spacing: 0.14em;
        }

        .pp-small {
            font-size: 0.82rem;
            color: var(--pp-muted);
        }

        /* ================= HERO ================= */

        .pp-hero {
            padding: 2rem 2.2rem;
            border: 1px solid #6B541A;
            border-radius: 18px;

            background:
                radial-gradient(
                    circle at 85% 0%,
                    rgba(255, 210, 63, 0.18),
                    transparent 42%
                ),
                linear-gradient(
                    135deg,
                    #211B0C 0%,
                    #0F0E09 65%,
                    #080808 100%
                );

            margin-bottom: 1.25rem;
        }

        /* ================= CARDS ================= */

        .pp-card,
        .pp-kpi {
            background: rgba(17, 16, 12, 0.96);
            border: 1px solid var(--pp-border);
            border-radius: 15px;
        }

        .pp-card {
            padding: 1.15rem;
            min-height: 100%;
        }

        .pp-kpi {
            padding: 1rem 1.1rem;
        }

        .pp-kpi-label {
            color: var(--pp-muted);
            font-size: 0.82rem;
        }

        .pp-kpi-value {
            color: var(--pp-gold-light);
            font-size: 1.65rem;
            font-weight: 800;
            margin-top: 0.2rem;
        }

        /* ================= SCORE ================= */

        .pp-score {
            font-size: 3.7rem;
            font-weight: 900;
            line-height: 1;
            color: var(--pp-gold);
        }

        /* ================= RISK BADGES ================= */

        .pp-badge {
            display: inline-block;
            padding: 0.25rem 0.65rem;
            border-radius: 999px;
            font-size: 0.72rem;
            font-weight: 800;
        }

        .pp-low {
            color: #86EFAC;
            background: #123B2A;
        }

        .pp-medium {
            color: #FCD34D;
            background: #4A3510;
        }

        .pp-high {
            color: #FCA5A5;
            background: #4A171D;
        }

        .pp-info {
            color: var(--pp-gold-light);
            background: #3B2C0D;
        }

        /* ================= BUTTONS ================= */

        div.stButton > button {
            border-radius: 10px;
            border: 1px solid var(--pp-gold-dark);

            background: linear-gradient(
                180deg,
                #FFD84D 0%,
                #D9A900 100%
            );

            color: #080808;
            font-weight: 800;
            min-height: 42px;
        }

        div.stButton > button:hover {
            border-color: var(--pp-gold-light);

            background: linear-gradient(
                180deg,
                #FFE58A 0%,
                #EABF24 100%
            );

            color: #000000;
        }

        /* ================= INPUTS ================= */

        .stTextInput input,
        .stSelectbox div[data-baseweb="select"] {
            background: #0D0C09 !important;
            color: var(--pp-text) !important;
            border-color: #51421D !important;
        }

        .stTextInput input:focus {
            border-color: var(--pp-gold) !important;
            box-shadow: 0 0 0 1px var(--pp-gold) !important;
        }

        /* ================= PROGRESS ================= */

        .stProgress > div > div > div > div {
            background: linear-gradient(
                90deg,
                #B8860B,
                #FFD23F,
                #FFE58A
            );
        }

        /* ================= TABS & DIVIDERS ================= */

        button[data-baseweb="tab"] {
            color: #BEB6A3 !important;
        }

        button[data-baseweb="tab"][aria-selected="true"] {
            color: var(--pp-gold) !important;
        }

        hr {
            border-color: var(--pp-border) !important;
        }

        </style>
        """,
        unsafe_allow_html=True,
    )

# -----------------------------
# Database
# -----------------------------
def db_connect():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            package_name TEXT NOT NULL,
            manager TEXT NOT NULL,
            score INTEGER NOT NULL,
            level TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            top_threat TEXT
        )
        """
    )
    conn.commit()
    return conn


conn = db_connect()


def save_scan(name, manager, score, level, findings):
    threat = "None"
    for finding in findings:
        if finding.get("severity") in {"HIGH", "MEDIUM"} and finding.get("category") != "normal":
            threat = finding.get("title", "Security indicator")
            break
    conn.execute(
        """INSERT INTO scans (package_name, manager, score, level, timestamp, top_threat)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (name, manager, score, level, datetime.now(timezone.utc).isoformat(), threat),
    )
    conn.commit()


def load_history(limit=250):
    return pd.read_sql_query(
        """SELECT package_name, manager, score, level, timestamp, top_threat
           FROM scans ORDER BY id DESC LIMIT ?""",
        conn,
        params=(limit,),
    )


# -----------------------------
# Session state
# -----------------------------
def init_state():
    defaults = {
        "scan_result": None,
        "ai_explanation": None,
        "manager": "pip",
        "package_input": "",
        "version_input": "",
        "page": "Dashboard",
        "selected_history": None,
        "last_scan_saved": False,
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


# -----------------------------
# Helpers / presentation
# -----------------------------
def level_class(level):
    return {"LOW": "pp-low", "MEDIUM": "pp-medium", "HIGH": "pp-high", "CRITICAL": "pp-high"}.get(level, "pp-info")


def badge(level):
    return f'<span class="pp-badge {level_class(level)}">{level}</span>'


def finding_counts(analysis):
    counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for finding in analysis.get("findings", []):
        severity = str(finding.get("severity", "")).upper()
        if severity in counts:
            counts[severity] += 1
    return counts


def render_sidebar():
    with st.sidebar:
        st.markdown("## 🛡️ PackagePatrol AI")
        st.caption("Safer Dependencies. Stronger Code.")
        st.divider()
        st.session_state.page = st.radio(
            "Navigation",
            ["Dashboard", "Scan Package", "Scan History", "Reports", "Settings"],
            index=["Dashboard", "Scan Package", "Scan History", "Reports", "Settings"].index(st.session_state.page),
            label_visibility="collapsed",
        )
        st.divider()
        st.markdown("**Open Source Security Matters**")
        st.caption(
            "PackagePatrol AI helps developers detect vulnerabilities, malicious packages, "
            "typosquats and risky dependencies before they reach production."
        )
        st.caption("Supported ecosystems: **npm · PyPI**")
        st.divider()
        st.caption("Defensive scanner: metadata, heuristics and vulnerability lookup. It never installs or executes packages.")


def render_hero():
    st.markdown(
        """
        <div class="pp-hero">
          <div class="pp-eyebrow">Intelligent supply-chain security</div>
          <h1>Scan Before You Ship</h1>
          <p class="pp-muted">Detect vulnerabilities, malicious packages and risky dependencies in your open-source ecosystem.</p>
          <p>✓ Typosquat detection &nbsp;&nbsp; ✓ Malicious signals &nbsp;&nbsp; ✓ Plain-language AI explanations &nbsp;&nbsp; ✓ Risk-based decisions</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_kpis(history):
    vulnerabilities = 0
    malicious = 0
    dependencies = len(history)
    last_scan = "No scans yet"
    if not history.empty:
        vulnerabilities = int((history["top_threat"].fillna("").str.contains("Vulnerab", case=False)).sum())
        malicious = int((history["top_threat"].fillna("").str.contains("Malicious|Typosquat", case=False, regex=True)).sum())
        last_scan = pd.to_datetime(history.iloc[0]["timestamp"]).strftime("%d %b %Y")
    cols = st.columns(4)
    values = [
        ("Vulnerabilities Found", vulnerabilities),
        ("Malicious Signals", malicious),
        ("Dependencies Scanned", dependencies),
        ("Last Scan", last_scan),
    ]
    for col, (label, value) in zip(cols, values):
        with col:
            st.markdown(f'<div class="pp-kpi"><div class="pp-kpi-label">{label}</div><div class="pp-kpi-value">{value}</div></div>', unsafe_allow_html=True)


def run_scan(name, manager):
    package_name = clean_package_name(name)
    if not valid_package_name(package_name, manager):
        st.error("Invalid package name. Please verify the name for the selected ecosystem.")
        return
    st.session_state.scan_result = None
    st.session_state.ai_explanation = None
    st.session_state.last_scan_saved = False
    with st.status("Running PackagePatrol security checks…", expanded=True) as status:
        try:
            st.write("Retrieving package metadata…")
            result = full_scan(manager, package_name)
            st.write("Checking vulnerabilities and package signals…")
            if result is None:
                status.update(label="Package not found", state="error")
                st.error("Package not found. Please verify the package name and ecosystem.")
                return
            st.write("Calculating risk score…")
            st.session_state.scan_result = result
            analysis = result["analysis"]
            save_scan(package_name, manager, analysis["score"], analysis["level"], analysis["findings"])
            st.session_state.last_scan_saved = True
            status.update(label="Scan completed", state="complete")
        except Exception:
            status.update(label="Analysis unavailable", state="error")
            st.error("Unable to retrieve package information or complete the security analysis. Please try again.")


def render_scan_form():
    st.markdown("## 🔍 Scan Package")
    st.caption("Enter a package name and optional version to check available security signals.")
    with st.container(border=True):
        c1, c2 = st.columns([2, 1])
        with c1:
            st.text_input("Package Name", key="package_input", placeholder="requests, lodash, express…")
        with c2:
            st.selectbox("Ecosystem", ["pip", "npm"], key="manager", format_func=lambda x: "PyPI" if x == "pip" else "npm")
        st.text_input("Version (optional)", key="version_input", placeholder="e.g. 2.32.5")
        if st.button("🔍 Scan Package →", type="primary", use_container_width=True):
            run_scan(st.session_state.package_input, st.session_state.manager)
    st.caption("Try an example")
    demo_cols = st.columns(5)
    demos = [("requests", "pip"), ("lodash", "npm"), ("express", "npm"), ("axios", "npm"), ("django", "pip")]
    for col, (name, manager) in zip(demo_cols, demos):
        with col:
            if st.button(name, use_container_width=True, key=f"demo_{name}"):
                st.session_state.package_input = name
                st.session_state.manager = manager
                st.session_state.page = "Scan Package"
                st.rerun()


def render_score(analysis, package):
    score = max(0, min(100, int(analysis.get("score", 0))))
    level = analysis.get("level", "UNKNOWN")
    st.markdown(
        f'<div class="pp-card"><div class="pp-eyebrow">Security Risk</div><h2>{package.get("name", "Package")}</h2>'
        f'<p class="pp-small">{package.get("manager", "").upper()} · Version {package.get("version", "N/A")}</p>'
        f'<div style="margin:1.2rem 0 .6rem"><span class="pp-score">{score}</span><span class="pp-small"> / 100</span></div>'
        f'<div style="margin-bottom:.7rem">{badge(level)}</div><p class="pp-muted">{risk_summary(score, level)}</p></div>',
        unsafe_allow_html=True,
    )
    st.progress(score / 100, text=f"Risk score: {score}/100")


def render_security_checks(analysis):
    findings = analysis.get("findings", [])
    categories = {
        "Known Vulnerabilities": any(f.get("category") == "known_security" for f in findings),
        "Malicious Package": any("malicious" in str(f).lower() for f in findings),
        "Typosquat Risk": bool(analysis.get("typosquatting")),
        "Install Script Risk": any("install" in str(f).lower() for f in findings),
    }
    cols = st.columns(4)
    for col, (label, detected) in zip(cols, categories.items()):
        with col:
            state = "Detected" if detected else "No signal"
            icon = "⚠️" if detected else "✓"
            st.markdown(f'<div class="pp-card"><b>{label}</b><h3>{icon} {state}</h3><div class="pp-small">Based on available scanner evidence</div></div>', unsafe_allow_html=True)


def render_findings(analysis):
    st.markdown("## Security Findings")
    for finding in analysis.get("findings", []):
        severity = str(finding.get("severity", "INFO")).upper()
        title = finding.get("title", "Security Finding")
        explanation = finding.get("explanation", "No explanation available.")
        evidence = finding.get("evidence", "No evidence available.")
        with st.expander(f"{title} · {severity}", expanded=severity in {"HIGH", "MEDIUM"}):
            st.markdown(f"**Severity:** {badge(severity)}", unsafe_allow_html=True)
            st.write(explanation)
            st.caption(f"Evidence: {evidence}")


def render_result():
    result = st.session_state.scan_result
    if not result:
        return
    package, analysis = result["package"], result["analysis"]
    st.divider()
    st.markdown("## 🛡️ Scan Result")
    left, right = st.columns([1.2, 1])
    with left:
        render_score(analysis, package)
    with right:
        st.markdown("### Risk Breakdown")
        counts = finding_counts(analysis)
        total = sum(counts.values()) or 1
        for label, count in counts.items():
            st.write(f"**{label}** · {count}")
            st.progress(count / total)
        st.markdown("### Recommended Actions")
        level = analysis.get("level", "LOW")
        actions = {
            "LOW": ["Keep using this version if it meets your needs.", "Monitor new advisories.", "Consider dependency lock files."],
            "MEDIUM": ["Review the dependency and its findings.", "Check available updates.", "Monitor advisories before deployment."],
            "HIGH": ["Upgrade or replace the dependency.", "Review dependency usage and package source.", "Consider blocking deployment until reviewed.", "Investigate suspicious behavior."],
            "CRITICAL": ["Block deployment until investigated.", "Replace or remove the dependency.", "Review package source and transitive impact."],
        }
        for action in actions.get(level, actions["LOW"]):
            st.markdown(f"- {action}")
    st.markdown("### Security Checks")
    render_security_checks(analysis)
    st.markdown("### Why this score?")
    reasons = [f.get("explanation") for f in analysis.get("findings", []) if f.get("severity") in {"HIGH", "MEDIUM", "LOW"}]
    if reasons:
        for reason in reasons[:6]:
            st.markdown(f"- {reason}")
    else:
        st.caption("No additional scored findings were returned.")
    render_findings(analysis)
    st.markdown("### 🤖 AI Security Explanation")
    if st.session_state.ai_explanation:
        st.markdown(st.session_state.ai_explanation)
    elif st.button("Generate AI Explanation", key="ai_button"):
        with st.spinner("Generating an evidence-based explanation…"):
            try:
                st.session_state.ai_explanation = generate_ai_explanation(result)
                st.rerun()
            except Exception:
                st.warning("AI explanation is unavailable. Add GROQ_API_KEY in Streamlit Secrets or the environment.")
    st.markdown("### Package Details")
    details = {
        "Package": package.get("name"), "Ecosystem": package.get("manager"), "Version": package.get("version"),
        "Author / maintainer": package.get("author"), "Description": package.get("description"),
        "License": package.get("license"), "First release": package.get("release_date") or "N/A",
        "Last updated": package.get("last_updated") or "N/A", "Versions": package.get("versions_count"),
        "Dependencies": len(package.get("dependencies") or []),
    }
    st.dataframe(pd.DataFrame(details.items(), columns=["Field", "Value"]), use_container_width=True, hide_index=True)
    st.link_button("Open package registry page", package_url(package["manager"], package["name"]))


def render_dashboard():
    render_hero()
    history = load_history()
    render_kpis(history)
    st.markdown("## Start with a security scan")
    if st.button("🔍 Scan a package", type="primary"):
        st.session_state.page = "Scan Package"
        st.rerun()
    st.markdown("## Recent activity")
    if history.empty:
        st.info("No scans yet. Run your first package scan to populate the dashboard.")
    else:
        st.dataframe(history.head(8), use_container_width=True, hide_index=True)


def render_history():
    st.markdown("## 🕘 Scan History")
    history = load_history()
    if history.empty:
        st.info("No scan history available yet.")
        return
    c1, c2, c3 = st.columns(3)
    with c1:
        manager_filter = st.selectbox("Ecosystem", ["All", "pip", "npm"])
    with c2:
        level_filter = st.selectbox("Risk level", ["All", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
    with c3:
        package_filter = st.text_input("Package name", placeholder="Filter packages")
    filtered = history.copy()
    if manager_filter != "All":
        filtered = filtered[filtered.manager == manager_filter]
    if level_filter != "All":
        filtered = filtered[filtered.level == level_filter]
    if package_filter:
        filtered = filtered[filtered.package_name.str.contains(package_filter, case=False, na=False)]
    st.dataframe(filtered, use_container_width=True, hide_index=True)


def render_reports():
    st.markdown("## 📄 Reports")
    result = st.session_state.scan_result
    if not result:
        st.info("Run a scan first to generate a report.")
        return
    package, analysis = result["package"], result["analysis"]
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "package": package,
        "analysis": analysis,
        "ai_explanation": st.session_state.ai_explanation,
    }
    st.download_button(
        "📄 Download JSON Report",
        data=json.dumps(report, indent=2, ensure_ascii=False, default=str),
        file_name=f"packagepatrol-{package.get('name', 'scan')}.json",
        mime="application/json",
        use_container_width=True,
    )
    st.json(report)


def render_settings():
    st.markdown("## ⚙️ Settings")
    st.markdown("### Scanner configuration")
    st.write("Supported ecosystems: **PyPI** and **npm**")
    st.write("The scanner uses registry metadata, heuristic signals and OSV vulnerability records.")
    st.markdown("### AI configuration")
    st.write("Set `GROQ_API_KEY` in Streamlit Secrets or as an environment variable to enable AI explanations.")
    st.markdown("### Data")
    st.write(f"SQLite database: `{DB_FILE}`")
    st.caption("No packages are installed or executed by this application.")


# -----------------------------
# Main
# -----------------------------
init_state()
inject_css()
render_sidebar()

if st.session_state.page == "Dashboard":
    render_dashboard()
elif st.session_state.page == "Scan Package":
    render_scan_form()
    render_result()
elif st.session_state.page == "Scan History":
    render_history()
elif st.session_state.page == "Reports":
    render_reports()
elif st.session_state.page == "Settings":
    render_settings()



