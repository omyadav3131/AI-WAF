import html
import json
import time
from datetime import datetime
from pathlib import Path

import requests
import streamlit as st

API_URL = "http://localhost:8000"
CLASS_NAMES = ["BENIGN", "SQL Injection", "XSS"]
DECISION_THRESHOLD = 0.90
COLOR_VARS = {
    "BENIGN": "--benign",
    "SQL Injection": "--sqli",
    "XSS": "--xss",
}
PRESETS = {
    "Benign: product listing": (
        "GET /products?category=electronics&page=2 HTTP/1.1\n"
        "Host: shop.example.com\n"
        "User-Agent: Mozilla/5.0\n"
        "Accept: text/html"
    ),
    "Benign: search with SQL word": (
        "GET /search?q=select+shoes HTTP/1.1\n"
        "Host: shop.example.com\n"
        "Accept: text/html"
    ),
    "SQLi: tautology": (
        "GET /search?q=' OR 1=1-- HTTP/1.1\n"
        "Host: shop.example.com\n"
        "User-Agent: Mozilla/5.0"
    ),
    "SQLi: UNION SELECT": (
        "GET /products?id=1 UNION SELECT username,password FROM users-- HTTP/1.1\n"
        "Host: shop.example.com"
    ),
    "XSS: script tag": (
        "POST /comment HTTP/1.1\n"
        "Host: shop.example.com\n"
        "Content-Type: application/x-www-form-urlencoded\n\n"
        "body=<script>alert(document.cookie)</script>"
    ),
    "XSS: img onerror": (
        "GET /search?q=<img src=x onerror=alert(1)> HTTP/1.1\n"
        "Host: shop.example.com"
    ),
    "Custom": "",
}

BATCH_CASES = [
    {
        "request": "GET /products?category=electronics&page=2 HTTP/1.1\nHost: shop.example.com",
        "expected": "BENIGN",
    },
    {
        "request": "GET /search?q=select+shoes HTTP/1.1\nHost: shop.example.com",
        "expected": "BENIGN",
    },
    {
        "request": "GET /search?q=union+jack+flag HTTP/1.1\nHost: shop.example.com",
        "expected": "BENIGN",
    },
    {
        "request": "GET /guides/drop-shipping-guide HTTP/1.1\nHost: shop.example.com",
        "expected": "BENIGN",
    },
    {
        "request": "GET /account/profile HTTP/1.1\nHost: shop.example.com\nAccept: text/html",
        "expected": "BENIGN",
    },
    {
        "request": "GET /search?q=' OR 1=1-- HTTP/1.1\nHost: shop.example.com",
        "expected": "SQL Injection",
    },
    {
        "request": "GET /products?id=1 UNION SELECT username,password FROM users-- HTTP/1.1\nHost: shop.example.com",
        "expected": "SQL Injection",
    },
    {
        "request": "POST /login HTTP/1.1\nHost: shop.example.com\nContent-Type: application/x-www-form-urlencoded\n\nusername=admin'--&password=x",
        "expected": "SQL Injection",
    },
    {
        "request": "GET /item?id=1; DROP TABLE users HTTP/1.1\nHost: shop.example.com",
        "expected": "SQL Injection",
    },
    {
        "request": "GET /search?q=1 AND SLEEP(5) HTTP/1.1\nHost: shop.example.com",
        "expected": "SQL Injection",
    },
    {
        "request": "POST /comment HTTP/1.1\nHost: shop.example.com\nContent-Type: application/x-www-form-urlencoded\n\nbody=<script>alert(1)</script>",
        "expected": "XSS",
    },
    {
        "request": "GET /search?q=<img src=x onerror=alert(1)> HTTP/1.1\nHost: shop.example.com",
        "expected": "XSS",
    },
    {
        "request": "GET /page?q=<svg onload=alert(1)> HTTP/1.1\nHost: shop.example.com",
        "expected": "XSS",
    },
    {
        "request": "POST /profile HTTP/1.1\nHost: shop.example.com\nContent-Type: application/x-www-form-urlencoded\n\nname=<iframe src=javascript:alert(1)>",
        "expected": "XSS",
    },
    {
        "request": "GET /search?q=javascript:alert(document.cookie) HTTP/1.1\nHost: shop.example.com",
        "expected": "XSS",
    },
]

st.set_page_config(page_title="AI-WAF Console", layout="wide")

st.markdown(
    """
    <style>
    :root {
        --bg: #0b0f14;
        --surface: #121821;
        --surface-2: #18202b;
        --border: #243040;
        --text: #d7dee8;
        --muted: #7d8a9b;
        --benign: 47, 191, 113;
        --sqli: 255, 93, 93;
        --xss: 245, 165, 36;
        --accent: #4aa3ff;
        --mono: "JetBrains Mono", "Cascadia Code", Consolas, monospace;
        --sans: Inter, "Segoe UI", sans-serif;
    }
    html, body, [data-testid="stAppViewContainer"] {
        background: var(--bg);
        color: var(--text);
        font-family: var(--sans);
    }
    [data-testid="stHeader"], [data-testid="stDecoration"], [data-testid="stToolbar"],
    #MainMenu, footer, header button[title="View fullscreen"] {
        visibility: hidden;
        height: 0;
    }
    [data-testid="stAppViewContainer"] > .main .block-container {
        max-width: 1480px;
        padding: 1.15rem 1.65rem 2rem;
    }
    h1, h2, h3, p, label, li, [data-testid="stMetricLabel"] {
        font-family: var(--sans);
    }
    h1 { font-size: 1.55rem; letter-spacing: -0.025em; margin: 0; }
    h2 { font-size: 1.08rem; letter-spacing: -0.01em; }
    h3 { font-size: 0.95rem; }
    p, label, li { color: var(--text); }
    [data-testid="stMarkdownContainer"] p { line-height: 1.48; }
    [data-testid="stTabs"] [role="tablist"] {
        border-bottom: 1px solid var(--border);
        gap: 1.15rem;
    }
    [data-testid="stTabs"] button[role="tab"] {
        color: var(--muted);
        font-family: var(--sans);
        padding: 0.65rem 0.15rem;
    }
    [data-testid="stTabs"] button[role="tab"][aria-selected="true"] {
        color: var(--text);
        border-bottom-color: var(--accent);
    }
    [data-testid="stTextArea"] textarea, [data-testid="stTextInput"] input,
    [data-testid="stSelectbox"] div[data-baseweb="select"] {
        background: var(--surface);
        color: var(--text);
        border-color: var(--border);
        border-radius: 8px;
    }
    [data-testid="stTextArea"] textarea {
        font-family: var(--mono);
        font-size: 0.82rem;
        line-height: 1.55;
    }
    [data-testid="stSelectbox"] * { font-family: var(--sans); }
    .stButton button {
        border: 1px solid var(--border);
        border-radius: 8px;
        min-height: 2.45rem;
        font-family: var(--sans);
        font-weight: 600;
        background: var(--surface-2);
        color: var(--text);
    }
    .stButton button[kind="primary"] {
        background: var(--accent);
        color: #07111d;
        border-color: var(--accent);
    }
    [data-testid="stMetric"] {
        background: var(--surface);
        border: 1px solid var(--border);
        border-radius: 9px;
        padding: 0.72rem 0.9rem;
    }
    [data-testid="stMetricLabel"] { color: var(--muted); }
    [data-testid="stMetricValue"] { font-family: var(--mono); font-size: 1.25rem; }
    [data-testid="stAlert"] { border-radius: 8px; }
    .console-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 16px;
        margin: 0 0 1.2rem;
        padding: 0.1rem 0 0.95rem;
        border-bottom: 1px solid var(--border);
    }
    .console-kicker {
        color: var(--muted);
        font: 600 0.67rem var(--mono);
        letter-spacing: 0.13em;
        text-transform: uppercase;
        margin-bottom: 0.28rem;
    }
    .status-strip { display: flex; flex-wrap: wrap; gap: 7px; justify-content: flex-end; }
    .status-item {
        background: var(--surface);
        border: 1px solid var(--border);
        border-radius: 7px;
        color: var(--muted);
        padding: 0.38rem 0.56rem;
        font: 0.68rem var(--mono);
        white-space: nowrap;
    }
    .status-online { color: rgb(var(--benign)); }
    .status-offline { color: rgb(var(--sqli)); }
    .panel {
        background: var(--surface);
        border: 1px solid var(--border);
        border-radius: 10px;
        padding: 1rem 1.05rem;
        margin-bottom: 0.75rem;
    }
    .panel-label {
        color: var(--muted);
        font: 600 0.66rem var(--mono);
        letter-spacing: 0.1em;
        text-transform: uppercase;
        margin-bottom: 0.45rem;
    }
    .verdict {
        background: var(--surface);
        border: 1px solid var(--border);
        border-left: 4px solid rgb(var(--verdict-color));
        border-radius: 9px;
        padding: 1rem 1.1rem;
        margin: 0.15rem 0 0.8rem;
    }
    .verdict-label {
        color: rgb(var(--verdict-color));
        font: 700 1.55rem var(--mono);
        letter-spacing: -0.04em;
    }
    .verdict-action {
        color: var(--text);
        font: 700 0.78rem var(--mono);
        letter-spacing: 0.08em;
        margin-top: 0.65rem;
    }
    .verdict-meta { color: var(--muted); font: 0.72rem var(--mono); margin-top: 0.3rem; }
    .prob-row {
        display: grid;
        grid-template-columns: 110px minmax(50px, 1fr) 62px;
        gap: 10px;
        align-items: center;
        margin: 0.65rem 0;
    }
    .prob-name, .prob-value { font: 0.72rem var(--mono); }
    .prob-name { color: var(--muted); }
    .prob-value { color: var(--text); text-align: right; }
    .prob-track {
        background: var(--surface-2);
        border: 1px solid var(--border);
        height: 8px;
        border-radius: 20px;
        overflow: hidden;
    }
    .prob-fill { height: 100%; border-radius: 20px; }
    .latency-line { color: var(--muted); font: 0.7rem var(--mono); margin-top: 0.7rem; }
    .attention-flow {
        background: var(--surface);
        border: 1px solid var(--border);
        border-radius: 9px;
        padding: 1rem;
        line-height: 2.15;
        overflow-wrap: anywhere;
        font: 0.78rem/2.15 var(--mono);
    }
    .attention-token {
        display: inline;
        color: var(--text);
        border-radius: 3px;
        padding: 0.18rem 0.05rem;
        white-space: pre-wrap;
    }
    .small-note { color: var(--muted); font-size: 0.72rem; }
    .error-card {
        background: rgba(var(--sqli), 0.08);
        border: 1px solid rgba(var(--sqli), 0.42);
        border-left: 3px solid rgb(var(--sqli));
        border-radius: 8px;
        color: var(--text);
        padding: 0.75rem 0.9rem;
        margin: 0.6rem 0;
        font: 0.78rem/1.5 var(--sans);
    }
    .error-card code { color: var(--text); font-family: var(--mono); }
    .result-table { width: 100%; border-collapse: collapse; font: 0.72rem var(--mono); }
    .result-table th, .result-table td {
        border-bottom: 1px solid var(--border);
        padding: 0.55rem 0.45rem;
        text-align: left;
        vertical-align: top;
    }
    .result-table th { color: var(--muted); font-weight: 600; }
    .result-pass { color: rgb(var(--benign)); font-weight: 700; }
    .result-fail { color: rgb(var(--sqli)); font-weight: 700; }
    @media (max-width: 780px) {
        [data-testid="stAppViewContainer"] > .main .block-container { padding: 0.8rem; }
        .console-header { align-items: flex-start; flex-direction: column; }
        .status-strip { justify-content: flex-start; }
        .prob-row { grid-template-columns: 92px minmax(35px, 1fr) 54px; gap: 6px; }
    }
    </style>
    """,
    unsafe_allow_html=True,
)

def escape(value):
    return html.escape(str(value), quote=True)


def get_health():
    try:
        response = requests.get(f"{API_URL}/health", timeout=1.0)
        response.raise_for_status()
        payload = response.json()
        return True, str(payload.get("version", "v3"))
    except (requests.RequestException, ValueError):
        return False, "v3"


def show_api_error():
    st.markdown(
        '<div class="error-card">API is unavailable. Start it with '
        '<code>uvicorn api.app:app --host 0.0.0.0 --port 8000</code>.</div>',
        unsafe_allow_html=True,
    )


def update_request_from_preset():
    selected = st.session_state.get("preset_choice", "Custom")
    if selected in PRESETS and selected != "Custom":
        st.session_state["request_text"] = PRESETS[selected]


def clear_request():
    st.session_state["request_text"] = ""
    st.session_state["preset_choice"] = "Custom"
    st.session_state["analysis_result"] = None
    st.session_state["analysis_error"] = None


def predict(request_text, timeout=60):
    started = time.perf_counter()
    response = requests.post(
        f"{API_URL}/predict",
        json={"request": request_text},
        timeout=timeout,
    )
    response.raise_for_status()
    result = response.json()
    elapsed_ms = (time.perf_counter() - started) * 1000.0
    return result, elapsed_ms


def label_color(label):
    return COLOR_VARS.get(label, COLOR_VARS["BENIGN"])


def render_verdict(result, latency_ms):
    label = str(result.get("label", "Unknown"))
    confidence = float(result.get("confidence", 0.0))
    color = label_color(label)
    is_benign = label == "BENIGN"
    if is_benign:
        action = "ALLOW"
    elif confidence < DECISION_THRESHOLD:
        action = "FLAG FOR REVIEW"
    else:
        action = "BLOCK"

    st.markdown(
        f"""
        <div class="verdict" style="--verdict-color:var({color})">
            <div class="panel-label">Classification verdict</div>
            <div class="verdict-label">{escape(label)}</div>
            <div class="verdict-action">{action}</div>
            <div class="verdict-meta">Confidence: {confidence:.2%}</div>
            <div class="verdict-meta">Decision threshold: {DECISION_THRESHOLD:.2f}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    probabilities = result.get("probs", [])
    rows = []
    for index, name in enumerate(CLASS_NAMES):
        probability = float(probabilities[index]) if index < len(probabilities) else 0.0
        width = max(0.0, min(100.0, probability * 100.0))
        color = COLOR_VARS[name]
        rows.append(
            f'<div class="prob-row"><span class="prob-name">{escape(name)}</span>'
            f'<div class="prob-track"><div class="prob-fill" style="width:{width:.2f}%;background:rgb(var({color}))"></div></div>'
            f'<span class="prob-value">{probability:.4f}</span></div>'
        )
    st.markdown(
        '<div class="panel"><div class="panel-label">Class probabilities</div>'
        + "".join(rows)
        + f'<div class="latency-line">Inference latency: {latency_ms:.1f} ms</div></div>',
        unsafe_allow_html=True,
    )


def render_attention(result):
    label = str(result.get("label", "BENIGN"))
    color = label_color(label)
    color_variable = label_color(label)
    tokens = result.get("tokens", [])
    weights = result.get("attention_weights", [])
    groups = []

    for token, raw_weight in zip(tokens, weights):
        token = str(token)
        if token in ("[CLS]", "[SEP]", "[PAD]"):
            continue
        try:
            weight = max(0.0, min(1.0, float(raw_weight)))
        except (TypeError, ValueError):
            weight = 0.0
        if token.startswith("##") and groups:
            groups[-1]["text"] += token[2:]
            groups[-1]["weights"].append(weight)
        else:
            groups.append({"text": token, "weights": [weight]})

    spans = []
    for group in groups:
        mean_weight = sum(group["weights"]) / len(group["weights"])
        alpha = 0.08 + mean_weight * 0.72
        title_weights = ", ".join(f"{item:.4f}" for item in group["weights"])
        spans.append(
            f'<span class="attention-token" title="Attention weight: {title_weights}" '
            f'style="background-color:rgba(var({color_variable}), {alpha:.3f})">{escape(group["text"])}</span>'
        )

    st.markdown("### Token attention")
    if spans:
        st.markdown(
            '<div class="attention-flow">' + " ".join(spans) + "</div>",
            unsafe_allow_html=True,
        )
    else:
        st.markdown('<div class="panel small-note">No displayable tokens.</div>', unsafe_allow_html=True)

    top_tokens = []
    for token, raw_weight in zip(tokens, weights):
        if str(token) in ("[CLS]", "[SEP]", "[PAD]"):
            continue
        try:
            weight = float(raw_weight)
        except (TypeError, ValueError):
            continue
        top_tokens.append((str(token), weight))
    top_tokens.sort(key=lambda row: row[1], reverse=True)
    st.markdown("#### Top 5 tokens")
    if top_tokens:
        st.table(
            [{"Token": token, "Weight": f"{weight:.4f}"} for token, weight in top_tokens[:5]]
        )
    st.markdown(
        '<div class="small-note">Attention weights are an interpretability aid, not causal proof.</div>',
        unsafe_allow_html=True,
    )


def render_history():
    history = st.session_state.get("analysis_history", [])
    st.markdown("### Session history")
    if not history:
        st.markdown('<div class="small-note">No analyses in this session.</div>', unsafe_allow_html=True)
        return
    st.table(
        [
            {
                "Time": row["time"],
                "Label": row["label"],
                "Confidence": f'{row["confidence"]:.2%}',
                "Request": row["request"],
            }
            for row in history[-10:]
        ]
    )


def render_batch_table(rows):
    body = []
    for row in rows:
        verdict_class = "result-pass" if row["passed"] else "result-fail"
        status = "PASS" if row["passed"] else "FAIL"
        body.append(
            "<tr>"
            f'<td>{row["number"]}</td>'
            f'<td>{escape(row["request"])}</td>'
            f'<td>{escape(row["expected"])}</td>'
            f'<td>{escape(row["predicted"])}</td>'
            f'<td>{row["confidence"]:.2%}</td>'
            f'<td class="{verdict_class}">{status}</td>'
            "</tr>"
        )
    st.markdown(
        '<table class="result-table"><thead><tr><th>#</th><th>Request</th>'
        "<th>Expected</th><th>Predicted</th><th>Confidence</th><th>Result</th></tr></thead>"
        "<tbody>"
        + "".join(body)
        + "</tbody></table>",
        unsafe_allow_html=True,
    )


def run_batch():
    results = []
    progress = st.progress(0.0)
    status = st.empty()
    for index, case in enumerate(BATCH_CASES, start=1):
        status.caption(f"Analyzing request {index} of {len(BATCH_CASES)}")
        try:
            prediction, latency_ms = predict(case["request"], timeout=60)
            predicted = str(prediction["label"])
            confidence = float(prediction["confidence"])
            results.append(
                {
                    "number": index,
                    "request": case["request"].replace("\n", " ")[:92],
                    "expected": case["expected"],
                    "predicted": predicted,
                    "confidence": confidence,
                    "passed": predicted == case["expected"],
                    "latency_ms": latency_ms,
                }
            )
        except Exception as error:
            results.append(
                {
                    "number": index,
                    "request": case["request"].replace("\n", " ")[:92],
                    "expected": case["expected"],
                    "predicted": f"ERROR: {error}",
                    "confidence": 0.0,
                    "passed": False,
                    "latency_ms": None,
                }
            )
        progress.progress(index / len(BATCH_CASES))
    status.empty()
    st.session_state["batch_results"] = results


if "request_text" not in st.session_state:
    st.session_state["request_text"] = PRESETS["Benign: product listing"]
if "preset_choice" not in st.session_state:
    st.session_state["preset_choice"] = "Benign: product listing"
if "analysis_result" not in st.session_state:
    st.session_state["analysis_result"] = None
if "analysis_error" not in st.session_state:
    st.session_state["analysis_error"] = None
if "analysis_history" not in st.session_state:
    st.session_state["analysis_history"] = []
if "last_latency_ms" not in st.session_state:
    st.session_state["last_latency_ms"] = None

api_online, api_version = get_health()
latency_value = st.session_state["last_latency_ms"]
latency_text = f"{latency_value:.1f} ms" if latency_value is not None else "not measured"
api_class = "status-online" if api_online else "status-offline"
api_word = "online" if api_online else "offline"

st.markdown(
    f"""
    <div class="console-header">
        <div>
            <div class="console-kicker">Web application firewall / monitoring</div>
            <h1>AI-WAF Console</h1>
        </div>
        <div class="status-strip">
            <div class="status-item">API: <span class="{api_class}">{api_word}</span></div>
            <div class="status-item">Model: {escape(api_version)}</div>
            <div class="status-item">Last request: {escape(latency_text)}</div>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

if not api_online:
    show_api_error()

analyze_tab, batch_tab, info_tab = st.tabs(["Analyze", "Batch Test", "Model Info"])

with analyze_tab:
    left, right = st.columns([5, 7], gap="large")
    with left:
        st.markdown("### Request inspection")
        st.selectbox(
            "Preset request",
            options=list(PRESETS.keys()),
            key="preset_choice",
            on_change=update_request_from_preset,
        )
        st.text_area(
            "Raw HTTP request",
            key="request_text",
            height=248,
            help="Paste an HTTP request for classification.",
        )
        button_left, button_right = st.columns([3, 2])
        with button_left:
            analyze_clicked = st.button("Analyze", type="primary", use_container_width=True)
        with button_right:
            st.button("Clear", use_container_width=True, on_click=clear_request)

        if analyze_clicked:
            request_value = st.session_state.get("request_text", "")
            if not request_value.strip():
                st.session_state["analysis_error"] = "Enter an HTTP request before analyzing."
                st.session_state["analysis_result"] = None
            else:
                try:
                    result, latency_ms = predict(request_value)
                    st.session_state["analysis_result"] = result
                    st.session_state["analysis_error"] = None
                    st.session_state["last_latency_ms"] = latency_ms
                    history = st.session_state["analysis_history"]
                    history.append(
                        {
                            "time": datetime.now().strftime("%H:%M:%S"),
                            "label": str(result.get("label", "Unknown")),
                            "confidence": float(result.get("confidence", 0.0)),
                            "request": request_value.replace("\n", " ")[:50],
                        }
                    )
                    st.session_state["analysis_history"] = history[-10:]
                except requests.RequestException:
                    st.session_state["analysis_error"] = "API request failed."
                    st.session_state["analysis_result"] = None
                except (ValueError, KeyError, TypeError) as error:
                    st.session_state["analysis_error"] = f"Invalid API response: {error}"
                    st.session_state["analysis_result"] = None
            st.rerun()

    with right:
        result = st.session_state.get("analysis_result")
        error_message = st.session_state.get("analysis_error")
        if error_message:
            st.markdown(
                f'<div class="error-card">{escape(error_message)}</div>',
                unsafe_allow_html=True,
            )
            if not api_online:
                show_api_error()
        elif result:
            render_verdict(result, st.session_state.get("last_latency_ms") or 0.0)
        else:
            st.markdown(
                '<div class="panel"><div class="panel-label">Awaiting request</div>'
                '<div class="small-note">Choose a preset or paste a request, then analyze it.</div></div>',
                unsafe_allow_html=True,
            )

    result = st.session_state.get("analysis_result")
    if result:
        render_attention(result)
    render_history()

with batch_tab:
    st.markdown("### Batch test")
    st.markdown(
        '<div class="small-note">15 fixed requests, five per class. Results are shown as returned by the API.</div>',
        unsafe_allow_html=True,
    )
    if st.button("Run all tests", type="primary", disabled=not api_online):
        run_batch()

    batch_results = st.session_state.get("batch_results")
    if batch_results:
        passed = sum(1 for row in batch_results if row["passed"])
        total = len(batch_results)
        false_positives = sum(
            1
            for row in batch_results
            if row["expected"] == "BENIGN" and row["predicted"] != "BENIGN"
        )
        metric_a, metric_b, metric_c = st.columns(3)
        metric_a.metric("Passed / total", f"{passed} / {total}")
        metric_b.metric("Accuracy", f"{(passed / total * 100.0) if total else 0.0:.1f}%")
        metric_c.metric("False positives", false_positives)
        render_batch_table(batch_results)
    elif not api_online:
        show_api_error()

with info_tab:
    st.markdown("### Model information")
    st.markdown(
        """
        **Model:** bert-base-uncased fine-tuned for three classes

        **Maximum sequence length:** 128 tokens

        **Inference preprocessing:** URL decode, HTML unescape, and whitespace normalisation.

        **Version history:** v2 learned a length shortcut and misclassified a normal
        request as SQL Injection. v3 uses paired benign and attack templates.
        """
    )

    config_path = Path(__file__).resolve().parents[1] / "models" / "bert" / "model_config_v3.json"
    if config_path.is_file():
        try:
            with config_path.open("r", encoding="utf-8") as config_file:
                model_config = json.load(config_file)
            score_values = []
            if "best_val_macro_f1" in model_config:
                score_values.append(("Best validation Macro F1", model_config["best_val_macro_f1"]))
            if "test_macro_f1" in model_config:
                score_values.append(("Test Macro F1", model_config["test_macro_f1"]))
            if score_values:
                score_columns = st.columns(len(score_values))
                for column, (title, value) in zip(score_columns, score_values):
                    column.metric(title, f"{float(value):.4f}")
        except (OSError, ValueError, TypeError):
            pass

    st.markdown("#### Limitations")
    st.markdown(
        """
        - Training and test data are mostly synthetic templates.
        - Coverage is limited to SQL Injection and XSS.
        - Attention weights are not causal explanations.
        - CPU inference is slow for high traffic.
        """
    )
