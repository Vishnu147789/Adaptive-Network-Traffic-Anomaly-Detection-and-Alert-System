from __future__ import annotations

from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

st.set_page_config(page_title="Enterprise SOC Dashboard", layout="wide")
DARK_TEMPLATE = "plotly_dark"


def inject_styles() -> None:
    st.markdown(
        """
        <style>
        .stApp {
            background: radial-gradient(circle at top, #0f172a 0%, #020617 55%, #000000 100%);
            color: #E5E7EB;
        }
        .block-container {
            padding-top: 1.15rem;
            padding-bottom: 1rem;
            max-width: 96rem;
        }
        .dashboard-title {
            font-size: 1.85rem;
            font-weight: 700;
            color: #F8FAFC;
            margin-bottom: 0.15rem;
        }
        .dashboard-subtitle {
            color: #94A3B8;
            margin-bottom: 0.9rem;
        }
        .panel {
            border: 1px solid rgba(71, 85, 105, 0.45);
            background: rgba(15, 23, 42, 0.72);
            border-radius: 12px;
            padding: 0.85rem;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def load_data(path: str = "alerts.csv") -> tuple[pd.DataFrame, bool]:
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"{path} not found")

    try:
        df = pd.read_csv(file_path)
        used_fallback = False
    except pd.errors.ParserError:
        # Fallback parser skips malformed rows instead of crashing the dashboard.
        df = pd.read_csv(file_path, engine="python", on_bad_lines="skip")
        used_fallback = True

    if "time" in df.columns:
        df["time"] = pd.to_datetime(df["time"], errors="coerce")
        df = df.dropna(subset=["time"]).sort_values("time")

    return df, used_fallback


def classify_threat(alert_count: int) -> tuple[str, str]:
    if alert_count >= 100:
        return "CRITICAL", "#EF4444"
    if alert_count >= 30:
        return "ELEVATED", "#F59E0B"
    return "GUARDED", "#10B981"


def panel_start() -> None:
    st.markdown('<div class="panel">', unsafe_allow_html=True)


def panel_end() -> None:
    st.markdown("</div>", unsafe_allow_html=True)


def metric_card(column, label: str, value: int) -> None:
    with column:
        panel_start()
        st.metric(label, f"{value:,}")
        panel_end()


inject_styles()
st.markdown('<div class="dashboard-title">SOC Command Center</div>', unsafe_allow_html=True)
st.markdown(
    '<div class="dashboard-subtitle">Splunk / IBM QRadar / Darktrace style dashboard for real-time anomaly monitoring.</div>',
    unsafe_allow_html=True,
)

window_minutes = st.sidebar.slider("Timeline window (minutes)", 5, 180, 30)
st.sidebar.caption("Tip: Press 'R' in the browser or use Streamlit's rerun for live refresh.")

try:
    data, used_fallback = load_data()
except Exception as err:
    st.error(f"Unable to load alerts.csv: {err}")
    st.stop()

if used_fallback:
    st.warning("Malformed rows were detected in alerts.csv. Invalid lines were skipped so the dashboard can continue.")

if data.empty:
    st.warning("No valid data available in alerts.csv yet.")
    st.stop()

if "time" not in data.columns:
    st.error("`alerts.csv` must contain a `time` column.")
    st.stop()

cutoff = data["time"].max() - pd.Timedelta(minutes=window_minutes)
recent = data[data["time"] >= cutoff].copy()

if "anomaly" in recent.columns:
    anomalies = recent[recent["anomaly"].astype(str).str.upper() == "YES"]
else:
    anomalies = pd.DataFrame(columns=recent.columns)

normal_count = len(recent[recent["traffic_type"] == "Normal Traffic"]) if "traffic_type" in recent.columns else 0
alert_count = len(anomalies)
total_events = len(recent)
attack_events = total_events - normal_count
unique_sources = recent["src_ip"].nunique() if "src_ip" in recent.columns else 0
eps = round(total_events / max(window_minutes * 60, 1), 2)

threat_label, threat_color = classify_threat(alert_count)
st.markdown(
    f"<div class='panel'><b>Threat Posture:</b> <span style='color:{threat_color}; font-weight:700;'>{threat_label}</span> &nbsp;|&nbsp; Alerts in window: <b>{alert_count}</b> &nbsp;|&nbsp; Events/sec: <b>{eps}</b></div>",
    unsafe_allow_html=True,
)

r1 = st.columns(5)
metric_card(r1[0], "Events", total_events)
metric_card(r1[1], "Threat Alerts", alert_count)
metric_card(r1[2], "Normal Sessions", normal_count)
metric_card(r1[3], "Attack Events", attack_events)
metric_card(r1[4], "Unique Source IPs", unique_sources)

c1, c2 = st.columns([2, 1])
with c1:
    panel_start()
    st.subheader("Security Event Timeline")
    per_min = recent.set_index("time").resample("1min").size().reset_index(name="events")
    fig_timeline = px.area(
        per_min,
        x="time",
        y="events",
        template=DARK_TEMPLATE,
        color_discrete_sequence=["#38BDF8"],
    )
    fig_timeline.update_layout(height=280, margin=dict(l=10, r=10, t=10, b=10))
    st.plotly_chart(fig_timeline, use_container_width=True)
    panel_end()

with c2:
    panel_start()
    st.subheader("Events / Second")
    fig_gauge = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=eps,
            title={"text": "EPS"},
            gauge={
                "axis": {"range": [0, max(20, eps * 2)]},
                "bar": {"color": "#F43F5E"},
                "steps": [
                    {"range": [0, 5], "color": "#1F2937"},
                    {"range": [5, 12], "color": "#374151"},
                    {"range": [12, max(20, eps * 2)], "color": "#4B5563"},
                ],
            },
        )
    )
    fig_gauge.update_layout(template=DARK_TEMPLATE, height=280, margin=dict(l=10, r=10, t=10, b=10))
    st.plotly_chart(fig_gauge, use_container_width=True)
    panel_end()

c3, c4, c5 = st.columns(3)
with c3:
    panel_start()
    st.subheader("Traffic Composition")
    if "traffic_type" in recent.columns:
        traffic_types = recent["traffic_type"].value_counts().reset_index()
        traffic_types.columns = ["type", "count"]
        fig_pie = px.pie(traffic_types, names="type", values="count", hole=0.45, template=DARK_TEMPLATE)
        fig_pie.update_layout(height=320, margin=dict(l=10, r=10, t=10, b=10))
        st.plotly_chart(fig_pie, use_container_width=True)
    else:
        st.info("No `traffic_type` column found.")
    panel_end()

with c4:
    panel_start()
    st.subheader("Top Suspicious Source IPs")
    if not anomalies.empty and "src_ip" in anomalies.columns:
        top_ips = anomalies["src_ip"].value_counts().head(10).reset_index()
        top_ips.columns = ["src_ip", "alerts"]
        fig_ips = px.bar(
            top_ips,
            x="src_ip",
            y="alerts",
            template=DARK_TEMPLATE,
            color="alerts",
            color_continuous_scale="reds",
        )
        fig_ips.update_layout(height=320, margin=dict(l=10, r=10, t=10, b=10), coloraxis_showscale=False)
        st.plotly_chart(fig_ips, use_container_width=True)
    else:
        st.info("No suspicious source IPs in this window.")
    panel_end()

with c5:
    panel_start()
    st.subheader("Anomaly Score Distribution")
    if not anomalies.empty and "anomaly_score" in anomalies.columns:
        fig_score = px.histogram(
            anomalies,
            x="anomaly_score",
            nbins=20,
            template=DARK_TEMPLATE,
            color_discrete_sequence=["#F97316"],
        )
        fig_score.update_layout(height=320, margin=dict(l=10, r=10, t=10, b=10))
        st.plotly_chart(fig_score, use_container_width=True)
    else:
        st.info("No anomaly score data in this window.")
    panel_end()

c6, c7 = st.columns(2)
with c6:
    panel_start()
    st.subheader("High-Priority Alerts")
    if not anomalies.empty:
        cols = [
            c
            for c in ["time", "src_ip", "dst_ip", "traffic_type", "packet_length", "anomaly_score"]
            if c in anomalies.columns
        ]
        st.dataframe(anomalies.sort_values("time", ascending=False)[cols].head(25), use_container_width=True, height=320)
    else:
        st.success("No active anomalies in the selected window.")
    panel_end()

with c7:
    panel_start()
    st.subheader("Live Event Stream")
    st.dataframe(recent.sort_values("time", ascending=False).head(40), use_container_width=True, height=320)
    panel_end()
