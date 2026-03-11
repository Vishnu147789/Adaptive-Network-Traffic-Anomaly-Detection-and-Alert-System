import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import time

st.set_page_config(page_title="SOC Dashboard", layout="wide")

st.title("Security Operations Center (SOC)")
st.caption("Real-Time Network Intrusion Detection System")

while True:

    try:

        df = pd.read_csv("alerts.csv")
        df["time"] = pd.to_datetime(df["time"])

        anomalies = df[df["anomaly"]=="YES"]

        total_logs = len(df)
        alerts = len(anomalies)
        normal = len(df[df["traffic_type"]=="Normal Traffic"])
        attacks = total_logs - normal

        # ---------------------------
        # THREAT LEVEL
        # ---------------------------

        if alerts > 100:
            threat = "HIGH"
            st.error("🚨 Threat Level: HIGH")
        elif alerts > 20:
            threat = "MEDIUM"
            st.warning("⚠ Threat Level: MEDIUM")
        else:
            threat = "LOW"
            st.success("✅ Threat Level: LOW")

        # ---------------------------
        # TOP METRICS
        # ---------------------------

        c1,c2,c3,c4 = st.columns(4)

        c1.metric("Total Logs", total_logs)
        c2.metric("Threat Alerts", alerts)
        c3.metric("Normal Traffic", normal)
        c4.metric("Attack Events", attacks)

        # ---------------------------
        # TRAFFIC GRAPHS
        # ---------------------------

        col1,col2,col3 = st.columns(3)

        with col1:

            st.subheader("Log Volume")

            logs = df.groupby(df["time"].dt.minute).size()

            fig = px.bar(
                x=logs.index,
                y=logs.values,
                labels={"x":"Time","y":"Logs"}
            )

            st.plotly_chart(fig,use_container_width=True)

        with col2:

            st.subheader("Traffic Timeline")

            timeline = df.groupby(df["time"].dt.second).size()

            fig2 = px.line(
                x=timeline.index,
                y=timeline.values
            )

            st.plotly_chart(fig2,use_container_width=True)

        with col3:

            st.subheader("Traffic Types")

            types = df["traffic_type"].value_counts()

            fig3 = px.pie(
                values=types.values,
                names=types.index
            )

            st.plotly_chart(fig3,use_container_width=True)

        # ---------------------------
        # NETWORK ACTIVITY GRAPH
        # ---------------------------

        st.subheader("Network Activity Monitor")

        traffic = df.groupby(df["time"].dt.second).size()

        fig4 = px.area(
            x=traffic.index,
            y=traffic.values
        )

        st.plotly_chart(fig4,use_container_width=True)

        # ---------------------------
        # SOC PANELS
        # ---------------------------

        colA,colB,colC = st.columns(3)

        # SERVER STATUS
        with colA:

            st.subheader("System Status")

            st.metric("CPU Usage","12%")
            st.metric("Memory","28%")
            st.metric("Disk","17%")

        # ATTACKER IPs
        with colB:

            st.subheader("Top Suspicious IPs")

            if len(anomalies)>0:

                ips = anomalies["src_ip"].value_counts().head(10)

                fig5 = px.bar(
                    x=ips.index,
                    y=ips.values,
                    labels={"x":"IP Address","y":"Attacks"}
                )

                st.plotly_chart(fig5,use_container_width=True)

        # EVENTS PER SECOND
        with colC:

            st.subheader("Events Per Second")

            eps = len(df)/60

            fig6 = go.Figure(go.Indicator(
                mode="gauge+number",
                value=eps,
                title={'text':"EPS"},
                gauge={'axis':{'range':[0,1000]},
                       'bar':{'color':"red"}}
            ))

            st.plotly_chart(fig6,use_container_width=True)

        # ---------------------------
        # ANOMALY TABLE
        # ---------------------------

        st.subheader("Detected Anomaly Packets")

        if len(anomalies)>0:

            table = anomalies[[
                "time",
                "src_ip",
                "dst_ip",
                "packet_length",
                "anomaly_score"
            ]]

            st.dataframe(table.tail(20),use_container_width=True)

        # ---------------------------
        # LIVE LOGS
        # ---------------------------

        st.subheader("Live Network Logs")

        st.dataframe(df.tail(30),use_container_width=True)

    except:

        st.warning("Waiting for traffic data...")

    time.sleep(2)
    st.rerun()