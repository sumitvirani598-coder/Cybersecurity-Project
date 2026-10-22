import streamlit as st
import pandas as pd
import plotly.express as px
from pathlib import Path
from datetime import datetime, timedelta
import random

ROOT=Path(__file__).parent; DATA=ROOT/"data"/"login_logs.csv"
REQUIRED=["timestamp","username","ip_address","login_status"]
st.set_page_config(page_title="CyberShield",page_icon="🛡️",layout="wide")
st.markdown("<style>.stApp{background:#0b1220;color:#e8eef8}[data-testid=stMetric]{background:#121d30;border:1px solid #26364d;padding:14px;border-radius:12px}section[data-testid=stSidebar]{background:#101a2b}</style>",unsafe_allow_html=True)

def generate_data(n=100):
    now=datetime.now().replace(microsecond=0); users=["alex","sam","jordan","taylor","casey","morgan"]
    ips=[f"192.0.2.{i}" for i in range(10,25)]+[f"198.51.100.{i}" for i in range(10,20)]; rows=[]
    for _ in range(n): rows.append({"timestamp":now-timedelta(minutes=random.randint(0,1440)),"username":random.choice(users),"ip_address":random.choice(ips),"login_status":"Success" if random.random()<.72 else "Failed"})
    for i in range(5): rows.append({"timestamp":now-timedelta(minutes=4-i),"username":"demo_user","ip_address":"192.0.2.250","login_status":"Failed"})
    return pd.DataFrame(rows).sort_values("timestamp",ascending=False).reset_index(drop=True)

def validate(df):
    missing=[c for c in REQUIRED if c not in df.columns]
    if missing: return None,"Missing columns: "+", ".join(missing)
    d=df[REQUIRED].copy(); d["timestamp"]=pd.to_datetime(d["timestamp"],errors="coerce"); d["username"]=d["username"].fillna("unknown").astype(str); d["ip_address"]=d["ip_address"].fillna("unknown").astype(str); d["login_status"]=d["login_status"].astype(str).str.title(); d=d[d.timestamp.notna() & d.login_status.isin(["Success","Failed"])]
    return d.sort_values("timestamp",ascending=False).reset_index(drop=True),None

def detect(df):
    d=df.copy(); d["failed_in_window"]=0; d["risk_level"]="LOW"; d["detection_reason"]="No rule triggered"
    failed=d[d.login_status.eq("Failed")]
    for ip,g in failed.groupby("ip_address"):
        ids=list(g.sort_values("timestamp").index); times=d.loc[ids,"timestamp"]
        for idx in ids:
            t=d.at[idx,"timestamp"]; count=int(((times>=t-pd.Timedelta(minutes=5))&(times<=t)).sum()); d.at[idx,"failed_in_window"]=count
            if count>=5: d.at[idx,"risk_level"]="HIGH"; d.at[idx,"detection_reason"]=f"{count} failed attempts from this IP within 5 minutes"
            elif count>=3: d.at[idx,"risk_level"]="MEDIUM"; d.at[idx,"detection_reason"]=f"{count} recent failed attempts from this IP"
    return d

if "records" not in st.session_state:
    if DATA.exists():
        try: st.session_state.records=validate(pd.read_csv(DATA))[0]
        except Exception: st.session_state.records=None
    if st.session_state.records is None or st.session_state.records.empty:
        st.session_state.records=generate_data(); DATA.parent.mkdir(exist_ok=True); st.session_state.records.to_csv(DATA,index=False)
st.sidebar.title("🛡️ CyberShield"); page=st.sidebar.radio("Navigate",["Dashboard","Login Activity","Security Alerts","Analytics","About"])
with st.sidebar.expander("Data Management"):
    if st.button("Generate 20 Sample Records"):
        st.session_state.records=pd.concat([st.session_state.records,generate_data(20)],ignore_index=True); st.session_state.records.to_csv(DATA,index=False); st.rerun()
    upload=st.file_uploader("Upload login CSV",type=["csv"])
    if upload is not None:
        incoming=pd.read_csv(upload); valid,error=validate(incoming)
        if error: st.error(error)
        else: st.session_state.records=valid; st.success(f"Loaded {len(valid)} records")
d=detect(st.session_state.records.copy()); total=len(d); succ=int((d.login_status=="Success").sum()); fail=int((d.login_status=="Failed").sum()); high=int((d.risk_level=="HIGH").sum())
st.title("🛡️ CyberShield"); st.caption("Automated Login Attack Detection & Security Monitoring Dashboard")
if page=="Dashboard":
    a,b,c,e=st.columns(4); a.metric("Total Login Attempts",total); b.metric("Successful Logins",succ); c.metric("Failed Logins",fail); e.metric("Suspicious Attempts",high)
    if high: st.error(f"HIGH RISK: {high} records meet the detection threshold.")
    else: st.success("No high-risk pattern detected.")
    x,y=st.columns(2); counts=d.login_status.value_counts().rename_axis("Status").reset_index(name="Count"); x.plotly_chart(px.pie(counts,names="Status",values="Count",title="Success vs Failed"),use_container_width=True); risks=d.risk_level.value_counts().rename_axis("Risk").reset_index(name="Count"); y.plotly_chart(px.bar(risks,x="Risk",y="Count",title="Risk Distribution"),use_container_width=True)
    st.subheader("Recent Login Activity"); st.dataframe(d.head(10),use_container_width=True,hide_index=True)
elif page=="Login Activity":
    st.subheader("Login Activity"); s=st.multiselect("Status",["Success","Failed"],default=["Success","Failed"]); r=st.multiselect("Risk",["LOW","MEDIUM","HIGH"],default=["LOW","MEDIUM","HIGH"]); u=st.text_input("Username contains"); v=d[d.login_status.isin(s)&d.risk_level.isin(r)]; v=v[v.username.str.contains(u,case=False,na=False)] if u else v; st.dataframe(v,use_container_width=True,hide_index=True); st.download_button("Download filtered CSV",v.to_csv(index=False).encode(),"cybershield_report.csv","text/csv")
elif page=="Security Alerts":
    alerts=d[d.risk_level.isin(["HIGH","MEDIUM"])].sort_values("timestamp",ascending=False); st.subheader("Security Alerts")
    if alerts.empty: st.success("No alerts found.")
    for _,row in alerts.iterrows():
        with st.expander(f"{row.risk_level} — {row.ip_address} — {row.timestamp}"): st.write(f"Username: {row.username}"); st.write(f"Failed attempts in window: {row.failed_in_window}"); st.write(f"Reason: {row.detection_reason}"); st.write("Recommended action: Review authorized logs and apply rate limiting according to policy.")
elif page=="Analytics":
    st.subheader("Login Analytics"); d["hour"]=d.timestamp.dt.floor("h"); trend=d.groupby(["hour","login_status"]).size().reset_index(name="Count"); st.plotly_chart(px.line(trend,x="hour",y="Count",color="login_status",markers=True),use_container_width=True); f=d[d.login_status=="Failed"].groupby("ip_address").size().reset_index(name="Failures").sort_values("Failures",ascending=False).head(10); st.plotly_chart(px.bar(f,x="ip_address",y="Failures",title="Top IPs by Failed Attempts"),use_container_width=True)
else:
    st.subheader("About CyberShield"); st.write("Educational demo that analyzes fictional authentication records and highlights repeated failed logins."); st.markdown("**Stack:** Python, Streamlit, Pandas, Plotly, CSV.\n\n**Rule:** Five or more failures from one IP within a rolling five-minute window = HIGH; three or four = MEDIUM.\n\n**Limitation:** Does not connect to real systems or monitor live authentication events."); st.info("Use authorized logs only. The sample IP ranges are reserved for documentation.")
