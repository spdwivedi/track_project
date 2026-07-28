import streamlit as st
import pandas as pd
import time
import os
from user_agents import parse
from pymongo import MongoClient
from dotenv import load_dotenv

st.set_page_config(page_title="V2 Advanced Panel (MongoDB)", layout="wide")
REFRESH_RATE = 3 
ALERT_THRESHOLD = 20 

# Load MongoDB connection
load_dotenv()
MONGO_URI = os.getenv("MONGO_URI")

@st.cache_resource
def init_connection():
    return MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)

try:
    client = init_connection()
    db = client.get_default_database()
    collection = db["traffic_logs_v2"]
except Exception as e:
    st.error(f"Could not connect to MongoDB: {e}")
    st.stop()

st.title("🛡️ Level 2: Advanced Hardware & Network Tracking")

def parse_device_info(ua_string):
    if ua_string == "Unknown" or pd.isna(ua_string):
        return "Unknown", "Unknown"
    ua = parse(str(ua_string))
    return f"{ua.os.family} {ua.os.version_string}".strip(), ua.browser.family

# Fetch data from MongoDB instead of CSV
def get_data_from_db():
    # .find({}, {"_id": 0}) grabs everything but drops the MongoDB specific ID so Pandas can read it cleanly
    cursor = collection.find({}, {"_id": 0})
    return pd.DataFrame(list(cursor))

df = get_data_from_db()

if df.empty:
    st.info("Database is empty. Send traffic to the sensor to populate data.")
else:
    os_list, browsers = [], []
    for _, row in df.iterrows():
        os_info, browser_info = parse_device_info(row.get("User_Agent", "Unknown"))
        os_list.append(os_info)
        browsers.append(browser_info)

    df["OS"] = os_list
    df["Browser"] = browsers
    df["Lat"] = pd.to_numeric(df["Lat"], errors='coerce')
    df["Lon"] = pd.to_numeric(df["Lon"], errors='coerce')

    total_requests = len(df)
    unique_ips = df["IP_Address"].nunique()
    ip_counts = df["IP_Address"].value_counts().reset_index()
    ip_counts.columns = ["IP_Address", "Request_Count"]
    suspicious_ips = ip_counts[ip_counts["Request_Count"] > ALERT_THRESHOLD]
    
    col1, col2, col3 = st.columns(3)
    col1.metric("Total Requests", total_requests)
    col2.metric("Unique IPs", unique_ips)
    col3.metric("Flagged Threats", len(suspicious_ips), delta_color="inverse")
    
    st.markdown("---")

    st.subheader("🌍 Request Origin Map")
    map_df = df.dropna(subset=["Lat", "Lon"]).rename(columns={"Lat": "lat", "Lon": "lon"})
    if not map_df.empty:
        st.map(map_df, size=200, color="#ff4b4b")
    else:
        st.info("No valid coordinates available.")

    st.markdown("---")

    st.subheader("📡 Live Traffic Feed (MongoDB Backend)")
    
    display_columns = [
        "Timestamp", "IP_Address", "City", "Lat", "Lon", "OS", "Browser", 
        "Resolution", "CPU_Cores", "RAM_GB", "Battery_%", "Charging", 
        "Network", "Touch_Points", "Timezone", "Referrer", "Path"
    ]
    
    existing_cols = [col for col in display_columns if col in df.columns]
    df_display = df.sort_values(by="Timestamp", ascending=False)[existing_cols]
    
    def highlight_threats(row):
        if row["IP_Address"] in suspicious_ips["IP_Address"].values:
            return ['background-color: rgba(255, 0, 0, 0.2)'] * len(row)
        return [''] * len(row)

    st.dataframe(df_display.style.apply(highlight_threats, axis=1), use_container_width=True)

time.sleep(REFRESH_RATE)
st.rerun()