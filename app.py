from flask import Flask, render_template, request, redirect, session
from datetime import datetime
from model import predict_threat
from agent import agent_decision, take_action
from anomaly import detect_anomaly
from ml_model import predict_from_dataset
from pymongo import MongoClient
from collections import deque
import requests

app = Flask(__name__)
app.secret_key = "supersecretkey"

# MongoDB
client = MongoClient("mongodb://localhost:27017/")
db = client["threat_db"]
soc_logs = db["soc_logs"]

# GLOBALS
blocked_ips = set()
attack_tracker = {}
log_memory = deque(maxlen=50)

# 🌍 Location
def get_location(ip):
    if ip == "127.0.0.1":
        return "Localhost"
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}", timeout=2)
        data = res.json()
        return f"{data.get('city','')}, {data.get('country','')}"
    except:
        return "Unknown"

# 🧠 MITRE Mapping
def map_mitre(activity, status):
    activity = activity.lower()
    status = status.lower()

    if "powershell" in activity:
        return "T1059 - Command & Scripting"
    if "port scan" in activity:
        return "T1046 - Network Discovery"
    if "login" in activity and status == "failed":
        return "T1110 - Brute Force"
    if "login" in activity and status == "success":
        return "T1078 - Valid Account"

    return "N/A"

# 🔗 Kill Chain
def detect_kill_chain(ip, activity, status):

    if ip not in attack_tracker:
        attack_tracker[ip] = []

    attack_tracker[ip].append(activity.lower())

    if len(attack_tracker[ip]) > 6:
        attack_tracker[ip].pop(0)

    history = " ".join(attack_tracker[ip])

    if "port scan" in history and \
       history.count("failed login") >= 2 and \
       "login" in history and status.lower() == "success":
        return "🚨 ATTACK CHAIN DETECTED"

    return None

# 🔥 ADVANCED RISK
def calculate_risk(severity, anomaly, threat, memory_count):

    severity_score = {
        "Low": 20,
        "Medium": 40,
        "High": 60,
        "Critical": 80
    }.get(severity, 20)

    risk = severity_score

    if threat == "Attack":
        risk += 15

    if anomaly == "Anomaly":
        risk += 20

    if memory_count >= 3:
        risk += 25
    elif memory_count == 2:
        risk += 10

    return min(risk, 100)

#  Block IP
@app.before_request
def block_ip():
    ip = request.remote_addr
    if ip != "127.0.0.1" and ip in blocked_ips:
        return "🚫 Your IP is BLOCKED", 403

# 🔐 Login
@app.route("/login")
def login_page():
    return render_template("login.html")

@app.route("/login", methods=["POST"])
def login():
    if request.form.get("username") == "admin" and request.form.get("password") == "admin123":
        session["user"] = "admin"
        return redirect("/logs")
    return render_template("login.html", error="Invalid Login")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

@app.route("/")
def home():
    return redirect("/login")

# ➕ ADD LOG
@app.route("/add_log", methods=["POST"])
def add_log():

    if "user" not in session:
        return redirect("/login")

    user = request.form.get("user")
    activity = request.form.get("activity")
    status = request.form.get("status")

    ip = request.remote_addr or "127.0.0.1"
    location = get_location(ip)

    # MEMORY
    log_memory.append(activity.lower())
    failed_count = list(log_memory).count("failed login")

    # ML + RULE
    ml_result = predict_from_dataset(6, len(activity))
    rule_result = predict_threat(activity, status)
    threat = ml_result if ml_result != "Normal" else rule_result

    anomaly = detect_anomaly(len(activity))

    # AI
    ai_result = agent_decision({
        "activity": activity,
        "status": status,
        "ip": ip
    })

    # MEMORY OVERRIDE
    if failed_count >= 3:
        ai_result = {
            "decision": f"Brute Force (Memory Based - {failed_count})",
            "action": "Block IP",
            "severity": "Critical"
        }

    mitre = map_mitre(activity, status)
    kill_chain = detect_kill_chain(ip, activity, status)

    if kill_chain:
        ai_result["decision"] = kill_chain
        ai_result["severity"] = "Critical"

    # 🔥 FIXED RISK
    risk = calculate_risk(
        ai_result["severity"],
        anomaly,
        threat,
        failed_count
    )

    take_action(ai_result["action"], ip, blocked_ips)

    soc_logs.insert_one({
        "user": user,
        "activity": activity,
        "status": status,
        "threat": threat,
        "anomaly": anomaly,
        "ai_decision": ai_result["decision"],
        "ai_action": ai_result["action"],
        "severity": ai_result["severity"],
        "risk": risk,
        "kill_chain": kill_chain,
        "mitre": mitre,
        "ip": ip,
        "location": location,
        "timestamp": datetime.now()
    })

    return redirect("/logs")

#  LOGS
@app.route("/logs")
def get_logs():
    if "user" not in session:
        return redirect("/login")
    logs = list(soc_logs.find().sort("timestamp", -1))
    return render_template("logs.html", logs=logs)

# TEST
@app.route("/add_test")
def add_test():

    if "user" not in session:
        return redirect("/login")

    ip = "127.0.0.1"
    activity = "failed login"
    status = "failed"

    log_memory.append(activity.lower())
    failed_count = list(log_memory).count("failed login")

    ml_result = predict_from_dataset(6, len(activity))
    rule_result = predict_threat(activity, status)
    threat = ml_result if ml_result != "Normal" else rule_result

    anomaly = detect_anomaly(len(activity))

    ai_result = agent_decision({
        "activity": activity,
        "status": status,
        "ip": ip
    })

    if failed_count >= 3:
        ai_result = {
            "decision": f"Brute Force (Memory Based - {failed_count})",
            "action": "Block IP",
            "severity": "Critical"
        }

    mitre = map_mitre(activity, status)
    kill_chain = detect_kill_chain(ip, activity, status)

    #  FIXED RISK
    risk = calculate_risk(
        ai_result["severity"],
        anomaly,
        threat,
        failed_count
    )

    take_action(ai_result["action"], ip, blocked_ips)

    soc_logs.insert_one({
        "user": "test",
        "activity": activity,
        "status": status,
        "threat": threat,
        "anomaly": anomaly,
        "ai_decision": ai_result["decision"],
        "ai_action": ai_result["action"],
        "severity": ai_result["severity"],
        "risk": risk,
        "kill_chain": kill_chain,
        "mitre": mitre,
        "ip": ip,
        "location": "Local",
        "timestamp": datetime.now()
    })

    return redirect("/logs")

# 🚀 RUN
if __name__ == "__main__":
    print("🚀 Server running...")
    app.run(debug=True)