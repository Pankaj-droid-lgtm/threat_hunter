import requests
import time

URL = "http://127.0.0.1:5000/add_log"

def send_log(user, activity, status):
    data = {
        "user": user,
        "activity": activity,
        "status": status
    }
    requests.post(URL, data=data)


# 🔥 ATTACK SCENARIO
def simulate_attack():

    print("🚀 Starting Attack Simulation...")

    # 1️⃣ PORT SCAN
    for i in range(3):
        print("🔍 Port Scan...")
        send_log("attacker", "port scan", "success")
        time.sleep(1)

    # 2️⃣ BRUTE FORCE
    for i in range(4):
        print("🔐 Failed Login Attempt...")
        send_log("attacker", "failed login", "failed")
        time.sleep(1)

    # 3️⃣ SUCCESS LOGIN
    print("✅ Login Success (Compromise)")
    send_log("attacker", "login", "success")
    time.sleep(1)

    # 4️⃣ MALWARE EXECUTION
    print("💀 Running Malware (PowerShell)")
    send_log("attacker", "powershell attack", "success")

    print("🔥 Attack Simulation Complete!")


if __name__ == "__main__":
    simulate_attack()