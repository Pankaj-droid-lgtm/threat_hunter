# 🔁 Global tracking
failed_attempts = {}

def agent_decision(log):

    activity = log.get("activity", "").lower()
    status = log.get("status", "").lower()
    ip = log.get("ip", "unknown")

    #  Malware Detection
    if "powershell" in activity:
        return {
            "decision": "Malware Detected",
            "action": "Kill Process",
            "severity": "Critical"
        }

    #  Network Attack
    if "scan" in activity or "port" in activity:
        return {
            "decision": "Recon Attack",
            "action": "Block IP",
            "severity": "High"
        }

    # Brute Force Logic
    if "login" in activity and status == "failed":

        failed_attempts[ip] = failed_attempts.get(ip, 0) + 1

        if failed_attempts[ip] >= 3:
            return {
                "decision": f"Brute Force Attack ({failed_attempts[ip]} attempts) 🚨",
                "action": "Block IP",
                "severity": "Critical"
            }

        return {
            "decision": f"Suspicious Login Attempt ({failed_attempts[ip]})",
            "action": "Monitor User",
            "severity": "Medium"
        }

    #  Reset on success
    if "login" in activity and status == "success":
        failed_attempts[ip] = 0

    return {
        "decision": "Normal Activity",
        "action": "No Action",
        "severity": "Low"
    }


# REQUIRED FUNCTION (ERROR FIX)
def take_action(action, ip=None, blocked_ips=None):

    if action == "Kill Process":
        print("🔴 AI: Process Terminated")

    elif action == "Block IP":
        if ip and blocked_ips is not None:
            blocked_ips.add(ip)
        print(" AI: IP Blocked")

    elif action == "Monitor User":
        print("👁 AI: Monitoring User")

    else:
        print(" AI: No Action")