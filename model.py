def predict_threat(activity, status):

    activity = activity.lower()
    status = status.lower()

    # 🚨 Brute Force
    if "login" in activity and status == "failed":
        return "Brute Force Attack"

    # 💻 Malware
    if "powershell" in activity or "cmd" in activity:
        return "Malware Activity"

    # 🌐 Network Attack
    if "scan" in activity or "port" in activity:
        return "Network Attack"

    return "Normal"