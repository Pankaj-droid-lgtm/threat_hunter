import random
import time

activities = ["login", "powershell", "port scan", "normal browsing"]
status = ["success", "failed"]

while True:
    log = {
        "user": random.choice(["admin", "user1", "guest"]),
        "activity": random.choice(activities),
        "status": random.choice(status)
    }

    print(log)  # later we push to system
    time.sleep(2)