from sklearn.ensemble import IsolationForest

model = IsolationForest(contamination=0.1)

data = [[1], [2], [3], [100], [120]]
model.fit(data)

def detect_anomaly(value):
    result = model.predict([[value]])
    return "Anomaly" if result[0] == -1 else "Normal"