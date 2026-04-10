import pandas as pd
import os
import joblib   #  NEW

model = None

def train_model():
    global model

    path = "dataset/"
    files = os.listdir(path)

    df_list = []

    
    for file in files[:1]:
        if file.endswith(".csv"):
            df = pd.read_csv(
                path + file,
                usecols=["Protocol", "Flow Duration", "Label"],
                nrows=10000,
                low_memory=False
            )
            df_list.append(df)

    data = pd.concat(df_list, ignore_index=True)

    print("Total Data:", data.shape)

    data = data.sample(n=5000, random_state=42)

    data["Label"] = data["Label"].apply(lambda x: 0 if x == "BENIGN" else 1)

    from sklearn.ensemble import RandomForestClassifier

    X = data.drop("Label", axis=1)
    y = data["Label"]

    model = RandomForestClassifier()
    model.fit(X, y)

    print("Model trained successfully!")

   
    joblib.dump(model, "model.pkl")
    print("Model saved as model.pkl")

def load_model():
    global model

    if os.path.exists("model.pkl"):
        model = joblib.load("model.pkl")
        print("Model loaded from file ✅")
    else:
        print("No saved model found → training now...")
        train_model()

def predict_from_dataset(protocol, duration):
    global model

    if model is None:
        load_model()   # 🔥 LOAD instead of always training

    pred = model.predict([[protocol, duration]])

    return "Attack" if pred[0] == 1 else "Normal"


if __name__ == "__main__":
    train_model()