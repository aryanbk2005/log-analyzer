from flask import Flask, render_template, request
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

app = Flask(__name__)

# -----------------------------
# Log Parser
# -----------------------------
def parse_log(lines):
    logs = []
    for line in lines:
        if isinstance(line, bytes):
            line = line.decode("utf-8")

        failed = 1 if "Failed password" in line else 0
        accepted = 1 if "Accepted password" in line else 0
        sudo = 1 if "sudo" in line else 0

        logs.append([failed, accepted, sudo])

    return pd.DataFrame(logs, columns=["failed_login","accepted_login","sudo_usage"])


# -----------------------------
# ML Function
# -----------------------------
def analyze_logs(data):
    scaler = StandardScaler()
    scaled = scaler.fit_transform(data)

    model = IsolationForest(n_estimators=100, contamination=0.2, random_state=42)
    model.fit(scaled)

    data["anomaly"] = model.predict(scaled)

    result = {
        "total": len(data),
        "normal": (data["anomaly"] == 1).sum(),
        "anomalies": (data["anomaly"] == -1).sum()
    }

    return data.to_dict(orient="records"), result


# -----------------------------
# Home Page
# -----------------------------
@app.route("/")
def home():
    return render_template("home.html")


# -----------------------------
# Option 1: Self Log
# -----------------------------
@app.route("/self_log", methods=["POST"])
def self_log():
    with open("linux.log", "r") as f:
        lines = f.readlines()

    data = parse_log(lines)
    logs, result = analyze_logs(data)

    return render_template("result.html", logs=logs, result=result)


# -----------------------------
# Option 2: Upload Log
# -----------------------------
@app.route("/upload_log", methods=["POST"])
def upload_log():
    file = request.files["logfile"]

    data = parse_log(file)
    logs, result = analyze_logs(data)

    return render_template("result.html", logs=logs, result=result)


# -----------------------------
if __name__ == "__main__":
    app.run(debug=True)