from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS
import os

app = Flask(__name__)
CORS(app)

# 📄 IDS 로그 API
@app.route("/api/logs")
def get_logs():
    log_path = os.path.join(os.path.dirname(__file__), "ids_log.txt")
    if not os.path.exists(log_path):
        return jsonify([])
    with open(log_path, "r", encoding="utf-8") as f:
        logs = [line.strip() for line in f.readlines()[-300:]]  # 최근 300줄만
    return jsonify(logs)

# 🌐 대시보드 HTML 제공
@app.route("/")
def serve_dashboard():
    frontend_path = os.path.join(os.path.dirname(__file__), "..", "frontend")
    return send_from_directory(frontend_path, "dashboard.html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
