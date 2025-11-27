from flask import Flask, jsonify, send_from_directory, request
from flask_cors import CORS
import os
import json
from dotenv import load_dotenv
from google import genai

app = Flask(__name__)
CORS(app)

# 환경 변수에서 GEMINI_API_KEY 읽기
load_dotenv()
API_KEY = os.getenv("GEMINI_API_KEY")
client = genai.Client(api_key=API_KEY)

# 기준 경로
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_PATH = os.path.join(BASE_DIR, "ids_log.txt")
FRONTEND_DIR = os.path.join(BASE_DIR, "..", "frontend")


# 📄 IDS 로그 API
@app.route("/api/logs")
def get_logs():
    if not os.path.exists(LOG_PATH):
        return jsonify([])

    with open(LOG_PATH, "r", encoding="utf-8") as f:
        logs = [line.strip() for line in f.readlines()[-300:]]
    return jsonify(logs)


# 🤖 선택한 로그 한 줄을 즉석 분석
@app.route("/api/analyze-log", methods=["POST"])
def analyze_log():
    body = request.get_json(silent=True) or {}
    line = body.get("line", "").strip()

    if not line:
        return jsonify({"result": "분석할 로그가 전달되지 않았습니다."}), 400

    prompt = f"""
당신은 네트워크 보안 전문가입니다.

아래 IDS 로그 한 줄의 의미를 상세히 분석해 주세요.

로그:
{line}

요구사항:
1. 이 로그가 나타내는 상황을 설명
2. 공격/이상 징후인지 여부와 근거
3. 관리자에게 필요한 추가 확인 사항
4. 대응 방안 제안 (bullet 형태)
"""

    try:
        result = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt
        )
        analysis_text = result.text
    except Exception as e:
        analysis_text = f"Gemini 분석 오류: {str(e)}"

    return jsonify({"result": analysis_text})


# 🧹 로그 전체 삭제 API
@app.route("/api/clear-logs", methods=["POST"])
def clear_logs():
    try:
        # 파일 비우기 (파일이 없으면 새로 생성)
        with open(LOG_PATH, "w", encoding="utf-8") as f:
            f.write("")
        return jsonify({"status": "ok", "message": "로그가 초기화되었습니다."})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# 🌐 대시보드 HTML 제공
@app.route("/")
def serve_dashboard():
    return send_from_directory(FRONTEND_DIR, "dashboard.html")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
