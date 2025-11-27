🛠️ 실행 방법
1. 가상환경 생성 & 활성화
python -m venv venv
source venv/bin/activate     # Mac/Linux
venv\Scripts\activate        # Windows

2. 패키지 설치
pip install -r requirements.txt

3. .env 파일 생성 (업로드 금지)
GEMINI_API_KEY=your_api_key_here

4. IDS 실행
python backend/ids.py

5. 서버 실행
python backend/server.py

6. 브라우저에서 접속
http://localhost:8000
