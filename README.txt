SCAMSHIELD AI - COMPLETE STUDENT DEMO

CONTENTS
- backend/main.py: FastAPI API and demo ML classifier
- frontend/index.html: web dashboard
- requirements.txt: Python packages
- setup_and_run.bat: automatic Windows setup and launch

REQUIREMENTS
- Windows 10/11
- Python 3.10 or newer (install from python.org; enable "Add Python to PATH")
- Internet connection for the first package installation

OPTION A - AUTOMATIC (EASIEST)
1. Extract this ZIP completely.
2. Open the extracted ScamShield_AI_Complete folder.
3. Double-click setup_and_run.bat.
4. Wait while Python creates the environment and installs packages.
5. Two black terminal windows should open. Keep both open.
6. The website opens at http://127.0.0.1:5500.
7. API documentation: http://127.0.0.1:8000/docs

OPTION B - RUN USING COMMANDS
Open Command Prompt in the extracted ScamShield_AI_Complete folder.

Run these commands one at a time:
  py -3 -m venv .venv
  .venv\Scripts\python.exe -m pip install --upgrade pip
  .venv\Scripts\python.exe -m pip install -r requirements.txt

BACKEND TERMINAL:
Run this command from the project root folder:
  .venv\Scripts\python.exe -m uvicorn backend.main:app --reload
Leave this terminal open.

FRONTEND TERMINAL:
Open a SECOND Command Prompt in the project root folder, then run:
  cd frontend
  ..\.venv\Scripts\python.exe -m http.server 5500
Leave this terminal open.

Then open this address in your browser:
  http://127.0.0.1:5500

TEST MESSAGE
Congratulations! You won a prize. Click here to claim your reward.

IMPORTANT
This is a student demonstration, not a production security product. The model uses a tiny sample dataset and its score is not a calibrated probability. It can miss scams or flag legitimate messages. Never click suspicious links or share OTPs/passwords.
