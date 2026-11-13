from pathlib import Path
import re
import sqlite3
from datetime import datetime

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

ROOT = Path(__file__).resolve().parent.parent
DB_PATH = ROOT / "scamshield.db"

app = FastAPI(title="ScamShield AI", description="Student demonstration scam-message scanner")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Small teaching dataset only. This is not a production-grade scam detector.
training_texts = [
    "Your account has been credited with salary",
    "Are we still meeting at the library tomorrow",
    "Please find the class notes attached",
    "Your parcel delivery is scheduled for today",
    "Congratulations you won a free prize claim now",
    "Urgent account blocked verify password immediately",
    "You have won cash click this link to claim reward",
    "Send your OTP to receive your lottery money",
    "Your bank account will close confirm details now",
    "Limited offer claim your gift card today",
]
training_labels = [0, 0, 0, 0, 1, 1, 1, 1, 1, 1]
vectorizer = TfidfVectorizer()
X = vectorizer.fit_transform(training_texts)
model = LogisticRegression(random_state=42)
model.fit(X, training_labels)

SUSPICIOUS_WORDS = [
    "prize", "claim", "winner", "won", "urgent", "otp", "password",
    "verify", "blocked", "gift card", "lottery", "click here", "bank details",
]
URL_PATTERN = re.compile(r"https?://[^\s]+|www\.[^\s]+", re.IGNORECASE)


class ScanRequest(BaseModel):
    text: str


def init_db():
    with sqlite3.connect(DB_PATH) as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message TEXT NOT NULL,
                risk TEXT NOT NULL,
                score INTEGER NOT NULL,
                reasons TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)


def inspect_url(url):
    reasons = []
    lower = url.lower()
    if lower.startswith("http://"):
        reasons.append("Link does not use secure HTTPS")
    if re.search(r"@", url):
        reasons.append("Link contains an unusual @ symbol")
    if len(url) > 90:
        reasons.append("Link is unusually long")
    if any(word in lower for word in ["login", "verify", "secure", "update"]):
        reasons.append("Link contains a word often used in phishing links")
    return reasons


def get_urls(text):
    return URL_PATTERN.findall(text)


@app.on_event("startup")
def startup():
    init_db()


@app.get("/")
def home():
    return {"message": "ScamShield AI API is running", "docs": "/docs"}


@app.get("/stats")
def stats():
    init_db()
    with sqlite3.connect(DB_PATH) as con:
        rows = con.execute("SELECT risk, COUNT(*) FROM scans GROUP BY risk").fetchall()
        total = con.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    counts = {risk: count for risk, count in rows}
    return {
        "total_scans": total,
        "high_risk": counts.get("High", 0),
        "medium_risk": counts.get("Medium", 0),
        "low_risk": counts.get("Low", 0),
    }


@app.get("/history")
def history():
    init_db()
    with sqlite3.connect(DB_PATH) as con:
        con.row_factory = sqlite3.Row
        rows = con.execute(
            "SELECT id, message, risk, score, reasons, created_at "
            "FROM scans ORDER BY id DESC LIMIT 20"
        ).fetchall()
    return [dict(row) for row in rows]


@app.delete("/history")
def clear_history():
    init_db()
    with sqlite3.connect(DB_PATH) as con:
        con.execute("DELETE FROM scans")
    return {"message": "Scan history cleared"}


@app.post("/predict")
def predict(data: ScanRequest):
    message = data.text.strip()
    if not message:
        return {"error": "Please enter a message or link."}

    model_score = float(model.predict_proba(vectorizer.transform([message]))[0][1])
    reasons = []
    lower = message.lower()

    found_words = [word for word in SUSPICIOUS_WORDS if word in lower]
    if found_words:
        reasons.append("Potentially risky words found: " + ", ".join(found_words))

    urls = get_urls(message)
    for url in urls:
        url_reasons = inspect_url(url)
        reasons.extend(url_reasons)

    # Combine demo model score with transparent rule-based indicators.
    score = int(model_score * 65 + min(len(found_words), 4) * 7 + min(len(urls), 2) * 5)
    if any("Link" in reason or "Link contains" in reason for reason in reasons):
        score = max(score, 70)
    score = max(0, min(score, 99))

    if score >= 70:
        risk = "High"
    elif score >= 40:
        risk = "Medium"
    else:
        risk = "Low"

    if not reasons:
        reasons.append("No obvious warning signs found by this demo scanner")

    reasons_text = " | ".join(reasons)
    with sqlite3.connect(DB_PATH) as con:
        con.execute(
            "INSERT INTO scans (message, risk, score, reasons, created_at) VALUES (?, ?, ?, ?, ?)",
            (message, risk, score, reasons_text, datetime.now().isoformat(timespec="seconds")),
        )

    return {
        "result": "Suspicious" if risk != "Low" else "Likely Safe",
        "risk": risk,
        "score": score,
        "reasons": reasons,
        "urls_found": urls,
        "disclaimer": "Student demo only. It can miss scams or flag safe messages. Never share OTPs or passwords.",
    }
