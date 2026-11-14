
from pathlib import Path
import os
import re
import sqlite3
from datetime import datetime

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from pwdlib import PasswordHash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

ROOT = Path(__file__).resolve().parent.parent
DB_PATH = ROOT / "scamshield.db"

TOKEN_SECRET = os.getenv(
    "TOKEN_SECRET",
    "local-development-secret-change-before-deployment"
)
serializer = URLSafeTimedSerializer(TOKEN_SECRET, salt="scamshield-auth")
password_hash = PasswordHash.recommended()
security = HTTPBearer()

app = FastAPI(
    title="ScamShield AI",
    description="Student demonstration scam-message scanner"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5500",
        "https://singular-panda-8736b1.netlify.app"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Demo machine learning dataset
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
    "prize", "claim", "winner", "won", "urgent", "otp",
    "password", "verify", "blocked", "gift card",
    "lottery", "click here", "bank details",
]

URL_PATTERN = re.compile(
    r"https?://[^\s]+|www\.[^\s]+",
    re.IGNORECASE
)


# Request models
class RegisterRequest(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    email: str = Field(min_length=5, max_length=254)
    password: str = Field(min_length=8, max_length=128)


class LoginRequest(BaseModel):
    email: str
    password: str


class ScanRequest(BaseModel):
    text: str


# Database
def init_db():
    with sqlite3.connect(DB_PATH) as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)

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

        columns = [
            row[1] for row in
            con.execute("PRAGMA table_info(scans)").fetchall()
        ]

        if "user_id" not in columns:
            con.execute(
                "ALTER TABLE scans ADD COLUMN user_id INTEGER"
            )


@app.on_event("startup")
def startup():
    init_db()


# Authentication
def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    try:
        data = serializer.loads(
            credentials.credentials,
            max_age=7 * 24 * 60 * 60
        )
        user_id = data["user_id"]
    except (BadSignature, SignatureExpired, KeyError):
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired login. Please log in again."
        )

    with sqlite3.connect(DB_PATH) as con:
        con.row_factory = sqlite3.Row
        user = con.execute(
            "SELECT id, name, email FROM users WHERE id = ?",
            (user_id,)
        ).fetchone()

    if user is None:
        raise HTTPException(status_code=401, detail="User not found")

    return dict(user)


@app.post("/register")
def register(data: RegisterRequest):
    name = data.name.strip()
    email = data.email.strip().lower()

    if not name or not email or "@" not in email:
        raise HTTPException(
            status_code=400,
            detail="Enter a valid name and email."
        )

    hashed_password = password_hash.hash(data.password)

    try:
        with sqlite3.connect(DB_PATH) as con:
            con.execute(
                """
                INSERT INTO users (name, email, password, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (
                    name,
                    email,
                    hashed_password,
                    datetime.now().isoformat(timespec="seconds")
                )
            )
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=409,
            detail="This email is already registered."
        )

    return {"message": "Registration successful. Please log in."}


@app.post("/login")
def login(data: LoginRequest):
    email = data.email.strip().lower()

    with sqlite3.connect(DB_PATH) as con:
        con.row_factory = sqlite3.Row
        user = con.execute(
            "SELECT id, password FROM users WHERE email = ?",
            (email,)
        ).fetchone()

    if user is None or not password_hash.verify(
        data.password, user["password"]
    ):
        raise HTTPException(
            status_code=401,
            detail="Incorrect email or password."
        )

    token = serializer.dumps({"user_id": user["id"]})

    return {
        "message": "Login successful",
        "access_token": token,
        "token_type": "bearer"
    }


@app.get("/me")
def me(user=Depends(get_current_user)):
    return user


# Scam detection helpers
def inspect_url(url):
    reasons = []
    lower = url.lower()

    if lower.startswith("http://"):
        reasons.append("Link does not use secure HTTPS")

    if "@" in url:
        reasons.append("Link contains an unusual @ symbol")

    if len(url) > 90:
        reasons.append("Link is unusually long")

    if any(word in lower for word in [
        "login", "verify", "secure", "update"
    ]):
        reasons.append(
            "Link contains a word often used in phishing links"
        )

    return reasons


def get_urls(text):
    return URL_PATTERN.findall(text)


# Home
@app.get("/")
def home():
    return {
        "message": "ScamShield AI API is running",
        "docs": "/docs"
    }


# User-specific statistics
@app.get("/stats")
def stats(user=Depends(get_current_user)):
    with sqlite3.connect(DB_PATH) as con:
        rows = con.execute(
            """
            SELECT risk, COUNT(*)
            FROM scans
            WHERE user_id = ?
            GROUP BY risk
            """,
            (user["id"],)
        ).fetchall()

        total = con.execute(
            "SELECT COUNT(*) FROM scans WHERE user_id = ?",
            (user["id"],)
        ).fetchone()[0]

    counts = {risk: count for risk, count in rows}

    return {
        "total_scans": total,
        "high_risk": counts.get("High", 0),
        "medium_risk": counts.get("Medium", 0),
        "low_risk": counts.get("Low", 0)
    }


# User-specific history
@app.get("/history")
def history(user=Depends(get_current_user)):
    with sqlite3.connect(DB_PATH) as con:
        con.row_factory = sqlite3.Row
        rows = con.execute(
            """
            SELECT id, message, risk, score, reasons, created_at
            FROM scans
            WHERE user_id = ?
            ORDER BY id DESC LIMIT 20
            """,
            (user["id"],)
        ).fetchall()

    return [dict(row) for row in rows]


@app.delete("/history")
def clear_history(user=Depends(get_current_user)):
    with sqlite3.connect(DB_PATH) as con:
        con.execute(
            "DELETE FROM scans WHERE user_id = ?",
            (user["id"],)
        )

    return {"message": "Your scan history was cleared"}


# Protected scam scanning
@app.post("/predict")
def predict(data: ScanRequest, user=Depends(get_current_user)):
    message = data.text.strip()

    if not message:
        return {"error": "Please enter a message or link."}

    model_score = float(
        model.predict_proba(
            vectorizer.transform([message])
        )[0][1]
    )

    reasons = []
    lower = message.lower()

    found_words = [
        word for word in SUSPICIOUS_WORDS if word in lower
    ]

    if found_words:
        reasons.append(
            "Potentially risky words found: "
            + ", ".join(found_words)
        )

    urls = get_urls(message)

    for url in urls:
        reasons.extend(inspect_url(url))

    score = int(
        model_score * 65
        + min(len(found_words), 4) * 7
        + min(len(urls), 2) * 5
    )

    if any(
        "Link" in reason or "Link contains" in reason
        for reason in reasons
    ):
        score = max(score, 70)

    score = max(0, min(score, 99))

    if score >= 70:
        risk = "High"
    elif score >= 40:
        risk = "Medium"
    else:
        risk = "Low"

    if not reasons:
        reasons.append(
            "No obvious warning signs found by this demo scanner"
        )

    reasons_text = " | ".join(reasons)

    with sqlite3.connect(DB_PATH) as con:
        con.execute(
            """
            INSERT INTO scans
            (message, risk, score, reasons, created_at, user_id)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                message,
                risk,
                score,
                reasons_text,
                datetime.now().isoformat(timespec="seconds"),
                user["id"]
            )
        )

    return {
        "result": "Suspicious" if risk != "Low" else "Likely Safe",
        "risk": risk,
        "score": score,
        "reasons": reasons,
        "urls_found": urls,
        "disclaimer": (
            "Student demo only. It can miss scams or flag safe messages. "
            "Never share OTPs or passwords."
        )
    }
