"""
High School Management System API

A super simple FastAPI application that allows students to view and sign up
for extracurricular activities at Mergington High School.
"""

from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Generator, List, Optional
import os
import secrets
import sqlite3

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr

app = FastAPI(
    title="Mergington High School API",
    description="API for viewing and signing up for extracurricular activities",
)

# Paths and security constants
current_dir = Path(__file__).parent
DB_PATH = current_dir / "school.db"
CSRF_TOKEN = "mshs-csrf-token-2026"
SESSION_DURATION_MINUTES = 60

# Mount the static files directory
app.mount("/static", StaticFiles(directory=current_dir / "static"), name="static")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

DEFAULT_ACTIVITIES = [
    {
        "name": "Chess Club",
        "description": "Learn strategies and compete in chess tournaments",
        "schedule": "Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 12,
    },
    {
        "name": "Programming Class",
        "description": "Learn programming fundamentals and build software projects",
        "schedule": "Tuesdays and Thursdays, 3:30 PM - 4:30 PM",
        "max_participants": 20,
    },
    {
        "name": "Gym Class",
        "description": "Physical education and sports activities",
        "schedule": "Mondays, Wednesdays, Fridays, 2:00 PM - 3:00 PM",
        "max_participants": 30,
    },
    {
        "name": "Soccer Team",
        "description": "Join the school soccer team and compete in matches",
        "schedule": "Tuesdays and Thursdays, 4:00 PM - 5:30 PM",
        "max_participants": 22,
    },
    {
        "name": "Basketball Team",
        "description": "Practice and play basketball with the school team",
        "schedule": "Wednesdays and Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
    },
    {
        "name": "Art Club",
        "description": "Explore your creativity through painting and drawing",
        "schedule": "Thursdays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
    },
    {
        "name": "Drama Club",
        "description": "Act, direct, and produce plays and performances",
        "schedule": "Mondays and Wednesdays, 4:00 PM - 5:30 PM",
        "max_participants": 20,
    },
    {
        "name": "Math Club",
        "description": "Solve challenging problems and participate in math competitions",
        "schedule": "Tuesdays, 3:30 PM - 4:30 PM",
        "max_participants": 10,
    },
    {
        "name": "Debate Team",
        "description": "Develop public speaking and argumentation skills",
        "schedule": "Fridays, 4:00 PM - 5:30 PM",
        "max_participants": 12,
    },
]


class ActivityOut(BaseModel):
    name: str
    description: str
    schedule: str
    max_participants: int
    participants: List[EmailStr]


class ActivityCreate(BaseModel):
    name: str
    description: str
    schedule: str
    max_participants: int


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str


def get_db() -> Generator[sqlite3.Connection, None, None]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
    finally:
        conn.close()


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, hashed_password: str) -> bool:
    return pwd_context.verify(password, hashed_password)


def verify_csrf_token(x_csrf_token: str = Header(...)) -> None:
    if x_csrf_token != CSRF_TOKEN:
        raise HTTPException(status_code=403, detail="Invalid CSRF token")


def create_tables() -> None:
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    with conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS activities (
                id INTEGER PRIMARY KEY,
                name TEXT UNIQUE NOT NULL,
                description TEXT NOT NULL,
                schedule TEXT NOT NULL,
                max_participants INTEGER NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS participants (
                id INTEGER PRIMARY KEY,
                activity_id INTEGER NOT NULL,
                email TEXT NOT NULL,
                UNIQUE(activity_id, email),
                FOREIGN KEY(activity_id) REFERENCES activities(id) ON DELETE CASCADE
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                expires_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )
    conn.close()


def seed_default_data() -> None:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    with conn:
        existing = conn.execute("SELECT COUNT(*) FROM activities").fetchone()[0]
        if existing == 0:
            for activity in DEFAULT_ACTIVITIES:
                conn.execute(
                    "INSERT INTO activities (name, description, schedule, max_participants) VALUES (?, ?, ?, ?)",
                    (
                        activity["name"],
                        activity["description"],
                        activity["schedule"],
                        activity["max_participants"],
                    ),
                )
        users_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if users_count == 0:
            conn.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                ("admin", hash_password("adminpass"), "admin"),
            )
    conn.close()


def get_activity_by_name(conn: sqlite3.Connection, activity_name: str) -> Optional[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM activities WHERE name = ?",
        (activity_name,),
    ).fetchone()


def get_activity_participants(conn: sqlite3.Connection, activity_id: int) -> List[str]:
    rows = conn.execute(
        "SELECT email FROM participants WHERE activity_id = ? ORDER BY email",
        (activity_id,),
    ).fetchall()
    return [row["email"] for row in rows]


def get_all_activities(conn: sqlite3.Connection) -> Dict[str, Dict]:
    activities = {}
    rows = conn.execute(
        "SELECT id, name, description, schedule, max_participants FROM activities ORDER BY name"
    ).fetchall()
    for row in rows:
        activities[row["name"]] = {
            "description": row["description"],
            "schedule": row["schedule"],
            "max_participants": row["max_participants"],
            "participants": get_activity_participants(conn, row["id"]),
        }
    return activities


def create_session(conn: sqlite3.Connection, user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    expires_at = (datetime.utcnow() + timedelta(minutes=SESSION_DURATION_MINUTES)).isoformat()
    conn.execute(
        "INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)",
        (token, user_id, expires_at),
    )
    return token


def get_current_user(
    authorization: Optional[str] = Header(None),
    conn: sqlite3.Connection = Depends(get_db),
) -> Dict[str, str]:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid authorization header")

    token = authorization.split("Bearer ", 1)[1].strip()
    session = conn.execute(
        "SELECT user_id, expires_at FROM sessions WHERE token = ?",
        (token,),
    ).fetchone()
    if not session:
        raise HTTPException(status_code=401, detail="Invalid session token")

    expires_at = datetime.fromisoformat(session["expires_at"])
    if expires_at < datetime.utcnow():
        raise HTTPException(status_code=401, detail="Session token has expired")

    user = conn.execute(
        "SELECT username, role FROM users WHERE id = ?",
        (session["user_id"],),
    ).fetchone()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    return {"username": user["username"], "role": user["role"]}


def require_admin(user: Dict[str, str] = Depends(get_current_user)) -> Dict[str, str]:
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


@app.on_event("startup")
def startup() -> None:
    create_tables()
    seed_default_data()


@app.get("/")
def root() -> RedirectResponse:
    return RedirectResponse(url="/static/index.html")


@app.get("/activities")
def get_activities(db: sqlite3.Connection = Depends(get_db)) -> Dict[str, Dict]:
    return get_all_activities(db)


@app.post("/activities/{activity_name}/signup")
def signup_for_activity(
    activity_name: str,
    email: EmailStr,
    db: sqlite3.Connection = Depends(get_db),
    _: None = Depends(verify_csrf_token),
) -> Dict[str, str]:
    if not get_activity_by_name(db, activity_name):
        raise HTTPException(status_code=404, detail="Activity not found")

    activity = get_activity_by_name(db, activity_name)
    participants = get_activity_participants(db, activity["id"])
    if email in participants:
        raise HTTPException(status_code=400, detail="Student is already signed up")

    if len(participants) >= activity["max_participants"]:
        raise HTTPException(status_code=400, detail="Activity is full")

    db.execute(
        "INSERT INTO participants (activity_id, email) VALUES (?, ?)",
        (activity["id"], email),
    )
    db.commit()
    return {"message": f"Signed up {email} for {activity_name}"}


@app.delete("/activities/{activity_name}/unregister")
def unregister_from_activity(
    activity_name: str,
    email: EmailStr,
    db: sqlite3.Connection = Depends(get_db),
    _: None = Depends(verify_csrf_token),
) -> Dict[str, str]:
    activity = get_activity_by_name(db, activity_name)
    if not activity:
        raise HTTPException(status_code=404, detail="Activity not found")

    participant = db.execute(
        "SELECT id FROM participants WHERE activity_id = ? AND email = ?",
        (activity["id"], email),
    ).fetchone()
    if not participant:
        raise HTTPException(status_code=400, detail="Student is not signed up for this activity")

    db.execute("DELETE FROM participants WHERE id = ?", (participant["id"],))
    db.commit()
    return {"message": f"Unregistered {email} from {activity_name}"}


@app.post("/activities")
def create_activity(
    activity: ActivityCreate,
    db: sqlite3.Connection = Depends(get_db),
    _: None = Depends(verify_csrf_token),
    __: Dict[str, str] = Depends(require_admin),
) -> Dict[str, str]:
    existing = get_activity_by_name(db, activity.name)
    if existing:
        raise HTTPException(status_code=400, detail="Activity already exists")

    db.execute(
        "INSERT INTO activities (name, description, schedule, max_participants) VALUES (?, ?, ?, ?)",
        (activity.name, activity.description, activity.schedule, activity.max_participants),
    )
    db.commit()
    return {"message": f"Activity '{activity.name}' created successfully"}


@app.post("/auth/login", response_model=LoginResponse)
def login(login_data: LoginRequest, db: sqlite3.Connection = Depends(get_db)) -> LoginResponse:
    user = db.execute(
        "SELECT id, username, password_hash, role FROM users WHERE username = ?",
        (login_data.username,),
    ).fetchone()
    if not user or not verify_password(login_data.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    token = create_session(db, user["id"])
    db.commit()
    return LoginResponse(access_token=token, role=user["role"])


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
