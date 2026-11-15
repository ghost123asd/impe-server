import os
import psycopg2
from fastapi import FastAPI, HTTPException, Depends, status
from pydantic import BaseModel
from passlib.context import CryptContext
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from datetime import datetime, timedelta, timezone
import jwt
import traceback

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["https://твой-сайт.com", "http://localhost:3000"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

SECRET_KEY = os.environ.get("SECRET_KEY", "fallback_secret_change_me")
ALGORITHM = "HS256"
security = HTTPBearer()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class UserData(BaseModel):
    username: str
    password: str

class ActivateData(BaseModel):
    key_code: str

class AdminAction(BaseModel):
    target_user: str
    action: str
    duration_days: int = 0

class AnnouncementData(BaseModel):
    message: str

def get_db():
    url = os.environ.get("DATABASE_URL")
    if not url: raise Exception("DATABASE_URL is missing!")
    return psycopg2.connect(url)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(days=7)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None: raise HTTPException(status_code=401, detail="Invalid token")
        return username
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

def is_owner(cur, username):
    cur.execute('SELECT "rank" FROM users WHERE username = %s', (username,))
    row = cur.fetchone()
    return row and row[0] == "owner"

@app.on_event("startup")
def setup_db():
    print("Checking database tables...")
    try:
        conn = get_db()
        with conn.cursor() as cur:
            cur.execute("CREATE TABLE IF NOT EXISTS announcements (id SERIAL PRIMARY KEY, message TEXT NOT NULL, is_active BOOLEAN DEFAULT TRUE, created_at TIMESTAMPTZ DEFAULT NOW());")
            cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS is_banned BOOLEAN DEFAULT FALSE;")
            cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS ban_until TIMESTAMPTZ;")
            cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS premium_until TIMESTAMPTZ;")
            cur.execute('ALTER TABLE users ADD COLUMN IF NOT EXISTS "rank" TEXT DEFAULT \'user\';')
        conn.commit(); conn.close()
        print("DB setup complete.")
    except Exception as e:
        print(f"DB SETUP ERROR: {e}")

@app.get("/")
def health_check():
    try:
        conn = get_db(); conn.close()
        return {"status": "ok"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.post("/register")
def register(data: UserData):
    if len(data.password) < 4: raise HTTPException(status_code=400, detail="Password too short")
    try:
        conn = get_db()
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM users WHERE username = %s", (data.username,))
            if cur.fetchone(): raise HTTPException(status_code=400, detail="Exists")
            hashed = pwd_context.hash(data.password)
            cur.execute("INSERT INTO users (username, password_hash) VALUES (%s, %s)", (data.username, hashed))
        conn.commit(); conn.close()
        return {"status": "ok"}
    except HTTPException: raise
    except Exception as e: 
        print(f"REGISTER ERROR: {e}"); raise HTTPException(status_code=500, detail="Error")

@app.post("/login")
def login(data: UserData):
    try:
        conn = get_db()
        with conn.cursor() as cur:
            cur.execute('SELECT password_hash, is_premium, "rank", is_banned, ban_until, premium_until FROM users WHERE username = %s', (data.username,))
            row = cur.fetchone()
            if not row: raise HTTPException(status_code=401, detail="Not found")
            if not pwd_context.verify(data.password, row[0]): raise HTTPException(status_code=401, detail="Wrong password")
            
            is_banned, ban_until = row[3], row[4]
            if is_banned and ban_until:
                if ban_until < datetime.now(timezone.utc):
                    cur.execute("UPDATE users SET is_banned = FALSE, ban_until = NULL WHERE username = %s", (data.username,))
                    conn.commit(); is_banned = False
                else: return {"status": "banned", "ban_until": str(ban_until)}
            if is_banned and not ban_until: return {"status": "banned", "ban_until": "permanent"}

            is_premium, premium_until = row[1], row[5]
            if is_premium and premium_until:
                if premium_until < datetime.now(timezone.utc):
                    cur.execute("UPDATE users SET is_premium = FALSE, premium_until = NULL WHERE username = %s", (data.username,))
                    conn.commit(); is_premium = False

            cur.execute("SELECT message FROM announcements WHERE is_active = TRUE ORDER BY id DESC LIMIT 1")
            ann = cur.fetchone()
            announcement = ann[0] if ann else ""

            token = create_access_token(data={"sub": data.username, "rank": row[2]})
            return {"status": "ok", "token": token, "username": data.username, "is_premium": is_premium, "rank": row[2], "announcement": announcement}
    except HTTPException: raise
    except Exception as e: 
        print(f"LOGIN ERROR: {e}"); raise HTTPException(status_code=500, detail="Error")

@app.post("/activate")
def activate_key(data: ActivateData, current_user: str = Depends(get_current_user)):
    try:
        conn = get_db()
        with conn.cursor() as cur:
            # Атомарная проверка и активация (защита от гонки)
            cur.execute("UPDATE license_keys SET is_used = TRUE, used_by = %s WHERE key_code = %s AND is_used = FALSE RETURNING id", (current_user, data.key_code))
            if not cur.fetchone():
                raise HTTPException(status_code=400, detail="Key not found or already used")
            
            cur.execute("UPDATE users SET is_premium = TRUE WHERE username = %s", (current_user,))
        conn.commit(); conn.close()
        return {"status": "ok"}
    except HTTPException: raise
    except Exception as e: 
        print(f"ACTIVATE ERROR: {e}"); raise HTTPException(status_code=500, detail="Error")

@app.get("/admin/users")
def get_users(search: str = "", current_user: str = Depends(get_current_user)):
    try:
        conn = get_db()
        with conn.cursor() as cur:
            if not is_owner(cur, current_user): raise HTTPException(status_code=403, detail="Access denied")
            query = 'SELECT username, "rank", is_premium, is_banned, ban_until, premium_until FROM users'
            if search: query += " WHERE username ILIKE %s"
            query += " ORDER BY id DESC LIMIT 50"
            cur.execute(query, (f"%{search}%",) if search else ())
            
            users = [{"username": r[0], "rank": r[1], "is_premium": r[2], "is_banned": r[3], "ban_until": str(r[4]) if r[4] else None, "premium_until": str(r[5]) if r[5] else None} for r in cur.fetchall()]
            return {"status": "ok", "users": users}
    except HTTPException: raise
    except Exception as e: raise HTTPException(status_code=500, detail="Error")

@app.post("/admin/action")
def admin_action(data: AdminAction, current_user: str = Depends(get_current_user)):
    try:
        conn = get_db()
        with conn.cursor() as cur:
            if not is_owner(cur, current_user): raise HTTPException(status_code=403, detail="Access denied")
            
            print(f"[ADMIN LOG] {current_user} -> {data.action} on {data.target_user} (Days: {data.duration_days})")
            
            if data.action == "give_prem":
                if data.duration_days > 0:
                    until = datetime.now(timezone.utc) + timedelta(days=data.duration_days)
                    cur.execute("UPDATE users SET is_premium = TRUE, premium_until = %s WHERE username = %s", (until, data.target_user))
                else:
                    cur.execute("UPDATE users SET is_premium = TRUE, premium_until = NULL WHERE username = %s", (data.target_user,))
            elif data.action == "remove_prem":
                cur.execute("UPDATE users SET is_premium = FALSE, premium_until = NULL WHERE username = %s", (data.target_user,))
            elif data.action == "ban_temp":
                until = datetime.now(timezone.utc) + timedelta(days=data.duration_days)
                cur.execute("UPDATE users SET is_banned = TRUE, ban_until = %s WHERE username = %s", (until, data.target_user))
            elif data.action == "ban_perm":
                cur.execute("UPDATE users SET is_banned = TRUE, ban_until = NULL WHERE username = %s", (data.target_user,))
            elif data.action == "unban":
                cur.execute("UPDATE users SET is_banned = FALSE, ban_until = NULL WHERE username = %s", (data.target_user,))
        conn.commit(); conn.close()
        return {"status": "ok"}
    except HTTPException: raise
    except Exception as e: raise HTTPException(status_code=500, detail="Error")

@app.post("/admin/announce")
def set_announcement(data: AnnouncementData, current_user: str = Depends(get_current_user)):
    try:
        conn = get_db()
        with conn.cursor() as cur:
            if not is_owner(cur, current_user): raise HTTPException(status_code=403, detail="Access denied")
            cur.execute("UPDATE announcements SET is_active = FALSE")
            if data.message.strip():
                cur.execute("INSERT INTO announcements (message) VALUES (%s)", (data.message,))
        conn.commit(); conn.close()
        return {"status": "ok"}
    except HTTPException: raise
    except Exception as e: raise HTTPException(status_code=500, detail="Error")