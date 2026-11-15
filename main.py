import os
import psycopg2
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from passlib.context import CryptContext
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timedelta, timezone
import traceback

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class UserData(BaseModel):
    username: str
    password: str

class ActivateData(BaseModel):
    username: str
    key_code: str

class AdminAction(BaseModel):
    requester: str
    target_user: str
    action: str
    duration_days: int = 0

class AnnouncementData(BaseModel):
    requester: str
    message: str

def get_db():
    url = os.environ.get("DATABASE_URL")
    if not url: raise Exception("DATABASE_URL is missing!")
    return psycopg2.connect(url)

# --- АВТО-МИГРАЦИЯ ПРИ СТАРТЕ ---
@app.on_event("startup")
def setup_db():
    print("Checking database tables...")
    try:
        conn = get_db()
        with conn.cursor() as cur:
            # Создаем таблицу announcements если её нет
            cur.execute("""
                CREATE TABLE IF NOT EXISTS announcements (
                    id SERIAL PRIMARY KEY,
                    message TEXT NOT NULL,
                    is_active BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMPTZ DEFAULT NOW()
                );
            """)
            # Добавляем колонки если их нет
            cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS is_banned BOOLEAN DEFAULT FALSE;")
            cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS ban_until TIMESTAMPTZ;")
            cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS premium_until TIMESTAMPTZ;")
            cur.execute('ALTER TABLE users ADD COLUMN IF NOT EXISTS "rank" TEXT DEFAULT \'user\';')
        conn.commit()
        conn.close()
        print("DB setup complete.")
    except Exception as e:
        print(f"DB SETUP ERROR: {e}")

def is_owner(cur, username):
    cur.execute('SELECT "rank" FROM users WHERE username = %s', (username,))
    row = cur.fetchone()
    return row and row[0] == "owner"

@app.get("/")
def health_check():
    try:
        conn = get_db(); conn.close()
        return {"status": "ok"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.post("/register")
def register(data: UserData):
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
        print(f"REGISTER ERROR: {e}")
        print(traceback.format_exc())
        raise HTTPException(status_code=500, detail="Error")

@app.post("/login")
def login(data: UserData):
    try:
        conn = get_db()
        with conn.cursor() as cur:
            cur.execute('SELECT password_hash, is_premium, "rank", is_banned, ban_until, premium_until FROM users WHERE username = %s', (data.username,))
            row = cur.fetchone()
            if not row: raise HTTPException(status_code=401, detail="Not found")
            if not pwd_context.verify(data.password, row[0]): raise HTTPException(status_code=401, detail="Wrong password")
            
            is_banned = row[3]
            ban_until = row[4]
            if is_banned and ban_until:
                now = datetime.now(timezone.utc)
                if ban_until < now:
                    cur.execute("UPDATE users SET is_banned = FALSE, ban_until = NULL WHERE username = %s", (data.username,))
                    conn.commit()
                    is_banned = False
                else:
                    return {"status": "banned", "ban_until": str(ban_until)}
            if is_banned and not ban_until:
                return {"status": "banned", "ban_until": "permanent"}

            is_premium = row[1]
            premium_until = row[5]
            if is_premium and premium_until:
                now = datetime.now(timezone.utc)
                if premium_until < now:
                    cur.execute("UPDATE users SET is_premium = FALSE, premium_until = NULL WHERE username = %s", (data.username,))
                    conn.commit()
                    is_premium = False

            cur.execute("SELECT message FROM announcements WHERE is_active = TRUE ORDER BY id DESC LIMIT 1")
            ann = cur.fetchone()
            announcement = ann[0] if ann else ""

            return {"status": "ok", "username": data.username, "is_premium": is_premium, "rank": row[2], "announcement": announcement}
    except HTTPException: raise
    except Exception as e: 
        print(f"LOGIN ERROR: {e}")
        print(traceback.format_exc())
        raise HTTPException(status_code=500, detail="Error")

@app.post("/activate")
def activate_key(data: ActivateData):
    try:
        conn = get_db()
        with conn.cursor() as cur:
            cur.execute("SELECT is_used FROM license_keys WHERE key_code = %s", (data.key_code,))
            row = cur.fetchone()
            if not row: raise HTTPException(status_code=400, detail="Key not found")
            if row[0] == True: raise HTTPException(status_code=400, detail="Key used")
            
            cur.execute("UPDATE license_keys SET is_used = TRUE, used_by = %s WHERE key_code = %s", (data.username, data.key_code))
            cur.execute("UPDATE users SET is_premium = TRUE WHERE username = %s", (data.username,))
        conn.commit(); conn.close()
        return {"status": "ok"}
    except HTTPException: raise
    except Exception as e: 
        print(f"ACTIVATE ERROR: {e}")
        raise HTTPException(status_code=500, detail="Error")

@app.get("/admin/users")
def get_users(requester: str, search: str = ""):
    try:
        conn = get_db()
        with conn.cursor() as cur:
            if not is_owner(cur, requester): raise HTTPException(status_code=403, detail="Access denied")
            query = 'SELECT username, "rank", is_premium, is_banned, ban_until, premium_until FROM users'
            if search: query += " WHERE username ILIKE %s"
            query += " ORDER BY id DESC LIMIT 50"
            
            cur.execute(query, (f"%{search}%",) if search else ())
            rows = cur.fetchall()
            
            users = []
            for r in rows:
                users.append({
                    "username": r[0], "rank": r[1], "is_premium": r[2], 
                    "is_banned": r[3], "ban_until": str(r[4]) if r[4] else None,
                    "premium_until": str(r[5]) if r[5] else None
                })
            return {"status": "ok", "users": users}
    except HTTPException: raise
    except Exception as e: 
        print(f"ADMIN USERS ERROR: {e}")
        raise HTTPException(status_code=500, detail="Error")

@app.post("/admin/action")
def admin_action(data: AdminAction):
    try:
        conn = get_db()
        with conn.cursor() as cur:
            if not is_owner(cur, data.requester): raise HTTPException(status_code=403, detail="Access denied")
            
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
    except Exception as e: 
        print(f"ADMIN ACTION ERROR: {e}")
        raise HTTPException(status_code=500, detail="Error")

@app.post("/admin/announce")
def set_announcement(data: AnnouncementData):
    try:
        conn = get_db()
        with conn.cursor() as cur:
            if not is_owner(cur, data.requester): raise HTTPException(status_code=403, detail="Access denied")
            cur.execute("UPDATE announcements SET is_active = FALSE")
            if data.message.strip():
                cur.execute("INSERT INTO announcements (message) VALUES (%s)", (data.message,))
        conn.commit(); conn.close()
        return {"status": "ok"}
    except HTTPException: raise
    except Exception as e: 
        print(f"ANNOUNCE ERROR: {e}")
        raise HTTPException(status_code=500, detail="Error")