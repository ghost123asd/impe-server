import os
import psycopg2
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from passlib.context import CryptContext
from typing import List

app = FastAPI()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class UserData(BaseModel):
    username: str
    password: str

class ActivateData(BaseModel):
    username: str
    key_code: str

class ChatMessage(BaseModel):
    username: str
    text: str

def get_db():
    url = os.environ.get("DATABASE_URL")
    if not url:
        raise Exception("DATABASE_URL не задан!")
    return psycopg2.connect(url)

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
            if cur.fetchone():
                raise HTTPException(status_code=400, detail="Exists")
            hashed = pwd_context.hash(data.password)
            cur.execute("INSERT INTO users (username, password_hash) VALUES (%s, %s)", (data.username, hashed))
        conn.commit(); conn.close()
        return {"status": "ok"}
    except HTTPException: raise
    except Exception as e:
        print(e); raise HTTPException(status_code=500, detail="Error")

@app.post("/login")
def login(data: UserData):
    try:
        conn = get_db()
        with conn.cursor() as cur:
            cur.execute("SELECT password_hash, is_premium FROM users WHERE username = %s", (data.username,))
            row = cur.fetchone()
            if not row: raise HTTPException(status_code=401, detail="Not found")
            if not pwd_context.verify(data.password, row[0]): raise HTTPException(status_code=401, detail="Wrong password")
            
            return {"status": "ok", "username": data.username, "is_premium": row[1]}
    except HTTPException: raise
    except Exception as e:
        print(e); raise HTTPException(status_code=500, detail="Error")

@app.post("/activate")
def activate_key(data: ActivateData):
    try:
        conn = get_db()
        with conn.cursor() as cur:
            cur.execute("SELECT is_used FROM license_keys WHERE key_code = %s", (data.key_code,))
            row = cur.fetchone()
            if not row: raise HTTPException(status_code=400, detail="Key not found")
            if row[0] == True: raise HTTPException(status_code=400, detail="Key used")
            
            # Помечаем ключ использованным и выдаем премиум пользователю
            cur.execute("UPDATE license_keys SET is_used = TRUE, used_by = %s WHERE key_code = %s", (data.username, data.key_code))
            cur.execute("UPDATE users SET is_premium = TRUE WHERE username = %s", (data.username,))
        conn.commit(); conn.close()
        return {"status": "ok"}
    except HTTPException: raise
    except Exception as e:
        print(e); raise HTTPException(status_code=500, detail="Error")

@app.post("/chat/send")
def send_chat(data: ChatMessage):
    try:
        conn = get_db()
        with conn.cursor() as cur:
            cur.execute("INSERT INTO chat_messages (username, text) VALUES (%s, %s)", (data.username, data.text))
        conn.commit(); conn.close()
        return {"status": "ok"}
    except Exception as e:
        print(e); raise HTTPException(status_code=500, detail="Error")

@app.get("/chat/get")
def get_chat():
    try:
        conn = get_db()
        with conn.cursor() as cur:
            cur.execute("SELECT username, text FROM chat_messages ORDER BY id DESC LIMIT 20")
            rows = cur.fetchall()
        conn.close()
        # Возвращаем в хронологическом порядке
        return [{"username": r[0], "text": r[1]} for r in reversed(rows)]
    except Exception as e:
        print(e); raise HTTPException(status_code=500, detail="Error")