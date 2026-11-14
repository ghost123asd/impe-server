import os
import psycopg2
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from passlib.context import CryptContext

app = FastAPI()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class UserData(BaseModel):
    username: str
    password: str

def get_db():
    url = os.environ.get("DATABASE_URL")
    if not url:
        raise Exception("DATABASE_URL не задан!")
    return psycopg2.connect(url)

@app.get("/")
def health_check():
    try:
        conn = get_db()
        conn.close()
        return {"status": "ok", "message": "База подключена!"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.post("/register")
def register(data: UserData):
    try:
        conn = get_db()
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM users WHERE username = %s", (data.username,))
            if cur.fetchone():
                raise HTTPException(status_code=400, detail="User already exists")
            hashed = pwd_context.hash(data.password)
            cur.execute("INSERT INTO users (username, password_hash) VALUES (%s, %s)", (data.username, hashed))
        conn.commit()
        conn.close()
        return {"status": "ok"}
    except Exception as e:
        print(e)
        raise HTTPException(status_code=500, detail="Error")

@app.post("/login")
def login(data: UserData):
    try:
        conn = get_db()
        with conn.cursor() as cur:
            cur.execute("SELECT password_hash FROM users WHERE username = %s", (data.username,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=401, detail="Not found")
            if not pwd_context.verify(data.password, row[0]):
                raise HTTPException(status_code=401, detail="Wrong password")
        conn.close()
        return {"status": "ok"}
    except HTTPException:
        raise
    except Exception as e:
        print(e)
        raise HTTPException(status_code=500, detail="Error")