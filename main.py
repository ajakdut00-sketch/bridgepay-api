
from fastapi import FastAPI
import sqlite3
import uuid
from datetime import datetime, timedelta

from jose import jwt, JWTError
from passlib.context import CryptContext

app = FastAPI()

# ================= AUTH =================
SECRET_KEY = "bridgepay-secret"
ALGORITHM = "HS256"
EXPIRE_MINUTES = 60

pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_pw(pw):
    return pwd.hash(pw)

def verify_pw(plain, hashed):
    return pwd.verify(plain, hashed)

def create_token(data):
    payload = data.copy()
    payload["exp"] = datetime.utcnow() + timedelta(minutes=EXPIRE_MINUTES)
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return None

# ================= DATABASE =================
conn = sqlite3.connect("bridgepay.db", check_same_thread=False)
cur = conn.cursor()

cur.execute("""
CREATE TABLE IF NOT EXISTS users (
    name TEXT PRIMARY KEY,
    password TEXT,
    balance REAL
)
""")

cur.execute("""
CREATE TABLE IF NOT EXISTS ledger (
    id TEXT,
    type TEXT,
    timestamp TEXT,
    data TEXT
)
""")

conn.commit()

# ================= HELPERS =================
def now():
    return datetime.utcnow().isoformat()

def log(tx_type, data):
    cur.execute("""
        INSERT INTO ledger VALUES (?, ?, ?, ?)
    """, (
        str(uuid.uuid4()),
        tx_type,
        now(),
        str(data)
    ))
    conn.commit()

# ================= API =================

@app.get("/test")
def test():
    return {"status": "ok"}

@app.post("/signup")
def signup(name: str, password: str):
    hashed = hash_pw(password)

    cur.execute("INSERT OR IGNORE INTO users VALUES (?, ?, ?)",
                (name, hashed, 0))
    conn.commit()

    log("signup", {"user": name})

    return {"status": "user created"}

@app.post("/login")
def login(name: str, password: str):
    cur.execute("SELECT password FROM users WHERE name=?", (name,))
    row = cur.fetchone()

    if not row:
        return {"error": "user not found"}

    if not verify_pw(password, row[0]):
        return {"error": "wrong password"}

    token = create_token({"user": name})

    return {"token": token}

@app.post("/deposit")
def deposit(name: str, amount: float, token: str):
    user = decode_token(token)

    if not user or user["user"] != name:
        return {"error": "unauthorized"}

    cur.execute("SELECT balance FROM users WHERE name=?", (name,))
    row = cur.fetchone()

    if not row:
        return {"error": "user not found"}

    new_balance = row[0] + amount

    cur.execute("UPDATE users SET balance=? WHERE name=?",
                (new_balance, name))
    conn.commit()

    log("deposit", {"user": name, "amount": amount})

    return {"status": "deposit successful", "balance": new_balance}

@app.post("/transfer")
def transfer(sender: str, receiver: str, amount: float, token: str):
    user = decode_token(token)

    if not user or user["user"] != sender:
        return {"error": "unauthorized"}

    cur.execute("SELECT balance FROM users WHERE name=?", (sender,))
    s = cur.fetchone()

    cur.execute("SELECT balance FROM users WHERE name=?", (receiver,))
    r = cur.fetchone()

    if not s or not r:
        return {"error": "user not found"}

    if s[0] < amount:
        return {"error": "insufficient funds"}

    cur.execute("UPDATE users SET balance=? WHERE name=?",
                (s[0] - amount, sender))

    cur.execute("UPDATE users SET balance=? WHERE name=?",
                (r[0] + amount, receiver))

    conn.commit()

    log("transfer", {
        "from": sender,
        "to": receiver,
        "amount": amount
    })

    return {"status": "transfer successful"}

@app.get("/balance")
def balance(name: str, token: str):
    user = decode_token(token)

    if not user or user["user"] != name:
        return {"error": "unauthorized"}

    cur.execute("SELECT balance FROM users WHERE name=?", (name,))
    row = cur.fetchone()

    if not row:
        return {"error": "user not found"}

    return {"balance": row[0]}

@app.get("/ledger")
def ledger(token: str):
    user = decode_token(token)

    if not user:
        return {"error": "unauthorized"}

    cur.execute("SELECT * FROM ledger")
    return cur.fetchall()
