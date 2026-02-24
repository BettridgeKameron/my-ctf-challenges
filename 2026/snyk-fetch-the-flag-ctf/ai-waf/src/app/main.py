import time
import secrets
import jwt
import bcrypt
from datetime import datetime, timedelta
from typing import Dict, Optional

import uvicorn
from fastapi import FastAPI, Request, HTTPException, Depends, status
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel

app = FastAPI()

# Auth Configuration
SECRET_KEY = secrets.token_hex(32)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 240  # 4 hours

# In-memory storage
# users = { "username": { "password": hashed_bytes, "content": str, "last_submit": float } }
users: Dict[str, Dict] = {}

# Global registration rate limit
last_registration_ts = 0.0
REGISTRATION_LIMIT_SECONDS = 5

# Task rate limit (per user)
TASK_LIMIT_SECONDS = 5

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/login")

class UserAuth(BaseModel):
    username: str
    password: str

class TaskSubmit(BaseModel):
    content: str

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception
    
    user = users.get(username)
    if user is None:
        raise credentials_exception
    return username

@app.post("/api/register", response_class=JSONResponse)
async def register(auth: UserAuth):
    global last_registration_ts
    now = time.time()
    
    # Global registration rate limit
    if now - last_registration_ts < REGISTRATION_LIMIT_SECONDS:
        return JSONResponse({"error": "Registration rate limit (global) exceeded. Try again in 5 seconds."}, status_code=429)
    
    if len(auth.username) < 6 or len(auth.password) < 6:
        return JSONResponse({"error": "Username and password must be at least 6 characters long"}, status_code=400)
    
    if auth.username in users:
        # Don't update timestamp on failure to prevent denial of service by spamming invalid users
        return JSONResponse({"error": "Username already taken"}, status_code=400)
    
    hashed_pw = bcrypt.hashpw(auth.password.encode('utf-8'), bcrypt.gensalt())
    
    users[auth.username] = {
        "password": hashed_pw,
        "content": "Today I will do my chores and homework!",
        "last_submit": 0.0
    }
    
    last_registration_ts = now
    return JSONResponse({"status": "User created successfully"})

@app.post("/api/login", response_class=JSONResponse)
async def login(auth: UserAuth):
    user = users.get(auth.username)
    if not user:
        return JSONResponse({"error": "Invalid credentials"}, status_code=401)
    
    if not bcrypt.checkpw(auth.password.encode('utf-8'), user["password"]):
        return JSONResponse({"error": "Invalid credentials"}, status_code=401)
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": auth.username}, expires_delta=access_token_expires
    )
    return JSONResponse({"access_token": access_token, "token_type": "bearer"})

@app.get("/api/task", response_class=JSONResponse)
async def get_task(username: str = Depends(get_current_user)):
    user = users[username]
    return JSONResponse({"rendered": user["content"]})

@app.post("/api/task", response_class=JSONResponse)
async def set_task(request: Request, username: str = Depends(get_current_user)):
    user = users[username]
    now = time.time()
    
    # Per-user rate limit
    if now - user["last_submit"] < TASK_LIMIT_SECONDS:
        return PlainTextResponse("Too many submissions. Wait a few seconds.\n", status_code=429)

    # WAF has already sanitized the content
    content = ""
    try:
        data = await request.json()
        content = data.get("content", "")
    except Exception:
        pass
        
    user["content"] = content
    user["last_submit"] = now
    return JSONResponse({"status": "ok", "rendered": content})

@app.get("/", response_class=HTMLResponse)
async def read_root():
    return """
<html>
  <head>
    <title>Task Board</title>
    <style>
      :root {
        --bg: #050a0a;
        --panel: #0a1414;
        --border: #1a3030;
        --text: #e0f0e0;
        --muted: #6b9b7b;
        --accent: #00ff88;
        --accent-2: #00cc6f;
        --accent-dark: #009955;
        --danger: #ff4444;
      }
      * { box-sizing: border-box; margin: 0; padding: 0; }
      body { 
        font-family: "Consolas", "Monaco", "Courier New", monospace; 
        background: radial-gradient(ellipse at top, #0a1a1a 0%, #050a0a 100%);
        background-attachment: fixed;
        color: var(--text); 
        margin: 0; 
        padding: 0; 
        min-height: 100vh;
        display: flex;
        align-items: center;
        justify-content: center;
        position: relative;
        overflow-x: hidden;
      }
      body::before {
        content: '';
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background-image: 
          repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0, 255, 136, 0.02) 2px, rgba(0, 255, 136, 0.02) 4px),
          repeating-linear-gradient(90deg, transparent, transparent 2px, rgba(0, 255, 136, 0.02) 2px, rgba(0, 255, 136, 0.02) 4px);
        pointer-events: none;
        z-index: 0;
      }
      body::after {
        content: '';
        position: fixed;
        top: -50%;
        left: -50%;
        width: 200%;
        height: 200%;
        background: radial-gradient(circle, rgba(0, 255, 136, 0.03) 1px, transparent 1px);
        background-size: 50px 50px;
        animation: drift 60s linear infinite;
        pointer-events: none;
        z-index: 0;
      }
      @keyframes drift {
        0% { transform: translate(0, 0); }
        100% { transform: translate(50px, 50px); }
      }
      .container {
        width: 100%;
        max-width: 1400px;
        padding: 40px;
        z-index: 1;
      }
      .box { 
        width: 100%;
        margin: 0 auto 30px; 
        padding: 0;
        border: 2px solid var(--border); 
        background: var(--panel);
        border-radius: 0;
        box-shadow: 
          0 0 0 1px rgba(0, 255, 136, 0.1),
          0 20px 60px rgba(0, 0, 0, 0.8),
          0 0 40px rgba(0, 255, 136, 0.05),
          inset 0 1px 0 rgba(0, 255, 136, 0.1);
        position: relative;
        overflow: hidden;
        animation: fadeIn 0.4s ease-out;
      }
      @keyframes fadeIn {
        from { opacity: 0; transform: translateY(20px); }
        to { opacity: 1; transform: translateY(0); }
      }
      .box::before {
        content: '';
        position: absolute;
        top: 0;
        left: 0;
        width: 100%;
        height: 4px;
        background: linear-gradient(90deg, transparent, var(--accent), transparent);
        animation: scan 3s ease-in-out infinite;
      }
      @keyframes scan {
        0%, 100% { opacity: 0.3; }
        50% { opacity: 1; }
      }
      .box::after {
        content: '';
        position: absolute;
        top: 4px;
        right: 0;
        bottom: 0;
        left: 0;
        border: 1px solid rgba(0, 255, 136, 0.05);
        pointer-events: none;
      }
      .box > * {
        padding: 0 36px;
      }
      h1, h2 { 
        margin: 0 0 20px; 
        letter-spacing: 2px; 
        text-transform: uppercase;
        font-weight: 700;
        font-size: 16px;
        padding-top: 32px;
        color: var(--accent);
        text-shadow: 0 0 20px rgba(0, 255, 136, 0.5);
      }
      h1 { 
        font-size: 22px; 
        letter-spacing: 3px;
      }
      input, textarea { 
        width: 100%; 
        box-sizing: border-box; 
        background: #050c0c; 
        color: var(--text); 
        border: 2px solid var(--border); 
        border-radius: 0;
        padding: 16px 18px; 
        font-family: "Consolas", "Monaco", "Courier New", monospace; 
        font-size: 14px; 
        margin-bottom: 16px;
        transition: all 0.2s;
      }
      input:focus, textarea:focus { 
        outline: none; 
        border-color: var(--accent);
        background: #060d0d;
        box-shadow: 0 0 0 4px rgba(0, 255, 136, 0.1), 0 0 20px rgba(0, 255, 136, 0.2);
      }
      button { 
        padding: 14px 32px; 
        border: 2px solid var(--accent); 
        background: var(--accent);
        color: #000; 
        border-radius: 0;
        cursor: pointer; 
        font-weight: 700; 
        letter-spacing: 2px;
        text-transform: uppercase;
        font-size: 13px;
        font-family: "Consolas", "Monaco", "Courier New", monospace;
        box-shadow: 0 0 20px rgba(0, 255, 136, 0.4), 0 4px 12px rgba(0, 0, 0, 0.6);
        transition: all 0.2s;
        position: relative;
        overflow: hidden;
      }
      button::before {
        content: '';
        position: absolute;
        top: 50%;
        left: 50%;
        width: 0;
        height: 0;
        background: rgba(255, 255, 255, 0.2);
        border-radius: 50%;
        transform: translate(-50%, -50%);
        transition: width 0.3s, height 0.3s;
      }
      button:hover::before {
        width: 300px;
        height: 300px;
      }
      button:hover {
        background: var(--accent-2);
        border-color: var(--accent-2);
        transform: translateY(-2px);
        box-shadow: 0 0 30px rgba(0, 255, 136, 0.6), 0 6px 20px rgba(0, 0, 0, 0.8);
      }
      button:active {
        transform: translateY(0);
      }
      button.secondary { 
        background: transparent; 
        border: 2px solid var(--border); 
        color: var(--accent); 
        box-shadow: none;
      }
      button.secondary:hover {
        border-color: var(--accent);
        background: rgba(0, 255, 136, 0.05);
        transform: translateY(-1px);
        box-shadow: 0 0 20px rgba(0, 255, 136, 0.2);
      }
      .task { 
        margin-top: 20px; 
        padding: 24px; 
        border: 2px solid var(--border); 
        border-radius: 0;
        background: #050c0c;
        white-space: pre-wrap; 
        line-height: 1.8;
        font-size: 14px;
        box-shadow: inset 0 2px 10px rgba(0, 0, 0, 0.5), inset 0 0 40px rgba(0, 255, 136, 0.02);
        color: var(--text);
      }
      .status { 
        margin-top: 18px; 
        margin-bottom: 24px;
        color: var(--muted); 
        font-size: 12px; 
        display: flex; 
        align-items: center; 
        gap: 12px;
        text-transform: uppercase;
        letter-spacing: 1px;
      }
      .error { color: var(--danger); }
      .spinner { 
        width: 16px; 
        height: 16px; 
        border: 2px solid var(--accent); 
        border-top-color: transparent; 
        border-radius: 50%; 
        animation: spin 0.6s linear infinite;
      }
      @keyframes spin { to { transform: rotate(360deg); } }
      .pill { 
        display: inline-flex; 
        align-items: center; 
        gap: 8px; 
        padding: 10px 16px; 
        border-radius: 0;
        border: 1px solid var(--border); 
        background: #050c0c;
        color: var(--accent); 
        font-size: 11px; 
        margin-right: 10px; 
        margin-bottom: 10px;
        text-transform: uppercase;
        letter-spacing: 1px;
        font-weight: 600;
        box-shadow: inset 0 1px 3px rgba(0, 0, 0, 0.3), 0 0 10px rgba(0, 255, 136, 0.1);
        transition: all 0.2s;
        cursor: pointer;
        user-select: none;
      }
      .pill:hover {
        border-color: var(--accent);
        box-shadow: inset 0 1px 3px rgba(0, 0, 0, 0.3), 0 0 15px rgba(0, 255, 136, 0.3);
        transform: translateY(-2px);
      }
      .pill:active {
        transform: translateY(0);
        box-shadow: inset 0 1px 3px rgba(0, 0, 0, 0.3), 0 0 20px rgba(0, 255, 136, 0.5);
      }
      .hidden { display: none; }
      .auth-toggle { 
        margin-top: 20px; 
        margin-bottom: 32px;
        font-size: 13px; 
        cursor: pointer; 
        color: var(--accent); 
        text-decoration: none;
        text-transform: uppercase;
        letter-spacing: 1px;
        font-weight: 600;
        display: inline-block;
        transition: all 0.2s;
      }
      .auth-toggle:hover {
        color: var(--accent-2);
        text-shadow: 0 0 10px rgba(0, 255, 136, 0.5);
        transform: translateX(4px);
      }
      #authSection > *, #appSection > * {
        padding-left: 36px;
        padding-right: 36px;
      }
      #authSection h1, #appSection h1 {
        padding-top: 32px;
      }
      form { padding-bottom: 32px; }
    </style>
  </head>
  <body>
    <div class="container">
    <div id="authSection" class="box">
      <h1>Welcome</h1>
      <div id="loginForm">
        <h2>Login</h2>
        <input type="text" id="loginUser" placeholder="Username" />
        <input type="password" id="loginPass" placeholder="Password" />
        <button onclick="doLogin()">Login</button>
        <div class="auth-toggle" onclick="toggleAuth()">Need an account? Register</div>
      </div>
      <div id="registerForm" class="hidden">
        <h2>Register</h2>
        <input type="text" id="regUser" placeholder="Username" />
        <input type="password" id="regPass" placeholder="Password" />
        <button onclick="doRegister()">Register</button>
        <div class="auth-toggle" onclick="toggleAuth()">Have an account? Login</div>
      </div>
      <div id="authStatus" class="status"></div>
    </div>

    <div id="appSection" class="box hidden">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
        <h1>Task Board</h1>
        <button class="secondary" onclick="doLogout()" style="padding:6px 12px; font-size:12px;">Logout</button>
      </div>
      
      <div style="margin-bottom:12px; display:flex; flex-wrap:wrap;">
        <div class="pill" onclick="insertPlaceholder('{{date}}')">{{date}} UTC date</div>
        <div class="pill" onclick="insertPlaceholder('{{time}}')">{{time}} UTC time</div>
        <div class="pill" onclick="insertPlaceholder('{{now}}')">{{now}} UTC ISO</div>
        <div class="pill" onclick="insertPlaceholder('{{timestamp}}')">{{timestamp}} Timestamp</div>
        <div class="pill" onclick="insertPlaceholder('{{uuid}}')">{{uuid}} UUID</div>
        <div class="pill" onclick="insertPlaceholder('{{random_int}}')">{{random_int}} Random 1-1000</div>
      </div>

      <form id="taskForm">
        <textarea id="taskInput" rows="5"></textarea><br/>
        <button type="submit">Save</button>
      </form>
      <div id="appStatus" class="status"><span class="spinner"></span><span>Getting task...</span></div>
      <h2>Current Task:</h2>
      <div id="taskRendered" class="task"></div>
    </div>
    </div>

    <script>
      let token = localStorage.getItem('token');
      const authSection = document.getElementById('authSection');
      const appSection = document.getElementById('appSection');
      const authStatus = document.getElementById('authStatus');
      const appStatus = document.getElementById('appStatus');

      function insertPlaceholder(placeholder) {
        const textarea = document.getElementById('taskInput');
        const start = textarea.selectionStart;
        const end = textarea.selectionEnd;
        const text = textarea.value;
        const before = text.substring(0, start);
        const after = text.substring(end, text.length);
        textarea.value = before + placeholder + after;
        textarea.selectionStart = textarea.selectionEnd = start + placeholder.length;
        textarea.focus();
      }

      function showApp() {
        authSection.classList.add('hidden');
        appSection.classList.remove('hidden');
        loadTask();
      }

      function showAuth() {
        authSection.classList.remove('hidden');
        appSection.classList.add('hidden');
        authStatus.innerText = '';
      }

      if (token) {
        showApp();
      } else {
        showAuth();
      }

      function toggleAuth() {
        document.getElementById('loginForm').classList.toggle('hidden');
        document.getElementById('registerForm').classList.toggle('hidden');
        document.getElementById('loginPass').value = '';
        document.getElementById('regPass').value = '';
        authStatus.innerText = '';
      }

      async function doLogin() {
        const u = document.getElementById('loginUser').value;
        const p = document.getElementById('loginPass').value;
        authStatus.innerText = 'Logging in...';
        
        try {
          const res = await fetch('/api/login', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({username: u, password: p})
          });
          const data = await res.json();
          if (res.ok) {
            token = data.access_token;
            localStorage.setItem('token', token);
            authStatus.innerText = '';
            showApp();
          } else {
            authStatus.innerText = 'Error: ' + (data.error || 'Login failed');
          }
        } catch (e) {
          authStatus.innerText = 'Error: ' + e.message;
        }
      }

      async function doRegister() {
        const u = document.getElementById('regUser').value;
        const p = document.getElementById('regPass').value;
        authStatus.innerText = 'Registering...';
        
        try {
          const res = await fetch('/api/register', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({username: u, password: p})
          });
          const data = await res.json();
          if (res.ok) {
            authStatus.innerText = 'Registered! Please login.';
            toggleAuth();
            document.getElementById('loginUser').value = u;
            document.getElementById('loginPass').value = '';
          } else {
            authStatus.innerText = 'Error: ' + (data.error || 'Registration failed');
          }
        } catch (e) {
          authStatus.innerText = 'Error: ' + e.message;
        }
      }

      function doLogout() {
        token = null;
        localStorage.removeItem('token');
        showAuth();
        document.getElementById('taskRendered').innerText = '';
        document.getElementById('taskInput').value = '';
      }

      function setAppStatus(text, loading=false) {
        const spinner = '<span class="spinner"></span>';
        appStatus.innerHTML = (loading ? spinner : '') + '<span>' + text + '</span>';
      }

      async function loadTask() {
        setAppStatus('Getting task...', true);
        try {
          const res = await fetch('/api/task', {
            headers: {'Authorization': 'Bearer ' + token}
          });
          if (res.status === 401) {
            doLogout();
            return;
          }
          if (!res.ok) {
            const txt = await res.text();
            setAppStatus('Error loading task: ' + txt);
            return;
          }
          const data = await res.json();
          document.getElementById('taskRendered').innerText = data.rendered;
          setAppStatus('Loaded.');
        } catch (e) {
          setAppStatus('Error loading task.');
        }
      }

      document.getElementById('taskForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const content = document.getElementById('taskInput').value;
        setAppStatus('Saving...', true);
        
        try {
          const res = await fetch('/api/task', {
            method: 'POST',
            headers: {
              'Content-Type':'application/json',
              'Authorization': 'Bearer ' + token
            },
            body: JSON.stringify({content})
          });
          
          if (res.status === 401) {
            doLogout();
            return;
          }
          
          if (res.ok) {
            await loadTask();
          } else {
            const txt = await res.text();
            setAppStatus('Error: ' + txt);
          }
        } catch (e) {
          setAppStatus('Error: ' + e.message);
        }
      });
    </script>
  </body>
</html>
"""

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
