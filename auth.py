import os
import sqlite3
import hashlib
import secrets
import logging
from datetime import datetime
import streamlit as st
from config import DB_FILE

logger = logging.getLogger(__name__)

def hash_password(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100_000).hex()


def create_user(username: str, password: str):
    if not username or not password:
        return False, "Username & password required"
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    try:
        salt = secrets.token_hex(16)
        ph = hash_password(password, salt)
        c.execute(
            "INSERT INTO users(username, password_hash, salt, created_at, provider, external_id) VALUES (?,?,?,?,?,?)",
            (username.strip(), ph, salt, datetime.utcnow().isoformat(), 'local', None),
        )
        conn.commit()
        conn.close()
        logger.info("User created username=%s", username)
        return True, "User created"
    except sqlite3.IntegrityError:
        conn.close()
        return False, "Username already exists"
    except Exception as e:
        conn.close()
        logger.error("Create user failed: %s", e)
        return False, str(e)


def authenticate(username: str, password: str):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT id, password_hash, salt FROM users WHERE username = ? AND provider='local'", (username.strip(),))
    row = c.fetchone()
    conn.close()
    if not row:
        logger.warning("Login failed (no user) username=%s", username)
        return False, None, "Invalid credentials"
    user_id, pw_hash, salt = row
    if hash_password(password, salt) == pw_hash:
        logger.info("Login success username=%s", username)
        return True, user_id, "Login successful"
    logger.warning("Login failed (bad password) username=%s", username)
    return False, None, "Invalid credentials"


def ensure_session_state():
    for k, v in {"user_id": None, "username": None}.items():
        st.session_state.setdefault(k, v)


def render_local_auth(create_user_fn, authenticate_fn):
    if not st.session_state.get("user_id"):
        auth_tab, register_tab = st.tabs(["Login", "Register"])
        with auth_tab:
            st.subheader("Login")
            login_user = st.text_input("Username", key="login_user")
            login_pass = st.text_input("Password", type="password", key="login_pass")
            if st.button("Login"):
                ok, uid, msg = authenticate_fn(login_user, login_pass)
                if ok:
                    st.session_state.user_id = uid
                    st.session_state.username = login_user
                    st.rerun()
                else:
                    st.error(msg)
        with register_tab:
            st.subheader("Register")
            reg_user = st.text_input("New Username", key="reg_user")
            reg_pass = st.text_input("New Password", type="password", key="reg_pass")
            if st.button("Create Account"):
                ok, msg = create_user_fn(reg_user, reg_pass)
                if ok:
                    st.success("Account created. Please log in.")
                else:
                    st.error(msg)
        st.stop()


def render_google_oauth():
    # Imported from original app (simplified logging lines)
    from config import AUTH_PROVIDER
    if AUTH_PROVIDER != 'google_oauth':
        return
    import streamlit as st  # local import ensures Streamlit context
    import os
    CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
    CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
    REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI")
    if not (CLIENT_ID and CLIENT_SECRET and REDIRECT_URI):
        st.warning("Google OAuth not configured. Set GOOGLE_CLIENT_ID / SECRET / REDIRECT_URI.")
        st.stop(); return
    try:
        from authlib.integrations.requests_client import OAuth2Session
    except ImportError:
        st.error("Install 'authlib' to use Google OAuth (pip install authlib)")
        st.stop(); return
    try:
        from google.oauth2 import id_token as _google_id_token  # type: ignore
        from google.auth.transport import requests as _google_requests  # type: ignore
        verify_available = True
    except Exception:
        verify_available = False
    if st.session_state.get("user_id"):
        return
    params = st.query_params
    code = params.get("code")
    scope = "openid email profile"
    oauth = OAuth2Session(CLIENT_ID, CLIENT_SECRET, scope=scope, redirect_uri=REDIRECT_URI)
    if not code:
        auth_url, _ = oauth.create_authorization_url("https://accounts.google.com/o/oauth2/v2/auth", prompt="select_account")
        st.markdown(f"[🔐 Sign in with Google]({auth_url})")
        st.stop(); return
    try:
        token = oauth.fetch_token("https://oauth2.googleapis.com/token", code=code, grant_type="authorization_code")
    except Exception as e:
        st.error(f"OAuth error: {e}")
        st.stop(); return
    id_tok = token.get("id_token")
    if not id_tok:
        st.error("No id_token returned.")
        st.stop(); return
    email = None; sub = None
    if verify_available:
        try:
            req = _google_requests.Request()
            claims = _google_id_token.verify_oauth2_token(id_tok, req, CLIENT_ID)
            email = claims.get("email"); sub = claims.get("sub")
        except Exception as e:
            st.error(f"ID token verification failed: {e}")
            st.stop(); return
    else:
        import base64, json as _json
        try:
            payload_part = id_tok.split(".")[1]
            padded = payload_part + "=" * (-len(payload_part) % 4)
            claims = _json.loads(base64.urlsafe_b64decode(padded.encode()).decode())
            email = claims.get("email"); sub = claims.get("sub")
        except Exception:
            st.error("Failed to parse ID token.")
            st.stop(); return
    if not (email and sub):
        st.error("Required claims missing (email/sub).")
        st.stop(); return
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE provider=? AND external_id=?", ("google", sub))
    row = c.fetchone()
    if row:
        uid = row[0]
    else:
        salt = secrets.token_hex(16)
        ph = hashlib.pbkdf2_hmac('sha256', secrets.token_hex(12).encode(), salt.encode(), 100_000).hex()
        c.execute("INSERT INTO users(username, password_hash, salt, created_at, provider, external_id) VALUES (?,?,?,?,?,?)", (email, ph, salt, datetime.utcnow().isoformat(), 'google', sub))
        conn.commit(); uid = c.lastrowid
    conn.close()
    st.session_state.user_id = uid
    st.session_state.username = email
    logger.info("Google OAuth login success email=%s", email)
    st.query_params.clear(); st.rerun()
