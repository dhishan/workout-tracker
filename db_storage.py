import os
import sqlite3
import pandas as pd
import json
import secrets
import hashlib
from datetime import datetime
import logging
from config import DB_FILE, LOG_FILE, TEMPLATE_FILE

logger = logging.getLogger(__name__)


def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            created_at TEXT NOT NULL,
            provider TEXT NOT NULL DEFAULT 'local',
            external_id TEXT
        )
        """
    )
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS workouts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            Date TEXT,
            Day TEXT,
            Exercise TEXT,
            Sets INTEGER,
            Reps INTEGER,
            Weight REAL,
            RPE INTEGER,
            Notes TEXT
        )
        """
    )
    c.execute("PRAGMA table_info(workouts)")
    cols = [r[1] for r in c.fetchall()]
    if 'user_id' not in cols:
        c.execute("ALTER TABLE workouts ADD COLUMN user_id INTEGER REFERENCES users(id) DEFAULT 1")
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS exercises (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            day_type TEXT NOT NULL,
            exercise TEXT NOT NULL,
            UNIQUE(day_type, exercise)
        )
        """
    )
    c.execute("CREATE INDEX IF NOT EXISTS idx_exercises_day ON exercises(day_type)")
    conn.commit()
    c.execute("PRAGMA table_info(users)")
    ucols = [r[1] for r in c.fetchall()]
    if 'provider' not in ucols:
        c.execute("ALTER TABLE users ADD COLUMN provider TEXT NOT NULL DEFAULT 'local'")
    if 'external_id' not in ucols:
        c.execute("ALTER TABLE users ADD COLUMN external_id TEXT")
    c.execute("UPDATE users SET provider='local' WHERE provider IS NULL")
    c.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_provider_external ON users(provider, external_id)")
    c.execute("SELECT id FROM users WHERE id=1")
    if not c.fetchone():
        salt = secrets.token_hex(16)
        pwd = secrets.token_hex(8)
        ph = hashlib.pbkdf2_hmac('sha256', pwd.encode(), salt.encode(), 100_000).hex()
        c.execute("INSERT OR IGNORE INTO users(id, username, password_hash, salt, created_at, provider) VALUES (1,?,?,?,?,?)", ("default", ph, salt, datetime.utcnow().isoformat(), 'local'))
    conn.commit()
    conn.close()
    logger.info("Database initialized / migrated")


def migrate_csv_to_db():
    if not os.path.exists(LOG_FILE):
        return
    try:
        df = pd.read_csv(LOG_FILE)
        if df.empty:
            return
        conn = sqlite3.connect(DB_FILE)
        expected = ["Date","Day","Exercise","Sets","Reps","Weight","RPE","Notes"]
        df = df[[c for c in expected if c in df.columns]]
        df.to_sql("workouts", conn, if_exists="append", index=False)
        conn.close()
        logger.info("Migrated legacy CSV log -> SQLite (%s rows)", len(df))
    except Exception as e:
        logger.warning("CSV migration failed: %s", e)


def migrate_templates_json_to_db():
    if not os.path.exists(TEMPLATE_FILE):
        return
    try:
        with open(TEMPLATE_FILE) as f:
            data = json.load(f)
        default = data.get("Default", {}) if isinstance(data, dict) else {}
        if not default:
            return
        rows = []
        for day_type, exercises in default.items():
            for ex in exercises:
                rows.append((day_type, ex))
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.executemany("INSERT OR IGNORE INTO exercises(day_type, exercise) VALUES(?,?)", rows)
        conn.commit()
        conn.close()
        logger.info("Migrated templates JSON -> DB (%s rows)", len(rows))
    except Exception as e:
        logger.warning("Template migration failed: %s", e)


def load_log(user_id: int | None):
    conn = sqlite3.connect(DB_FILE)
    if user_id:
        df = pd.read_sql_query(
            "SELECT Date, Day, Exercise, Sets, Reps, Weight, RPE, Notes FROM workouts WHERE user_id = ? ORDER BY Date DESC, id DESC",
            conn,
            params=(user_id,),
        )
    else:
        df = pd.read_sql_query(
            "SELECT Date, Day, Exercise, Sets, Reps, Weight, RPE, Notes FROM workouts ORDER BY Date DESC, id DESC",
            conn,
        )
    conn.close()
    return df


def add_workout(row: dict, user_id: int):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute(
        "INSERT INTO workouts (Date, Day, Exercise, Sets, Reps, Weight, RPE, Notes, user_id) VALUES (?,?,?,?,?,?,?,?,?)",
        (
            row["Date"], row["Day"], row["Exercise"], int(row["Sets"]), int(row["Reps"]), float(row["Weight"]), int(row["RPE"]), row["Notes"], user_id
        ),
    )
    conn.commit()
    conn.close()
    logger.info("Workout added user=%s day=%s ex=%s", user_id, row.get("Day"), row.get("Exercise"))


def get_day_types():
    conn = sqlite3.connect(DB_FILE)
    df = pd.read_sql_query("SELECT DISTINCT day_type FROM exercises ORDER BY day_type", conn)
    conn.close()
    return df['day_type'].tolist()


def get_exercises(day_type: str):
    conn = sqlite3.connect(DB_FILE)
    df = pd.read_sql_query("SELECT exercise FROM exercises WHERE day_type = ? ORDER BY exercise", conn, params=(day_type,))
    conn.close()
    return df['exercise'].tolist()


def add_exercise(day_type: str, exercise: str):
    if not day_type or not exercise:
        return False, "Day type and exercise required"
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    try:
        c.execute("INSERT OR IGNORE INTO exercises(day_type, exercise) VALUES(?,?)", (day_type.strip(), exercise.strip()))
        conn.commit()
        inserted = c.rowcount > 0
        conn.close()
        if inserted:
            logger.info("Exercise added day=%s ex=%s", day_type, exercise)
            return True, "Exercise added"
        return False, "Duplicate entry ignored"
    except Exception as e:
        conn.close()
        logger.error("Add exercise failed: %s", e)
        return False, str(e)
