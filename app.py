import streamlit as st
import pandas as pd
from datetime import date
import os
from logging_config import setup_logging
from config import AUTH_PROVIDER, DB_FILE, TEMPLATE_FILE, APP_LOG_PATH
from db_storage import (
    init_db, migrate_csv_to_db, migrate_templates_json_to_db,
    load_log as load_log_db, add_workout as add_workout_db,
    add_exercise as add_exercise_db, get_day_types, get_exercises
)
from auth import (
    ensure_session_state, render_local_auth, render_google_oauth,
    create_user, authenticate
)
import logging
import sqlite3
import json

logger = setup_logging()

#############################################
# Template (day/exercise) storage now in DB #
#############################################

## Database initialization & migrations


# Initialize database and migrate if needed
db_existed_before = os.path.exists(DB_FILE)
init_db()
if not db_existed_before:
    migrate_csv_to_db()
    migrate_templates_json_to_db()
else:
    try:
        import sqlite3
        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM exercises")
        count = cur.fetchone()[0]
        conn.close()
        if count == 0 and os.path.exists(TEMPLATE_FILE):
            migrate_templates_json_to_db()
    except Exception as e:
        logger.warning("Template fallback migration check failed: %s", e)

def load_log():
    return load_log_db(st.session_state.get("user_id"))


def add_workout(row: dict):
    add_workout_db(row, st.session_state.get("user_id", 1))


## Wrappers now imported directly; keep names for compatibility

# ----------------- Authentication Helpers -----------------
ensure_session_state()


def add_exercise(day_type: str, exercise: str):
    return add_exercise_db(day_type, exercise)

st.title("🏋️ Workout Tracker")

#############################################
# AUTH PROVIDER SELECTION                    #
#############################################

from auth import render_local_auth as _local_renderer
from auth import render_google_oauth as _google_renderer

AUTH_RENDERERS = {'local': lambda: _local_renderer(create_user, authenticate), 'google_oauth': _google_renderer}
AUTH_RENDERERS.get(AUTH_PROVIDER, AUTH_RENDERERS['local'])()

# Logged-in banner and logout
st.caption(f"Logged in as {st.session_state.username}")
if st.button("Logout"):
    st.session_state.user_id = None
    st.session_state.username = None
    st.rerun()

tab1, tab2, tab3, tab4 = st.tabs(["Log Workout", "View History", "Manage Templates", "Logs"])

with tab1:
    st.header("Log a Workout")
    log_date = st.date_input("Date", value=date.today())
    available_days = get_day_types()
    if not available_days:
        st.info("No day types found. Add some in 'Manage Templates' tab.")
        day_type = st.text_input("Day (manual entry)")
        exercise_list = []
    else:
        day_type = st.selectbox("Select Day", available_days)
        exercise_list = get_exercises(day_type) if day_type else []
    exercise = st.selectbox("Exercise", exercise_list) if exercise_list else st.text_input("Exercise (manual entry)")
    sets = st.number_input("Sets", min_value=1, max_value=10, value=3)
    reps = st.number_input("Reps", min_value=1, max_value=30, value=10)
    weight = st.number_input("Weight (kg)", min_value=0, max_value=500, value=0)
    rpe = st.slider("RPE", 1, 10, 7)
    notes = st.text_area("Notes")
    if st.button("Add Workout"):
        if not day_type or not exercise:
            st.error("Day and Exercise are required.")
        else:
            new_row = {
                "Date": log_date.isoformat(),
                "Day": day_type,
                "Exercise": exercise,
                "Sets": sets,
                "Reps": reps,
                "Weight": weight,
                "RPE": rpe,
                "Notes": notes,
            }
            add_workout(new_row)
            st.success("Workout added!")
            logger.info("Workout logged date=%s day=%s ex=%s", new_row['Date'], new_row['Day'], new_row['Exercise'])

with tab2:
    st.header("Workout History")
    df = load_log()
    if df.empty:
        st.write("No workouts logged yet.")
    else:
        # Optional raw table toggle
        show_raw = st.checkbox("Show raw table", value=False)
        # Compute a per-row volume metric (not stored in DB)
        # Ensure numeric types (coerce errors to NaN then fill 0)
        for col in ["Sets","Reps","Weight","RPE"]:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)
        df["Volume"] = df.get("Sets", 0) * df.get("Reps", 0) * df.get("Weight", 0)
        # Recreate with sorted unique dates (newest first)
        dates_ordered = sorted(df['Date'].unique(), reverse=True)
        for d in dates_ordered:
            g = df[df['Date'] == d].copy()
            day_labels = ", ".join(sorted(set(g['Day'].dropna())))
            total_sets = int(g['Sets'].sum()) if 'Sets' in g else 0
            total_reps = int((g['Sets'] * g['Reps']).sum()) if set(['Sets','Reps']).issubset(g.columns) else 0
            total_volume = int(g['Volume'].sum()) if 'Volume' in g else 0
            header = f"{d}  | Days: {day_labels} | Sets: {total_sets} | Est.Reps: {total_reps} | Volume: {total_volume}"
            with st.expander(header, expanded=False):
                display_cols = [c for c in ["Day","Exercise","Sets","Reps","Weight","RPE","Volume","Notes"] if c in g.columns]
                st.dataframe(g[display_cols].reset_index(drop=True))
        if show_raw:
            st.subheader("Raw Table")
            st.dataframe(df)

with tab3:
    st.header("Manage Templates")
    st.write("Add or update exercises per day type (stored in database).")
    col1, col2 = st.columns(2)
    with col1:
        day_type_input = st.text_input("Day Type (e.g., Push, Pull, Legs)")
    with col2:
        exercise_input = st.text_input("Exercise Name")
    if st.button("Add Exercise to Day"):
        ok, msg = add_exercise(day_type_input, exercise_input)
        if ok:
            st.success(msg)
            logger.info("Template exercise added day=%s ex=%s", day_type_input, exercise_input)
        else:
            st.warning(msg)

    # Manual import option if legacy JSON still present
    if os.path.exists(TEMPLATE_FILE):
        if st.button("Import legacy JSON templates"):
            migrate_templates_json_to_db()

    st.subheader("Current Templates")
    day_types = get_day_types()
    if not day_types:
        st.caption("No templates yet.")
    else:
        for dt in day_types:
            exs = get_exercises(dt)
            st.markdown(f"**{dt}**: {', '.join(exs) if exs else '—'}")

with tab4:
    st.header("Application Logs")
    if os.path.exists(APP_LOG_PATH):
        with open(APP_LOG_PATH, 'r') as f:
            # Tail last 400 lines
            from collections import deque
            lines = deque(f, maxlen=400)
        st.text("".join(lines))
        if st.button("Refresh Logs"):
            st.rerun()
    else:
        st.info("Log file not found yet.")