# Workout Tracker

A simple Streamlit app to log and track your workouts, with editable exercise templates.

## Features
- Log daily workouts with sets, reps, weight, RPE, and notes
- View history in a table
- Manage exercise templates (add new exercises or day types)

## How to Run
1. Clone this repo or unzip files
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the app:
   ```bash
   streamlit run app.py
   ```

Workout logs are stored in a local SQLite database `workout.db` (automatically created).
If an older `workout_log.csv` file exists, it's migrated into the database on first run.
Exercise templates (day types + exercises) are stored in the same SQLite DB (`exercises` table). A legacy `workout_templates.json` file (if present) is migrated automatically on first run.