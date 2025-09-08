import os
from dotenv import load_dotenv

load_dotenv()

LOG_FILE = "workout_log.csv"  # legacy CSV
DB_FILE = "workout.db"
TEMPLATE_FILE = "workout_templates.json"
APP_LOG_PATH = os.getenv("APP_LOG_PATH", "app.log")
AUTH_PROVIDER = os.getenv("AUTH_PROVIDER", "local").lower()  # 'local' | 'google_oauth'
