import os
import subprocess
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

os.environ.setdefault("JOBBOARD_SECRET_KEY", "dev-secret-key-12345678901234567890")
os.environ.setdefault("JOBBOARD_ADMIN_PHONE", "0810000000")
os.environ.setdefault("JOBBOARD_ADMIN_PASSWORD", "AdminPass12345")

print("Running Auto Job Engine...")
subprocess.run([sys.executable, "auto_job_engine.py", "--demo"], cwd=BASE_DIR)
print("Done.")
