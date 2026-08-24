"""Shared pytest setup.

Point the API at an isolated temp SQLite file and raise the scan rate limit
*before* anything imports the api package — get_settings() and the rate-limit
decorator both read these at import time.
"""
import os
import tempfile

_TEST_DB = os.path.join(tempfile.gettempdir(), "vantis_test.db")
os.environ.setdefault("VANTIS_DATABASE_URL", f"sqlite:///{_TEST_DB}")
os.environ.setdefault("VANTIS_SCAN_RATE_LIMIT", "1000/hour")

# Start each session from a clean database file.
if os.path.exists(_TEST_DB):
    try:
        os.remove(_TEST_DB)
    except OSError:
        pass
