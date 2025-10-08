#!/usr/bin/env python3
"""
CyberThreatWatch Local Agent Installer

Cross-platform lightweight agent that reads local system logs
and pushes them securely to Supabase in near real time.

✅ Features
- Linux/macOS (journalctl/tail)
- Windows (wevtutil / win32evtlog)
- Supabase insert-only mode with anon key + RLS
- Persistent dedupe cache
- Priority detection (keywords → severity=critical)
- PID + status files for control via dashboard
- Optional --test mode for connectivity verification

Usage:
    python agent_installer.py --interval 30 --batch 20
    python agent_installer.py --detach --interval 60
    python agent_installer.py --test
"""

import os
import sys
import time
import json
import argparse
import logging
import platform
import subprocess
import threading
from datetime import datetime, timezone
from typing import List, Dict, Set, Optional

# === Try to import Supabase client ===
try:
    from supabase import create_client
except Exception:
    create_client = None

# === Try to import Windows event log reader ===
try:
    import win32evtlog  # type: ignore
    import win32evtlogutil  # type: ignore
    WIN32EVT_AVAILABLE = True
except Exception:
    WIN32EVT_AVAILABLE = False


# === Defaults ===
DEFAULT_INTERVAL = 60
DEFAULT_BATCH_SIZE = 50
HOME = os.path.expanduser("~")
LOCAL_LOGFILE = os.path.join(HOME, ".cyberthreatwatch_agent.log")
SENT_CACHE_FILE = os.path.join(HOME, ".ctw_sent_cache.json")
PID_FILE = os.path.join(HOME, ".ctw_agent.pid")
STATUS_FILE = os.path.join(HOME, ".ctw_agent.status.json")
PRIORITY_KEYWORDS = ["attack", "unauthorized", "denied", "failed login", "ransomware", "malware", "critical", "panic"]

# === Logging configuration ===
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler(LOCAL_LOGFILE), logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("ctw-agent")


# === Utility: persistent sent cache (dedupe) ===
def load_sent_cache() -> Set[str]:
    try:
        if os.path.exists(SENT_CACHE_FILE):
            with open(SENT_CACHE_FILE, "r") as f:
                data = json.load(f)
                return set(data.get("sent", []))
    except Exception as e:
        logger.warning(f"Could not load sent cache: {e}")
    return set()


def save_sent_cache(sent: Set[str]):
    try:
        to_save = list(sent)[-2000:]
        with open(SENT_CACHE_FILE, "w") as f:
            json.dump({"sent": to_save}, f)
    except Exception as e:
        logger.warning(f"Could not save sent cache: {e}")


# === Supabase client helper ===
def supabase_client_from_env() -> Optional[object]:
    """
    Creates a Supabase client using restricted anon key.
    Only supports insert operations (enforced by RLS).
    """
    url = os.environ.get("SUPABASE_URL")
    key = os.environ.get("SUPABASE_KEY")

    if not url or not key:
        logger.error("Missing SUPABASE_URL or SUPABASE_KEY in environment variables.")
        return None

    if create_client is None:
        logger.error("Supabase client library not installed. Run: pip install supabase")
        return None

    try:
        client = create_client(url, key)
        if not url.startswith("https://") or ".supabase.co" not in url:
            logger.warning("Supabase URL may be invalid. Expected format: https://<project>.supabase.co")
        logger.info("Supabase client initialized (insert-only mode with anon key).")
        return client
    except Exception as e:
        logger.error(f"Failed to create Supabase client: {e}")
        return None


# === System Log Readers ===
def shutil_which(name: str) -> Optional[str]:
    try:
        import shutil
        return shutil.which(name)
    except Exception:
        return None


class UnixTailer:
    """Tails system logs (Linux/macOS)."""
    def __init__(self):
        self.proc = None
        self.buffer = []
        self._stop = threading.Event()
        self.lock = threading.Lock()

    def start(self):
        if shutil_which("journalctl"):
            cmd = ["journalctl", "-f", "-o", "short"]
        else:
            candidates = ["/var/log/syslog", "/var/log/system.log", "/var/log/messages"]
            logfile = next((p for p in candidates if os.path.exists(p)), None)
            cmd = ["tail", "-F", logfile] if logfile else None
        if not cmd:
            logger.warning("No valid system log source found.")
            return
        try:
            self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            threading.Thread(target=self._reader, daemon=True).start()
            logger.info(f"UnixTailer started with {' '.join(cmd)}")
        except Exception as e:
            logger.error(f"UnixTailer error: {e}")

    def _reader(self):
        if not self.proc or not self.proc.stdout:
            return
        for line in self.proc.stdout:
            if self._stop.is_set():
                break
            if line.strip():
                with self.lock:
                    self.buffer.append(line.strip())

    def read_now(self):
        with self.lock:
            out = list(self.buffer)
            self.buffer.clear()
        return out

    def stop(self):
        self._stop.set()
        if self.proc:
            try:
                self.proc.terminate()
            except Exception:
                pass


class WindowsPoller:
    """Polls Windows Event Log periodically."""
    def __init__(self):
        self.buffer = []
        self.lock = threading.Lock()
        self._stop = threading.Event()

    def start(self):
        threading.Thread(target=self._poll_loop, daemon=True).start()
        logger.info("WindowsPoller started")

    def _poll_loop(self):
        while not self._stop.is_set():
            try:
                lines = self._read_latest()
                if lines:
                    with self.lock:
                        self.buffer.extend(lines)
            except Exception as e:
                logger.debug(f"Poll error: {e}")
            time.sleep(2)

    def _read_latest(self):
        if WIN32EVT_AVAILABLE:
            return self._read_win32()
        return self._read_wevtutil()

    def _read_win32(self):
        out = []
        try:
            h = win32evtlog.OpenEventLog(None, "System")
            events = win32evtlog.ReadEventLog(h, win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ, 0)
            for ev in events[-50:]:
                msg = str(ev)
                out.append(msg)
            win32evtlog.CloseEventLog(h)
        except Exception:
            pass
        return out

    def _read_wevtutil(self):
        cmd = ["wevtutil", "qe", "System", "/c:50", "/f:text"]
        try:
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=5)
            return [l.strip() for l in proc.stdout.splitlines() if l.strip()]
        except Exception:
            return []

    def read_now(self):
        with self.lock:
            out = list(self.buffer)
            self.buffer.clear()
        return out

    def stop(self):
        self._stop.set()


# === Core Agent ===
class CTWAgent:
    def __init__(self, interval=DEFAULT_INTERVAL, batch_size=DEFAULT_BATCH_SIZE, keywords=None):
        self.interval = interval
        self.batch_size = batch_size
        self.keywords = keywords or PRIORITY_KEYWORDS
        self.sent_cache = load_sent_cache()
        self.client = supabase_client_from_env()
        self.running = False
        self.reader = WindowsPoller() if "windows" in platform.system().lower() else UnixTailer()
        self.queue = []
        self.queue_lock = threading.Lock()

    def start(self):
        if not self.client:
            logger.error("Supabase not configured.")
            return False
        self.reader.start()
        self.running = True
        threading.Thread(target=self._collector, daemon=True).start()
        threading.Thread(target=self._sender, daemon=True).start()
        self._status("running")
        logger.info("CTWAgent started.")
        return True

    def stop(self):
        self.running = False
        self.reader.stop()
        save_sent_cache(self.sent_cache)
        self._status("stopped")
        logger.info("CTWAgent stopped.")

    def _collector(self):
        while self.running:
            lines = self.reader.read_now()
            if lines:
                recs = self._lines_to_records(lines)
                with self.queue_lock:
                    self.queue.extend(recs)
            time.sleep(0.5)

    def _lines_to_records(self, lines):
        out = []
        for line in lines:
            key = line[:600]
            if key in self.sent_cache:
                continue
            severity = "critical" if any(k in line.lower() for k in self.keywords) else "info"
            rec = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source": platform.node(),
                "message": line,
                "severity": severity,
            }
            out.append({"rec": rec, "key": key})
        return out

    def _sender(self):
        while self.running:
            start = time.time()
            try:
                with self.queue_lock:
                    batch = [self.queue.pop(0) for _ in range(min(self.batch_size, len(self.queue)))]
                if batch:
                    recs = [b["rec"] for b in batch]
                    keys = [b["key"] for b in batch]
                    if self._send(recs):
                        for k in keys:
                            self.sent_cache.add(k)
                        save_sent_cache(self.sent_cache)
            except Exception as e:
                logger.debug(f"Send loop: {e}")
            time.sleep(max(1, self.interval - (time.time() - start)))

    def _send(self, recs):
        try:
            self.client.table("alerts").insert(recs).execute()
            logger.info(f"Inserted {len(recs)} log(s).")
            return True
        except Exception as e:
            logger.error(f"Insert error: {e}")
            return False

    def _status(self, state):
        try:
            with open(STATUS_FILE, "w") as f:
                json.dump({"state": state, "time": datetime.now().isoformat()}, f)
        except Exception:
            pass


# === CLI ===
def parse_args():
    p = argparse.ArgumentParser(description="CyberThreatWatch local agent")
    p.add_argument("--interval", type=int, default=DEFAULT_INTERVAL, help="Flush interval in seconds")
    p.add_argument("--batch", type=int, default=DEFAULT_BATCH_SIZE, help="Max batch size per upload")
    p.add_argument("--detach", action="store_true", help="Run as background process")
    p.add_argument("--test", action="store_true", help="Run connectivity & insert test")
    return p.parse_args()


def detach_run(args):
    python = sys.executable
    cmd = [python, os.path.abspath(__file__), "--interval", str(args.interval), "--batch", str(args.batch)]
    try:
        subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        logger.info("Detached agent started.")
    except Exception as e:
        logger.error(f"Detach failed: {e}")


def test_mode():
    logger.info("Running in test mode...")
    client = supabase_client_from_env()
    if not client:
        logger.error("Cannot initialize Supabase client.")
        return
    try:
        rec = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": platform.node(),
            "message": "🔍 Test event from CyberThreatWatch agent.",
            "severity": "info",
        }
        client.table("alerts").insert([rec]).execute()
        logger.info("✅ Test insert successful — check Supabase 'alerts' table.")
    except Exception as e:
        logger.error(f"Test insert failed: {e}")


def main():
    args = parse_args()

    if args.test:
        test_mode()
        return

    if args.detach:
        detach_run(args)
        return

    agent = CTWAgent(args.interval, args.batch)
    if agent.start():
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Stopping agent...")
        finally:
            agent.stop()


if __name__ == "__main__":
    main()
