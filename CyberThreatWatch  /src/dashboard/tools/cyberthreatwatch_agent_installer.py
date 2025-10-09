#!/usr/bin/env python3
"""
cyberthreatwatch_agent_installer.py

Full CyberThreatWatch local agent (cross-platform) that tails/polls system logs
and posts batches to your Supabase Edge Function ingest endpoint.

Usage examples:
    # test run (single insert)
    CTW_EDGE_URL="https://.../ingest-logs" CTW_EDGE_SECRET="secret" python3 cyberthreatwatch_agent_installer.py --test

    # foreground run
    CTW_EDGE_URL="https://.../ingest-logs" CTW_EDGE_SECRET="secret" python3 cyberthreatwatch_agent_installer.py --interval 30

    # detach (best-effort)
    CTW_EDGE_URL="https://.../ingest-logs" CTW_EDGE_SECRET="secret" python3 cyberthreatwatch_agent_installer.py --detach --interval 60

Notes:
 - The agent authenticates to the edge function with header `x-ctw-secret`.
 - The ingest endpoint must verify that header server-side.
 - The script writes a small status/pid/cache into the user's home folder.
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

# Optional dependency
try:
    import requests
except Exception:
    requests = None

# === Defaults / files ===
DEFAULT_INTERVAL = 60
DEFAULT_BATCH_SIZE = 50
HOME = os.path.expanduser("~")
AGENT_DIR = os.path.join(HOME, ".cyberthreatwatch")
LOCAL_LOGFILE = os.path.join(AGENT_DIR, "agent.log")
SENT_CACHE_FILE = os.path.join(AGENT_DIR, "sent_cache.json")
PID_FILE = os.path.join(AGENT_DIR, "agent.pid")
STATUS_FILE = os.path.join(AGENT_DIR, "agent.status.json")

PRIORITY_KEYWORDS = ["attack", "unauthorized", "denied", "failed login", "ransomware", "malware", "critical", "panic"]

# Logging
os.makedirs(AGENT_DIR, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler(LOCAL_LOGFILE), logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("ctw-agent")

# Platform-specific support for Windows event logs if available
try:
    import win32evtlog  # type: ignore
    WIN32EVT_AVAILABLE = True
except Exception:
    WIN32EVT_AVAILABLE = False


def load_sent_cache() -> Set[str]:
    try:
        if os.path.exists(SENT_CACHE_FILE):
            with open(SENT_CACHE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                return set(data.get("sent", []))
    except Exception as e:
        logger.warning(f"Could not load sent cache: {e}")
    return set()


def save_sent_cache(sent: Set[str]):
    try:
        to_save = list(sent)[-2000:]
        with open(SENT_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump({"sent": to_save}, f)
    except Exception as e:
        logger.warning(f"Could not save sent cache: {e}")


def shutil_which(name: str) -> Optional[str]:
    try:
        import shutil
        return shutil.which(name)
    except Exception:
        return None


class UnixTailer:
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
            if logfile and shutil_which("tail"):
                cmd = ["tail", "-F", logfile]
            else:
                logger.warning("No journalctl/tail available; UnixTailer will poll files instead")
                self.proc = None
                return
        try:
            self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            threading.Thread(target=self._reader_loop, daemon=True).start()
            logger.info(f"UnixTailer started: {' '.join(cmd)}")
        except Exception as e:
            logger.error(f"UnixTailer start error: {e}")

    def _reader_loop(self):
        if not self.proc or not self.proc.stdout:
            return
        for line in self.proc.stdout:
            if self._stop.is_set():
                break
            ln = line.strip()
            if ln:
                with self.lock:
                    self.buffer.append(ln)

    def read_now(self) -> List[str]:
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
                logger.debug(f"WindowsPoller error: {e}")
            time.sleep(1)

    def _read_latest(self) -> List[str]:
        if WIN32EVT_AVAILABLE:
            return self._read_win32()
        else:
            return self._read_wevtutil()

    def _read_win32(self) -> List[str]:
        out = []
        try:
            h = win32evtlog.OpenEventLog(None, "System")
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events = win32evtlog.ReadEventLog(h, flags, 0)
            for ev in events[-50:]:
                out.append(str(ev))
            win32evtlog.CloseEventLog(h)
        except Exception:
            pass
        return out

    def _read_wevtutil(self) -> List[str]:
        cmd = ["wevtutil", "qe", "System", "/c:50", "/f:text"]
        try:
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=6)
            return [l.strip() for l in proc.stdout.splitlines() if l.strip()]
        except Exception:
            return []

    def read_now(self) -> List[str]:
        with self.lock:
            out = list(self.buffer)
            self.buffer.clear()
        return out

    def stop(self):
        self._stop.set()


class CTWAgent:
    def __init__(self, ingest_url: str, ingest_secret: str, interval: int = DEFAULT_INTERVAL, batch_size: int = DEFAULT_BATCH_SIZE):
        self.ingest_url = ingest_url.rstrip("/")
        self.ingest_secret = ingest_secret
        self.interval = max(1, interval)
        self.batch_size = max(1, batch_size)
        self.sent_cache = load_sent_cache()
        self.running = False
        self.reader = WindowsPoller() if "windows" in platform.system().lower() else UnixTailer()
        self.queue = []
        self.queue_lock = threading.Lock()

    def start(self) -> bool:
        if not self.ingest_url or not self.ingest_secret:
            logger.error("Ingest URL or secret missing.")
            return False
        if requests is None:
            logger.error("requests package not installed in environment.")
            return False
        self.reader.start()
        self.running = True
        threading.Thread(target=self._collector_loop, daemon=True).start()
        threading.Thread(target=self._sender_loop, daemon=True).start()
        self._write_status({"state": "running", "start_time": datetime.now(timezone.utc).isoformat()})
        logger.info("CTWAgent started.")
        return True

    def stop(self):
        self.running = False
        try:
            self.reader.stop()
        except Exception:
            pass
        save_sent_cache(self.sent_cache)
        self._write_status({"state": "stopped", "stopped_time": datetime.now(timezone.utc).isoformat()})
        logger.info("CTWAgent stopped.")

    def _collector_loop(self):
        while self.running:
            try:
                lines = self.reader.read_now()
                if lines:
                    recs = self._lines_to_records(lines)
                    with self.queue_lock:
                        self.queue.extend(recs)
            except Exception as e:
                logger.debug(f"Collector error: {e}")
            time.sleep(0.2)

    def _lines_to_records(self, lines: List[str]) -> List[Dict]:
        out = []
        for line in lines:
            key = (line or "")[:800]
            if key in self.sent_cache:
                continue
            severity = "critical" if any(kw in line.lower() for kw in PRIORITY_KEYWORDS) else "info"
            rec = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source": platform.node(),
                "message": line,
                "severity": severity
            }
            out.append({"rec": rec, "key": key})
        return out

    def _sender_loop(self):
        while self.running:
            start_ts = time.time()
            try:
                batch_items = []
                with self.queue_lock:
                    while self.queue and len(batch_items) < self.batch_size:
                        batch_items.append(self.queue.pop(0))
                if batch_items:
                    records = [it["rec"] for it in batch_items]
                    keys = [it["key"] for it in batch_items]
                    ok = self._post_to_ingest(records)
                    if ok:
                        for k in keys:
                            self.sent_cache.add(k)
                        save_sent_cache(self.sent_cache)
            except Exception as e:
                logger.exception(f"Sender loop: {e}")
            elapsed = time.time() - start_ts
            sleep_for = max(0.5, self.interval - elapsed)
            time.sleep(sleep_for)

    def _post_to_ingest(self, records: List[Dict]) -> bool:
        if not records:
            return True
        try:
            headers = {"Content-Type": "application/json", "x-ctw-secret": self.ingest_secret}
            payload = {"logs": records}
            resp = requests.post(self.ingest_url, json=payload, headers=headers, timeout=15)
            if resp.status_code == 200:
                logger.info(f"Uploaded {len(records)} record(s) to ingest endpoint.")
                return True
            else:
                logger.warning(f"Ingest returned {resp.status_code}: {resp.text}")
                return False
        except Exception as e:
            logger.error(f"Ingest POST error: {e}")
            return False

    def _write_status(self, obj: Dict):
        try:
            with open(STATUS_FILE, "w", encoding="utf-8") as f:
                json.dump(obj, f)
        except Exception:
            pass


def write_pid(pidfile: str = PID_FILE):
    try:
        with open(pidfile, "w", encoding="utf-8") as f:
            f.write(str(os.getpid()))
    except Exception:
        pass


def read_pid(pidfile: str = PID_FILE) -> Optional[int]:
    try:
        if os.path.exists(pidfile):
            with open(pidfile, "r", encoding="utf-8") as f:
                return int(f.read().strip())
    except Exception:
        pass
    return None


def remove_pid(pidfile: str = PID_FILE):
    try:
        if os.path.exists(pidfile):
            os.remove(pidfile)
    except Exception:
        pass


def detach_and_run(args):
    python = sys.executable or "python3"
    cmd = [python, os.path.abspath(__file__), "--interval", str(args.interval), "--batch", str(args.batch)]
    env = os.environ.copy()
    # pass ingest url + secret via environment if present
    if args.ingest_url:
        env["CTW_EDGE_URL"] = args.ingest_url
    if args.ingest_secret:
        env["CTW_EDGE_SECRET"] = args.ingest_secret
    # Start detached process (best-effort)
    try:
        if platform.system().lower() == "windows":
            DETACHED_PROCESS = 0x00000008
            proc = subprocess.Popen(cmd, env=env, creationflags=DETACHED_PROCESS, close_fds=True)
        else:
            proc = subprocess.Popen(cmd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, preexec_fn=os.setpgrp)
        # write pid file for controller
        try:
            with open(PID_FILE, "w", encoding="utf-8") as f:
                f.write(str(proc.pid))
        except Exception:
            pass
        print(proc.pid)
        logger.info(f"Detached agent started (pid {proc.pid})")
        return proc.pid
    except Exception as e:
        logger.error(f"Detach failed: {e}")
        return None


def parse_args():
    p = argparse.ArgumentParser(description="CyberThreatWatch local agent (HTTP ingest)")
    p.add_argument("--interval", type=int, default=DEFAULT_INTERVAL, help="Interval between flushes (seconds)")
    p.add_argument("--batch", type=int, default=DEFAULT_BATCH_SIZE, help="Max batch size per upload")
    p.add_argument("--detach", action="store_true", help="Run detached/background")
    p.add_argument("--test", action="store_true", help="Run a test insert once")
    p.add_argument("--ingest-url", dest="ingest_url", type=str, default=None, help="Ingest endpoint URL (overrides env)")
    p.add_argument("--ingest-secret", dest="ingest_secret", type=str, default=None, help="Ingest secret (overrides env)")
    return p.parse_args()


def test_insert(ingest_url: str, ingest_secret: str):
    if requests is None:
        logger.error("requests not installed.")
        return False
    try:
        headers = {"Content-Type": "application/json", "x-ctw-secret": ingest_secret}
        rec = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": platform.node(),
            "message": "CTW agent connectivity test event",
            "severity": "info"
        }
        payload = {"logs": [rec]}
        r = requests.post(ingest_url, json=payload, headers=headers, timeout=10)
        logger.info(f"Test insert status: {r.status_code} {r.text}")
        return r.status_code == 200
    except Exception as e:
        logger.error(f"Test insert error: {e}")
        return False


def main():
    args = parse_args()

    ingest_url = args.ingest_url or os.environ.get("CTW_EDGE_URL") or os.environ.get("CTW_INGEST_URL") or os.environ.get("CTW_EDGE_ENDPOINT") or os.environ.get("CTW_EDGE_URL")
    ingest_secret = args.ingest_secret or os.environ.get("CTW_EDGE_SECRET") or os.environ.get("CTW_INGEST_SECRET") or os.environ.get("CTW_EDGE_SECRET")

    if args.test:
        ok = test_insert(ingest_url, ingest_secret)
        if ok:
            logger.info("Test upload succeeded.")
        else:
            logger.error("Test upload failed.")
        return

    if args.detach:
        pid = detach_and_run(args)
        if pid:
            logger.info(f"Detached agent started (pid {pid})")
            return
        else:
            logger.error("Detach failed — running in foreground.")

    # Write pid file for foreground controller
    write_pid()
    agent = CTWAgent(ingest_url=ingest_url, ingest_secret=ingest_secret, interval=args.interval, batch_size=args.batch)
    ok = agent.start()
    if not ok:
        logger.error("Agent failed to start (check ingest url/secret and requests installed)")
        return

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Agent interrupted — shutting down")
    finally:
        agent.stop()
        remove_pid()


if __name__ == "__main__":
    main()
