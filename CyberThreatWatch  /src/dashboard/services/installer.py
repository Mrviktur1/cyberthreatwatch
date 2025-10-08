# dashboard/services/installer.py
import os
import subprocess
import sys
import stat
import time
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

AGENT_FILENAME = "agent_installer.py"
AGENT_TARGET_DIR = os.path.expanduser("~/.cyberthreatwatch")  # hidden folder in user's home
AGENT_PATH = os.path.join(AGENT_TARGET_DIR, AGENT_FILENAME)
PIDFILE = os.path.join(AGENT_TARGET_DIR, "agent.pid")

def ensure_agent_dir():
    os.makedirs(AGENT_TARGET_DIR, exist_ok=True)
    return AGENT_TARGET_DIR

def write_agent_file(agent_source: str):
    """Write the provided agent_source string to AGENT_PATH; make executable."""
    ensure_agent_dir()
    with open(AGENT_PATH, "w", encoding="utf-8") as f:
        f.write(agent_source)
    try:
        os.chmod(AGENT_PATH, os.stat(AGENT_PATH).st_mode | stat.S_IEXEC)
    except Exception as e:
        logger.debug(f"Could not make agent executable: {e}")
    return AGENT_PATH

def start_agent(detach=True, interval=60, env=None):
    """
    Start the agent in background. Returns subprocess.Popen or raises on error.
    env: dict of env vars to pass (e.g., SUPABASE_URL/KEY)
    """
    ensure_agent_dir()
    if not os.path.exists(AGENT_PATH):
        raise FileNotFoundError("Agent file not present. Call write_agent_file first.")
    python_exe = sys.executable or "python"
    cmd = [python_exe, AGENT_PATH, "--interval", str(int(interval))]
    # On Windows use DETACHED_PROCESS, on POSIX use preexec_fn=os.setpgrp
    creationflags = 0
    kwargs = {}
    if os.name == "nt":
        # DETACHED_PROCESS flag 0x00000008; redirect IO to log file
        creationflags = 0x00000008
        kwargs["creationflags"] = creationflags
        # redirect stdout/stderr to file to avoid console spawns
        logfile = open(os.path.join(AGENT_TARGET_DIR, "agent_stdout.log"), "a+")
        kwargs["stdout"] = logfile
        kwargs["stderr"] = logfile
    else:
        # POSIX
        kwargs["stdout"] = open(os.path.join(AGENT_TARGET_DIR, "agent_stdout.log"), "a+")
        kwargs["stderr"] = kwargs["stdout"]
        kwargs["preexec_fn"] = os.setpgrp

    # merge env
    env_vars = os.environ.copy()
    if env:
        env_vars.update(env)
    kwargs["env"] = env_vars
    kwargs["cwd"] = AGENT_TARGET_DIR
    kwargs["close_fds"] = True

    proc = subprocess.Popen(cmd, **kwargs)
    # write pid
    try:
        with open(PIDFILE, "w") as f:
            f.write(str(proc.pid))
    except Exception:
        pass
    return proc

def stop_agent():
    """Stop agent using PID file."""
    if os.path.exists(PIDFILE):
        try:
            pid = int(open(PIDFILE).read().strip())
            if os.name == "nt":
                subprocess.run(["taskkill", "/PID", str(pid), "/F"])
            else:
                os.kill(pid, 15)  # SIGTERM
            os.remove(PIDFILE)
            return True
        except Exception as e:
            logger.error(f"Could not stop agent: {e}")
            return False
    return False

def agent_status():
    if os.path.exists(PIDFILE):
        try:
            pid = int(open(PIDFILE).read().strip())
            # check process exists
            if os.name == "nt":
                # on Windows, tasklist check
                out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}"], stdout=subprocess.PIPE, text=True)
                return "running" if str(pid) in out.stdout else "stopped"
            else:
                os.kill(pid, 0)
                return "running"
        except Exception:
            return "stopped"
    return "stopped"
