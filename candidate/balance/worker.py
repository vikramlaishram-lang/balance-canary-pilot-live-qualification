"""One coordinator worker per durable volume. Restart resumes stored objectives."""
import fcntl
import os
import signal
import time
from pathlib import Path

from .http import configured


def main():
    directory = Path(os.environ.get("BALANCE_DATA", "/data"))
    directory.mkdir(parents=True, exist_ok=True)
    lock = (directory / "worker.lock").open("a")
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    coordinator = configured("gateway")
    stopping = False
    def stop(*_):
        nonlocal stopping
        stopping = True
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    while not stopping:
        for record in coordinator.store.list():
            if stopping:
                break
            if record["state"] in {"READY", "OBSERVING", "OUTCOME_UNKNOWN"} or (
                record["state"] == "COMPLETED" and not record["document"].get("settled")):
                coordinator.advance(record["id"])
        time.sleep(1)


if __name__ == "__main__":
    main()
