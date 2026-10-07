import threading
import time
from .models import Session

class StateTable:
    def __init__(self, ttl=30.0):
        self.ttl = ttl
        self.sessions = {}
        self.lock = threading.Lock()

    def add(self, key, protocol, fragment):
        with self.lock:
            session = self.sessions.get(key)
            if session is None:
                session = Session(key=key, protocol=protocol, last_seen=fragment.timestamp)
                self.sessions[key] = session
            session.fragments.append(fragment)
            session.total_bytes += len(fragment.payload)
            session.last_seen = fragment.timestamp
            if "F" in fragment.flags:
                session.fin_seen = True
            return session

    def get(self, key):
        with self.lock:
            return self.sessions.get(key)

    def pop(self, key):
        with self.lock:
            return self.sessions.pop(key, None)

    def garbage_collect(self, now=None):
        now = now or time.time()
        removed = []
        with self.lock:
            for key, session in list(self.sessions.items()):
                if now - session.last_seen > self.ttl:
                    removed.append(key)
                    del self.sessions[key]
        return removed

    def collect_stale(self, now=None):
        now = now or time.time()
        removed = []
        with self.lock:
            for key, session in list(self.sessions.items()):
                if now - session.last_seen > self.ttl:
                    removed.append(session)
                    del self.sessions[key]
        return removed

    def snapshot(self):
        with self.lock:
            return {str(k): len(v.fragments) for k, v in self.sessions.items()}
