import os
import time
import threading
import queue
import psutil
from typing import Dict, List, Any

class LogCollector:
    def __init__(self, log_paths: List[str] = None):
        if log_paths is None:
            self.log_paths = ["/var/log/auth.log", "/var/log/syslog"]
        else:
            self.log_paths = log_paths
        
        self.event_queue = queue.Queue()
        self.threads = []
        self.running = False

    def _tail_file(self, filepath: str):
        print(f"Collector: Starting thread to tail {filepath}")
        
        # If file doesn't exist, wait for it
        while self.running and not os.path.exists(filepath):
            print(f"Collector: Waiting for {filepath} to be created...")
            time.sleep(5)
            
        if not self.running:
            return

        try:
            with open(filepath, "r", errors="ignore") as f:
                # Seek to end so we only get new logs
                f.seek(0, os.SEEK_END)
                while self.running:
                    line = f.readline()
                    if not line:
                        time.sleep(0.1)
                        # Check rotation/truncation
                        try:
                            if os.path.exists(filepath) and os.path.getsize(filepath) < f.tell():
                                print(f"Collector: File {filepath} was truncated/rotated. Reopening...")
                                f.close()
                                f = open(filepath, "r", errors="ignore")
                        except OSError:
                            pass
                        continue
                    
                    self.event_queue.put({
                        "type": "log",
                        "source": os.path.basename(filepath),
                        "timestamp": time.time(),
                        "content": line.strip()
                    })
        except PermissionError:
            print(f"Collector Error: Permission denied reading {filepath}. Run with sudo or add user to 'adm' group.")
            self.event_queue.put({
                "type": "error",
                "source": os.path.basename(filepath),
                "timestamp": time.time(),
                "content": f"Permission denied reading {filepath}"
            })
        except Exception as e:
            print(f"Collector Error in {filepath}: {e}")
            self.event_queue.put({
                "type": "error",
                "source": os.path.basename(filepath),
                "timestamp": time.time(),
                "content": f"Error: {str(e)}"
            })

    def start(self):
        self.running = True
        for path in self.log_paths:
            t = threading.Thread(target=self._tail_file, args=(path,), daemon=True)
            t.start()
            self.threads.append(t)

    def stop(self):
        self.running = False

    def get_new_events(self) -> List[Dict[str, Any]]:
        """
        Retrieves all currently queued log events. Non-blocking.
        """
        events = []
        while not self.event_queue.empty():
            try:
                events.append(self.event_queue.get_nowait())
            except queue.Empty:
                break
        return events

    def get_active_connections(self) -> List[Dict[str, Any]]:
        """
        Returns active network connections using psutil.
        """
        connections = []
        try:
            for conn in psutil.net_connections(kind='inet'):
                laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
                raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
                connections.append({
                    "fd": conn.fd,
                    "family": str(conn.family),
                    "type": str(conn.type),
                    "local_address": laddr,
                    "remote_address": raddr,
                    "status": conn.status,
                    "pid": conn.pid
                })
        except PermissionError:
            # Under standard user on Linux, psutil.net_connections might raise PermissionError.
            # We return an empty or partial list or print warning.
            pass
        except Exception as e:
            print(f"Collector Error: Failed to list connections: {e}")
        return connections
