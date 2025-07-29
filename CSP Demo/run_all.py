import subprocess
import sys
import os

servers = [
    ("example1_dynamic_hash.py", 5001),
    ("example2_self_open_redirect.py", 5002),
    ("example3_nonce_dom_sink.py", 5003),
    ("evil_server.py", 9000)
]

processes = []

def run_servers():
    for script, port in servers:
        cmd = [sys.executable, script]
        p = subprocess.Popen(cmd)
        processes.append(p)
        print(f"Started {script} on port {port}")

def stop_servers():
    print("Stopping servers...")
    for p in processes:
        p.terminate()
    print("All servers stopped.")

if __name__ == "__main__":
    try:
        run_servers()
        print("All servers running. Press Ctrl+C to stop.")
        while True:
            pass
    except KeyboardInterrupt:
        stop_servers()
