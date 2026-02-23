#!/usr/bin/env python3

import socket
import requests
import urllib3
import threading
import sys
import os
import time
import argparse
from datetime import datetime
from requests.auth import HTTPBasicAuth
import signal

# Suppress unverified HTTPS warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# =========================================================
# ARGUMENTS
# =========================================================
parser = argparse.ArgumentParser(description="Loxone UDP Debug Monitor (multi-MSV)")

parser.add_argument("--msv", required=True,
                    help="Comma separated MSV IPs (e.g. 192.168.88.77,192.168.88.78)")

parser.add_argument("--listen-ip", help="Local IP for receiving logs (auto detect if omitted)")
parser.add_argument("--port", type=int, default=7777, help="UDP port to listen on (default 7777)")
parser.add_argument("--user", default=os.getenv("LOX_USER", "admin"), help="Miniserver username (default 'admin' or LOX_USER env)")
parser.add_argument("--password", default=os.getenv("LOX_PASS", "password"), help="Miniserver password (default 'password' or LOX_PASS env)")
parser.add_argument("--https", action="store_true", help="Force HTTPS connection")
parser.add_argument("--raw", action="store_true", help="Print raw packet hexdump")
parser.add_argument("--logfile", help="Path to file where raw output will be written")

args = parser.parse_args()


MSV_IPS = [x.strip() for x in args.msv.split(",")]
UDP_PORT = args.port
USERNAME = args.user
PASSWORD = args.password
USE_HTTPS = args.https
RAW_MODE = args.raw
LOGFILE = args.logfile


# =========================================================
# AUTO DETECT LOCAL IP (important for /log/<ip>)
# =========================================================
def detect_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip


LOCAL_IP = args.listen_ip or detect_local_ip()


# =========================================================
PREFIXES = (
    b"PRG", b"LNK", b"TCP", b"DNS", b"MSE",
    b"HTC", b"SPS", b"IO ", b"Stream", b"Try",
)

packet_counter = 0
running = True
log_handle = open(LOGFILE, "a") if LOGFILE else None


# =========================================================
def hexdump(data, width=16):
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        print(f"{i:04x}   {hex_part:<48}  {ascii_part}")
    print()


def colorize(msg: str) -> str:
    if " PRG " in msg:
        return f"\033[96m{msg}\033[0m"
    if " LNK " in msg:
        return f"\033[92m{msg}\033[0m"
    if " TCP " in msg:
        return f"\033[93m{msg}\033[0m"
    if " DNS " in msg:
        return f"\033[95m{msg}\033[0m"
    if "error" in msg.lower():
        return f"\033[91m{msg}\033[0m"
    if "HTTP0 Webservice request keepalive" in msg:
        return f"\033[90m{msg}\033[0m"
    return msg


# =========================================================
# PARSER
# =========================================================
def extract_log_line(data: bytes):
    """
    Proper, future-proof extraction.

    Strategy:
      1. Remove trailing 00 1f 1f
      2. Walk backwards
      3. Take last continuous printable ASCII block
    """

    # strip terminator
    end = data.find(b"\x00\x1f\x1f")
    if end != -1:
        data = data[:end]

    # printable ASCII range
    def printable(b):
        return 32 <= b <= 126 or b in (9,)

    i = len(data) - 1

    # skip trailing non-printable
    while i >= 0 and not printable(data[i]):
        i -= 1

    if i <= 0:
        return None

    end_idx = i

    # walk backwards until non-printable
    while i >= 0 and printable(data[i]):
        i -= 1

    start_idx = i + 1

    msg = data[start_idx:end_idx + 1].decode(errors="ignore").strip()

    # discard tiny junk
    if len(msg) < 4:
        return None

    return msg



# =========================================================
# UDP LISTENER
# =========================================================
def start_udp_listener():
    global packet_counter

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", UDP_PORT))

    print(f"Listening on {LOCAL_IP}:{UDP_PORT}\n")

    while running:
        try:
            data, addr = sock.recvfrom(8192)
        except:
            break

        if RAW_MODE:
            hexdump(data)

        msg = extract_log_line(data)
        if not msg:
            continue

        packet_counter += 1
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]

        line = f"{packet_counter:08d} {addr[0]:15} {ts} {msg}"

        print(colorize(line))

        if log_handle:
            log_handle.write(line + "\n")
            log_handle.flush()


# =========================================================
# HTTP CONTROL
# =========================================================
def http_call(msv, path, is_retry=False):
    global USE_HTTPS
    scheme = "https" if USE_HTTPS else "http"
    port = 443 if USE_HTTPS else 80
    url = f"{scheme}://{msv}:{port}{path}"

    print(f"\n  [Connecting to: {url}] ", end="", flush=True)

    response = requests.get(
        url,
        auth=HTTPBasicAuth(USERNAME, PASSWORD),
        verify=False,
        timeout=3,
        allow_redirects=False
    )

    if response.is_redirect:
        redirect_url = response.headers.get("Location")
        print(f"→ Redirected to: {redirect_url} ", end="", flush=True)
        if redirect_url and redirect_url.startswith("https://") and not USE_HTTPS:
            print("(Switching to HTTPS) ", end="", flush=True)
            USE_HTTPS = True
            if not is_retry:
                return http_call(msv, path, is_retry=True)
        # If it's a redirect to the same protocol or we already retried, let requests handle it or fail
        response = requests.get(
            redirect_url,
            auth=HTTPBasicAuth(USERNAME, PASSWORD),
            verify=False,
            timeout=3
        )

    response.raise_for_status()


def enable_logs():
    for msv in MSV_IPS:
        print(f"Enable logs on {msv} → {LOCAL_IP} ... ", end="", flush=True)
        try:
            http_call(msv, f"/dev/sps/log/{LOCAL_IP}")
            print("OK")
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                print("FAILED (401 Unauthorized - Invalid username or password)")
            else:
                print(f"FAILED (HTTP {e.response.status_code}: {e.response.reason})")
            print("Error: Failed to connect to MSV to enable logging. Exiting program.")
            sys.exit(1)
        except Exception as e:
            print(f"FAILED ({type(e).__name__})")
            print("Error: Failed to connect to MSV to enable logging. Exiting program.")
            sys.exit(1)


def disable_logs():
    for msv in MSV_IPS:
        print(f"Disable logs on {msv} ... ", end="", flush=True)
        try:
            http_call(msv, "/dev/sps/log")
            print("OK")
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                print("FAILED (401 Unauthorized)")
            else:
                print(f"FAILED (HTTP {e.response.status_code})")
        except Exception as e:
            print(f"FAILED ({type(e).__name__})")


# =========================================================
# CLEAN SHUTDOWN
# =========================================================
def shutdown(sig=None, frame=None):
    global running
    running = False

    print("\nStopping log streams...")
    disable_logs()

    if log_handle:
        log_handle.close()

    sys.exit(0)


signal.signal(signal.SIGINT, shutdown)
signal.signal(signal.SIGTERM, shutdown)


# =========================================================
# MAIN
# =========================================================
def main():
    print("\n=== Loxone Debug Monitor ===")
    print("MSVs:", ", ".join(MSV_IPS))
    print("Receiver:", LOCAL_IP)
    print()

    enable_logs()

    t = threading.Thread(target=start_udp_listener, daemon=True)
    t.start()

    while True:
         time.sleep(1)


if __name__ == "__main__":
    main()
