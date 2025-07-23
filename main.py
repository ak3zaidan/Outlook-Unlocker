from ctypes import c_char_p, POINTER, c_char
import threading
import random
import ctypes
import json
import time
import os

funcap_key = "..."
sms_key = "..."
proxyFile = "../outlookProxies1.txt"

THREADS = 5

# Helpers

proxies = []
locked = []

workIndex = 0
index_lock = threading.Lock()
failure = []
failure_lock = threading.Lock()

green_text = '\033[92m'  # 92 is the ANSI code for bright green text
reset = '\033[0m'  # Reset the color to default terminal color
red_text = '\033[91m'  # 91 is the ANSI code for bright red text

def load_proxies():
    global proxies

    if not os.path.exists(proxyFile):
        print("Error: 'proxies.txt' not found.")
        return
    with open(proxyFile, "r") as file:
        proxies = [line.strip() for line in file if line.strip()]

    print(f"\n\nLoaded {len(proxies)} proxies.")

def parse_proxy(proxy_string):
    try:
        parts = proxy_string.split(':')

        if len(parts) == 2:
            host, port = parts
            return host, port
        elif len(parts) == 4:
            host, port, username, password = parts
            return host, port, username, password
        else:
            print(f"\033[93mWarning: Invalid proxy format: {proxy_string}\033[0m")
            return "", "", "", ""
    except Exception as e:
        print(f"\033[91mError parsing proxy: {str(e)}\033[0m")
        return "", "", "", ""

def load_emails():
    global locked

    if not os.path.exists("locked.txt"):
        print("Error: 'locked.txt' not found. Please create the file and add emails.")
        return
    
    with open("locked.txt", "r") as file:
        locked = [line.strip() for line in file if line.strip()]

    print(f"Loaded {len(locked)} emails from 'locked.txt'.")

def clear_file(file_path):
    try:
        # Open the file in write mode ('w'), which truncates the file
        with open(file_path, 'w') as file:
            pass
    except Exception as e:
        print(f"Error clearing file: {e}")

def write_array_to_file(file_path, string_array):
    try:
        with open(file_path, 'w') as file:
            for line in string_array:
                file.write(f"{line}\n")

    except Exception as e:
        print(f"Error writing to file: {e}")

def addAccount(email, password):
    with open("unlocked.txt", "a") as file:
        file.write(f"{email}:{password}\n")

def random_proxy():
    global proxies

    proxy = random.choice(proxies) if proxies else None

    if proxy:
        proxy_parts = parse_proxy(proxy)
        
        if len(proxy_parts) == 2:
            host, port = proxy_parts
            return f"http://{host}:{port}"
        elif len(proxy_parts) == 4:
            host, port, username, proxyPass = proxy_parts
            return f"http://{username}:{proxyPass}@{host}:{port}"
        else:
            print("\033[93mWarning bad proxies\033[0m")
    else:
        print("\033[93mWarning add proxies\033[0m")
    
    return ""

def format(data):
    try:
        return json.loads(data)
    except json.JSONDecodeError:
        return {
            "success": False,
            "message": data
        }

# Main

def call_rust(account, password, country, proxy):
    lib_path = os.path.abspath("target/release/libunlockbridge.dylib")
    lib = ctypes.cdll.LoadLibrary(lib_path)

    lib.main_unlocker_ffi.argtypes = [c_char_p, c_char_p, c_char_p, c_char_p, c_char_p, c_char_p]
    lib.main_unlocker_ffi.restype = POINTER(c_char)

    lib.free_string.argtypes = [POINTER(c_char)]
    lib.free_string.restype = None

    result_ptr = lib.main_unlocker_ffi(
        account.encode('utf-8') if account else None,
        password.encode('utf-8') if password else None,
        country.encode('utf-8') if country else None,
        proxy.encode('utf-8') if proxy else None,
        funcap_key.encode('utf-8'),
        sms_key.encode('utf-8')
    )

    result = ctypes.string_at(result_ptr).decode('utf-8')
    lib.free_string(result_ptr)

    return result

def unlock(email, password):
    proxy_url = random_proxy()

    result1 = format(call_rust(email, password, "US", proxy_url))

    if result1["success"]:
        print(green_text + "Account unlocked 1st try: " + email + reset)
        addAccount(email, password)
        return
    else:
        print(f"{red_text}Failure unlock 1: {result1["message"]}{reset}")

    time.sleep(5)

    result2 = format(call_rust(email, password, "US", proxy_url))

    if result2["success"]:
        print(green_text + "Account unlocked 2st try: " + email + reset)
        addAccount(email, password)
        return
    else:
        print(f"{red_text}Failure unlock 2: {result2["message"]}{reset}")

    with failure_lock:
        failure.append(f'{email}:{password}')

def worker():
    global workIndex, locked

    while True:
        with index_lock:
            if workIndex >= len(locked):
                break
            account = locked[workIndex]
            print(f'Unlocking acc {workIndex}')
            workIndex += 1

        try:
            email, password = account.split(":", 1)

            unlock(email, password)
        except Exception as e:
            print(f"Error in task: {e}")

if __name__ == "__main__":
    load_proxies()
    load_emails()

    threads = []
    for _ in range(THREADS):
        thread = threading.Thread(target=worker)
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    tries = 0
    while True:
        clear_file("locked.txt")
        if len(failure) > 5:
            write_array_to_file("locked.txt", failure)

            print("\n\n\nRETRYING failures---")

            locked = failure
            failure = []
            workIndex = 0

            threads = []
            for _ in range(THREADS):
                thread = threading.Thread(target=worker)
                threads.append(thread)
                thread.start()

            for thread in threads:
                thread.join()

            tries += 1

            if tries == 3:
                break
        else:
            break

    print("\n\nDone")
