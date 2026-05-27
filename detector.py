import psutil
from colorama import Fore, init

init(autoreset=True)

with open("suspicious.txt", "r") as f:
    suspicious_keywords = [line.strip().lower() for line in f]

print(Fore.CYAN + "\n[+] Scanning running processes...\n")

found = False

for process in psutil.process_iter(['pid', 'name', 'cmdline']):

    try:
        process_name = process.info['name']
        cmdline = " ".join(process.info['cmdline']).lower()

        for keyword in suspicious_keywords:

            if keyword in process_name.lower() or keyword in cmdline:

                print(Fore.RED + "[!] Suspicious Process Found")
                print(Fore.YELLOW + f"PID: {process.info['pid']}")
                print(Fore.YELLOW + f"Name: {process_name}")
                print(Fore.YELLOW + f"Command: {cmdline}")
                print("-" * 50)

                found = True

    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass

if not found:
    print(Fore.GREEN + "[✓] No suspicious processes detected.")
