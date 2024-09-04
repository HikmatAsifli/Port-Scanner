import socket
import sys
import threading
from datetime import datetime
import os

# ANSI escape codes for color
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
WHITE = "\033[97m"
RESET = "\033[0m"

def clear():
    if os.name == 'nt':
        _ = os.system('cls')
    else:
        _ = os.system('clear')

clear()

print(f'''
{RED}      
$$$$$$$\                        $$\                          $$$$$$\                                                              
$$  __$$\                       $$ |                        $$  __$$\                                                             
$$ |  $$ | $$$$$$\   $$$$$$\  $$$$$$\                       $$ /  \__| $$$$$$$\  $$$$$$\  $$$$$$$\  $$$$$$$\   $$$$$$\   $$$$$$\  
$$$$$$$  |$$  __$$\ $$  __$$\ \_$$  _|        $$$$$$\       \$$$$$$\  $$  _____| \____$$\ $$  __$$\ $$  __$$\ $$  __$$\ $$  __$$\ 
$$  ____/ $$ /  $$ |$$ |  \__|  $$ |          \______|       \____$$\ $$ /       $$$$$$$ |$$ |  $$ |$$ |  $$ |$$$$$$$$ |$$ |  \__|
$$ |      $$ |  $$ |$$ |        $$ |$$\                     $$\   $$ |$$ |      $$  __$$ |$$ |  $$ |$$ |  $$ |$$   ____|$$ |      
$$ |      \$$$$$$  |$$ |        \$$$$  |                    \$$$$$$  |\$$$$$$$\ \$$$$$$$ |$$ |  $$ |$$ |  $$ |\$$$$$$$\ $$ |      
\__|       \______/ \__|         \____/                      \______/  \_______| \_______|\__|  \__|\__|  \__| \_______|\__|      
|                                                                                                                          |
{YELLOW}|------------------------------------------------{MAGENTA}Coded by Hikmat{YELLOW}-----------------------------------------------------------|{RESET}''')

print(f"\n{CYAN}Github: https://github.com/HikmatAsifli{RESET}\n")

def get_target():
    while True:
        target = input(f"{YELLOW}Enter target IP/domain: {RESET}")
        try:
            target_ip = socket.gethostbyname(target)
            return target_ip
        except socket.gaierror:
            print(f"{RED}Invalid hostname. Please try again.{RESET}")
            continue

target_ip = get_target()

def get_scan_mode():
    while True:
        print(f"\n{YELLOW}Select your scan type:{RESET}")
        print(f"{BLUE}[1] 1 to 1024 port scanning{RESET}")
        print(f"{BLUE}[2] 1 to 65535 port scanning{RESET}")
        print(f"{BLUE}[3] Custom port scanning{RESET}")
        print(f"{BLUE}[4] Exit{RESET}\n")
        mode = input(f"{YELLOW}Select an option: {RESET}")
        if mode.isdigit() and 1 <= int(mode) <= 4:
            return int(mode)
        else:
            print(f"{RED}Invalid input. Please enter a number between 1 and 4.{RESET}")
            continue

mode = get_scan_mode()

if mode == 3:
    while True:
        try:
            custom_port_start = int(input(f"{YELLOW}[+] Enter starting port number: {RESET}"))
            custom_port_end = int(input(f"{YELLOW}[+] Enter ending port number: {RESET}"))
            break
        except ValueError:
            print(f"{RED}Invalid input. Please enter numeric values for port numbers.{RESET}")

print(f"{WHITE}-" * 50)
print(f"{GREEN}Target IP: {target_ip}{RESET}")
print(f"{GREEN}Scanning started at: {datetime.now()}{RESET}")
print(f"{WHITE}-" * 50)

def scan_port(port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)  # Reduced timeout for faster scanning
            result = s.connect_ex((target_ip, port))
            if result == 0:
                print(f"{GREEN}Port {port} is open!{RESET}")
                return True
            return False
    except KeyboardInterrupt:
        sys.exit()
    except socket.gaierror:
        print(f"{RED}Hostname could not be resolved.{RESET}")
        sys.exit()
    except socket.error:
        print(f"{RED}Could not connect to server.{RESET}")
        sys.exit()

def scan_ports(port_range):
    for port in port_range:
        scan_port(port)

open_ports = []

def run_scanner(threads, mode):
    if mode == 1:
        ports = range(1, 1025)
    elif mode == 2:
        ports = range(1, 65536)
    elif mode == 3:
        ports = range(custom_port_start, custom_port_end + 1)
    else:
        sys.exit()

    port_ranges = [list(ports)[i::threads] for i in range(threads)]
    
    thread_list = []

    for port_range in port_ranges:
        thread = threading.Thread(target=scan_ports, args=(port_range,))
        thread_list.append(thread)
        thread.start()

    for thread in thread_list:
        thread.join()

run_scanner(100, mode)

print(f"{GREEN}Scanning complete at: {datetime.now()}{RESET}")
