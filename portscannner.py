import socket
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import os
import logging

# ANSI escape codes for color
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
WHITE = "\033[97m"
RESET = "\033[0m"

# Set up logging
logging.basicConfig(level=logging.INFO, format=f"{WHITE}%(message)s{RESET}")

def clear():
    if os.name == 'nt':
        os.system('cls')
    else:
        os.system('clear')

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
            logging.error(f"{RED}Invalid hostname. Please try again.{RESET}")
            continue

target_ip = get_target()

def get_scan_mode():
    while True:
        logging.info(f"\n{YELLOW}Select your scan type:{RESET}")
        logging.info(f"{BLUE}[1] 1 to 1024 port scanning{RESET}")
        logging.info(f"{BLUE}[2] 1 to 65535 port scanning{RESET}")
        logging.info(f"{BLUE}[3] Custom port scanning{RESET}")
        logging.info(f"{BLUE}[4] Exit{RESET}\n")
        mode = input(f"{YELLOW}Select an option: {RESET}")
        if mode.isdigit() and 1 <= int(mode) <= 4:
            return int(mode)
        else:
            logging.error(f"{RED}Invalid input. Please enter a number between 1 and 4.{RESET}")
            continue

mode = get_scan_mode()

if mode == 3:
    while True:
        try:
            custom_port_start = int(input(f"{YELLOW}[+] Enter starting port number: {RESET}"))
            custom_port_end = int(input(f"{YELLOW}[+] Enter ending port number: {RESET}"))
            if 1 <= custom_port_start <= custom_port_end <= 65535:
                break
            else:
                logging.error(f"{RED}Invalid port range. Please enter valid port numbers between 1 and 65535.{RESET}")
        except ValueError:
            logging.error(f"{RED}Invalid input. Please enter numeric values for port numbers.{RESET}")

logging.info(f"{WHITE}-" * 50)
logging.info(f"{GREEN}Target IP: {target_ip}{RESET}")
logging.info(f"{GREEN}Scanning started at: {datetime.now()}{RESET}")
logging.info(f"{WHITE}-" * 50)

open_ports = []

def scan_port(port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)  # Reduced timeout for faster scanning
            result = s.connect_ex((target_ip, port))
            if result == 0:
                logging.info(f"{GREEN}Port {port} is open!{RESET}")
                open_ports.append(port)
                return True
            return False
    except socket.error:
        logging.error(f"{RED}Could not connect to server on port {port}.{RESET}")
        return False

def run_scanner(threads, mode):
    if mode == 1:
        ports = range(1, 1025)
    elif mode == 2:
        ports = range(1, 65536)
    elif mode == 3:
        ports = range(custom_port_start, custom_port_end + 1)
    else:
        sys.exit()

    with ThreadPoolExecutor(max_workers=threads) as executor:
        executor.map(scan_port, ports)

run_scanner(100, mode)

logging.info(f"{WHITE}-" * 50)
logging.info(f"{GREEN}Scanning complete at: {datetime.now()}{RESET}")
logging.info(f"{WHITE}Open ports: {open_ports if open_ports else 'None'}{RESET}")
