import socket
import sys
import threading
from datetime import datetime
import os

def clear():
    # for windows
    if os.name == 'nt':
        _ = os.system('cls')
    # for mac and linux
    else:
        _ = os.system('clear')

clear()

print('''
      
$$$$$$$\                        $$\                          $$$$$$\                                                              
$$  __$$\                       $$ |                        $$  __$$\                                                             
$$ |  $$ | $$$$$$\   $$$$$$\  $$$$$$\                       $$ /  \__| $$$$$$$\  $$$$$$\  $$$$$$$\  $$$$$$$\   $$$$$$\   $$$$$$\  
$$$$$$$  |$$  __$$\ $$  __$$\ \_$$  _|        $$$$$$\       \$$$$$$\  $$  _____| \____$$\ $$  __$$\ $$  __$$\ $$  __$$\ $$  __$$\ 
$$  ____/ $$ /  $$ |$$ |  \__|  $$ |          \______|       \____$$\ $$ /       $$$$$$$ |$$ |  $$ |$$ |  $$ |$$$$$$$$ |$$ |  \__|
$$ |      $$ |  $$ |$$ |        $$ |$$\                     $$\   $$ |$$ |      $$  __$$ |$$ |  $$ |$$ |  $$ |$$   ____|$$ |      
$$ |      \$$$$$$  |$$ |        \$$$$  |                    \$$$$$$  |\$$$$$$$\ \$$$$$$$ |$$ |  $$ |$$ |  $$ |\$$$$$$$\ $$ |      
\__|       \______/ \__|         \____/                      \______/  \_______| \_______|\__|  \__|\__|  \__| \_______|\__|      
|                                                                                                                          |
|------------------------------------------------Coded by Hikmat-----------------------------------------------------------|''')

print("\nGithub: https://github.com/HikmatAsifli\n")

def get_target():
    while True:
        target = input("Enter target IP/domain: ")
        try:
            target_ip = socket.gethostbyname(target)
            return target_ip
        except socket.gaierror:
            print("Invalid hostname. Please try again.")
            continue

target_ip = get_target()

def get_scan_mode():
    while True:
        print("\nSelect your scan type:")
        print("[1] 1 to 1024 port scanning")
        print("[2] 1 to 65535 port scanning")
        print("[3] Custom port scanning")
        print("[4] Exit\n")
        mode = input("Select an option: ")
        if mode.isdigit() and 1 <= int(mode) <= 4:
            return int(mode)
        else:
            print("Invalid input. Please enter a number between 1 and 4.")
            continue

mode = get_scan_mode()

if mode == 3:
    while True:
        try:
            custom_port_start = int(input("[+] Enter starting port number: "))
            custom_port_end = int(input("[+] Enter ending port number: "))
            break
        except ValueError:
            print("Invalid input. Please enter numeric values for port numbers.")

print("-" * 50)
print(f"Target IP: {target_ip}")
print("Scanning started at:", datetime.now())
print("-" * 50)

def scan_port(port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            result = s.connect_ex((target_ip, port))
            if result == 0:
                print(f"Port {port} is open!")
                return True
            else:
                return False
    except KeyboardInterrupt:
        sys.exit()
    except socket.gaierror:
        print("Hostname could not be resolved.")
        sys.exit()
    except socket.error:
        print("Could not connect to server.")
        sys.exit()

def scan_ports(ports):
    for port in ports:
        if scan_port(port):
            open_ports.append(port)

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

    thread_list = []

    for _ in range(threads):
        thread = threading.Thread(target=scan_ports, args=(ports,))
        thread_list.append(thread)
        thread.start()

    for thread in thread_list:
        thread.join()

run_scanner(1021, mode)

print("Scanning complete at:", datetime.now())
