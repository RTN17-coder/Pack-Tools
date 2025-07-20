import os
import sys
import pyfiglet
import socket
import ipaddress
import subprocess
import threading
import platform
import re
import paramiko

from concurrent.futures import ThreadPoolExecutor, as_completed
from termcolor import colored
from ftplib import FTP, error_perm
from requests.auth import HTTPBasicAuth
from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, Raw
from datetime import datetime

os.system('clear')

protocols = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    53: "DNS",
}

def packet_callback(packet):
    time_captured = datetime.now().strftime("%H:%M:%S")
    print(f"\nPacket captured at {time_captured}")

    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        proto_num = packet[IP].proto
        proto_name = protocols.get(proto_num, f"Unknown ({proto_num})")

        print(f"IP: {src} -> {dst} | Protocol: {proto_name}")

        # Mostrar portas TCP/UDP
        if TCP in packet:
            print(f"TCP Ports: {packet[TCP].sport} -> {packet[TCP].dport}")
        elif UDP in packet:
            print(f"UDP Ports: {packet[UDP].sport} -> {packet[UDP].dport}")

        # Mostrar conteúdo DNS
        if packet.haslayer(DNS):
            print("DNS Packet Detected")

        # Mostrar conteúdo bruto, se disponível
        if packet.haslayer(Raw):
            raw_data = bytes(packet[Raw]).decode(errors="ignore")
            print(f"Raw Data: {raw_data}")


def start_sniffer():
    print("Starting sniffer (CTRL+C to stop)...")
    sniff(prn=packet_callback, store=0)
        
def ftp_brute_force(ip, username, wordlist):
    print(f"\n[FTP] Trying brute force on {ip} with user '{username}'")
    with open(wordlist, "r") as file:
        for line in file:
            password = line.strip()
            try:
                ftp = FTP(ip)
                ftp.login(user=username, passwd=password)
                print(f"\033[92m[SUCESS] FTP Login: {username}:{password}\033[0m")
                ftp.quit()
                return
            except error_perm:
                print(f"[FAILED] {username}:{password}")
            except Exception as e:
                print(f"[ERROR] {str(e)}")
                break

def ssh_brute_force(ip, username, wordlist):
    print(f"\n[SSH] Trying brute force on {ip} with user '{username}'")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    with open(wordlist, "r") as file:
        for line in file:
            password = line.strip()
            try:
                ssh.connect(ip, user=username, passwd=password, timeout=3)
                print(f"\033[92m[SUCESS] SSH Login: {username}:{password}\033[0m")
                ssh.close()
                return
            except error_perm:
                print(f"[FAILED] {username}:{password}")
            except Exception as e:
                print(f"[ERROR] {str(e)}")
                break

def http_brute_force(url, username, wordlist):
    print(f"\n[HTTP] Trying brute force on {url} with user '{username}'")
    with open(wordlist, "r") as file:
        for line in file:
            password = line.strip()
            try:
                response = requests.get(url, auth=HTTPBasicAuth(username, password), timeout=3)
                if response.status_code == 200:
                    print(f"\033[92m[SUCESS] FTP Login: {username}:{password}\033[0m")
                    return
                else:
                    print(f"[FAILED] {username}:{password} (Status {response.status_code})")
            except Exception as e:
                print(f"[ERROR] {str(e)}")
                break

def get_ttl(ip):
    try:
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        output = subprocess.check_output(['ping', param, '1', ip], universal_newlines=True, stderr=subprocess.DEVNULL)

        ttl_match = re.search(r'ttl=(\d+)', output, re.IGNORECASE)
        if ttl_match:
            return int(ttl_match.group(1))
        else:
            return None
    except Exception:
        return None

def guess_os(ttl):
    if ttl is None:
        return "Unknown"

    # Valores típicos de TTL (podem variar um pouco)
    if ttl >= 128:
        return "Windows"
    elif ttl >= 64:
        return "Linux/Unix"
    elif ttl >= 255:
        return "Cisco/Network Device"
    else:
        return "Unknown"

def vulnerability(ip, open_ports):
    vulns = []
    if 23 in open_ports:
        vulns.append("!!!! Telnet Activated (port 23) - not safe")
    if 21 in open_ports:
        vulns.append("!!!! FTP Activated (port 21) - may allow anonymous login")
    if 80 in open_ports and 443 not in open_ports:
        vulns.append("!!!! HTTP (port 443 not found)")

    if 22 in open_ports:
        vulns.append("!!!! SSH on default port (22) — can be the target of brute force")

    if 445 in open_ports:
        vulns.append("SMB ativated (porta 445) — vulnerable if exposed")

    if vulns:
        print(f"\n[!] Possible vulnerabilities detected on {ip}:")
        for v in vulns:
            print(f"  - {v}")

def scan_single_ip(ip_str, ports_to_scan, only_alive):
    if only_alive and not is_ip_alive(ip_str):
        print(f"\033[90m{ip_str} OFF.\033[0m")
        return

    print(f"\n\033[94m[ SCANNING IP: {ip_str} ]\033[0m")

    ttl = get_ttl(ip_str)
    os_guess = guess_os(ttl)
    print(f"Detected OS: {os_guess} (TTL={ttl})")

    open_ports = port_scan(ip_str, ports_to_scan)

    if open_ports:
        print(f"\033[92m[+] Open Ports: {open_ports}\033[0m")
        vulnerability(ip_str, open_ports)
    else:
        print(f"\033[93m[-] No open ports found on {ip_str}.\033[0m")


def is_ip_alive(ip):
    try:
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        result = subprocess.run(
            ["ping", param, "1", ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return result.returncode == 0
    except Exception:
        return False
def scan_ip_range(start_ip, end_ip, ports_to_scan, only_alive=False):
    """Escaneia um intervalo de IPs e verifica se estão ativos antes de escanear portas"""
    try:
        ip_range = ipaddress.summarize_address_range(
            ipaddress.IPv4Address(start_ip),
            ipaddress.IPv4Address(end_ip)
        )

        max_threads = 500  # limite máximo de threads simultâneas
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = []

            for subnet in ip_range:
                for ip in subnet.hosts():
                    ip_str = str(ip)
                    futures.append(executor.submit(scan_single_ip, ip_str, ports_to_scan, only_alive))

            # Espera todas as tasks finalizarem (pode ser omitido, mas é bom garantir)
            for future in as_completed(futures):
                pass

    except Exception as e:
        print(f"\033[91m[ERROR]\033[0m {str(e)}")



def port_scan(ip, ports_to_scan, max_threads=500):
    open_ports = []

    def scan_port(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.7)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                print(f"Port: {port} \033[92mOPEN\033[0m")
                open_ports.append(port)
        except Exception as e:
            print(f"Port: {port} \033[93mERROR\033[0m ({str(e)})")

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = [executor.submit(scan_port, port) for port in ports_to_scan]
        for future in as_completed(futures):
            pass

    return open_ports

def show_menu():
    """Exibe o menu principal"""
    banner = """
⠀⠀⠀⠀⢀⣀⣤⣤⣤⣤⣄⡀⠀⠀⠀⠀            
⠀⢀⣤⣾⣿⣾⣿⣿⣿⣿⣿⣿⣷⣄⠀⠀
⢠⣾⣿⢛⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡀    
⣾⣯⣷⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧     
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿      
⣿⡿⠻⢿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠻⢿⡵       
⢸⡇⠀⠀⠉⠛⠛⣿⣿⠛⠛⠉⠀⠀⣿⡇        
⢸⣿⣀⠀⢀⣠⣴⡇⠹⣦⣄⡀⠀⣠⣿⡇
⠈⠻⠿⠿⣟⣿⣿⣦⣤⣼⣿⣿⠿⠿⠟⠀
⠀⠀⠀⠀⠸⡿⣿⣿⢿⡿⢿⠇⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠈⠁⠈⠁⠀⠀⠀⠀⠀⠀
"""

    print(colored(banner, color="green", attrs=["bold"]))
    print("!!!!! PACK TOOLS FOR USE ONLY EDUCATIONAL OR ETHICAL !!!!!")
    print("""\n
    [1] Scan Ports
    [2] Scan Range of IPs
    [3] FTP Brute Force
    [4] SSH Brute Force
    [5] HTTP Basic Auth Brute Force
    [6] SNIFFRER package""")
    return input("Enter your choice: ")

def main():
    """Função principal"""
    common_ports = list(range(1, 65536))

    while True:
        choice = show_menu()

        if choice == "1":
            target_ip = input("Type your IP or IP server: ")
            print(f"\nScanning common ports on {target_ip}...\n")

            ttl = get_ttl(target_ip)
            os_guess = guess_os(ttl)
            print(f"Detected OS: {os_guess} (TTL={ttl})")

            open_ports = port_scan(target_ip, common_ports)
            if open_ports:
                print(f"\n033[92m[+] Open Ports: {open_ports}\033[0m]")
                vulnerability(target_ip, open_ports)
            else:
                print(f"\n033[92m[-] No open ports found.\033[0m]")
            print("\nScan completed!\n")
            _ = input("Press Enter to continue")
            os.system('clear')

        elif choice == "2":
            start_ip = input("Enter start IP (e.g. 192.168.1.1): ")
            end_ip = input("Enter end IP (e.g. 192.168.1.10): ")
            only_alive = input("Scan only alive IPs? (Y/n): ").lower() == "y"
            print(f"\nScanning range {start_ip} to {end_ip}...\n")
            scan_ip_range(start_ip, end_ip, common_ports, only_alive)
            print("\nRange scan completed!\n")
            _ = input("Press Enter to continue")
            os.system('clear')
        
        elif choice == "3":
            ip = input("FTP IP: ")
            user = input("Username: ")
            wordlist = input("Path to wordlist: ")
            ftp_brute_force(ip, user, wordlist)

        elif choice == "4":
            ip = input("SSH IP: ")
            user = input("Username: ")
            wordlist = input("Path to wordlist: ")
            ssh_brute_force(ip, user, wordlist)

        elif choice == "5":
            url = input("HTTP URL: ")
            user = input("Username: ")
            wordlist = input("Path to wordlist: ")
            http_brute_force(url, user, wordlist)
        
        elif choice == "6":
            start_sniffer()
            _ = input("\n Press ENTER to continue")
            os.system('clear')

        else:
            print("Invalid option. Please try again.")

if __name__ == "__main__":
    main()
