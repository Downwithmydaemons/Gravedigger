#!/bin/python3

import subprocess
from subprocess import Popen, PIPE, STDOUT
from threading import Thread
import ipaddress
from tqdm import tqdm
from termcolor import colored
import os
import re
from urllib.parse import urlparse
import socket

# Input Validation
def is_valid_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        print(f"{ip} is a valid IP address")
        return True
    except ValueError:
        print(f"ERROR: {ip} is not a valid IP address")
        return False

print(colored('╦ ╦┌─┐┌─┐┬  ┌─┐┌┬┐┌─┐  ┌┬┐┌─┐  ┌┬┐┬ ┬┌─┐  ┌─┐┬─┐┌─┐┬  ┬┌─┐┬ ┬┌─┐┬─┐┌┬┐', 'green'))
print(colored('║║║├┤ │  │  │ ││││├┤    │ │ │   │ ├─┤├┤   │ ┬├┬┘├─┤└┐┌┘├┤ └┬┘├─┤├┬┘ ││', 'red'))
print(colored('╚╩╝└─┘└─┘┴─┘└─┘┴ ┴└─┘   ┴ └─┘   ┴ ┴ ┴└─┘  └─┘┴└─┴ ┴ └┘ └─┘ ┴ ┴ ┴┴└──┴┘', 'green'))

# User input with validation
while True:
    target = input("Enter IP: ")
    if is_valid_ip(target):
        break
    else:
        print("Please enter a valid IP address.")

# Run rustscan command and save results
with open("Results.txt", "w") as f:
    cmd = ["rustscan_binary", "-a", target, "-n", "--ulimit", "70000", "-t", "7000", "--", "-A", "-Pn"]
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)

    pbar = tqdm(desc="Running rustscan", unit=" lines", unit_scale=True)
    for stdout_line in process.stdout:
        f.write(stdout_line)
        pbar.update()
    process.communicate()
    pbar.close()

# Dictionary to store found services
services_found = {
    'FTP': '21/tcp',
    'SSH': '22/tcp',
    'TELNET': '23/tcp',
    'SMTP': '25/tcp',
    'DNS': '53/tcp',
    'HTTP': '80/tcp',
    'KERBEROS': '88/tcp',
    'RPC': '135/tcp',
    'SMB137': '139/tcp',
    'SMB445': '445/tcp',
    'POP3': '110/tcp',
    'IMAP': '143/tcp',
    'HTTPS': '443/tcp',
    'RDP': '3389/tcp',
    'WINRM': '5985/tcp'
}



# Set to store detected services
detected_services = set()

# Set to store ports not in services_found
unknown_ports = set()

with open("Results.txt", "r") as fp:
    for line in fp:
        found = False
        for service, port in services_found.items():
            if port in line:
                detected_services.add(service)
                found = True
                break
        if not found:
            # Extract port number from line and add to unknown_ports set
            parts = line.split()
            if len(parts) > 0:
                port_number = parts[0].strip('/tcp')
                if port_number.isdigit():  # Check if port_number is a valid integer
                    unknown_ports.add(port_number)

# Additional commands based on detected services
##############################SSH##############################
if 'SSH' in detected_services:
    print(colored('SSH', 'red'),"is open on standard port, come back when you have credientals.")

##############################DNS##############################
if 'DNS' in detected_services:
    with open("DNS.txt", "w") as r:
        print(colored('DNS', 'red'),"is Present")
        print("Running dig....")
        cmd = ["dig", "any", target]
        print(" ".join(cmd))
        subprocess.run(cmd, stdout=r)
        print(colored('Output located in DNS.txt.', 'yellow'))

##############################RPC##############################
if 'RPC' in detected_services or 'SMB445' in detected_services:
    with open("Anon_logon.txt", "w") as r:
        print(colored('SMB', 'red'),"is Present")
        print("Running enum4linux....")
        cmd = ["enum4linux-ng", "-A", target]
        print(" ".join(cmd))
        subprocess.run(cmd, stdout=r)
        print("Running nxc smb....")
        cmd = ["nxc", "smb", target, "-u", "", "-p", "", "--shares"]
        print(" ".join(cmd))
        subprocess.run(cmd, stdout=r)
        print(colored('Output located in Anon_logon.txt.', 'yellow'))

##############################Hostname##############################
def extract_hostname_from_file(file_path):
    try:
        with open(file_path, 'r') as file:
            output_text = file.read()
            # Regex pattern to find hostname after "Did not follow redirect to"
            pattern = r'Did not follow redirect to (http|https)://([^/\s]+)'
            match = re.search(pattern, output_text)
            if match:
                return match.group(2)  # Return the hostname captured by group 2
            else:
                return None
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        return None

# Example usage
file_path = "Results.txt"
hostname = extract_hostname_from_file(file_path)
if hostname:
    print(f"Hostname found: {hostname}")
else:
    print("No hostname found or file not found.")


##############################HTTP/HTTPS##############################  
if 'HTTP' in detected_services or 'HTTPS' in detected_services:
    print(colored('HTTP/HTTPS', 'red'),"is Present")
    fuff_runner = input("Would you like to ffuf? (Y/N): ").strip().upper()
    if fuff_runner == "Y":
        Super_runner = input("Would you like to FFUF and IP or HOSTNAME?(If you are fuzzing a hostname add to /etc/hosts file before continuing)").strip().upper()
        if Super_runner == "IP":
            with open("http.txt", "w") as r:
                print("ffufing files.....")
                cmd = ["ffuf", "-w", "/usr/share/seclists/Discovery/Web-Content/raft-medium-files-lowercase.txt:FUZZ", "-u", f"http://{target}/FUZZ"]
                print(" ".join(cmd))
                subprocess.run(cmd, stdout=r, stderr=subprocess.PIPE, universal_newlines=True)
                print("ffufing directories....")
                cmd = ["ffuf", "-w", "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt:FUZZ", "-u", f"http://{target}/FUZZ"]
                print(" ".join(cmd))
                subprocess.run(cmd, stdout=r, stderr=subprocess.PIPE, universal_newlines=True)
                print(colored('Output located in http.txt.', 'yellow'))
        elif Super_runner == "HOSTNAME":
            with open("http.txt", "w") as r:
                Hosty = input("What is the hostname?: ")
                print("ffufing files.....")
                cmd = ["ffuf", "-w", "/usr/share/seclists/Discovery/Web-Content/raft-medium-files-lowercase.txt:FUZZ", "-u", f"http://{Hosty}/FUZZ"]
                print(" ".join(cmd))
                subprocess.run(cmd, stdout=r, stderr=subprocess.PIPE, universal_newlines=True)
                print("ffufing directories....")
                cmd = ["ffuf", "-w", "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt:FUZZ", "-u", f"http://{Hosty}/FUZZ"]
                print(" ".join(cmd))
                subprocess.run(cmd, stdout=r, stderr=subprocess.PIPE, universal_newlines=True)
                print(colored('Output located in http.txt.', 'yellow'))
                print(colored(f"Automated VHOST fuzzing currently unavaible run the following if you wish to check for vhosts: \nffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://{Hosty}/ -H 'Host: FUZZ.{Hosty}' -ac", "green"))
        else:
            print("Invalid input. Please enter 'IP' or 'HOSTNAME'.")
    elif fuff_runner == "N":
        print("Skipping ffuf...")
    else:
        print("Invalid input. Please enter 'Y' or 'N'.")


"""BROKEN Vhost hunter
    sub_runner = input("Would you like to fuzz for vhosts? /n **Hostname is required** (Y/N): ").strip().upper()
    Hostt = input("What is the hostname?: ")
    if sub_runner == "Y":
        with open("Subhost.txt", "w") as r:
            print("ffufing vhosts....")
            cmd = ["wfuzz", "-H", f"'Host: FUZZ.{Hostt}'", "--hc", "404,403,301", "-H", "'User-Agent: PENTEST'", "-c", "-z", "file,'/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt'", f"{target}"]
            print(" ".join(cmd))
            subprocess.run(cmd, stdout=r, stderr=subprocess.PIPE, universal_newlines=True)
            print(colored('Output located in Subhost.txt.', 'yellow'))
    elif fuff_runner == "N":
        print("Skipping ffuf...")
    else:
        print("Invalid input. Please enter 'Y' or 'N'.")
"""

##############################RDP##############################
if 'RDP' in detected_services:
    print(colored('RDP', 'red'),"is open on standard port, come back when you have credientals.")

##############################WINRM##############################
if 'WINRM' in detected_services:
    print(colored('WINRM', 'red'),"is open on standard port, come back when you have credientals.")

# Output unknown ports
if unknown_ports:
    print(colored("Ports without known services found:", 'green'))
    for port in sorted(unknown_ports, key=int):
        print(colored(port, 'blue'))

# End message
print(colored("Graves have been dug, good luck!", 'magenta'))
