#!/bin/python3

import subprocess
import ipaddress
from tqdm import tqdm
from termcolor import colored

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
    'FTP': '21/tcp    open',
    'SSH': '22/tcp    open',
    'TELNET': '23/tcp    open',
    'SMTP': '25/tcp    open',
    'DNS': '53/tcp    open',
    'HTTP': '80/tcp    open',
    'KERBEROS': '88/tcp    open',
    'RPC': '135/tcp   open',
    'SMB137': '139/tcp   open',
    'SMB445': '445/tcp   open',
    'POP3': '110/tcp',
    'IMAP': '143/tcp',
    'HTTPS': '443/tcp   open',
    'RDP': '3389/tcp  open',
    'WINRM': '5985/tcp  open'
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
if 'DNS' in detected_services:
    with open("DNS.txt", "w") as r:
        print(colored('DNS', 'red'),"is Present")
        print("Running dig....")
        cmd = ["dig", "any", target]
        subprocess.run(cmd, stdout=r)
        print(colored('Output located in DNS.txt', 'yellow'))

if 'RPC' in detected_services or 'SMB445' in detected_services:
    with open("Anon_logon.txt", "w") as r:
        print(colored('SMB', 'red'),"is Present")
        print("Running enum4linux....")
        cmd = ["enum4linux-ng", "-A", target]
        subprocess.run(cmd, stdout=r)
        print("Running nxc smb....")
        cmd = ["nxc", "smb", target, "-u", "", "-p", "", "--shares"]
        subprocess.run(cmd, stdout=r)
        print(colored('Output located in Anon_logon.txt', 'yellow'))

if 'HTTP' in detected_services or 'HTTPS' in detected_services:
    print(colored('HTTP/HTTPS', 'red'),"is Present")
    fuff_runner = input("Would you like to ffuf the IP? (Y/N): ").strip().upper()
    if fuff_runner == "Y":
        with open("http.txt", "w") as r:
            print("ffufing files.....")
            cmd = ["ffuf", "-w", "/usr/share/seclists/Discovery/Web-Content/raft-medium-files-lowercase.txt:FUZZ", "-u", f"http://{target}/FUZZ"]
            subprocess.run(cmd, stdout=r)
            print("ffufing directories....")
            cmd = ["ffuf", "-w", "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt:FUZZ", "-u", f"http://{target}/FUZZ"]
            subprocess.run(cmd, stdout=r)
            print(colored('Output located in http.txt', 'yellow'))
    elif fuff_runner == "N":
        print("Skipping ffuf...")
    else:
        print("Invalid input. Please enter 'Y' or 'N'.")

if 'RDP' in detected_services:
    print(colored('RDP', 'red'),"is open on standard port, come back when you have credientals")

if 'WINRM' in detected_services:
    print(colored('WINRM', 'red'),"is open on standard port, come back when you have credientals")

# Output unknown ports
if unknown_ports:
    print(colored("Ports not without known services found:", 'green'))
    for port in sorted(unknown_ports, key=int):
        print(colored(port, 'blue'))

# End message
print(colored("Graves have been dug, good luck!", 'magenta'))
