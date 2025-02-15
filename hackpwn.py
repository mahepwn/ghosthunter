import socket
import requests
import threading
import tkinter as tk
from tkinter import messagebox, ttk
import subprocess

# Function to scan ports
def scan_ports(target, option):
    open_ports = []
    if option == "Common Ports":
        ports = [22, 80, 443, 21, 53]
    elif option == "Full Scan":
        ports = range(1, 65535)
    else:
        return []
    
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports

# Function to perform subdomain enumeration
def enumerate_subdomains(domain):
    subdomains = []
    subdomains_list = ["www", "mail", "ftp", "blog", "test"]
    for subdomain in subdomains_list:
        subdomain_url = f"http://{subdomain}.{domain}"
        try:
            response = requests.get(subdomain_url)
            if response.status_code == 200:
                subdomains.append(subdomain_url)
        except requests.exceptions.RequestException:
            pass
    return subdomains

# Function to run basic vulnerability scan (using nmap for simplicity)
def run_vuln_scan(target):
    try:
        result = subprocess.run(['nmap', '-sV', target], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.stdout.decode('utf-8')
    except Exception as e:
        return f"Error: {e}"

# Function to handle port scan button click (with threading)
def start_port_scan():
    target = target_entry.get()
    option = port_option.get()
    result_label.config(text="Scanning ports... Please wait.")
    
    def port_scan_thread():
        open_ports = scan_ports(target, option)
        result_text = f"Port Scan Results:\nOpen ports: {', '.join(map(str, open_ports))}" if open_ports else "No open ports found."
        result_label.config(text=result_text)
    
    # Run the port scan in a separate thread
    threading.Thread(target=port_scan_thread).start()

# Function to handle subdomain enumeration button click (with threading)
def start_subdomain_enum():
    domain = target_entry.get()
    result_label.config(text="Enumerating subdomains... Please wait.")
    
    def subdomain_enum_thread():
        subdomains = enumerate_subdomains(domain)
        result_text = "Subdomain Enumeration Results:\n"
        if subdomains:
            result_text += "\n".join(subdomains)
        else:
            result_text += "No subdomains found."
        result_label.config(text=result_text)
    
    # Run the subdomain enumeration in a separate thread
    threading.Thread(target=subdomain_enum_thread).start()

# Function to handle vulnerability scan button click (with threading)
def start_vuln_scan():
    target = target_entry.get()
    result_label.config(text="Running vulnerability scan... Please wait.")
    
    def vuln_scan_thread():
        results = run_vuln_scan(target)
        result_text = f"Vulnerability Scan Results:\n{results}"
        result_label.config(text=result_text)
    
    # Run the vulnerability scan in a separate thread
    threading.Thread(target=vuln_scan_thread).start()

# Create the main window
root = tk.Tk()
root.title("Security Scanner Tool")
root.geometry("800x600")  # Resize the window

# Create a tab control
tab_control = ttk.Notebook(root)

# Create frames for each functionality
port_scan_frame = ttk.Frame(tab_control)
subdomain_enum_frame = ttk.Frame(tab_control)
vuln_scan_frame = ttk.Frame(tab_control)

# Add frames to tab control
tab_control.add(port_scan_frame, text="Port Scanner")
tab_control.add(subdomain_enum_frame, text="Subdomain Enumeration")
tab_control.add(vuln_scan_frame, text="Vulnerability Scanner")
tab_control.pack(expand=1, fill="both")

# Port Scan Tab Widgets
target_label = tk.Label(port_scan_frame, text="Target Domain/IP:", font=("Arial", 14))
target_label.grid(row=0, column=0, padx=10, pady=10)
target_entry = tk.Entry(port_scan_frame, font=("Arial", 14))
target_entry.grid(row=0, column=1, padx=10, pady=10)

port_option_label = tk.Label(port_scan_frame, text="Select Port Scan Option:", font=("Arial", 14))
port_option_label.grid(row=1, column=0, padx=10, pady=10)

port_option = ttk.Combobox(port_scan_frame, values=["Common Ports", "Full Scan"], font=("Arial", 14))
port_option.set("Common Ports")  # Default value
port_option.grid(row=1, column=1, padx=10, pady=10)

scan_button = tk.Button(port_scan_frame, text="Start Port Scan", font=("Arial", 14), command=start_port_scan)
scan_button.grid(row=2, columnspan=2, pady=20)

# Subdomain Enum Tab Widgets
enum_button = tk.Button(subdomain_enum_frame, text="Start Subdomain Enumeration", font=("Arial", 14), command=start_subdomain_enum)
enum_button.grid(row=0, columnspan=2, pady=20)

# Vulnerability Scan Tab Widgets
vuln_scan_button = tk.Button(vuln_scan_frame, text="Start Vulnerability Scan", font=("Arial", 14), command=start_vuln_scan)
vuln_scan_button.grid(row=0, columnspan=2, pady=20)

# Result Label
result_label = tk.Label(root, text="Results will appear here.", font=("Arial", 14), justify=tk.LEFT)
result_label.pack(pady=20)

# Run the GUI loop
root.mainloop()

