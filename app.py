import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import nmap
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
import time
import threading

result_list = []
services = []
result_lock = threading.Lock()

def scan_service(ip_address, service):
    try:
        driver = webdriver.Chrome()

        driver.get("https://www.exploit-db.com/search?")

        search_box = driver.find_element(By.ID, "titleSearch")
        search_box.send_keys(f"{service}")
        search_box.send_keys(Keys.RETURN)

        driver.implicitly_wait(10)

        result_element = driver.find_element(By.CSS_SELECTOR, "#exploits-table > tbody")
        result_text = result_element.text

        with result_lock:
            if "No data available in table" not in result_text:
                result_list.append(result_text)

        time.sleep(3)
        driver.quit()
    except Exception as e:
        print(f"scanning..!", {e})

def scan_ports(ip_address, port_range):
    try:
        scanner = nmap.PortScanner()
        scanner.scan(ip_address, port_range, arguments=f"-sV ")

        open_ports = []

        for host in scanner.all_hosts():
            for proto in scanner[host].all_protocols():
                lport = scanner[host][proto].keys()
                for port in lport:
                    service = scanner[host][proto][port]
                    port_info = {
                        "port": port,
                        "protocol": proto,
                        "service": service.get("product", "Unknown"),
                        "version": service.get("version", "Unknown"),
                        "state": service.get("state", "Unknown")
                    }
                    open_ports.append(port_info)

        if open_ports:
            print("Open ports:")
            for port_info in open_ports:
                services.append(port_info["service"] + " " + port_info["version"])
        else:
            print("No open ports found.")

        threads = []

        for i in services:
            thread = threading.Thread(target=scan_service, args=(ip_address, i))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        return result_list
    except Exception as e:
        print(f"scanning1..!", {e})
        return []

def gui():
    ip = ip_entry.get()
    port_range_str = port_entry.get()

    if not port_range_str:
        messagebox.showerror("Error", "Please enter a port range")
        return

    try:
        start_port, end_port = map(int, port_range_str.split('-'))
    except ValueError:
        messagebox.showerror("Error", "Port range should contain only numbers in the format 'start-end'")
        return

    result_box.config(state=tk.NORMAL)
    result_box.delete(1.0, tk.END)  # Clear the text box

    result_list = scan_ports(ip, f"{start_port}-{end_port}")

    for result in result_list:
        result_box.insert(tk.END, result + '\n')

    result_box.config(state=tk.DISABLED)

app = tk.Tk()
app.title("Port Scanner")

frame = ttk.Frame(app)
frame.grid(column=0, row=0, padx=10, pady=10)

ip_label = ttk.Label(frame, text="IP Address:")
ip_label.grid(column=0, row=0, sticky=tk.W)

ip_entry = ttk.Entry(frame)
ip_entry.grid(column=1, row=0, padx=5)

port_label = ttk.Label(frame, text="Port Range (e.g., 80-100):")
port_label.grid(column=0, row=1, sticky=tk.W)

port_entry = ttk.Entry(frame)
port_entry.grid(column=1, row=1, padx=5)

scan_button = ttk.Button(frame, text="Scan Ports", command=gui)
scan_button.grid(column=0, row=2, columnspan=2, pady=10)

result_box = tk.Text(frame, wrap=tk.WORD, state=tk.DISABLED)
result_box.grid(column=0, row=3, columnspan=2, pady=10)

app.mainloop()
