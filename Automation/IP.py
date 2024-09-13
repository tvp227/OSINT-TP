import tkinter as tk
import requests
from datetime import datetime
import webbrowser
from bs4 import BeautifulSoup
import sys
import os
import ssl
import socket


# IP Abuse Report

def ip_abuse_report(ip, report_file):
    api_key = ""
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Raise an exception if the request was not successful
        data = response.json()
        if "data" in data:
            abuse_report = data["data"]
            abuse_score = abuse_report.get("abuseConfidenceScore", "N/A")
            isp = abuse_report.get("isp", "N/A")
            usage_type = abuse_report.get("usageType", "N/A")
            hostnames = abuse_report.get("hostnames", [])
            domain = abuse_report.get("domain", "N/A")
            country = abuse_report.get("countryCode", "N/A")
            city = abuse_report.get("city", "N/A")

            report_file.write(f"IP Abuse Report for {ip}:\n")
            report_file.write(f"Abuse Score: {abuse_score}\n")
            report_file.write(f"ISP: {isp}\n")
            report_file.write(f"Usage Type: {usage_type}\n")
            report_file.write(f"Hostnames: {', '.join(hostnames)}\n")
            report_file.write(f"Domain: {domain}\n")
            report_file.write(f"Country: {country}\n")
            report_file.write(f"City: {city}\n")
        else:
            report_file.write(f"No abuse report found for {ip}\n")
    except requests.exceptions.RequestException as e:
        report_file.write(f"Error: {e}\n")

def print_abuse_report_to_terminal(ip):
    print(f"AbuseIPDB Report for {ip}:")
    ip_abuse_report(ip, sys.stdout)
def button1_clicked():
    if button1["bg"] == "black":
        button1["bg"] = "red"
    else:
        button1["bg"] = "black"


# Google Search function

def google_search(domain, report_file):
    search_term = f"What is {domain}"
    api_key = "" # Serpapi API key
    params = {
        "q": search_term,
        "api_key": api_key
    }

    try:
        response = requests.get("https://serpapi.com/search", params=params)
        response.raise_for_status()  # Raise an exception if the request was not successful
        data = response.json()
        if "organic_results" in data:
            organic_results = data["organic_results"]
            if organic_results:
                first_result = organic_results[0]
                title = first_result.get("title", "")
                url = first_result.get("link", "")
                snippet = first_result.get("snippet", "")
                soup = BeautifulSoup(snippet, "html.parser")
                description = soup.get_text(separator=" ")
                report_file.write(f"Google search summary for {domain}:\n")
                report_file.write(f"Title: {title}\n")
                report_file.write(f"URL: {url}\n")
                report_file.write(f"Description: {description}\n")
            else:
                report_file.write(f"No summary found for {domain}\n")
        else:
            report_file.write("Error: Invalid response format.\n")
    except requests.exceptions.RequestException as e:
        report_file.write(f"Error: {e}\n")

def button2_clicked():
    if button2["bg"] == "black":
        button2["bg"] = "red"
    else:
        button2["bg"] = "black"

#Defing the execute clicked button

def execute_clicked():
    IP = IP_entry.get()
    if button1["bg"] == "red":
        print("AbuseIPDB Report:")
        ip_abuse_report(IP, sys.stdout)

    if button2["bg"] == "red":
        print("Google Search Summary:")
        google_search(IP, sys.stdout)
    

#============================================================Generating a report======================================================================================================
#------------------------------------------------------------                   ------------------------------------------------------------------------------------------------------

def generate_report(IP):
    report_filename = f"report_{IP}.html"

    try:
        # Create the HTML report
            
        with open(report_filename, "w") as report_file:
            report_file.write("<!DOCTYPE html>\n<html>\n<head>\n<title>OSINT Report for {IP}</title>")
            report_file.write("<style>")
            report_file.write("body { font-family: Arial, sans-serif; margin: 30px; }")
            report_file.write("h1 { color: #2c3e50; text-align: center; }")
            report_file.write("h2 { color: #2980b9; }")
            report_file.write("ul { list-style-type: disc; padding-left: 30px; }")
            report_file.write("li { margin-bottom: 10px; }")
            report_file.write("p { margin-bottom: 15px; }")
            report_file.write("table { border-collapse: collapse; width: 100%; }")
            report_file.write("th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }")
            report_file.write("</style>")
            report_file.write("</head>\n<body>")
            report_file.write(f"<h1>OSINT Report for {IP}</h1>")
            report_file.write("<br/>")

            # Google Search
            report_file.write("<h2>Google Search</h2>\n")
            google_search(IP, report_file)
            report_file.write("<br/>\n")

            # IPDB 
            report_file.write("<h2>IPDB information</h2>\n")
            report_file.write("<ul>\n")
            with open(os.devnull, "w") as null_file:
                ip_abuse_report(IP, null_file)  # Write the IP Abuse Report to /dev/null
                ip_abuse_report(IP, report_file)  # Write the IP Abuse Report to the HTML report
            report_file.write("</ul>\n")
            report_file.write("<br/>\n")

            report_file.write("</body>\n</html>")

        print(f"Report generated successfully. The report is saved in {report_filename}")
    except Exception as e:
        print(f"Error generating the report: {e}")

        report_file.write("</body>\n</html>")

        print(f"Report generated successfully. The report is saved in {report_filename}")
    except Exception as e:
        print(f"Error generating the report: {e}")
    
def button4_clicked():
    IP = IP_entry.get()
    generate_report(IP)

# Create the main window
window = tk.Tk()
window.title("OSINT Quick Search")
window.geometry("570x285")
window.resizable(False, False)

# Set the background image
background_image = tk.PhotoImage(file="Prereq/background2.png")
background_label = tk.Label(window, image=background_image)
background_label.place(x=0, y=0, relwidth=1, relheight=1)

# Create the IP input box
IP_label = tk.Label(window, text="Enter IP:")
IP_label.place(x=235, y=28)

IP_entry = tk.Entry(window)
IP_entry.place(x=190, y=50, width=200)

# Create the buttons
button1 = tk.Button(window, text="AbuseIPDB", fg="white", bg="black", command=button1_clicked)
button1.place(x=50, y=100, width=200, height=30)

button2 = tk.Button(window, text="Google search", fg="white", bg="black", command=button2_clicked)
button2.place(x=50, y=150, width=200, height=30)

button3 = tk.Button(window, text="Execute", fg="white", bg="red", command=execute_clicked)
button3.place(x=300, y=100, width=200, height=30)

button4 = tk.Button(window, text="Generate report", fg="white", bg="red", command=lambda: generate_report(IP_entry.get()))
button4.place(x=300, y=150, width=200, height=30)

window.mainloop()

