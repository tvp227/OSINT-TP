import tkinter as tk
import requests
from datetime import datetime
import webbrowser
from bs4 import BeautifulSoup
import sys
import os
import ssl
import socket

# Vendor Capture

def vendor_flag_search(domain):
    api_key = ""  # VT API key
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {
        "x-apikey": api_key
    }

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            vendor_flag_stats = data["data"]["attributes"]["last_analysis_stats"]
            malicious_vendors = []

            if isinstance(vendor_flag_stats["malicious"], dict):
                malicious_vendors = [vendor for vendor, result in vendor_flag_stats["malicious"].items() if result]
                num_malicious_vendors = len(malicious_vendors)
            else:
                num_malicious_vendors = vendor_flag_stats["malicious"]

            if num_malicious_vendors > 0:
                print(f"{num_malicious_vendors} vendor(s) deemed {domain} malicious.")
                if malicious_vendors:
                    print("Vendors that deemed it malicious:")
                    for vendor in malicious_vendors:
                        print(f"- {vendor}")
            else:
                print(f"No malicious vendors found for {domain}")
        else:
            print("Error: Request failed.")
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")


def button1_clicked():
    if button1["bg"] == "black":
        button1["bg"] = "red"
    else:
        button1["bg"] = "black"

# DNS Capture

def dns_records_search(domain, report_file=None):
    api_key = ""  # VT API key
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": api_key}

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        if "data" in data and "attributes" in data["data"]:
            dns_records = data["data"]["attributes"]["last_dns_records"]
            for record in dns_records:
                if report_file:
                    report_file.write(f"DNS Record: {record}\n")
                else:
                    print(f"DNS Record: {record}")
        else:
            if report_file:
                report_file.write(f"No DNS records found for {domain}\n")
            else:
                print(f"No DNS records found for {domain}")
    except requests.exceptions.RequestException as e:
        if report_file:
            report_file.write(f"Error: {e}\n")
        else:
            print(f"Error: {e}")

def button2_clicked():
    if button2["bg"] == "black":
        button2["bg"] = "red"
    else:
        button2["bg"] = "black"

# WHOIS Capture

def perform_whois_lookup(domain, report_file=None):
    api_key = ""
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": api_key}

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        if "data" in data and "attributes" in data["data"]:
            whois_info = data["data"]["attributes"]["whois"]
            if report_file:
                report_file.write(f"WHOIS Lookup for {domain}:\n{whois_info}\n")
            else:
                print(f"WHOIS Lookup for {domain}:\n{whois_info}")
        else:
            if report_file:
                report_file.write(f"No WHOIS information found for {domain}\n")
            else:
                print(f"No WHOIS information found for {domain}")
    except requests.exceptions.RequestException as e:
        if report_file:
            report_file.write(f"Error: {e}\n")
        else:
            print(f"Error: {e}")

def button3_clicked():
    if button3["bg"] == "black":
        button3["bg"] = "red"
    else:
        button3["bg"] = "black"

# URL2PNG implementation 

def button5_clicked():
    url = "https://www.url2png.com/"
    webbrowser.open_new(url)

# Google Search function

def google_search(domain, report_file=None):
    search_term = f"What is {domain}"
    api_key = "" # Serpapi API key
    params = {
        "q": search_term,
        "api_key": api_key
    }

    try:
        response = requests.get("https://serpapi.com/search", params=params)
        if response.status_code == 200:
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
                    result_str = f"Google search summary for {domain}:\nTitle: {title}\nURL: {url}\nDescription: {description}\n"
                    if report_file:
                        report_file.write(result_str)
                    else:
                        print(result_str)
                else:
                    no_summary_str = f"No summary found for {domain}\n"
                    if report_file:
                        report_file.write(no_summary_str)
                    else:
                        print(no_summary_str)
            else:
                invalid_response_str = "Error: Invalid response format.\n"
                if report_file:
                    report_file.write(invalid_response_str)
                else:
                    print(invalid_response_str)
        else:
            request_failed_str = "Error: Request failed.\n"
            if report_file:
                report_file.write(request_failed_str)
            else:
                print(request_failed_str)
    except requests.exceptions.RequestException as e:
        error_str = f"Error: {e}\n"
        if report_file:
            report_file.write(error_str)
        else:
            print(error_str)
def button6_clicked():
    if button6["bg"] == "black":
        button6["bg"] = "red"
    else:
        button6["bg"] = "black"

# SecurityTrails Subdomains request

def securitytrails_subdomains_enrichment(domain, report_file=None):
    api_key = "" #Security trails API key
    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    headers = {"APIKEY": api_key}

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        subdomains = data.get("subdomains", [])
        if subdomains:
            if report_file:
                report_file.write("<h2>SecurityTrails Subdomains</h2>\n")
                report_file.write("<ul>\n")
                for subdomain in subdomains:
                    report_file.write(f"<li>{subdomain}.{domain}</li>\n")
                report_file.write("</ul>\n")
            else:
                print("<h2>SecurityTrails Subdomains</h2>")
                print("<ul>")
                for subdomain in subdomains:
                    print(f"<li>{subdomain}.{domain}</li>")
                print("</ul>")
        else:
            if report_file:
                report_file.write("<p>No SecurityTrails subdomains found for this domain.</p>\n")
            else:
                print("<p>No SecurityTrails subdomains found for this domain.</p>")
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        if report_file:
            report_file.write(f"<p>Error: {e}</p>\n")
        else:
            print(f"Error: {e}")

def button4_clicked():
    if button4["bg"] == "black":
        button4["bg"] = "red"
    else:
        button4["bg"] = "black"

# Function to fetch SSL certificate information

def get_ssl_info(domain):
    try:
        # Use the requests library to send an HTTP GET request to the domain with HTTPS protocol
        response = requests.get(f"https://{domain}")

        if response.status_code == 200:
            return f"The website '{domain}' has an SSL certificate."
        else:
            return f"The website '{domain}' does not have an SSL certificate."
    except requests.exceptions.RequestException as e:
        return f"An error occurred while trying to connect to the website: {e}"

def button8_clicked():
    if button8["bg"] == "black":
        button8["bg"] = "red"
    else:
        button8["bg"] = "black"

# Google Image Search 

def google_images_search(domain):
    search_term = f"{domain} site:{domain} homepage screenshot"  # Add more relevant keywords as needed
    search_url = "https://www.googleapis.com/customsearch/v1"
    params = {
        "key": "AIzaSyBWjrOdZPsnXcTrom1NikBoRbri9fbo8zY",  # Google Custom Search API key
        "cx": "271426e1b03bb4534",  # search engine ID
        "q": search_term,
        "searchType": "image",
    }

    try:
        response = requests.get(search_url, params=params)
        response.raise_for_status()
        data = response.json()
        if "items" in data:
            image_urls = [item["link"] for item in data["items"]]
            return image_urls
        else:
            return []
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        return []

#---------------------Generate HTML report------------------------------------------------------------------------------------------------------------------------------------------
#--------------------                     ------------------------------------------------------------------------------------------------------------------------------------------

def generate_report(domain):
    report_filename = f"report_{domain}.html"

    # Create the HTML report
    with open(report_filename, "w") as report_file:
        report_file.write("<!DOCTYPE html>\n<html>\n<head>\n<title>OSINT Report for {domain}</title>")
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
        report_file.write(f"<h1>OSINT Report for {domain}</h1>")
        report_file.write("<br/>")

        # Vendor Flag Search
        report_file.write("<h2>Vendor Flag Search</h2>\n")
        api_key = ""  # Replace with your actual VirusTotal API key
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {"x-apikey": api_key}

        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                vendor_flag_score = data["data"]["attributes"]["last_analysis_stats"]["malicious"]
                result_str = f"Vendor Flag Score for {domain}: {vendor_flag_score}\n"
                report_file.write(result_str)
            else:
                error_str = "Error: Request failed.\n"
                report_file.write(error_str)
        except requests.exceptions.RequestException as e:
            error_str = f"Error: {e}\n"
            report_file.write(error_str)

        report_file.write("<br/>\n")

        # DNS Records Search
        report_file.write("<h2>DNS Records Search</h2>\n")
        api_key = ""  # Replace with your actual VirusTotal API key
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {"x-apikey": api_key}

        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            data = response.json()
            if "data" in data and "attributes" in data["data"]:
                dns_records = data["data"]["attributes"]["last_dns_records"]
                if dns_records:
                    report_file.write("<ul>\n")
                    for record in dns_records:
                        report_file.write(f"<li>{record}</li>\n")
                    report_file.write("</ul>\n")
                else:
                    no_info_str = f"No DNS records found for {domain}\n"
                    report_file.write(no_info_str)
            else:
                no_info_str = f"No DNS records found for {domain}\n"
                report_file.write(no_info_str)
        except requests.exceptions.RequestException as e:
            error_str = f"Error: {e}\n"
            report_file.write(error_str)

        report_file.write("<br/>\n")

        # WHOIS Capture
        report_file.write("<h2>WHOIS Capture</h2>\n")
        api_key = ""  # Replace with your actual VirusTotal API key
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {"x-apikey": api_key}

        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            data = response.json()
            if "data" in data and "attributes" in data["data"]:
                whois_info = data["data"]["attributes"]["whois"]
                whois_info_list = whois_info.split("\n")
                report_file.write("<ul>\n")
                for item in whois_info_list:
                    report_file.write(f"<li>{item}</li>\n")
                report_file.write("</ul>\n")
            else:
                no_info_str = f"No WHOIS information found for {domain}\n"
                report_file.write(no_info_str)
        except requests.exceptions.RequestException as e:
            error_str = f"Error: {e}\n"
            report_file.write(error_str)

        report_file.write("<br/>\n")       
        
        # Subdomains Search (SecurityTrails)
        report_file.write("<h2>Subdomains Search (SecurityTrails)</h2>\n")
        securitytrails_subdomains_enrichment(domain, report_file)
        report_file.write("<br/>\n")

        # SSL Certificate Information
        report_file.write("<h2>SSL Certificate Information</h2>\n")
        ssl_info = get_ssl_info(domain)
        report_file.write(f"<p>{ssl_info}</p>\n")
        report_file.write("<br/>\n")
        
        # Google Search
        report_file.write("<h2>Google Search</h2>\n")
        google_search(domain, report_file)
        report_file.write("<br/>\n")

        # Google Images Search
        report_file.write("<h2>Google Images</h2>\n")
        image_urls = google_images_search(domain)
        if image_urls:
            report_file.write("<ul>\n")
            for image_url in image_urls:
                report_file.write(f"<li><img src='{image_url}' alt='Google Image' width='200'></li>\n")
            report_file.write("</ul>\n")
        else:
            report_file.write("<p>No Google Images found for this domain.</p>\n")

        # Summary
        report_file.write("<h2>Summary</h2>\n")
        api_key = ""  # Replace with your actual VirusTotal API key
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {"x-apikey": api_key}

        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            data = response.json()
            summary_str = "Summary: "

            # Vendor Flag Score
            vendor_flag_stats = data["data"]["attributes"]["last_analysis_stats"]
            malicious_vendors = vendor_flag_stats.get("malicious", 0)
            if isinstance(malicious_vendors, dict):
                num_malicious_vendors = len([vendor for vendor, result in malicious_vendors.items() if result])
            else:
                num_malicious_vendors = malicious_vendors
            summary_str += f"{num_malicious_vendors} vendor(s) flagged as malicious. "

            # Domain Age 
            registered_on = None
            if "data" in data and "attributes" in data["data"]:
                whois_info = data["data"]["attributes"].get("whois")
                if whois_info:
                    whois_info_lines = whois_info.split("\n")
                    for line in whois_info_lines:
                        if "Registered on:" in line:
                            registered_on = line.replace("Registered on:", "").strip()
                            break

            if registered_on:
                domain_age_days = (datetime.utcnow() - datetime.strptime(registered_on, "%d-%b-%Y")).days
                summary_str += f"The domain was registered on {registered_on}. It is approximately {domain_age_days} days old. "
            else:
                summary_str += "No registration date information available. "

            # DNS Records
            dns_records = data["data"]["attributes"]["last_dns_records"]
            num_dns_records = len(dns_records)
            summary_str += f"The domain has {num_dns_records} DNS record(s). "

            report_file.write(f"<p>{summary_str}</p>\n")

        except requests.exceptions.RequestException as e:
            report_file.write(f"<p>Error: {e}</p>\n")

        report_file.write("<br/>\n")
        report_file.write("</body>\n</html>")

    print(f"HTML Report generated successfully. Filename: {report_filename}")

def button7_clicked():
    domain = domain_entry.get()
    generate_report(domain)


# Execute button clicked

def execute_clicked():
    domain = domain_entry.get()
    if button1["bg"] == "red":
        vendor_flag_search(domain)
    if button2["bg"] == "red":
        dns_records_search(domain)
    if button3["bg"] == "red":
        perform_whois_lookup(domain)
    if button4["bg"] == "red":
        securitytrails_subdomains_enrichment(domain)
    if button6["bg"] == "red":
        google_search(domain)
    if button8["bg"] == "red":
        get_ssl_info(domain)

import tkinter as tk

# Create the main window
window = tk.Tk()
window.title("OSINT Quick Search")
window.geometry("570x285")
window.resizable(False, False)

# Set the background image
background_image = tk.PhotoImage(file="Prereq/background2.png")
background_label = tk.Label(window, image=background_image)
background_label.place(x=0, y=0, relwidth=1, relheight=1)

# Create the domain input box
domain_label = tk.Label(window, text="Enter Domain:")
domain_label.place(x=235, y=28)

domain_entry = tk.Entry(window)
domain_entry.place(x=190, y=50, width=200)

# Create the buttons
button1 = tk.Button(window, text="Vendor Flag Search", fg="white", bg="black", command=button1_clicked)
button1.place(x=50, y=100, width=200, height=30)

button2 = tk.Button(window, text="DNS Records", fg="white", bg="black", command=button2_clicked)
button2.place(x=50, y=150, width=200, height=30)

button3 = tk.Button(window, text="WHOIS", fg="white", bg="black", command=button3_clicked)
button3.place(x=50, y=200, width=200, height=30)

button4 = tk.Button(window, text="Subdomains", fg="white", bg="black", command=button4_clicked)
button4.place(x=300, y=100, width=200, height=30)

button5 = tk.Button(window, text="URL2PNG", fg="black", bg="yellow", command=button5_clicked)
button5.place(x=300, y=150, width=200, height=30)

button6 = tk.Button(window, text="Google Search", fg="white", bg="black", command=button6_clicked)
button6.place(x=300, y=200, width=200, height=30)

button7 = tk.Button(window, text="Generate Report", fg="white", bg="blue", command=button7_clicked)
button7.place(x=50, y=250, width=95, height=30)

button8 = tk.Button(window, text="SSL record", fg="white", bg="black", command=button8_clicked)
button8.place(x=300, y=250, width=200, height=30)

execute_button = tk.Button(window, text="Execute", fg="black", bg="orange red", command=execute_clicked)
execute_button.place(x=150, y=250, width=95, height=30)

window.mainloop()
