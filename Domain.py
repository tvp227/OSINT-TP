import tkinter as tk
import requests
from datetime import datetime
import webbrowser
from bs4 import BeautifulSoup
import sys
import os

# Vendor Capture

def vendor_flag_search(domain):
    api_key = "1f08d5da08c5d5ea80ebd9a8873d00a2024b7d7bf6c7e77096da3c0338dc3a0d"  # VT API key
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
        button1["bg"] = "green"
    else:
        button1["bg"] = "black"

# DNS Capture

def dns_records_search(domain, report_file=None):
    api_key = "1f08d5da08c5d5ea80ebd9a8873d00a2024b7d7bf6c7e77096da3c0338dc3a0d"  # VT API key
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
        button2["bg"] = "green"
    else:
        button2["bg"] = "black"

# WHOIS Capture

def perform_whois_lookup(domain, report_file=None):
    api_key = "1f08d5da08c5d5ea80ebd9a8873d00a2024b7d7bf6c7e77096da3c0338dc3a0d"
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
        button3["bg"] = "green"
    else:
        button3["bg"] = "black"

# URL2PNG implementation 

def button5_clicked():
    url = "https://www.url2png.com/"
    webbrowser.open_new(url)

# Google Search function

def google_search(domain, report_file=None):
    search_term = f"What is {domain}"
    api_key = "199f400acde13092947ed40f48b68ed69049b1a2b29a054cee812ef2ddbd746c" # Serpapi API key
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
        button6["bg"] = "green"
    else:
        button6["bg"] = "black"

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


#Generate HTML report

def generate_report(domain):
    report_filename = f"report_{domain}.html"

    # Create the HTML report
    with open(report_filename, "w") as report_file:
        report_file.write(f"<!DOCTYPE html>\n<html>\n<head>\n<title>OSINT Report for {domain}</title>\n</head>\n<body>\n")
        report_file.write(f"<h1>--- OSINT Report for {domain} ---</h1>\n")
        report_file.write("<br/>\n")

        # Vendor Flag Search
        report_file.write("<h2>Vendor Flag Search</h2>\n")
        api_key = "1f08d5da08c5d5ea80ebd9a8873d00a2024b7d7bf6c7e77096da3c0338dc3a0d"  # VT API key
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
        api_key = "1f08d5da08c5d5ea80ebd9a8873d00a2024b7d7bf6c7e77096da3c0338dc3a0d"  # VT API key
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
        api_key = "1f08d5da08c5d5ea80ebd9a8873d00a2024b7d7bf6c7e77096da3c0338dc3a0d"
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
        summary_str = "Summary: "
        if vendor_flag_score is not None:
            summary_str += f"This domain has {vendor_flag_score} vendor flags. "
        else:
            summary_str += "No vendor flag information available. "

        try:
            creation_date = data["data"]["attributes"]["whois_date"]
            if creation_date:
                creation_timestamp = int(creation_date)
                creation_datetime = datetime.utcfromtimestamp(creation_timestamp)
                creation_date_str = creation_datetime.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
                domain_age_days = (datetime.utcnow() - creation_datetime).days
                summary_str += f"The domain was created on {creation_date_str}. It is approximately {domain_age_days} days old. "
            else:
                summary_str += "No creation date information available. "
        except KeyError:
            summary_str += "No creation date information available. "

        # Add DNS records information to the summary
        if dns_records:
            record_types = set(record["type"] for record in dns_records)
            num_dns_records = len(dns_records)
            dns_summary = f"This domain has {num_dns_records} DNS records, including: "
            if "A" in record_types:
                dns_summary += "'A' record (IPv4 address), "
            if "AAAA" in record_types:
                dns_summary += "'AAAA' record (IPv6 address), "
            if "CNAME" in record_types:
                dns_summary += "'CNAME' record, "
            if "MX" in record_types:
                dns_summary += "'MX' record (mail exchange), "
            if "TXT" in record_types:
                dns_summary += "'TXT' record, "
            # Addding more DNS enrichment in time 

            dns_summary += "meaning it can receive emails and may have additional configurations. "
            summary_str += dns_summary


        # Work in progree and am currently adding more to enrich the summary tab

        report_file.write(f"<p>{summary_str}</p>\n")

        report_file.write("<br/>\n")
        report_file.write("</body>\n</html>")

    print(f"HTML Report generated successfully. Filename: {report_filename}")


def button7_clicked():
    domain = domain_entry.get()
    generate_report(domain)


# Execute button clicked

def execute_clicked():
    domain = domain_entry.get()
    if button1["bg"] == "green":
        vendor_flag_search(domain)
    if button2["bg"] == "green":
        dns_records_search(domain)
    if button3["bg"] == "green":
        perform_whois_lookup(domain)
    if button6["bg"] == "green":
        google_search(domain)

# Create the main window
window = tk.Tk()
window.title("OSINT Quick Search")
window.geometry("580x300")
window.resizable(False, False)

# Set the background image
background_image = tk.PhotoImage(file="/home/tom/Documents/OSINT-TP/Prereq/background.png")
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

button5 = tk.Button(window, text="URL2PNG", fg="black", bg="yellow", command=button5_clicked)
button5.place(x=300, y=150, width=200, height=30)

button6 = tk.Button(window, text="Google Search", fg="white", bg="black", command=button6_clicked)
button6.place(x=300, y=100, width=200, height=30)

button7 = tk.Button(window, text="Generate Report", fg="white", bg="blue", command=button7_clicked)
button7.place(x=300, y=200, width=200, height=30)

execute_button = tk.Button(window, text="Execute", fg="white", bg="green", command=execute_clicked)
execute_button.place(x=225, y=250, width=100, height=30)

window.mainloop()