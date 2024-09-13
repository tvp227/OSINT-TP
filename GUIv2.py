import tkinter as tk
import subprocess
import getpass
import sys

username = getpass.getuser()

def execute_script(script):
    subprocess.Popen(["python3", script])
    sys.exit()

def create_main_window():
    window = tk.Tk()
    window.title("OSINT Quick Search")
    window.geometry("570x285")
    window.resizable(False, False)

    background_image = tk.PhotoImage(file="Prereq/background.png")
    background_label = tk.Label(window, image=background_image)
    background_label.place(x=0, y=0, relwidth=1, relheight=1)

    domain_button = tk.Button(window, text="Domain", command=lambda: execute_script(f"C:/Users/{username}/Documents/OSINT-TP/automation/domain.py"))
    domain_button.place(x=50, y=50, width=120, height=40)

    ip_button = tk.Button(window, text="IP", command=lambda: execute_script(f"C:/Users/{username}/Documents/OSINT-TP/automation/IP.py"))
    ip_button.place(x=50, y=100, width=120, height=40)

    md5_button = tk.Button(window, text="MD5", command=lambda: execute_script(f"C:/Users/{username}/Documents/OSINT-TP/automation/md5.py"))
    md5_button.place(x=50, y=150, width=120, height=40)

    window.mainloop()

print(f"Welcome, {username}, to quick OSINT by Tom Porter.")
print("Please select a category")

create_main_window()