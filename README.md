<p align="center">
  <img src="Boryoku-logo.png" alt="Boryoku Logo" width="400"/>
</p>

# Bōryoku - SMB Guest Access Scanner

[![Author](https://img.shields.io/badge/author-Dion%20Mulaj-blue)](https://github.com/dionmulaj)  
[![Python Version](https://img.shields.io/badge/python-3%2B-green)](https://www.python.org/)

---

## Overview

**Bōryoku** is a lightweight SMB Guest Access Scanner focused on identifying open SMB ports in a target IP range and checking for anonymous (guest) access to shares. It helps pentesters and sysadmins quickly discover SMB shares vulnerable to unauthorized guest access.

<p align="left">
  <img src="example.png" alt="Boryoku Example" width="350"/>
</p>

---

## ✨ Features

- 🔍 **Port Scanning:** Detects hosts with open SMB ports.
- 🔓 **Anonymous SMB Login:** Attempts guest access using null credentials.
- 📂 **Share Enumeration:** Lists accessible shares on each host.
- 📁 **File/Folder Listing:** Displays top-level contents of each accessible share.
- 💾 **Optional Output Saving:** Use `-o` to write results to a file.
- 🎨 **Colorful CLI Output**.
- 🧾 **Clean Usage Help & Author Info** shown at startup.

---

## Installation

Make sure you have Python 3 installed.

```bash
git clone https://github.com/dionmulaj/boryoku.git
cd boryoku
pip install -r requirements.txt
```
---

## Troubleshooting

If you encounter errors while running the tool, it can most likely be because of Impacket misconfiguration.
To fix such an issue, try running the command below:

```bash
sudo apt install python3-pip python3-dev build-essential libssl-dev libffi-dev
```

