# Netscanner — Python Network Scanner

**NetScanner** is a powerful and educational Python-based tool that automates network reconnaissance using Nmap.  
It performs:
- 🧭 **Target Discovery**
- ⚙️ **Port & Service Enumeration**
- 🧬 **Service Fingerprinting**
- 🛡️ **Vulnerability Detection (Nmap NSE)**
- 🔗 Optional **Nmap → OpenVAS Pipeline**

> ⚠️ Use this tool only on systems you own or have **explicit permission** to test.  
> Unauthorized scanning is illegal and unethical.

---

## 🧰 Features

✅ Target Discovery (Ping/ARP Scan)  
✅ Service Detection & Fingerprinting (`-sV`)  
✅ Vulnerability Detection using NSE scripts  
✅ OS Fingerprinting (optional `-O`)  
✅ SQLite Database for all scan results  
✅ Optional OpenVAS integration  
✅ Interactive Target Input if no `--targets` specified  

---

## 🖥️ System Requirements

| Requirement | Description |
|--------------|-------------|
| OS | Kali Linux / Ubuntu / Debian |
| Python | 3.8 or newer |
| Tools | `nmap`, `sqlite3` |
| Optional | `arp-scan`, `gvm-tools` |

---

## ⚙️ Installation

### 1️⃣ Clone this repository
```bash
git clone https://github.com/Rohitkattewar18/Netscanner
cd NetScanner
