# basicMitm.py

## Overview
`basicMitm.py` is a simple Python script that demonstrates **ARP poisoning / MITM** in a controlled lab environment.  
Think of it as a hands-on tool to learn how ARP spoofing works, see network traffic in action, and understand the risks and mitigations.  

![alt SyslogPic](screenshotA.png)

---

## Features
- Perform ARP poisoning between a router and a victim host (so just basic mechanism tho).  
- Grab MAC addresses automatically using `getmacbyip`.  
- Enable IP forwarding temporarily to relay packets by ```subprocess.Popen```.  
- Real-time packet sniffing with summaries.  
- Restores normal network traffic when you exit the script.  
- Pretty straight forward terminal output with colors for better readability.  

---

## Requirements
- Python 3.x  
- Linux environment (requires root privileges)  
- Python packages: `scapy`, `colorama`, `netifaces`

Install dependencies:
```pip install scapy colorama netifaces```

## How to Use

1.Clone the repo and go into the folder:
```
git clone https://github.com/YourUsername/Basic.py.git 
cd basicMitm.py
```

2.Run the script with root - important!:
```sudo python3 basicMitm.py```

3.Enter the requested info.
Watch the script run: it will poison the ARP caches, sniff packets, and show summaries in real-time.
4.Stop it anytime with Ctrl+C — it automatically restores ARP tables to prevent lasting network issues.

## Safety & Ethics
Use **only** in **lab** or **test networks**.
Always **have permission** to test.
Do **not use** on production or external networks.
I am **not responsible** for any misuse or damage.
The script will try to restore traffic on exit, but always double-check your test environment.
and again..

### **Important:** This is purely for **educational purposes**. Do not use it on networks you do not own or have permission to test. I am **not responsible** for any misuse, damage, or legal consequences caused by running this script.


## License
**MIT**
