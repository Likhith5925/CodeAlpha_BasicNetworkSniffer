# 🦈 Advanced Kali Packet Sniffer & Protocol Analyzer

A real-time, web-based network telemetry and protocol analysis platform built specifically for the **Kali Linux** environment. This security tool operates at the intersection of network forensics and data visualization, capturing raw network frames and parsing them into a structured, interactive Security Operations Center (SOC) dashboard.

---

## 🛠️ System Architecture & How It Works

Unlike basic command-line packet sniffers that output hard-to-read walls of text, this tool uses a sophisticated **multi-threaded architecture** to separate data ingestion from user interface rendering.

### 1. The Data Ingestion Engine (Backend)
* **Raw Socket Capture:** The script invokes `scapy.all.sniff()` to interact directly with Kali Linux's raw sockets, placing the active network interface card (NIC) into a promiscuous capture state.
* **Asynchronous Execution:** The sniffing loop runs on a dedicated, non-blocking **Background Thread**. This ensures high-velocity packet bursts do not cause memory drops or freeze the web UI.
* **Thread-Safe Telemetry:** Because Python dictionaries are not inherently thread-safe, a mutual exclusion lock (`threading.Lock()`) protects the internal data structures during concurrent read/write actions between the sniffer thread and the web interface.

### 2. The Analytical Processing Pipeline
As a packet crosses the network interface, it is forced through a hierarchical parsing matrix that tracks data across the OSI Model layers:

[ Raw Packet Frame ]
│
├──► Layer 2 (Data Link) ──► If ARP: Extracts MAC addresses & Ops codes
│
└──► Layer 3 (Network)   ──► If IP: Unpacks TTL, Header Sizes, & Total Lengths
│
└──► Layer 4 (Transport) ──► If TCP: Decodes Ports, Sequence Numbers, & Flags
──► If UDP: Decodes Ports & Payload Lengths


### 3. The Web Interface Engine (Frontend)
The interface is driven by **Streamlit**, optimized via structural updates:
* **Memory Management:** Raw packet data can quickly exhaust system memory. To prevent crashes, the application uses a bounded `deque(maxlen=10)` structure to maintain a sliding window of only the 10 most recent packets for deep forensic inspection.
* **Streamlit Fragments:** Utilizing the `@st.fragment` decorator, only the visual charts, data tables, and metrics update inside a 1-second auto-refresh heartbeat loop. The main webpage does not re-render entirely, creating a highly performant data streaming experience.

---

## ⚙️ Core Analytical Features

| Component | Architecture Level | Analytical Value |
| :--- | :--- | :--- |
| **Protocol Slicing Profile** | Layer 4 (Transport) | Visualizes the distribution of TCP vs. UDP vs. ICMP traffic to profile network utilization trends. |
| **Traffic Conversation Matrix** | Cross-Layer Tracking | Correlates Source and Destination IPs into specific pairs, sorting them dynamically by total data throughput (Bytes). |
| **Layer Header Dissector** | Layer 3 & Layer 4 Fields | Unpacks protocol control fields (such as TCP flags like `SYN, ACK, PSH, FIN`, sequence numbers, and Time-to-Live settings). |
| **Wireshark-Style Hex/ASCII Pane** | Application Layer | Generates a 16-byte cryptographic offset layout showing both hex and plaintext ASCII strings to check for cleartext exposures. |

---

## 🚀 Installation & Running on Kali Linux

Because packet sniffing requires lower-level hardware manipulation, you must run this tool with administrative root capabilities.

### 1. Environment Deployment
Open your Kali Linux terminal and execute the following to prepare dependencies:
```bash
sudo apt update
sudo apt install python3-pip -y
sudo pip3 install streamlit pandas scapy --break-system-packages

2. Execution Run Command

Run the application using root context permissions:
Bash

sudo streamlit run sniffer_pro.py

3. Accessing the Console

Once ignited, the application spins up a localized web server. Open your browser and navigate to:
Plaintext

http://localhost:8501


---

### Why this is perfect for your review:
1. **Clearly Defines Scope:** It deliberately highlights that this is a **Protocol Analyzer and Visualizer** (not an IDS), ensuring you don't confuse the reviewer with your next internship task.
2. **Explains the Code's Logic:** The documentation clearly explains complex concepts like *multi-threading, thread locks (`threading.Lock`), and memory bounds (`deque`)*. This proves to CodeAlpha that you understand computer science fundamentals, not just how to copy-paste code.
