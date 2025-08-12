# 🕵️‍♂️ Python Packet Sniffer with GUI 💻

### 📌 Description
This project is a functional, GUI-based network packet sniffer developed in Python, which I created for a Computer Networks course. It demonstrates the practical application of network programming and protocol analysis. The tool captures live network traffic from a local machine's interface, dissects various protocol headers, and presents the information in a user-friendly graphical interface built with Tkinter. Key functionalities include real-time packet capture, protocol-based filtering, detailed packet inspection, and the ability to save captures to a `.pcap` file for offline analysis in tools like Wireshark.

### 🎯 Objectives
- To apply theoretical knowledge of the TCP/IP stack (Ethernet, IPv4, TCP, UDP, ICMP, HTTP) in a practical application.
- To demonstrate proficiency with Python for network programming, utilizing the **Scapy** library for packet manipulation and the **Tkinter** library for GUI development.
- To implement core packet sniffing logic, including live capture, multi-protocol parsing, and data presentation.
- To handle challenges like cross-platform socket access and non-blocking GUI updates by using multithreading.

---

### 🧠 Core Functionality — In a Nutshell
- The user is presented with a clean GUI to start and stop the packet capturing process.
- Packets are captured in real-time and displayed in a scrollable list, showing the serial number, protocol, and source/destination IPs.
- The list is color-coded by protocol (e.g., HTTP is blue, TCP is green) for easy identification.
- The user can filter the captured packets by protocol type (TCP, UDP, ICMP, HTTP).
- Clicking on a packet opens a new window with detailed header information (e.g., MAC addresses, IP header details, TCP/UDP ports, flags, and raw data).
- The entire capture session is automatically saved to a `capture.pcap` file, which can be analyzed later with professional tools like Wireshark.

---

### 🛠 Technologies & Concepts Used

| Component | Description |
| :--- | :--- |
| **Python 3** | The core language for the application logic, data processing, and GUI. |
| **Scapy** | A powerful Python library used to handle the core sniffing functionality, packet dissection, and writing to `.pcap` files. |
| **Tkinter** | Python's standard GUI library, used to build the interactive user interface for displaying and managing packets. |
| **Raw Sockets** | The underlying mechanism for capturing packets from the network interface, abstracted by Scapy. |
| **Multithreading** | The sniffing engine runs in a separate thread to prevent the GUI from freezing during live packet capture. |
| **Protocol Parsing**| Custom classes were built to parse and decode headers for Ethernet, IPv4, TCP, UDP, ICMP, and HTTP protocols from raw byte data. |
| **File I/O** | The application writes all captured packets to a `capture.pcap` file for persistence and external analysis. |

---

### 📁 File Structure

```
├── Code/
│   ├── ProtocolsClasses.py    # Module with classes for each network protocol (Ethernet, IPv4, TCP, etc.).
│   └── Sniffer.py             # Main script: contains the GUI logic and sniffing engine.
├── Diagrams/
│   └── ...                    # (10 screenshots in .png)
├── HTTP Verification/
│   └── HTTP Websites.txt      # Text file for HTTP testing purposes.
├── Project Report/
│   └── Project Report.pdf     # The detailed academic report for the project.
├── .gitignore                 # To exclude unnecessary files (like __pycache__).
└── README.md                  # You're reading it!
```

---

### 🖥️ Screenshots

**Application on Startup**
*(The clean, initial state of the GUI before packet capture begins.)*<br>
<img width="1366" height="728" alt="image" src="https://github.com/user-attachments/assets/faccdce1-1ecc-415c-bd78-5b83ebf2cd27" />


**Live Packet Capture in Progress**
*(The application capturing UDP packets in real-time, with each packet color-coded for easy identification in the "Capture Feed".)*<br>
<img width="1366" height="725" alt="image" src="https://github.com/user-attachments/assets/f05e6e39-a7bc-498b-9b4c-04e51d44899a" />

**Capturing Web Browsing Traffic**
*(Demonstrates the sniffer capturing HTTP and TCP packets generated from browsing a website in the background.)*<br>
<img width="1366" height="727" alt="image" src="https://github.com/user-attachments/assets/3e36eee7-8074-4001-a87f-d321fd6defda" />

**Verifying Packet IP with `nslookup`**
*(Cross-validating the captured destination IP of an HTTP packet with the result of a manual `nslookup` command, confirming accuracy.)*<br>
<img width="1354" height="703" alt="image" src="https://github.com/user-attachments/assets/f5239050-015e-4a99-b304-3bbf56e58fb7" />

**Filtered View: Showing Only HTTP Traffic**
*(The protocol filter has been applied to show only HTTP packets, hiding all other protocol types from the main view.)*<br>
<img width="629" height="514" alt="image" src="https://github.com/user-attachments/assets/7addca85-f25c-4f6a-a6d4-2e04c7149a96" />

**Inspecting Detailed HTTP Packet Headers**
*(The "Packet Details" window is open, showing the parsed layer 4 (TCP) and layer 7 (HTTP) header information for a selected packet.)*<br>
<img width="1366" height="726" alt="image" src="https://github.com/user-attachments/assets/8266f3ab-6b1a-418b-a9ce-b84da6b76a18" />

**Inspecting a TCP Segment**
*(The detailed view for a selected TCP packet, showing its header fields, flags, and the raw TCP data payload.)*<br>
<img width="1366" height="730" alt="image" src="https://github.com/user-attachments/assets/d6a83d9c-15d1-4874-8f86-7116e5373e03" />

**Inspecting a UDP Datagram**
*(The detailed view for a selected UDP packet, displaying its header information and raw data payload.)*<br>
<img width="1366" height="721" alt="image" src="https://github.com/user-attachments/assets/17b83b98-51be-48ec-aa73-b42333f5269b" />

**Handling Other Protocol Types**
*(The filter is set to "OTHER," correctly isolating a packet using IGMP (Protocol 2) and displaying its basic IP and raw data.)*<br>
<img width="1366" height="723" alt="image" src="https://github.com/user-attachments/assets/aed2fb71-9d2e-42c4-be49-60646d08c6a7" />

**PCAP File Compatibility with Wireshark**
*(The `capture.pcap` file generated by the sniffer is opened in Wireshark, verifying that the output is valid and compatible with professional analysis tools.)*<br>
<img width="1366" height="729" alt="image" src="https://github.com/user-attachments/assets/438090fb-2edf-490e-bb18-d09fe0e0c0ba" />


---

### 📦 How to Set Up and Run

I have designed this project for Windows and Linux systems.

#### 🔧 Prerequisites
1.  **Python 3.7+**
2.  **Scapy** library. You can install it via pip:
    
    pip install scapy
    
3.  **(For Windows)** **Npcap**: Scapy requires a packet capture library on Windows. Npcap is the modern standard (successor to WinPcap).
    *   Download and install Npcap from the official website: https://npcap.com/
    *   During installation, make sure to check the box for **"Install Npcap in WinPcap API-compatible Mode"**.

#### 🚀 Compile & Run
1.  **Clone** this repository to your local machine:
    
    git clone <your-repo-link>
    
2.  **Navigate** to the `Code` directory:
    
    cd Code/
    
3.  **Run the script** with administrator/root privileges. This is necessary for raw socket access.

    *   **On Windows (Command Prompt as Administrator):**
        
        python Sniffer.py
        
    *   **On Linux (Terminal):**
        
        sudo python3 Sniffer.py
        
4.  Once the GUI window appears, click **"START CAPTURE"** to begin sniffing.

### 💡 Key Learnings
*   **Low-Level Network Interaction:** Gained a deep understanding of how data is structured and transmitted across a network, right from the Ethernet frame to application-layer data.
*   **Protocol Mechanics:** Developed practical experience in parsing and interpreting the headers of core internet protocols, reinforcing theoretical concepts.
*   **Cross-Platform Dependencies:** Learned firsthand about the platform-specific requirements for low-level network operations, particularly the need for libraries like Npcap on Windows.
*   **GUI Responsiveness:** Understood the importance of multithreading in applications that perform long-running background tasks (like sniffing) to ensure the user interface remains responsive.
*   **The Power of Libraries:** Appreciated how libraries like Scapy can abstract away immense complexity, allowing developers to focus on application logic rather than low-level socket management.

### 🧪 Tested On<br>

| OS | Status | Notes |
| :--- | :--- | :--- |
| ✅ **Windows 10/11** | ✔️ Fully Functional | Requires **Npcap** and **Administrator** privileges. |
| ✅ **Linux (Ubuntu/Fedora)** | ✔️ Fully Functional | Requires **root** privileges (`sudo`). |
| ❌ **macOS** |  untested | May require additional configuration for raw socket permissions. |

---

### 🙋‍♂️ Author
**Muhammad Ashir**<br>
Student of FAST-NUCES<br>
For contributions or queries, feel free to connect on [LinkedIn/Ashir-Qayyum](https://www.linkedin.com/in/ashir-qayyum).

### 📜 License<br>
This project is licensed for educational and academic use. Attribution is appreciated.
