🕵️‍♂️ Python Packet Sniffer with GUI 💻
📌 Description
This project is a functional, GUI-based network packet sniffer developed in Python. Created for a Computer Networks course, it demonstrates the practical application of network programming and protocol analysis. The tool captures live network traffic from a local machine's interface, dissects various protocol headers, and presents the information in a user-friendly graphical interface built with Tkinter. Key functionalities include real-time packet capture, protocol-based filtering, detailed packet inspection, and the ability to save captures to a .pcap file for offline analysis in tools like Wireshark.
🎯 Objectives
To apply theoretical knowledge of the TCP/IP stack (Ethernet, IPv4, TCP, UDP, ICMP, HTTP) in a practical application.
To demonstrate proficiency with Python for network programming, utilizing the Scapy library for packet manipulation and the Tkinter library for GUI development.
To implement core packet sniffing logic, including live capture, multi-protocol parsing, and data presentation.
To handle challenges like cross-platform socket access and non-blocking GUI updates by using multithreading.
🧠 Core Functionality — In a Nutshell
The user is presented with a clean GUI to start and stop the packet capturing process.
Packets are captured in real-time and displayed in a scrollable list, showing the serial number, protocol, and source/destination IPs.
The list is color-coded by protocol (e.g., HTTP is blue, TCP is green) for easy identification.
The user can filter the captured packets by protocol type (TCP, UDP, ICMP, HTTP).
Clicking on a packet opens a new window with detailed header information (e.g., MAC addresses, IP header details, TCP/UDP ports, flags, and raw data).
The entire capture session is automatically saved to a capture.pcap file, which can be analyzed later with professional tools like Wireshark.
🛠 Technologies & Concepts Used
Component	Description
Python 3	The core language for the application logic, data processing, and GUI.
Scapy	A powerful Python library used to handle the core sniffing functionality, packet dissection, and writing to .pcap files.
Tkinter	Python's standard GUI library, used to build the interactive user interface for displaying and managing packets.
Raw Sockets	The underlying mechanism for capturing packets from the network interface, abstracted by Scapy.
Multithreading	The sniffing engine runs in a separate thread to prevent the GUI from freezing during live packet capture.
Protocol Parsing	Custom classes were built to parse and decode headers for Ethernet, IPv4, TCP, UDP, ICMP, and HTTP protocols from raw byte data.
File I/O	The application writes all captured packets to a capture.pcap file for persistence and external analysis.
📁 File Structure
A clean repository is essential. This is the recommended file structure for the project.
code
Code
├── Code/
│   ├── ProtocolsClasses.py    # Module with classes for each network protocol (Ethernet, IPv4, TCP, etc.).
│   └── Sniffer.py             # Main script: contains the GUI logic and sniffing engine.
├── Diagrams/
│   ├── details_http.png       # Contains all GUI screenshots.
│   ├── details_tcp.png
│   └── ...                    # (and 8 more screenshots)
├── HTTP Verification/
│   └── HTTP Websites.txt      # Text file for HTTP testing purposes.
├── Project Report/
│   └── Project Report.pdf     # The detailed academic report for the project.
├── .gitignore                 # To exclude unnecessary files (like __pycache__).
└── README.md                  # You're reading it!
🖥️ Screenshots
Main Interface (Capturing UDP and TCP Traffic)
(Margin for your Main Interface screenshot)
<img width="1366" height="725" alt="main_gui" src="placeholder_for_main_gui.png" />
Applying a Filter (Showing only HTTP Traffic)
(Margin for your Filtered View screenshot)
<img width="1366" height="721" alt="filtered_view" src="placeholder_for_filtered_view.png" />
Detailed Packet View (Inspecting an HTTP Packet)
(Margin for your Detailed View screenshot)
<img width="1366" height="721" alt="detailed_view" src="placeholder_for_detailed_view.png" />
📦 How to Set Up and Run
This project is designed for Windows and Linux systems.
🔧 Prerequisites
Python 3.7+
Scapy library. You can install it via pip:
code
Bash
pip install scapy
(For Windows) Npcap: Scapy requires a packet capture library on Windows. Npcap is the modern standard (successor to WinPcap).
Download and install Npcap from the official website.
During installation, make sure to check the box for "Install Npcap in WinPcap API-compatible Mode".
🚀 Compile & Run
Clone this repository to your local machine:
code
Bash
git clone <your-repo-link>
Navigate to the Code directory:
code
Bash
cd Code/
Run the script with administrator/root privileges. This is necessary for raw socket access.
On Windows (Command Prompt as Administrator):
code
Bash
python Sniffer.py
On Linux (Terminal):
code
Bash
sudo python3 Sniffer.py
Once the GUI window appears, click "START CAPTURE" to begin sniffing.
💡 Key Learnings
Low-Level Network Interaction: Gained a deep understanding of how data is structured and transmitted across a network, right from the Ethernet frame to application-layer data.
Protocol Mechanics: Developed practical experience in parsing and interpreting the headers of core internet protocols, reinforcing theoretical concepts.
Cross-Platform Dependencies: Learned firsthand about the platform-specific requirements for low-level network operations, particularly the need for libraries like Npcap on Windows.
GUI Responsiveness: Understood the importance of multithreading in applications that perform long-running background tasks (like sniffing) to ensure the user interface remains responsive.
The Power of Libraries: Appreciated how libraries like Scapy can abstract away immense complexity, allowing developers to focus on application logic rather than low-level socket management.
🧪 Tested On<br>
OS	Status	Notes
✅ Windows 10/11	✔️ Fully Functional	Requires Npcap and Administrator privileges.
✅ Linux (Ubuntu/Fedora)	✔️ Fully Functional	Requires root privileges (sudo).
❌ macOS	untested	May require additional configuration for raw socket permissions.
🙋‍♂️ Author
Muhammad Ashir
Student of FAST-NUCES
For contributions or queries, feel free to connect on LinkedIn.
📜 License
This project is licensed for educational and academic use. Attribution is appreciated.
