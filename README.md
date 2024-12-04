# Packet Sniffer Tool

This Python-based packet sniffer tool captures and analyzes network traffic in real-time. It uses `scapy` for packet capturing and `tkinter` for the graphical user interface (GUI). The tool allows you to view detailed information about each captured packet, filter traffic by protocol, IP address, and display raw payload data.

## Features

- **Capture and Analyze Network Traffic**: Captures packets from your network interface in real-time.
- **Detailed Packet Information**: Displays source IP, destination IP, protocol, packet length, and payload data.
- **Filtering**: Filter packets by protocol (TCP, UDP, ICMP) and IP address (source or destination).
- **Sorting**: Sort packet data by columns (Source IP, Destination IP, Protocol, Length).
- **Payload Display**: View packet payload in both hex and ASCII format.
- **Logging**: Logs all captured packet details to a log file (`network_traffic.log`).

## Requirements

- Python 3.x
- `scapy` for packet sniffing
- `tkinter` for the GUI (usually pre-installed with Python)
- `binascii` for formatting payload data

## Installation

1. **Clone the repository**:

   ```bash
   git clone https://github.com/msuroor101/packet-sniffer.git
   cd packet-sniffer
   ```

2. **Install required libraries**:

   ```bash
   pip install scapy
   ```

   `tkinter` should be pre-installed with Python. If not, you can install it using:

   ```bash
   sudo apt-get install python3-tk
   ```

## Usage

1. **Run the tool**:
   
   To run the packet sniffer tool, simply execute the Python script:

   ```bash
   sudo python sniffer_tool.py
   ```

2. **Select a Network Interface**:
   - The tool will automatically detect available network interfaces. Select the appropriate interface for sniffing.

3. **Set Filters**:
   - **Protocol Filter**: Choose from `TCP`, `UDP`, `ICMP`, or `All`.
   - **Source IP**: Enter a source IP address to filter packets from a specific source.
   - **Destination IP**: Enter a destination IP address to filter packets going to a specific destination.

4. **Start/Stop Sniffing**:
   - Click the "Start" button to begin packet capture.
   - Click the "Stop" button to halt the capture process.

5. **View Packet Details**:
   - After capturing packets, select any packet from the captured list to view detailed information (including the payload) in a new window.

6. **Sorting**:
   - You can sort the captured packets by any of the columns (Source IP, Destination IP, Protocol, Length) by clicking on the column headers.

7. **Logs**:
   - All captured packet information is logged into a file named `network_traffic.log` in the project directory.

## Screenshots

Include a few screenshots here to show the GUI, how packets are displayed, and how filtering works.

## Troubleshooting

- **No packets captured**: Ensure that the network interface selected is the correct one and that your system has permission to capture packets. Run the script with `sudo` if needed on Linux/macOS.
  
- **Missing Payload**: Not all packets contain raw payload data, especially control packets like SYN/ACK. If no payload is available, the field will be empty.
