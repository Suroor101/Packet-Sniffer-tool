import tkinter as tk
from tkinter import ttk, messagebox
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, get_if_list
import logging
import threading
import binascii

# Configure logging
logging.basicConfig(filename="network_traffic.log", level=logging.DEBUG, format="%(asctime)s - %(message)s")

# Global variables
capture_active = False
stop_sniff = threading.Event()  # Event to stop sniffing
captured_packets = []
protocol_stats = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}
packet_count = 0
total_bytes = 0

# Function to format payload in hex and ASCII view
def format_payload(payload):
    if not payload:
        return "No Payload"
    
    hex_view = binascii.hexlify(payload).decode("utf-8", errors="replace")
    ascii_view = ''.join(chr(byte) if 32 <= byte <= 126 else '.' for byte in payload)

    formatted_payload = "\n".join(
        f"{hex_view[i:i+32]:<48} | {ascii_view[i:i+16]}"
        for i in range(0, len(hex_view), 32)
    )

    return f"Hex View:\n{formatted_payload}"

# Function to process packets
def process_packet(packet):
    global packet_count, total_bytes
    if not capture_active:
        return

    packet_count += 1
    total_bytes += len(packet)

    try:
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = get_protocol(packet)
            length = len(packet)
            payload = ""

            # Extract raw payload if available
            if Raw in packet and packet[Raw].load:
                payload = format_payload(packet[Raw].load)

            # Log packet details in the log file
            packet_info = f"Source IP: {src_ip} | Destination IP: {dst_ip} | Protocol: {protocol} | Length: {length} bytes"
            if payload:
                packet_info += f" | Payload: {payload[:50]}"  # Log first 50 characters of payload
            logging.info(packet_info)

            # Log the full packet if it's a raw payload
            logging.debug(f"Full Raw Packet: {packet.summary()}")

            # Log protocol stats
            packet_info = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": protocol,
                "length": length,
                "payload": payload
            }
            captured_packets.append(packet_info)

            # Update Treeview with packet info
            packet_tree.insert("", tk.END, values=(src_ip, dst_ip, protocol, length))

            # Update protocol stats
            if protocol in protocol_stats:
                protocol_stats[protocol] += 1
            else:
                protocol_stats["Other"] += 1
    except Exception as e:
        logging.error(f"Error processing packet: {e}")

# Function to determine protocol
def get_protocol(packet):
    if TCP in packet:
        return "TCP"
    elif UDP in packet:
        return "UDP"
    elif ICMP in packet:
        return "ICMP"
    return "Other"

# Start sniffing in a thread
def start_sniffing(interface, packet_filter):
    try:
        sniff(iface=interface, prn=process_packet, filter=packet_filter, stop_filter=lambda x: stop_sniff.is_set())
    except Exception as e:
        logging.error(f"Sniffing error: {e}")
        capture_active = False

# Stop sniffing
def stop_sniffing():
    stop_sniff.set()
    global capture_active
    capture_active = False
    logging.info("Packet capture stopped.")

# Start sniffing in a thread
def start_thread():
    global capture_active
    stop_sniff.clear()
    capture_active = True

    interface = interface_combobox.get()
    packet_filter = ""

    protocol = protocol_combobox.get()
    if protocol != "All":
        packet_filter += f" and {protocol.lower()}"
    
    src_ip_filter = src_ip_entry.get()
    if src_ip_filter:
        packet_filter += f" and src {src_ip_filter}"

    dst_ip_filter = dst_ip_entry.get()
    if dst_ip_filter:
        packet_filter += f" and dst {dst_ip_filter}"

    if not interface or interface not in interfaces:
        messagebox.showerror("Invalid Interface", "Please select a valid network interface.")
        return

    if not packet_filter:
        packet_filter = "tcp or udp or icmp"  # Default filter

    threading.Thread(target=start_sniffing, args=(interface, packet_filter), daemon=True).start()

# Show detailed packet information
def show_details():
    selected_item = packet_tree.focus()
    if not selected_item:
        messagebox.showinfo("No Selection", "Please select a packet to view details.")
        return

    packet_index = packet_tree.index(selected_item)
    packet_info = captured_packets[packet_index]

    details_window = tk.Toplevel(root)
    details_window.title("Packet Details")
    details_window.geometry("600x400")

    details_text = tk.Text(details_window, wrap=tk.WORD, height=20, width=80)
    details_text.pack(fill=tk.BOTH, expand=True)

    details = f"""
Source IP: {packet_info['src_ip']}
Destination IP: {packet_info['dst_ip']}
Protocol: {packet_info['protocol']}
Length: {packet_info['length']} bytes

Payload:
{packet_info['payload']}
"""
    details_text.insert(tk.END, details)
    details_text.config(state=tk.DISABLED)

# Update statistics
def update_statistics():
    stats_text.set(f"Packets Captured: {packet_count}\n"
                   f"Total Bytes: {total_bytes}\n"
                   f"TCP: {protocol_stats['TCP']}\n"
                   f"UDP: {protocol_stats['UDP']}\n"
                   f"ICMP: {protocol_stats['ICMP']}\n"
                   f"Other: {protocol_stats['Other']}")

# Periodic statistics update
def periodic_update():
    update_statistics()
    root.after(1000, periodic_update)

# Sorting function for Treeview columns
def sort_column(treeview, col, reverse=False):
    data = [(treeview.set(child, col), child) for child in treeview.get_children('')]
    data.sort(reverse=reverse)
    
    for index, item in enumerate(data):
        treeview.move(item[1], '', index)
    
    treeview.heading(col, command=lambda _col=col: sort_column(treeview, _col, not reverse))

# Set up GUI
root = tk.Tk()
root.title("Enhanced Packet Sniffer Tool")
root.geometry("1250x750")

# Fetch available interfaces
interfaces = get_if_list()

# Top control frame
control_frame = ttk.Frame(root)
control_frame.pack(fill=tk.X, padx=10, pady=10)

# Interface selection
ttk.Label(control_frame, text="Interface:").pack(side=tk.LEFT, padx=5)
interface_combobox = ttk.Combobox(control_frame, values=interfaces, width=25)
interface_combobox.set(interfaces[0] if interfaces else "No interfaces found")
interface_combobox.pack(side=tk.LEFT, padx=5)

# Protocol selection dropdown
ttk.Label(control_frame, text="Protocol:").pack(side=tk.LEFT, padx=5)
protocol_combobox = ttk.Combobox(control_frame, values=["All", "TCP", "UDP", "ICMP"], width=25)
protocol_combobox.set("All")
protocol_combobox.pack(side=tk.LEFT, padx=5)

# Source and Destination IP fields for filtering
ttk.Label(control_frame, text="Source IP:").pack(side=tk.LEFT, padx=5)
src_ip_entry = ttk.Entry(control_frame, width=15)
src_ip_entry.pack(side=tk.LEFT, padx=5)

ttk.Label(control_frame, text="Destination IP:").pack(side=tk.LEFT, padx=5)
dst_ip_entry = ttk.Entry(control_frame, width=15)
dst_ip_entry.pack(side=tk.LEFT, padx=5)

# Start/Stop buttons
start_button = ttk.Button(control_frame, text="Start", command=start_thread)
start_button.pack(side=tk.LEFT, padx=5)

stop_button = ttk.Button(control_frame, text="Stop", command=stop_sniffing)
stop_button.pack(side=tk.LEFT, padx=5)

# Packet display
packet_frame = ttk.LabelFrame(root, text="Captured Packets")
packet_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

columns = ("src_ip", "dst_ip", "protocol", "length")
packet_tree = ttk.Treeview(packet_frame, columns=columns, show="headings")

# Column headings with sorting functionality
packet_tree.heading("src_ip", text="Source IP", command=lambda: sort_column(packet_tree, "src_ip"))
packet_tree.heading("dst_ip", text="Destination IP", command=lambda: sort_column(packet_tree, "dst_ip"))
packet_tree.heading("protocol", text="Protocol", command=lambda: sort_column(packet_tree, "protocol"))
packet_tree.heading("length", text="Length", command=lambda: sort_column(packet_tree, "length"))

packet_tree.pack(fill=tk.BOTH, expand=True)

# Detailed view button
details_button = ttk.Button(root, text="View Details", command=show_details)
details_button.pack(pady=5)

# Statistics
stats_text = tk.StringVar()
stats_label = ttk.Label(root, textvariable=stats_text, anchor="w")
stats_label.pack(fill=tk.X, padx=10, pady=5)

root.after(1000, periodic_update)
root.mainloop()
