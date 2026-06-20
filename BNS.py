#!/usr/bin/env python3
import os
import sys
import time
import threading
from collections import Counter, deque
import pandas as pd
import streamlit as st

# Suppress Scapy boot warning outputs 
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, hexdump

# -------------------------------------------------------------
# ROOT PRIVILEGE CHECK
# -------------------------------------------------------------
if os.getuid() != 0:
    st.error("❌ CRITICAL: This application must be executed as root (sudo) to capture raw network frames.")
    st.stop()

# -------------------------------------------------------------
# GLOBAL TELEMETRY ENGINE (Singleton Storage)
# -------------------------------------------------------------
class AdvancedNetworkTelemetry:
    def __init__(self):
        self.lock = threading.Lock()
        self.protocol_counts = Counter({'TCP': 0, 'UDP': 0, 'ICMP': 0, 'ARP': 0, 'Other': 0})
        self.top_sources = Counter()
        self.packet_timestamps = []
        self.total_packets = 0
        self.start_time = time.time()
        
        # --- NEW PRO FEATURES DATA STRUCTURES ---
        self.conversations = {} # Key: (src, dst) -> Value: {'packets': x, 'bytes': y}
        self.recent_packets = deque(maxlen=10) # Caps memory storage to last 10 packets

@st.cache_resource
def get_telemetry_tracker():
    return AdvancedNetworkTelemetry()

telemetry = get_telemetry_tracker()

# -------------------------------------------------------------
# PACKET DISSECTION ENGINE
# -------------------------------------------------------------
def packet_callback(packet):
    proto = "Other"
    src_ip = "N/A"
    dst_ip = "N/A"
    packet_len = len(packet)
    
    # Layer Dissection Storage Dictionary
    packet_details = {
        'timestamp': time.strftime('%H:%M:%S'),
        'len': packet_len,
        'summary': packet.summary(),
        'layer3': {},
        'layer4': {},
        'hex_dump': hexdump(packet, dump=True) # Feature 1: Hex/ASCII Dump
    }
    
    # Feature 2: Deep Header Field Dissection
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        packet_details['layer3'] = {
            'Version': packet[IP].version,
            'TTL (Time to Live)': packet[IP].ttl,
            'Header Length': packet[IP].ihl * 4,
            'Total Length': packet[IP].len
        }
        
        if packet.haslayer(TCP): 
            proto = "TCP"
            packet_details['layer4'] = {
                'Source Port': packet[TCP].sport,
                'Destination Port': packet[TCP].dport,
                'Sequence Number': packet[TCP].seq,
                'Acknowledgment': packet[TCP].ack,
                'Flags': packet[TCP].sprintf("%TCP.flags%")
            }
        elif packet.haslayer(UDP): 
            proto = "UDP"
            packet_details['layer4'] = {
                'Source Port': packet[UDP].sport,
                'Destination Port': packet[UDP].dport,
                'Length': packet[UDP].len
            }
        elif packet.haslayer(ICMP): 
            proto = "ICMP"
            
    elif packet.haslayer(ARP):
        proto = "ARP"
        src_ip = packet[ARP].psrc
        dst_ip = packet[ARP].pdst
        packet_details['layer3'] = {
            'Hardware Type': packet[ARP].hwtype,
            'Protocol Type': packet[ARP].ptype,
            'Operation': packet[ARP].op
        }

    # Thread-safe updates
    with telemetry.lock:
        telemetry.total_packets += 1
        telemetry.protocol_counts[proto] += 1
        if src_ip != "N/A":
            telemetry.top_sources[src_ip] += 1
            
            # Feature 3: Conversation Matrix Tracker
            conv_key = (src_ip, dst_ip)
            if conv_key not in telemetry.conversations:
                telemetry.conversations[conv_key] = {'packets': 0, 'bytes': 0}
            telemetry.conversations[conv_key]['packets'] += 1
            telemetry.conversations[conv_key]['bytes'] += packet_len
            
        telemetry.packet_timestamps.append(time.time() - telemetry.start_time)
        telemetry.recent_packets.appendleft(packet_details)

def run_sniffer():
    sniff(prn=packet_callback, store=False)

@st.cache_resource
def initialize_sniffer_backend():
    thread = threading.Thread(target=run_sniffer, daemon=True)
    thread.start()
    return thread

initialize_sniffer_backend()

# -------------------------------------------------------------
# STREAMLIT USER INTERFACE DESIGN
# -------------------------------------------------------------
st.set_page_config(
    page_title="Advanced Kali Network Analyzer",
    page_icon="🦈",
    layout="wide"
)

st.title("🦈 KALI PACKET SNIFFER & PROTOCOL ANALYZER")
st.markdown("---")

# Refresh the frame container every 1.0 seconds
@st.fragment(run_every=1.0)
def build_realtime_dashboard():
    with telemetry.lock:
        total_p = telemetry.total_packets
        proto_data = dict(telemetry.protocol_counts)
        top_ips = telemetry.top_sources.most_common(5)
        timestamps = list(telemetry.packet_timestamps)
        conv_data = list(telemetry.conversations.items())
        live_packets = list(telemetry.recent_packets)
    
    # 1. Metric Row Indicators
    m1, m2, m3 = st.columns(3)
    m1.metric("Total Frames Inspected", total_p)
    m2.metric("Active Node Conversations", len(conv_data))
    elapsed = max(1, int(time.time() - telemetry.start_time))
    m3.metric("Data Velocity Rate", f"{round(total_p / elapsed, 2)} pkts/sec")
        
    # 2. Charts Matrix Block
    c1, c2 = st.columns(2)
    with c1:
        st.markdown("#### Protocol Mix")
        st.bar_chart(pd.DataFrame(list(proto_data.items()), columns=["Protocol", "Count"]), x="Protocol", y="Count", color="#00ffcc", height=200)
    with c2:
        st.markdown("#### High-Volume Senders")
        if top_ips:
            st.bar_chart(pd.DataFrame(top_ips, columns=["Source IP", "Packets"]), x="Packets", y="Source IP", color="#ff0055", height=200)
        else:
            st.info("Listening for source IPs...")

    # Time-Series Flow chart
    if timestamps:
        df_time = pd.DataFrame(timestamps, columns=["Timeline"])
        df_time['Seconds'] = df_time['Timeline'].astype(int)
        time_series = df_time.groupby('Seconds').size().reset_index(name='Packets')
        st.line_chart(time_series, x='Seconds', y='Packets', color='#0099ff', height=150)

    st.markdown("---")
    
    # 3. ADVANCED FEATURES INTERACTIVE INTERFACE
    st.subheader("⚙️ Deep Forensic Inspection Modules")
    
    tab1, tab2 = st.tabs(["📊 Traffic Conversation Matrix", "🔍 Live Packet Dissector & Hex Dump"])
    
    # --- FEATURE 3 DISPLAY: Conversation Matrix ---
    with tab1:
        st.markdown("##### Mapping Inter-Node Communications Matrix")
        if conv_data:
            flat_conv = []
            for (src, dst), metrics in conv_data:
                flat_conv.append({
                    "Source Address": src,
                    "Destination Address": dst,
                    "Total Packets Exchanged": metrics['packets'],
                    "Total Throughput (Bytes)": metrics['bytes']
                })
            df_matrix = pd.DataFrame(flat_conv).sort_values(by="Total Throughput (Bytes)", ascending=False)
            st.dataframe(df_matrix, use_container_width=True, hide_index=True)
        else:
            st.info("Constructing communication streams. Send active traffic through your interface...")

    # --- FEATURES 1 & 2 DISPLAY: Dissector + Hex View ---
    with tab2:
        st.markdown("##### Real-Time Stream Breakdown (Last 10 Packets)")
        if not live_packets:
            st.info("Waiting for frames to pass through the socket interface matrix...")
        
        for idx, pkt in enumerate(live_packets):
            expander_title = f"[{pkt['timestamp']}] Frame Size: {pkt['len']} Bytes | Summary: {pkt['summary']}"
            with st.expander(expander_title):
                
                # Column layouts for Layers 3 and 4 side-by-side
                l3_col, l4_col = st.columns(2)
                
                with l3_col:
                    st.markdown("**Layer 3 (Network Frame Decoding)**")
                    if pkt['layer3']:
                        st.json(pkt['layer3'])
                    else:
                        st.caption("No Network Layer details detected (Non-IP Frame).")
                        
                with l4_col:
                    st.markdown("**Layer 4 (Transport Segment Decoding)**")
                    if pkt['layer4']:
                        st.json(pkt['layer4'])
                    else:
                        st.caption("No Transport Layer fields available.")
                
                # Plain Text Raw Hex View Window
                st.markdown("**Raw Cryptographic Payload Inspection (Hex / ASCII)**")
                st.code(pkt['hex_dump'], language="text")

build_realtime_dashboard()
