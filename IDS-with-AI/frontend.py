import pygame
import requests
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
import ctypes
import time

# Backend URL
url = "http://127.0.0.1:5000/predict"

# Alert audio file
ALERT_FILE = "alert.wav"

# Initialize the mixer
pygame.mixer.init()

# Function to play the alert sound
def play_alert():
    try:
        pygame.mixer.music.load(ALERT_FILE)
        pygame.mixer.music.play()
    except Exception as e:
        print(f"Error playing alert sound: {e}")

# Function to display a Windows notification
def show_windows_notification(title, message):
    try:
        ctypes.windll.user32.MessageBoxW(0, message, title, 1)
    except Exception as e:
        print(f"Error showing notification: {e}")

# Function to send packet data to the backend
def send_packet_data(payload):
    try:
        response = requests.post(url, json=payload)
        if response.status_code == 200:
            prediction = response.json()
            print("Prediction:", prediction)

            # Check for an intrusion (use 'attack: 1' or other thresholds)
            if prediction.get("attack") == 1:
                print("[ALERT] Intrusion detected!")
                play_alert()
                show_windows_notification("Intrusion Alert", "An intrusion has been detected!")
        else:
            print(f"Error: Backend returned status code {response.status_code}")
    except Exception as e:
        print(f"Error sending data to backend: {e}")

# Packet processing function
def process_packet(packet):
    if IP in packet:
        try:
            # Extract basic packet information
            saddr = packet[IP].src
            daddr = packet[IP].dst
            proto = "tcp" if TCP in packet else "udp" if UDP in packet else "other"
            sport = packet.sport if hasattr(packet, "sport") else -1
            dport = packet.dport if hasattr(packet, "dport") else -1
            ttl = packet[IP].ttl
            packet_length = len(packet)

            # Add timing information
            current_time = time.time()

            # Feature engineering
            payload = {
                "seq": getattr(packet, "seq", 0),  # Sequence number
                "stddev": packet_length / (ttl + 1),  # Example: variability proxy
                "N_IN_Conn_P_SrcIP": packet_length,
                "min": min(ttl, packet_length),
                "state_number": ttl,
                "mean": packet_length / max(1, ttl),
                "N_IN_Conn_P_DstIP": len(daddr),
                "drate": packet_length / (ttl + 1),
                "srate": packet_length / (current_time + 1),
                "max": packet_length,
            }

            print(f"Payload: {payload}")

            # Send the payload to the backend
            send_packet_data(payload)

        except Exception as e:
            print(f"Error processing packet: {e}")

# Main function to monitor live traffic
def monitor_live_traffic(interface="eth0"):
    print(f"Starting live traffic monitoring on interface: {interface}")
    try:
        sniff(iface=interface, prn=process_packet, store=0)
    except KeyboardInterrupt:
        print("Monitoring stopped by user.")
    except Exception as e:
        print(f"Error starting packet capture: {e}")

if __name__ == "__main__":
    # Specify your network interface (e.g., "Wi-Fi", "Ethernet")
    network_interface = "Wi-Fi"  # Adjust this to your actual network interface name
    monitor_live_traffic(interface=network_interface)
