import os
import json
import pyshark
from kafka import KafkaProducer
from kafka.errors import KafkaError
from datetime import datetime

# Kafka configuration
KAFKA_BROKER = 'kafka.***:9092'  # Replace with your Kafka broker address
KAFKA_TOPIC = 'UC4.Aware.pcap'  # Replace with your Kafka topic name
KAFKA_USERNAME = '***'  # The SASL username
KAFKA_PASSWORD = '***'  # The SASL password

# Kafka producer configuration with SASL
producer = KafkaProducer(
    bootstrap_servers=KAFKA_BROKER,
    security_protocol='SASL_PLAINTEXT',  # Using SASL_PLAINTEXT for authentication
    sasl_mechanism='PLAIN',  # Mechanism for SASL
    sasl_plain_username=KAFKA_USERNAME,  # The username for authentication
    sasl_plain_password=KAFKA_PASSWORD,  # The password for authentication
    value_serializer=lambda v: json.dumps(v).encode('utf-8')
)

DISCARD_IP = "37.27.127.166"
DISCARD_IP2 = "127.0.0.1"

# Function to extract relevant information from packets
def packet_to_json(packet):
    if hasattr(packet, 'ip'):
        src_ip = packet.ip.src
        dst_ip = packet.ip.dst
        if src_ip == DISCARD_IP or dst_ip == DISCARD_IP or dst_ip == DISCARD_IP2 or src_ip == DISCARD_IP:
            return None  # Discard this packet

    # Initialize packet data dictionary
    packet_data = {
        "timestamp": str(packet.sniff_time),
        "protocol": packet.highest_layer if hasattr(packet, 'highest_layer') else None,
        "src_ip": packet.ip.src if hasattr(packet, 'ip') else None,
        "dst_ip": packet.ip.dst if hasattr(packet, 'ip') else None,
        "src_port": None,
        "dst_port": None,
        "length": packet.length,
        "tcp_flags": None,
        "payload_size": len(packet.payload) if hasattr(packet, 'payload') else 0,
    }

    # Check if the packet has a transport layer (TCP/UDP)
    if hasattr(packet, 'transport_layer'):
        # Safely access the transport layer if it exists
        if packet.transport_layer == 'TCP' and hasattr(packet, 'tcp'):
            packet_data["src_port"] = packet.tcp.srcport if hasattr(packet.tcp, 'srcport') else None
            packet_data["dst_port"] = packet.tcp.dstport if hasattr(packet.tcp, 'dstport') else None
            packet_data["tcp_flags"] = packet.tcp.flags if hasattr(packet.tcp, 'flags') else None
        elif packet.transport_layer == 'UDP' and hasattr(packet, 'udp'):
            packet_data["src_port"] = packet.udp.srcport if hasattr(packet.udp, 'srcport') else None
            packet_data["dst_port"] = packet.udp.dstport if hasattr(packet.udp, 'dstport') else None

    return packet_data

# Function to send packets to Kafka
def send_to_kafka(packet_data):
    # Ensure packet_data is not None or empty
    if packet_data and isinstance(packet_data, dict):
        try:
            # Send the packet data to Kafka
            producer.send(KAFKA_TOPIC, packet_data)
            producer.flush()
        except KafkaError as e:
            print(f"Error sending to Kafka: {e}")
    else:
        print("Skipping empty or invalid packet data.")

# Function to capture packets and save them to a pcap file with a timestamped folder
def capture_packets():
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    folder = f"pcap_files/{timestamp}"
    os.makedirs(folder, exist_ok=True)
    pcap_file = os.path.join(folder, f"{timestamp}.pcap")

    # Start packet capture using pyshark (set your network interface or use 'any' for all)
    cap = pyshark.LiveCapture(interface='any', output_file=pcap_file)  # This captures and saves the pcap file

    print(f"Saving packets to {pcap_file}...")

    # Filter packets before capturing them
    for packet in cap.sniff_continuously():
        # Discard packets from DISCARD_IP
        if hasattr(packet, 'ip'):
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            if src_ip == DISCARD_IP or dst_ip == DISCARD_IP or dst_ip == DISCARD_IP2 or src_ip == DISCARD_IP:
                continue  # Skip this packet

        packet_data = packet_to_json(packet)
        send_to_kafka(packet_data)

        
if __name__ == '__main__':
    capture_packets()
