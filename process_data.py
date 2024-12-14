import pyshark
import pandas as pd

def pcap_to_csv(pcap_file, output_csv):
    """
    Process a PCAP file using pyshark to extract features and save to csv.
    Parameters:
        pcap_file (str): Path to the PCAP file.
        output_csv (str): Path to save the output CSV file.
    """
    print(f"Processing PCAP file: {pcap_file}")
    try:
        cap = pyshark.FileCapture(pcap_file)
        data = []
        for packet in cap:
            try:
                # Initialize packet details with defaults
                packet_data = {
                    "timestamp": packet.sniff_time,
                    "protocol": packet.highest_layer,
                    "src_ip": None,
                    "dst_ip": None,
                    "src_port": None,
                    "dst_port": None,
                    "length": None,
                    "tcp_flags": None,
                    "payload_size": None,
                }

                # Extract IP layer information
                if hasattr(packet, "ip"):
                    packet_data["src_ip"] = packet.ip.src
                    packet_data["dst_ip"] = packet.ip.dst

                # Extract TCP layer information
                if hasattr(packet, "tcp"):
                    packet_data["src_port"] = packet.tcp.srcport
                    packet_data["dst_port"] = packet.tcp.dstport
                    packet_data["tcp_flags"] = packet.tcp.flags
                    packet_data["payload_size"] = len(packet.tcp.payload) if hasattr(packet.tcp, "payload") else None

                # Extract UDP layer information (if no TCP layer)
                elif hasattr(packet, "udp"):
                    packet_data["src_port"] = packet.udp.srcport
                    packet_data["dst_port"] = packet.udp.dstport

                # Extract packet length
                packet_data["length"] = int(packet.length)

                # Append packet info
                data.append(packet_data)
            except Exception as e:
                print(f"Error processing packet: {e}")
        cap.close()

        df = pd.DataFrame(data)

        #Replace missing tcp_flags with "none"
        df["tcp_flags"] = df["tcp_flags"].fillna("none")

        #Replace missing payload_size with 0
        df["payload_size"] = df["payload_size"].fillna(0)

        df.to_csv(output_csv, index=False, header=True)
        print(f"Saved extracted data to {output_csv}")
    except Exception as e:
        print(f"Error processing PCAP file: {e}")
        return

if __name__ == "__main__":
    pcap_file = "../data/UC4.1/Raw/Lockbit Execution in Doctors.pcap"
    output_file = "../data/example.csv"
    pcap_to_csv(pcap_file, output_file)
