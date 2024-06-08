from scapy.all import rdpcap
import matplotlib.pyplot as plt
import numpy as np
from tqdm import tqdm

def plot_traffic(pcap_files, labels):
    plt.figure(figsize=(12, 8))

    all_times = []

    # First pass to find the earliest time across all pcap files
    for pcap_file in pcap_files:
        packets = rdpcap(pcap_file)
        for packet in tqdm(packets, desc=f"Finding start time in {pcap_file}"):
            if packet.haslayer('IP'):
                all_times.append(packet.time)

    common_start_time = min(all_times)

    # Second pass to process and plot each file
    for pcap_file, label in zip(pcap_files, labels):
        print(f"Processing {pcap_file}...")
        packets = rdpcap(pcap_file)
        times = []
        packet_sizes = []

        for packet in tqdm(packets, desc=f"Reading {label}"):
            if packet.haslayer('IP'):
                times.append(packet.time)
                packet_sizes.append(len(packet))

        # Convert times to relative times using the common start time
        relative_times = [t - common_start_time for t in times]

        # Aggregate packet sizes over one-second intervals
        duration = int(max(relative_times)) + 1
        bytes_per_second = [0] * duration

        for rel_time, size in zip(relative_times, packet_sizes):
            index = int(rel_time)
            bytes_per_second[index] += size

        # Convert bytes per second to kilobytes per second
        kB_per_second = [b / 1024 for b in bytes_per_second]
        time_intervals = np.arange(duration)

        # Plotting each pcap file's data
        plt.plot(time_intervals, kB_per_second, label=label)
 
    plt.xlabel('Time (s)')
    plt.ylabel('Kilobytes per Second (kB/s)')
    plt.title('Network Traffic Over Time')
    plt.legend()
    plt.grid(True)
    plt.show()

if __name__ == "__main__":
    pcaps_folder = 'pcaps/'
    pcap_files = [
        's1-eth1_in.pcap', 
        's1-eth2_in.pcap', 
        's1-eth3_in.pcap', 
        's1-eth4_in.pcap', 
        's1-eth5_out.pcap'
    ]
    pcap_files = [pcaps_folder + pcap_file for pcap_file in pcap_files]
    labels = [
        's1-eth1_in', 
        's1-eth2_in', 
        's1-eth3_in', 
        's1-eth4_in', 
        's1-eth5_out'
    ]
    plot_traffic(pcap_files, labels)
