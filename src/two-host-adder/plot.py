from scapy.all import rdpcap, TCP
import matplotlib.pyplot as plt
import numpy as np

# Interval in seconds to aggregate packet sizes
INTERVAL = 2

def plot_all_traffic(pcap_files, labels, interval=INTERVAL):
    plt.figure(figsize=(12, 8))

    all_times = []

    # First pass to find the earliest time across all pcap files
    for pcap_file in pcap_files:
        packets = rdpcap(pcap_file)
        for packet in packets:
            if packet.haslayer('IP'):
                all_times.append(packet.time)

    common_start_time = min(all_times)

    # Second pass to process and plot each file
    for pcap_file, label in zip(pcap_files, labels):
        try:
            print(f"Processing {pcap_file} for combined plot...")
            packets = rdpcap(pcap_file)
            times = []
            packet_sizes = []

            for packet in packets:
                if packet.haslayer('IP'):
                    times.append(packet.time)
                    packet_sizes.append(len(packet))

            # Convert times to relative times using the common start time
            relative_times = [t - common_start_time for t in times]

            # Aggregate packet sizes over two-second intervals
            duration = int(max(relative_times)) // interval + 1
            bits_per_interval = [0] * duration

            for rel_time, size in zip(relative_times, packet_sizes):
                index = int(rel_time) // interval
                bits_per_interval[index] += size * 8

            # Convert bytes per interval to kilobytes per second
            kbits_per_second = [b / 1024 / interval for b in bits_per_interval]
            time_intervals = np.arange(duration) * interval

            # Plotting each pcap file's data
            plt.plot(time_intervals, kbits_per_second, label=label)
        except Exception as e:
            print(f"Error processing {pcap_file}: {e}")
            print("Skipping...")

    plt.xlabel('Time (s)')
    plt.ylabel('Kilobits per Second (kb/s)')
    plt.title('Network Traffic Over Time')
    plt.legend()
    plt.grid(True)
    
    # Save the combined plot
    plt.savefig('logs/combined_traffic_plot.png')
    plt.close()

def plot_individual_traffic(pcap_files, labels, interval=INTERVAL):
    all_times = []

    # First pass to find the earliest time across all pcap files
    for pcap_file in pcap_files:
        packets = rdpcap(pcap_file)
        for packet in packets:
            if packet.haslayer('IP'):
                all_times.append(packet.time)

    common_start_time = min(all_times)

    # Second pass to process and plot each file
    for pcap_file, label in zip(pcap_files, labels):
        try:
            print(f"Processing {pcap_file}...")
            packets = rdpcap(pcap_file)
            times = []
            packet_sizes = []

            for packet in packets:
                if packet.haslayer('IP'):
                    times.append(packet.time)
                    packet_sizes.append(len(packet))

            # Convert times to relative times using the common start time
            relative_times = [t - common_start_time for t in times]

            # Aggregate packet sizes over two-second intervals
            duration = int(max(relative_times)) // interval + 1
            bits_per_interval = [0] * duration

            for rel_time, size in zip(relative_times, packet_sizes):
                index = int(rel_time) // interval
                bits_per_interval[index] += size * 8

            # Convert bytes per interval to kilobits per second
            kbits_per_second = [b / 1024 / interval for b in bits_per_interval]
            time_intervals = np.arange(duration) * interval

            # Plotting each pcap file's data
            plt.figure(figsize=(12, 8))
            plt.plot(time_intervals, kbits_per_second, label=label)
            plt.xlabel('Time (s)')
            plt.ylabel('Kilobits per Second (kb/s)')
            plt.title(f'Network Traffic Over Time ({label})')
            plt.legend()
            plt.grid(True)
            
            # Save the plot
            plt.savefig(f'logs/{label}_traffic_plot.png')
            plt.close()
        except Exception as e:
            print(f"Error processing {pcap_file}: {e}")
            print("Skipping...")

def extract_cwnd(pcap_file, common_start_time):
    try:
        packets = rdpcap(pcap_file)
        times = []
        cwnd_sizes = []

        for packet in packets:
            if packet.haslayer(TCP):
                times.append(packet.time)
                cwnd_sizes.append(packet[TCP].window)

        # Convert times to relative times using the common start time
        relative_times = [t - common_start_time for t in times]

        # Aggregate cwnd sizes over specified intervals
        duration = int(max(relative_times)) // INTERVAL + 1
        cwnd_per_interval = [0] * duration
        counts_per_interval = [0] * duration

        for rel_time, cwnd in zip(relative_times, cwnd_sizes):
            index = int(rel_time) // INTERVAL
            cwnd_per_interval[index] += cwnd
            counts_per_interval[index] += 1

        # Average the cwnd size per interval
        avg_cwnd_per_interval = [cwnd / count if count != 0 else 0 for cwnd, count in zip(cwnd_per_interval, counts_per_interval)]
        time_intervals = np.arange(duration) * INTERVAL
    except Exception as e:
        print(f"Error processing {pcap_file}: {e}")
        print("Skipping...")
        avg_cwnd_per_interval = []
        time_intervals = []

    return time_intervals, avg_cwnd_per_interval

def plot_all_cwnd(pcap_files, labels):
    plt.figure(figsize=(12, 8))

    all_times = []

    # First pass to find the earliest time across all pcap files
    for pcap_file in pcap_files:
        packets = rdpcap(pcap_file)
        for packet in packets:
            if packet.haslayer(TCP):
                all_times.append(packet.time)

    common_start_time = min(all_times)

    # Second pass to process and plot each file
    for pcap_file, label in zip(pcap_files, labels):
        print(f"Processing {pcap_file} for combined CWND plot...")
        time_intervals, avg_cwnd_per_interval = extract_cwnd(pcap_file, common_start_time)

        # Plotting each pcap file's CWND data
        plt.plot(time_intervals, avg_cwnd_per_interval, label=label)

    plt.xlabel('Time (s)')
    plt.ylabel('Congestion Window Size (CWND)')
    plt.title('Congestion Window Over Time')
    plt.legend()
    plt.grid(True)
    
    # Save the combined plot
    plt.savefig('logs/combined_cwnd_plot.png')
    plt.close()

def plot_individual_cwnd(pcap_files, labels):
    all_times = []

    # First pass to find the earliest time across all pcap files
    for pcap_file in pcap_files:
        packets = rdpcap(pcap_file)
        for packet in packets:
            if packet.haslayer(TCP):
                all_times.append(packet.time)

    common_start_time = min(all_times)

    # Second pass to process and plot each file
    for pcap_file, label in zip(pcap_files, labels):
        print(f"Processing {pcap_file} for individual CWND plot...")
        time_intervals, avg_cwnd_per_interval = extract_cwnd(pcap_file, common_start_time)

        # Plotting each pcap file's CWND data
        plt.figure(figsize=(12, 8))
        plt.plot(time_intervals, avg_cwnd_per_interval, label=label)
        plt.xlabel('Time (s)')
        plt.ylabel('Congestion Window Size (CWND)')
        plt.title(f'Congestion Window Over Time ({label})')
        plt.legend()
        plt.grid(True)
        
        # Save the plot
        plt.savefig(f'logs/{label}_cwnd_plot.png')
        plt.close()

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
    
    # Plot all traffic in a single figure
    plot_all_traffic(pcap_files, labels)
    
    # Plot each traffic in a separate figure
    plot_individual_traffic(pcap_files, labels)

    # # Plot all CWND in a single figure
    # plot_all_cwnd(pcap_files, labels)

    # # Plot each CWND in a separate figure
    # plot_individual_cwnd(pcap_files, labels)