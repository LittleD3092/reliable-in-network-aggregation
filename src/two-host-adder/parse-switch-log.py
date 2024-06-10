from tqdm import tqdm

# Count the number of lines in the source file
with open('logs/s1.log', 'r') as source_file:
    total_lines = sum(1 for line in source_file)

# Open the source file for reading
with open('logs/s1.log', 'r') as source_file:
    # Open the destination file for writing
    with open('logs/parsed-s1.log', 'w') as destination_file:
        is_min_seq = False
        in_port = 0
        min_seq = 0
        max_seq = 0
        min_index = 0
        max_index = 0

        # Read each line from the source file
        for line in tqdm(source_file, total=total_lines):
            # Sequence number and Ack number
            if 'Wrote register \'MyIngress.debug_relative_seq_num\' at index 0 with value' in line:
                current_seq_num = int(line.split(' ')[-1])
                timestamp = line.split(' ')[0]
                destination_file.write(f'{timestamp} seq_num: {current_seq_num} ')

            el'logs/s1.log', 'r') as source_file:
    total_lines = sum(1 for line in source_file)
                current_ack_num = int(line.split(' ')[-1])
                timestamp = line.split(' ')[0]
                destination_file.write(f'    {timestamp} ack_num: {current_ack_num}\n')

            # Min sequence and Max sequence
            elif 'Primitive seq_num_buffer.read(min_seq, min_index_val)' in line:
                is_min_seq = True

            elif 'Primitive seq_num_buffer.read(max_seq, max_index_val)' in line:
                is_min_seq = False

            elif 'Read register \'MyIngress.seq_num_buffer\' at' in line:
                if is_min_seq:
                    min_seq = int(line.split(' ')[-1])
                    min_index = int(line.split(' ')[-4])
                    # destination_file.write(f'\nmin_seq: {min_seq} min_index: {min_index}\n')

                else:
                    max_seq = int(line.split(' ')[-1])
                    max_index = int(line.split(' ')[-4])
                    # destination_file.write(f'\nmax_seq: {max_seq} max_index: {max_index}\n')

            # Min sequence number increment
            elif 'Wrote register \'MyIngress.debug_increment_min_index_from\' at index 0 with value' in line:
                min_index = int(line.split(' ')[-1])
                # destination_file.write(f'min_index from: {min_index} ')

            elif 'Wrote register \'MyIngress.debug_increment_min_index_to\' at index 0 with value' in line:
                min_index = int(line.split(' ')[-1])
                # destination_file.write(f'to: {min_index}\n')

            # Drop due to acked
            elif 'Condition "relative_seq_num < min_seq" (node_21) is true' in line:
                destination_file.write('Drop acked\n')

            # Aggregated
            elif 'Condition "relative_seq_num >= min_seq && relative_seq_num <= max_seq" (node_23) is true' in line:
                destination_file.write('Aggregating ')

            elif 'Condition "in_port==1" (node_' in line and ') is true' in line:
                destination_file.write('port 1 ')

            elif 'Condition "in_port==2" (node_' in line and ') is true' in line:
                destination_file.write('port 2 ')

            elif 'Condition "in_port==3" (node_' in line and ') is true' in line:
                destination_file.write('port 3 ')

            elif 'Condition "in_port==4" (node_' in line and ') is true' in line:
                destination_file.write('port 4 ')

            elif 'Condition "(state&mask)==0" (node_' in line and ') is true' in line:
                destination_file.write('Do aggregation ')

            elif 'Condition "(state&mask)==0" (node_' in line and ') is false' in line:
                destination_file.write('No aggregation ')

            elif 'Condition "state==0xf" (node_38) is true' in line:
                destination_file.write('Send to h5\n')

            elif 'Condition "state==0xf" (node_38) is false' in line:
                destination_file.write('\n')

            # New number
            elif 'Wrote register \'MyIngress.debug_in_port\' at index 0 with value' in line:
                in_port = int(line.split(' ')[-1])

            elif 'Condition "max_seq < relative_seq_num && relative_seq_num < BUFFER_SIZE + min_seq - 1 || (max_index_val + 1) % BUFFER_SIZE == min_index_val" (node_41) is true' in line:
                destination_file.write('New number ')

            elif 'Condition "in_port == 1" (node_' in line and ') is true' in line:
                destination_file.write('port 1\n')

            elif 'Condition "in_port == 2" (node_' in line and ') is true' in line:
                destination_file.write('port 2\n')

            elif 'Condition "in_port == 3" (node_' in line and ') is true' in line:
                destination_file.write('port 3\n')

            elif 'Condition "in_port == 4" (node_' in line and ') is true' in line:
                destination_file.write('port 4\n')

            elif 'Primitive consecutive_buffer_full.write(0, consecutive_buffer_full_val + 1)' in line:
                destination_file.write(f'port {in_port} ')
                destination_file.write('Drop due to buffer full\n')

with open('logs/parsed-s1.log', 'r') as file:
    payloads = {}
    max_ack_num = 0
    min_seq = 0
    max_seq = 0
    min_index = 0
    max_index = 0

    error_flag = False

    for line in file:
        line_sep = line.strip().split(' ')
        print(line)
        if 'seq_num' in line and 'Drop' not in line:
            seq_num = int(line_sep[2])
            # find port
            port_index = line_sep.index('port') + 1
            port = int(line_sep[port_index])
            if seq_num not in payloads:
                payloads[seq_num] = {port}
            else:
                payloads[seq_num].add(port)
        if 'ack_num' in line:
            error_flag = False
            ack_num = int(line_sep[2])
            max_ack_num = max(max_ack_num, ack_num)
            if ack_num in payloads:
                for seq in list(payloads.keys()):
                    if seq <= ack_num:
                        del payloads[seq]

        print('seq\t1\t2\t3\t4')
        for seq_num, ports in payloads.items():
            print(seq_num, end='\t')
            for port in range(1, 5):
                if port in ports:
                    print('*', end='\t')
                else:
                    print(' ', end='\t')
            print()

        _ = input('Press enter to continue...')