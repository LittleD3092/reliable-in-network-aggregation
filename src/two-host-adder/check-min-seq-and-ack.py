with open('logs/s1.log', 'r') as source_file:
    max_ack = -1
    min_seq = 0
    flag = False
    for line in source_file:
        # update ack
        if 'Wrote register \'MyIngress.debug_ack_num\' at index 0 with value' in line:
            ack = int(line.split(' ')[-1])
            max_ack = max(max_ack, ack)
            print(f'ack: {ack}')
            flag = False
        # update min_seq
        elif 'Primitive seq_num_buffer.read(min_seq, min_index_val)' in line:
            flag = True
        elif 'Read register \'MyIngress.seq_num_buffer\' at' in line and flag:
            min_seq = int(line.split(' ')[-1])
            print(f'min_seq: {min_seq}')
            flag = False
            assert(max_ack < min_seq)
        elif 'Primitive seq_num_buffer.write(min_index_val, min_seq)' in line:
            flag = True
        elif 'Wrote register \'MyIngress.seq_num_buffer\' at' in line and flag:
            min_seq = int(line.split(' ')[-1])
            print(f'min_seq: {min_seq}')
            flag = False
            assert(max_ack < min_seq)
        else:
            flag = False