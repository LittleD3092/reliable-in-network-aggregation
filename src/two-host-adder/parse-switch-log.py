from tqdm import tqdm

BUFFER_SIZE = 128

# Count the number of lines in the source file
with open('logs/s1.log', 'r') as source_file:
    total_lines = sum(1 for line in source_file)

# Open the source file for reading
with open('logs/s1.log', 'r') as source_file:
    # Open the destination file for writing
    with open('logs/parsed-s1.log', 'w') as destination_file:
        destination_file.write('| Sequence Number | Collide with Number | Empty Buffer Size | Used Buffer Size |\n')
        destination_file.write('|-----------------|---------------------|-------------------|------------------|\n')
        is_min_seq = False
        hash_level = 0
        min_seq = 0
        max_seq = 0
        min_index = 0
        max_index = 0
        first_hash_seq = 0
        second_hash_seq = 0
        third_hash_seq = 0
        first_hash_index = 0
        second_hash_index = 0
        third_hash_index = 0
        
        seq_num_in_record = set()

        # Read each line from the source file
        for line in tqdm(source_file, total=total_lines):
            # Min sequence and Max sequence
            if 'Primitive seq_num_buffer.read(min_seq, min_index_val)' in line:
                is_min_seq = True

            elif 'Primitive seq_num_buffer.read(max_seq, max_index_val)' in line:
                is_min_seq = False

            elif 'Read register \'MyIngress.seq_num_buffer\' at' in line:
                if is_min_seq:
                    min_seq = int(line.split(' ')[-1])
                    min_index = int(line.split(' ')[-4])

                else:
                    max_seq = int(line.split(' ')[-1])
                    max_index = int(line.split(' ')[-4])

            # elif 'Primitive test_hash_seq.read(first_hash_seq_val, first_hash_index)' in line:
            #     hash_level = 1

            # elif 'Primitive test_hash_seq.read(second_hash_seq_val, second_hash_index)' in line:
            #     hash_level = 2

            # elif 'Primitive test_hash_seq.read(third_hash_seq_val, third_hash_index)' in line:
            #     hash_level = 3

            # elif 'Read register \'MyIngress.test_hash_seq\' at' in line:
            #     if hash_level == 1:
            #         first_hash_seq = int(line.split(' ')[-1])
            #         first_hash_index = int(line.split(' ')[-4])

            #     elif hash_level == 2:
            #         second_hash_seq = int(line.split(' ')[-1])
            #         second_hash_index = int(line.split(' ')[-4])

            #     elif hash_level == 3:
            #         third_hash_seq = int(line.split(' ')[-1])
            #         third_hash_index = int(line.split(' ')[-4])

            elif 'Read register \'MyIngress.test_hash_seq_1\' at' in line:
                first_hash_seq = int(line.split(' ')[-1])
                first_hash_index = int(line.split(' ')[-4])

            elif 'Read register \'MyIngress.test_hash_seq_2\' at' in line:
                second_hash_seq = int(line.split(' ')[-1])
                second_hash_index = int(line.split(' ')[-4])

            elif 'Wrote register \'MyIngress.debug_hash_collision_seq\' at index' in line:
                seq_num = int(line.split(' ')[-1])
                if seq_num not in seq_num_in_record:
                    seq_num_in_record.add(seq_num)
                    destination_file.write(f'| {seq_num} | {first_hash_seq}, {second_hash_seq} | {BUFFER_SIZE - (max_seq - min_seq + 1)} | {max_seq - min_seq + 1} |\n')