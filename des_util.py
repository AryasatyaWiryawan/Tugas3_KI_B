from table import initial_perm, expansion_table, sbox, pbox, final_perm, key_schedule

def permute(data, table):
    return ''.join(data[i - 1] for i in table)

def xor(bits1, bits2):
    return ''.join('1' if b1 != b2 else '0' for b1, b2 in zip(bits1, bits2))

def left_shift(bits, shifts):
    return bits[shifts:] + bits[:shifts]

def substitute(expanded_half_block):
    result = ''
    for i in range(8):  # S-Box operates on 6 bits at a time
        chunk = expanded_half_block[i * 6:(i + 1) * 6]
        row = int(chunk[0] + chunk[-1], 2)  # First and last bit determine the row
        col = int(chunk[1:5], 2)  # Middle four bits determine the column
        result += f"{sbox[i][row][col]:04b}"  # Look up in S-box and convert to binary
    return result

def generate_keys(key):
    # Initial Permutation of the key
    permuted_key = permute(key, initial_perm[:56])  # Using the first 56 bits for sub-keys
    left, right = permuted_key[:28], permuted_key[28:]
    sub_keys = []

    for shifts in key_schedule:
        left = left_shift(left, shifts)
        right = left_shift(right, shifts)
        combined_key = left + right
        sub_key = permute(combined_key, initial_perm[56:])  # Compress to 48 bits
        sub_keys.append(sub_key)

    return sub_keys

def des_encrypt_block(block, keys):
    # Initial Permutation
    block = permute(block, initial_perm)
    left, right = block[:32], block[32:]

    # 16 rounds of DES
    for key in keys:
        expanded_right = permute(right, expansion_table)
        xor_result = xor(expanded_right, key)
        substituted = substitute(xor_result)
        permuted = permute(substituted, pbox)
        left, right = right, xor(left, permuted)

    # Final combination and permutation
    combined = right + left
    return permute(combined, final_perm)

def des_decrypt_block(block, keys):
    # Reuse encryption logic with reversed keys
    return des_encrypt_block(block, keys[::-1])

# Padding for input
def pad_input(data):
    padding_len = 8 - (len(data) % 8)
    padding = chr(padding_len) * padding_len
    return data + padding

def unpad_input(data):
    padding_len = ord(data[-1])
    return data[:-padding_len]

def des_encrypt(data, key):
    keys = generate_keys(key)
    padded_data = pad_input(data)
    encrypted_blocks = []
    for i in range(0, len(padded_data), 8):  # Process 8 bytes (64 bits) at a time
        block = ''.join(f"{ord(char):08b}" for char in padded_data[i:i + 8])  # Convert to binary
        encrypted_block = des_encrypt_block(block, keys)
        encrypted_blocks.append(encrypted_block)
    return ''.join(encrypted_blocks)

def des_decrypt(data, key):
    keys = generate_keys(key)
    decrypted_blocks = []
    for i in range(0, len(data), 64):  # Process 64 bits (8 bytes) at a time
        block = data[i:i + 64]
        decrypted_block = des_decrypt_block(block, keys)
        decrypted_blocks.append(decrypted_block)
    decrypted_text = ''.join(
        ''.join(chr(int(decrypted_block[i:i + 8], 2)) for i in range(0, len(decrypted_block), 8))
        for decrypted_block in decrypted_blocks
    )
    return unpad_input(decrypted_text)
