from table import initial_perm, exp_d, sbox, per, final_perm, keyp, shift_table, key_comp

# Hexadecimal to Binary Conversion
def hex2bin(s):
    mp = {'0': "0000", '1': "0001", '2': "0010", '3': "0011",
          '4': "0100", '5': "0101", '6': "0110", '7': "0111",
          '8': "1000", '9': "1001", 'A': "1010", 'B': "1011",
          'C': "1100", 'D': "1101", 'E': "1110", 'F': "1111",
          'a': "0000", 'b': "0001", 'c': "0010", 'd': "0011",
          'e': "0100", 'f': "0101"}  # Include lowercase support
    bin_str = ""
    for ch in s:
        if ch in mp:
            bin_str += mp[ch]
        else:
            raise ValueError(f"Invalid hex character: {ch}")
    return bin_str


# Binary to Hexadecimal Conversion
def bin2hex(s):
    mp = {"0000": '0', "0001": '1', "0010": '2', "0011": '3',
          "0100": '4', "0101": '5', "0110": '6', "0111": '7',
          "1000": '8', "1001": '9', "1010": 'A', "1011": 'B',
          "1100": 'C', "1101": 'D', "1110": 'E', "1111": 'F'}
    return ''.join(mp[s[i:i+4]] for i in range(0, len(s), 4))

# Binary to Decimal Conversion
def bin2dec(binary):
    return int(binary, 2)

# Decimal to Binary Conversion
def dec2bin(num, bits=4):
    res = bin(num).replace("0b", "")
    return res.zfill(bits)

# Permutation Function
def permute(k, table, n):
    return ''.join(k[table[i] - 1] for i in range(n))

# XOR Function
def xor(a, b):
    return ''.join('0' if a[i] == b[i] else '1' for i in range(len(a)))

# Left Shift Function
def shift_left(key, shifts):
    return key[shifts:] + key[:shifts]

# Generate Round Keys
def generate_keys(key):
    key = hex2bin(key)
    key = permute(key, keyp, 56)
    left, right = key[:28], key[28:]
    rkb, rk = [], []
    for shift in shift_table:
        left = shift_left(left, shift)
        right = shift_left(right, shift)
        combine_str = left + right
        round_key = permute(combine_str, key_comp, 48)
        rkb.append(round_key)
        rk.append(bin2hex(round_key))
    return rkb, rk

# DES Round Function
def des_round(pt, rkb):
    pt = permute(pt, initial_perm, 64)
    left, right = pt[:32], pt[32:]
    for i in range(16):
        right_expanded = permute(right, exp_d, 48)
        xor_x = xor(right_expanded, rkb[i])
        sbox_str = ""
        for j in range(8):
            row = bin2dec(xor_x[j*6] + xor_x[j*6+5])
            col = bin2dec(xor_x[j*6+1:j*6+5])
            val = sbox[j][row][col]
            sbox_str += dec2bin(val, 4)
        result = xor(left, permute(sbox_str, per, 32))
        left, right = right, result
    combine = left + right
    return permute(combine, final_perm, 64)

# Encrypt Block
def des_encrypt_block(block, key):
    rkb, rk = generate_keys(key)
    return bin2hex(des_round(hex2bin(block), rkb))

# Decrypt Block
def des_decrypt_block(block, key):
    rkb, rk = generate_keys(key)
    rkb.reverse()
    return bin2hex(des_round(hex2bin(block), rkb))

# Pad Data
def pad(data):
    block_size = 16
    data_hex = data.encode('utf-8').hex()
    padding_len = block_size - (len(data_hex) % block_size)
    if padding_len == block_size:
        padding_len = 0
    data_hex += '0' * padding_len
    return data_hex, padding_len

# Unpad Data
def unpad(data, padding_len):
    return data[:-padding_len] if padding_len > 0 else data

# Encrypt Data in ECB Mode
def des_encrypt(data, key):
    data_hex, _ = pad(data)
    cipher_hex = ""
    for i in range(0, len(data_hex), 16):
        block = data_hex[i:i+16]
        cipher_hex += des_encrypt_block(block, key)
    return cipher_hex

# Decrypt Data in ECB Mode
def des_decrypt(cipher_hex, key):
    plain_hex = ""
    for i in range(0, len(cipher_hex), 16):
        block = cipher_hex[i:i+16]
        plain_hex += des_decrypt_block(block, key)
    plain_bytes = bytes.fromhex(plain_hex)
    return plain_bytes.rstrip(b'\x00').decode('utf-8')

# Add Padding for Blocks
def pad_ecb(pt):
    padding = ""
    padding_len = 16 - (len(pt) % 16)
    padding += "0" * padding_len
    return pt + padding, padding_len

# Encrypt in ECB Mode with Block Padding
def encrypt_ecb(pt, key):
    pt, _ = pad_ecb(pt)
    cipher_text = ""
    rkb, rk = generate_keys(key)
    for i in range(0, len(pt), 16):
        block = pt[i:i+16]
        cipher_text += des_encrypt_block(block, key)
    return cipher_text

# Decrypt in ECB Mode
def decrypt_ecb(cipher_hex, key):
    rkb, rk = generate_keys(key)
    rkb.reverse()
    plain_text = ""
    for i in range(0, len(cipher_hex), 16):
        block = cipher_hex[i:i+16]
        plain_text += des_decrypt_block(block, key)
    return bytes.fromhex(plain_text).rstrip(b'\x00').decode('utf-8')
