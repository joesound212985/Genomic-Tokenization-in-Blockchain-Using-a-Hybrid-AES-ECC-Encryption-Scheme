import time
import os
import numpy as np
import matplotlib.pyplot as plt

# PyCryptodome imports
from Crypto.Cipher import AES, Blowfish, DES3, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA

# PyNaCl for ECC (using Curve25519 / Edwards curve 25519)
from nacl.public import PrivateKey, Box

# -------------------------------------------------------
# Encryption/Decryption Functions

def aes_encrypt(data):
    key = get_random_bytes(16)  # AES-128 key
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    return (key, iv, ciphertext)

def aes_decrypt(key, iv, ciphertext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext

def blowfish_encrypt(data):
    key = get_random_bytes(16)
    iv = get_random_bytes(8)  # Blowfish block size is 8 bytes
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data, Blowfish.block_size))
    return (key, iv, ciphertext)

def blowfish_decrypt(key, iv, ciphertext):
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), Blowfish.block_size)
    return plaintext

def tripledes_encrypt(data):
    key = DES3.adjust_key_parity(get_random_bytes(24))
    iv = get_random_bytes(8)  # DES3 block size is 8 bytes
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data, DES3.block_size))
    return (key, iv, ciphertext)

def tripledes_decrypt(key, iv, ciphertext):
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), DES3.block_size)
    return plaintext

def aes_rsa_encrypt(data):
    # Encrypt data with AES first
    aes_key = get_random_bytes(16)
    iv = get_random_bytes(16)
    aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    ciphertext = aes_cipher.encrypt(pad(data, AES.block_size))
    # Wrap the AES key using RSA - use pre-generated key
    global rsa_key_pair
    cipher_rsa = PKCS1_OAEP.new(rsa_key_pair.publickey())
    enc_aes_key = cipher_rsa.encrypt(aes_key)
    return (rsa_key_pair, iv, ciphertext, enc_aes_key)

def aes_rsa_decrypt(rsa_key, iv, ciphertext, enc_aes_key):
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    aes_key = cipher_rsa.decrypt(enc_aes_key)
    aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    plaintext = unpad(aes_cipher.decrypt(ciphertext), AES.block_size)
    return plaintext

def hec_encrypt(data):
    """
    Hybrid AES/ECC encryption using Curve25519 (via PyNaCl):
      1. Encrypt data with AES.
      2. Encrypt the AES key with ECC (using an ephemeral sender and recipient).
    """
    # AES encryption of data
    aes_key = get_random_bytes(16)
    iv = get_random_bytes(16)
    aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    ciphertext = aes_cipher.encrypt(pad(data, AES.block_size))
    
    # ECC encryption: generate ephemeral keys
    sender_private = PrivateKey.generate()      # Sender's ephemeral private key
    sender_public = sender_private.public_key
    recipient_private = PrivateKey.generate()   # Recipient's ephemeral private key
    recipient_public = recipient_private.public_key
    
    box = Box(sender_private, recipient_public)
    ecc_encrypted_aes_key = box.encrypt(aes_key)
    
    return (recipient_private, sender_public, iv, ciphertext, ecc_encrypted_aes_key)

def hec_decrypt(recipient_private, sender_public, iv, ciphertext, ecc_encrypted_aes_key):
    box = Box(recipient_private, sender_public)
    aes_key = box.decrypt(ecc_encrypted_aes_key)
    aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    plaintext = unpad(aes_cipher.decrypt(ciphertext), AES.block_size)
    return plaintext

# -------------------------------------------------------
# Timing Function

def measure_algorithm_time(encrypt_func, decrypt_func, data, iterations=5):
    enc_times = []
    dec_times = []
    for _ in range(iterations):
        start = time.perf_counter()
        result = encrypt_func(data)
        enc_times.append(time.perf_counter() - start)
        start = time.perf_counter()
        decrypt_func(*result)
        dec_times.append(time.perf_counter() - start)
    return (sum(enc_times) / iterations, sum(dec_times) / iterations)

# -------------------------------------------------------
# Test Parameters

# Pre-generate RSA key pair to exclude generation time from measurements
rsa_key_pair = RSA.generate(1024)  # Generate once, outside timing measurements

# Generate 10 logarithmically spaced file sizes from 10^5 (100 KB) to 10^8 (100 MB)
file_sizes = np.logspace(5, 8, num=10, dtype=int).tolist()
print("Testing file sizes (in bytes):", file_sizes)

# Define algorithms to test
algorithms = {
    'HEC': (hec_encrypt, hec_decrypt),
    'AES': (aes_encrypt, aes_decrypt),
    'BLOWFISH': (blowfish_encrypt, blowfish_decrypt),
    'TRIPLEDES': (tripledes_encrypt, tripledes_decrypt),
    'AES_RSA': (aes_rsa_encrypt, aes_rsa_decrypt)
}

# Custom color map to match your PNG's color scheme
color_map = {
    'HEC': '#1f77b4',        # More precise teal blue
    'AES': '#ff7f0e',        # More precise orange
    'BLOWFISH': '#2ca02c',   # More precise green
    'TRIPLEDES': '#d62728',  # More precise red
    'AES_RSA': '#9467bd'     # More precise purple
}

# -------------------------------------------------------
# Collect Timing Results

results = {alg: {'enc': [], 'dec': []} for alg in algorithms}
sizes = []

for size in file_sizes:
    data = os.urandom(size)
    sizes.append(size)
    print(f"\nFile size: {size} bytes")
    for alg_name, (enc_func, dec_func) in algorithms.items():
        try:
            enc_time, dec_time = measure_algorithm_time(enc_func, dec_func, data)
            results[alg_name]['enc'].append(enc_time)
            results[alg_name]['dec'].append(dec_time)
            print(f"  {alg_name}: Encryption = {enc_time:.6f}s, Decryption = {dec_time:.6f}s")
        except Exception as e:
            print(f"  Error with {alg_name} on size {size}: {e}")
            results[alg_name]['enc'].append(None)
            results[alg_name]['dec'].append(None)

# -------------------------------------------------------
# Plot Results in Two Subplots (side by side) with grid lines and legend in the upper left

fig, axs = plt.subplots(1, 2, figsize=(12, 6))

# Left subplot: Encryption times
for alg_name in algorithms:
    axs[0].plot(sizes, results[alg_name]['enc'], marker='o', color=color_map[alg_name], label=alg_name)
axs[0].set_xscale('log')
axs[0].set_yscale('log')
axs[0].set_xlabel('File Size (bytes)')
axs[0].set_ylabel('Encryption Time (seconds)')
axs[0].set_title('Encryption Time vs. File Size')
axs[0].set_ylim(1e-5, 10)  # Setting y-axis limits to match PNG
axs[0].grid(True, which="major")  # Only major grid lines
axs[0].legend(loc='upper left')  # Added legend box

# Right subplot: Decryption times
for alg_name in algorithms:
    axs[1].plot(sizes, results[alg_name]['dec'], marker='o', color=color_map[alg_name], label=alg_name)
axs[1].set_xscale('log')
axs[1].set_yscale('log')
axs[1].set_xlabel('File Size (bytes)')
axs[1].set_ylabel('Decryption Time (seconds)')
axs[1].set_title('Decryption Time vs. File Size')
axs[1].set_ylim(1e-5, 10)  # Setting y-axis limits to match PNG
axs[1].grid(True, which="major")  # Only major grid lines
axs[1].legend(loc='upper left')  # Added legend box

plt.tight_layout()
plt.show()