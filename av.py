import os
import random
import string
import time
import psutil
import matplotlib.pyplot as plt
import warnings

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag
from cryptography.utils import CryptographyDeprecationWarning

# Suppress cryptography deprecation warnings
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

# =============================
# Key Generation and Schemes
# =============================
def generate_ecc_keys():
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_hec(plaintext, public_key):
    """
    Hybrid ECC/AES (HEC) encryption:
      - Generates a random AES key.
      - Uses an ephemeral ECC key to derive a shared key with the recipient's ECC public key.
      - Uses HKDF to derive a key from the shared secret.
      - Encrypts the AES key with AES-GCM using a random IV.
      - Encrypts the plaintext with AES-GCM using the generated AES key.
      
    Returns a 7-tuple:
      (ephemeral_public_bytes, encrypted_aes_key, tag_key, iv_key, ciphertext, tag_plain, iv_plain)
    """
    # Generate a random AES key
    aes_key = os.urandom(32)

    # Generate an ephemeral ECC key pair and perform key exchange
    ephemeral_private_key = x25519.X25519PrivateKey.generate()
    shared_key = ephemeral_private_key.exchange(public_key)
    ephemeral_public_bytes = ephemeral_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    # Derive a key from the shared key using HKDF
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'AES Key Encryption',
        backend=default_backend()
    ).derive(shared_key)

    # Encrypt the AES key using the derived key with AES-GCM
    iv_key = os.urandom(12)  # 12 bytes recommended for GCM
    cipher_key = Cipher(algorithms.AES(derived_key), modes.GCM(iv_key), backend=default_backend())
    encryptor_key = cipher_key.encryptor()
    encrypted_aes_key = encryptor_key.update(aes_key) + encryptor_key.finalize()
    tag_key = encryptor_key.tag

    # Encrypt the plaintext using AES-GCM with the generated AES key
    iv_plain = os.urandom(12)
    cipher_plain = Cipher(algorithms.AES(aes_key), modes.GCM(iv_plain), backend=default_backend())
    encryptor_plain = cipher_plain.encryptor()
    ciphertext = encryptor_plain.update(plaintext) + encryptor_plain.finalize()
    tag_plain = encryptor_plain.tag

    return (ephemeral_public_bytes, encrypted_aes_key, tag_key, iv_key, ciphertext, tag_plain, iv_plain)

def decrypt_hec(encrypted_key, encrypted_aes_key, tag_key, iv_key, ciphertext, tag_plain, iv_plain, private_key):
    """
    Decrypts data encrypted using the HEC scheme.
    """
    try:
        ephemeral_public_key = x25519.X25519PublicKey.from_public_bytes(encrypted_key)
        shared_key = private_key.exchange(ephemeral_public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'AES Key Encryption',
            backend=default_backend()
        ).derive(shared_key)

        # Decrypt the AES key
        cipher_key = Cipher(algorithms.AES(derived_key), modes.GCM(iv_key, tag_key), backend=default_backend())
        decryptor_key = cipher_key.decryptor()
        aes_key = decryptor_key.update(encrypted_aes_key) + decryptor_key.finalize()

        # Decrypt the ciphertext
        cipher_plain = Cipher(algorithms.AES(aes_key), modes.GCM(iv_plain, tag_plain), backend=default_backend())
        decryptor_plain = cipher_plain.decryptor()
        plaintext = decryptor_plain.update(ciphertext) + decryptor_plain.finalize()

        return plaintext
    except InvalidTag:
        print("Error: InvalidTag exception occurred during decryption in HEC scheme.")
        return None

# ----- AES in CBC mode -----
def encrypt_aes_cbc(plaintext, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder_obj = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder_obj.update(plaintext) + padder_obj.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return (ciphertext, iv)

def decrypt_aes_cbc(ciphertext, iv, key):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder_obj = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder_obj.update(padded_plaintext) + unpadder_obj.finalize()
    return plaintext

# ----- Blowfish in CBC mode -----
def encrypt_blowfish(plaintext, key):
    iv = os.urandom(8)
    cipher = Cipher(algorithms.Blowfish(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder_obj = padding.PKCS7(algorithms.Blowfish.block_size).padder()
    padded_data = padder_obj.update(plaintext) + padder_obj.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return (ciphertext, iv)

def decrypt_blowfish(ciphertext, iv, key):
    cipher = Cipher(algorithms.Blowfish(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder_obj = padding.PKCS7(algorithms.Blowfish.block_size).unpadder()
    plaintext = unpadder_obj.update(padded_plaintext) + unpadder_obj.finalize()
    return plaintext

# ----- TripleDES in CBC mode -----
def encrypt_tripledes(plaintext, key):
    iv = os.urandom(8)
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder_obj = padding.PKCS7(algorithms.TripleDES.block_size).padder()
    padded_data = padder_obj.update(plaintext) + padder_obj.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return (ciphertext, iv)

def decrypt_tripledes(ciphertext, iv, key):
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder_obj = padding.PKCS7(algorithms.TripleDES.block_size).unpadder()
    plaintext = unpadder_obj.update(padded_plaintext) + unpadder_obj.finalize()
    return plaintext

# =============================
# Performance & Avalanche Measurement
# =============================
def measure_avalanche_effect(encryption_func, plaintext, *enc_args, num_tests=100):
    """
    Encrypts the original plaintext and then, for a number of tests, flips one random bit in the plaintext.
    It then computes the normalized Hamming distance (avalanche score) between the ciphertexts.
    """
    # For avalanche measurement, the plaintext is provided separately and extra arguments come from get_encryption_args
    encryption_result = encryption_func(plaintext, *enc_args)
    # For HEC scheme, ciphertext is the 5th element; for others, it is the 1st element.
    if encryption_func == encrypt_hec:
        original_ciphertext = encryption_result[4]
    else:
        original_ciphertext = encryption_result[0]

    avalanche_scores = []
    for _ in range(num_tests):
        # Flip a random bit in the plaintext
        bit_position = random.randint(0, len(plaintext) * 8 - 1)
        byte_index = bit_position // 8
        bit_offset = bit_position % 8
        modified_plaintext = bytearray(plaintext)
        modified_plaintext[byte_index] ^= (1 << bit_offset)

        mod_encryption_result = encryption_func(bytes(modified_plaintext), *enc_args)
        if encryption_func == encrypt_hec:
            mod_ciphertext = mod_encryption_result[4]
        else:
            mod_ciphertext = mod_encryption_result[0]

        # Calculate Hamming distance
        min_len = min(len(original_ciphertext), len(mod_ciphertext))
        hamming_distance = 0
        for i in range(min_len):
            hamming_distance += bin(original_ciphertext[i] ^ mod_ciphertext[i]).count('1')
        # Account for extra bytes if lengths differ
        if len(original_ciphertext) != len(mod_ciphertext):
            longer = original_ciphertext if len(original_ciphertext) > len(mod_ciphertext) else mod_ciphertext
            for byte in longer[min_len:]:
                hamming_distance += bin(byte).count('1')
        total_bits = max(len(original_ciphertext), len(mod_ciphertext)) * 8
        avalanche_score = hamming_distance / total_bits
        avalanche_scores.append(avalanche_score)

    average_avalanche = sum(avalanche_scores) / num_tests
    return average_avalanche

def measure_performance(encryption_func, decryption_func, enc_args, dec_args, scheme):
    """
    Measures encryption and decryption times, memory usage, and CPU usage.
    The parameter 'scheme' is used to handle the differing return values
    (e.g. HEC returns a 7-tuple, while other schemes return a 2-tuple).
    """
    process = psutil.Process()
    num_cores = psutil.cpu_count(logical=True)

    mem_before = process.memory_info().rss
    cpu_before = process.cpu_percent(interval=1) / num_cores

    # Measure encryption time
    start_enc = time.time()
    encryption_result = encryption_func(*enc_args)
    encryption_time = time.time() - start_enc

    mem_after_enc = process.memory_info().rss
    cpu_after_enc = process.cpu_percent(interval=1) / num_cores

    # Measure decryption time
    start_dec = time.time()
    if scheme == 'hec':
        # For HEC, unpack the 7-tuple accordingly.
        decryption_result = decryption_func(encryption_result[0], encryption_result[1], encryption_result[2],
                                              encryption_result[3], encryption_result[4], encryption_result[5],
                                              encryption_result[6], *dec_args)
    else:
        decryption_result = decryption_func(encryption_result[0], encryption_result[1], *dec_args)
    decryption_time = time.time() - start_dec

    mem_after_dec = process.memory_info().rss
    cpu_after_dec = process.cpu_percent(interval=1) / num_cores

    return (mem_before, mem_after_enc, mem_after_dec,
            cpu_before, cpu_after_enc, cpu_after_dec,
            encryption_time, decryption_time)

def generate_random_file(size):
    """
    Generates a random file with a given size (in bytes) containing alphanumeric characters.
    """
    filename = f"random_file_{size}.txt"
    with open(filename, 'w') as f:
        content = ''.join(random.choices(string.ascii_letters + string.digits, k=size))
        f.write(content)
    return filename

def measure_avalanche_effect_for_file_sizes(file_sizes):
    avalanche_results = {'hec': [], 'aes': [], 'blowfish': [], 'tripledes': []}

    for size in file_sizes:
        filename = generate_random_file(size)
        with open(filename, 'rb') as f:
            plaintext = f.read()

        for scheme, enc_func in [
            ('hec', encrypt_hec),
            ('aes', encrypt_aes_cbc),
            ('blowfish', encrypt_blowfish),
            ('tripledes', encrypt_tripledes)
        ]:
            # For avalanche effect measurement, get only the extra parameter(s)
            enc_args = get_encryption_args(scheme, plaintext)
            avalanche_score = measure_avalanche_effect(enc_func, plaintext, *enc_args)
            avalanche_results[scheme].append(avalanche_score)

        os.remove(filename)

    return avalanche_results

def measure_performance_for_file_sizes(file_sizes):
    results = {
        'hec': {'encryption_times': [], 'decryption_times': [], 'memory_usage_before_encryption': [],
                'memory_usage_after_encryption': [], 'memory_usage_after_decryption': [],
                'cpu_usage_before_encryption': [], 'cpu_usage_after_encryption': [], 'cpu_usage_after_decryption': []},
        'aes': {'encryption_times': [], 'decryption_times': [], 'memory_usage_before_encryption': [],
                'memory_usage_after_encryption': [], 'memory_usage_after_decryption': [],
                'cpu_usage_before_encryption': [], 'cpu_usage_after_encryption': [], 'cpu_usage_after_decryption': []},
        'blowfish': {'encryption_times': [], 'decryption_times': [], 'memory_usage_before_encryption': [],
                     'memory_usage_after_encryption': [], 'memory_usage_after_decryption': [],
                     'cpu_usage_before_encryption': [], 'cpu_usage_after_encryption': [], 'cpu_usage_after_decryption': []},
        'tripledes': {'encryption_times': [], 'decryption_times': [], 'memory_usage_before_encryption': [],
                      'memory_usage_after_encryption': [], 'memory_usage_after_decryption': [],
                      'cpu_usage_before_encryption': [], 'cpu_usage_after_encryption': [], 'cpu_usage_after_decryption': []}
    }

    for size in file_sizes:
        filename = generate_random_file(size)
        with open(filename, 'rb') as f:
            plaintext = f.read()

        for scheme, funcs in [
            ('hec', (encrypt_hec, decrypt_hec)),
            ('aes', (encrypt_aes_cbc, decrypt_aes_cbc)),
            ('blowfish', (encrypt_blowfish, decrypt_blowfish)),
            ('tripledes', (encrypt_tripledes, decrypt_tripledes))
        ]:
            encryption_func, decryption_func = funcs
            # For performance measurement, include plaintext in the encryption arguments
            enc_args, dec_args = get_encryption_decryption_args(scheme, plaintext)
            metrics = measure_performance(encryption_func, decryption_func, enc_args, dec_args, scheme)

            results[scheme]['encryption_times'].append(metrics[6])
            results[scheme]['decryption_times'].append(metrics[7])
            results[scheme]['memory_usage_before_encryption'].append(metrics[0])
            results[scheme]['memory_usage_after_encryption'].append(metrics[1])
            results[scheme]['memory_usage_after_decryption'].append(metrics[2])
            results[scheme]['cpu_usage_before_encryption'].append(metrics[3])
            results[scheme]['cpu_usage_after_encryption'].append(metrics[4])
            results[scheme]['cpu_usage_after_decryption'].append(metrics[5])

        os.remove(filename)

    return results

def get_encryption_args(scheme, plaintext):
    """
    Returns only the extra parameters (beyond plaintext) needed for encryption.
    Used in the avalanche effect measurement.
    """
    if scheme == 'hec':
        return (public_key_ecc,)
    elif scheme == 'aes':
        return (aes_key,)
    elif scheme == 'blowfish':
        return (blowfish_key,)
    elif scheme == 'tripledes':
        return (tripledes_key,)

def get_encryption_decryption_args(scheme, plaintext):
    """
    Returns tuples for encryption and decryption that include the plaintext.
    Used in the performance measurements.
    """
    if scheme == 'hec':
        enc_args = (plaintext, public_key_ecc)
        dec_args = (private_key_ecc,)
    elif scheme == 'aes':
        enc_args = (plaintext, aes_key)
        dec_args = (aes_key,)
    elif scheme == 'blowfish':
        enc_args = (plaintext, blowfish_key)
        dec_args = (blowfish_key,)
    elif scheme == 'tripledes':
        enc_args = (plaintext, tripledes_key)
        dec_args = (tripledes_key,)
    return enc_args, dec_args

# =============================
# Plotting Functions
# =============================
def plot_avalanche_results(file_sizes, avalanche_results):
    plt.figure(figsize=(8, 6))
    for scheme in ['hec', 'aes', 'blowfish', 'tripledes']:
        plt.plot(file_sizes, avalanche_results[scheme], marker='o', label=scheme.upper())
    plt.xlabel('File Size (bytes)')
    plt.ylabel('Avalanche Effect Score')
    plt.title('Avalanche Effect Score vs. File Size')
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.savefig('avalanche_effect_plot.png')
    plt.close()

def plot_results(file_sizes, results):
    metrics = ['encryption_times', 'decryption_times', 'memory_usage_before_encryption',
               'memory_usage_after_encryption', 'memory_usage_after_decryption',
               'cpu_usage_before_encryption', 'cpu_usage_after_encryption', 'cpu_usage_after_decryption']

    for metric in metrics:
        plt.figure(figsize=(8, 6))
        for scheme in ['hec', 'aes', 'blowfish', 'tripledes']:
            plt.plot(file_sizes, results[scheme][metric], marker='o', label=scheme.upper())
        ylabel = 'CPU Usage (% per core)' if 'cpu_usage' in metric else metric.replace('_', ' ').title()
        plt.xlabel('File Size (bytes)')
        plt.ylabel(ylabel)
        plt.title(f'{metric.replace("_", " ").title()} vs. File Size')
        plt.legend()
        plt.grid(True)
        plt.tight_layout()
        plt.savefig(f'{metric}_plot.png')
        plt.close()

# =============================
# Main Execution
# =============================
# Generate keys
private_key_ecc, public_key_ecc = generate_ecc_keys()
aes_key = os.urandom(32)
blowfish_key = os.urandom(56)
tripledes_key = os.urandom(24)

# Define file sizes (in bytes)
file_sizes = [
    100 * 1024,
    1024 * 1024,
    5 * 1024 * 1024,
    10 * 1024 * 1024,
    20 * 1024 * 1024,
    50 * 1024 * 1024,
    100 * 1024 * 1024
]

# Measure avalanche effect and plot results
avalanche_results = measure_avalanche_effect_for_file_sizes(file_sizes)
plot_avalanche_results(file_sizes, avalanche_results)

# Measure performance and plot results
performance_results = measure_performance_for_file_sizes(file_sizes)
plot_results(file_sizes, performance_results)
