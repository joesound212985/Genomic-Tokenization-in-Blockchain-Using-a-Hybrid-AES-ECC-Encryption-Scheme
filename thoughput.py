import json
import os
import time
import hashlib
import matplotlib.pyplot as plt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.algorithms import AES, Blowfish, TripleDES
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import x25519, rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import padding

import json  # Make sure to import json

class SimpleBlockchain:
    def __init__(self):
        self.chain = []
        genesis_block = {
            'index': 0,
            'timestamp': time.time(),
            'data': {"info": "Genesis Block", 'token': None, 'encrypted_data': None},
            'previous_hash': "1",
            'hash': ''
        }
        genesis_block['hash'] = self.hash_block(genesis_block)
        self.chain.append(genesis_block)

    def add_block(self, data):
        previous_block = self.chain[-1]
        previous_hash = previous_block['hash']
        block = {
            'index': len(self.chain),
            'timestamp': time.time(),
            'data': data,
            'previous_hash': previous_hash,
            'hash': ''
        }
        block['hash'] = self.hash_block(block)
        self.chain.append(block)

    def hash_block(self, block):
        # Exclude the 'hash' key from the block before hashing
        block_string = json.dumps(block, sort_keys=True, default=str).encode()
        return hashlib.sha256(block_string).hexdigest()

    def retrieve_block(self, token):
        for block in self.chain:
            if isinstance(block['data'], dict) and 'token' in block['data'] and block['data']['token'] == token:
                return block
        return None

    def validate_chain(self):
        if len(self.chain) < 2:
            return True

        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]

            if current_block['hash'] != self.hash_block(current_block):
                print(f"Invalid hash at block {i}")
                return False

            if current_block['previous_hash'] != previous_block['hash']:
                print(f"Invalid previous hash at block {i}")
                return False

        print("Blockchain is valid.")
        return True


# Function to generate a token for the encrypted data
def generate_token(encrypted_data):
    return hashlib.sha256(encrypted_data).hexdigest()

# Function to compare original and decrypted data
def compare_data(original_data, decrypted_data):
    return original_data == decrypted_data

# Read genomic data from a file
file_path = "/home/joes985/hg38.fa"
with open(file_path, 'rb') as file:
    genomic_data = file.read()

data_length = len(genomic_data)
data_length_bits = data_length * 8  # Length of data in bits

# Placeholder for encryption and decryption times, and metrics
encryption_times = {}
decryption_times = {}
metrics = {}

# Placeholder for blockchain
blockchain = SimpleBlockchain()

# --- AES Encryption ---
aes_key = os.urandom(32)  # AES key size 256 bits
iv_aes = os.urandom(16)  # AES IV size 16 bytes
cipher_aes = Cipher(algorithms.AES(aes_key), modes.CFB(iv_aes), backend=default_backend())
start_time = time.time()
encryptor_aes = cipher_aes.encryptor()
ciphertext_aes = encryptor_aes.update(genomic_data) + encryptor_aes.finalize()
encryption_times['AES'] = time.time() - start_time
start_time = time.time()
decryptor_aes = cipher_aes.decryptor()
plaintext_aes = decryptor_aes.update(ciphertext_aes) + decryptor_aes.finalize()
decryption_times['AES'] = time.time() - start_time
metrics['AES'] = {
    'KGT': 0,  # Key generation time is negligible
    'TKL': len(aes_key),
    'ET': encryption_times['AES'],
    'DT': decryption_times['AES'],
    'TP': data_length_bits / encryption_times['AES']  # Throughput
}

# Store AES encrypted data in blockchain
token_aes = generate_token(ciphertext_aes)
block_data_aes = {'token': token_aes, 'encrypted_data': ciphertext_aes}
blockchain.add_block(block_data_aes)

# --- ECC/AES Encryption ---
ecc_start_time = time.time()
ecc_private_key = x25519.X25519PrivateKey.generate()
ecc_public_key = ecc_private_key.public_key()
shared_secret = ecc_private_key.exchange(x25519.X25519PublicKey.from_public_bytes(
    ecc_public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
))
ecc_end_time = time.time()
derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake data', backend=default_backend()).derive(shared_secret)
cipher_ecc_aes = Cipher(algorithms.AES(derived_key), modes.CFB(iv_aes), backend=default_backend())
start_time = time.time()
encryptor_ecc_aes = cipher_ecc_aes.encryptor()
ciphertext_ecc_aes = encryptor_ecc_aes.update(genomic_data) + encryptor_ecc_aes.finalize()
encryption_times['ECC/AES'] = time.time() - start_time
start_time = time.time()
decryptor_ecc_aes = cipher_ecc_aes.decryptor()
plaintext_ecc_aes = decryptor_ecc_aes.update(ciphertext_ecc_aes) + decryptor_ecc_aes.finalize()
decryption_times['ECC/AES'] = time.time() - start_time
metrics['ECC/AES'] = {
    'KGT': ecc_end_time - ecc_start_time,
    'TKL': len(derived_key),
    'ET': encryption_times['ECC/AES'],
    'DT': decryption_times['ECC/AES'],
    'TP': data_length_bits / encryption_times['ECC/AES']
}

# Store ECC/AES encrypted data in blockchain
token_ecc_aes = generate_token(ciphertext_ecc_aes)
block_data_ecc_aes = {'token': token_ecc_aes, 'encrypted_data': ciphertext_ecc_aes}
blockchain.add_block(block_data_ecc_aes)

# --- Blowfish Encryption ---
blowfish_key = os.urandom(32)  # Blowfish key size can be 128, 192, or 256 bits
iv_blowfish = os.urandom(8)  # Blowfish IV size 8 bytes
cipher_blowfish = Cipher(Blowfish(blowfish_key), modes.CFB(iv_blowfish), backend=default_backend())
start_time = time.time()
encryptor_blowfish = cipher_blowfish.encryptor()
ciphertext_blowfish = encryptor_blowfish.update(genomic_data) + encryptor_blowfish.finalize()
encryption_times['Blowfish'] = time.time() - start_time
start_time = time.time()
decryptor_blowfish = cipher_blowfish.decryptor()
plaintext_blowfish = decryptor_blowfish.update(ciphertext_blowfish) + decryptor_blowfish.finalize()
decryption_times['Blowfish'] = time.time() - start_time
metrics['Blowfish'] = {
    'KGT': 0,  # Key generation time is negligible
    'TKL': len(blowfish_key),
    'ET': encryption_times['Blowfish'],
    'DT': decryption_times['Blowfish'],
    'TP': data_length_bits / encryption_times['Blowfish']
}

# Store Blowfish encrypted data in blockchain
token_blowfish = generate_token(ciphertext_blowfish)
block_data_blowfish = {'token': token_blowfish, 'encrypted_data': ciphertext_blowfish}
blockchain.add_block(block_data_blowfish)

# --- TripleDES Encryption ---
tripledes_key = os.urandom(24)  # TripleDES key size 192 bits
iv_tripledes = os.urandom(8)  # TripleDES IV size 8 bytes
cipher_tripledes = Cipher(TripleDES(tripledes_key), modes.CFB(iv_tripledes), backend=default_backend())
start_time = time.time()
encryptor_tripledes = cipher_tripledes.encryptor()
ciphertext_tripledes = encryptor_tripledes.update(genomic_data) + encryptor_tripledes.finalize()
encryption_times['TripleDES'] = time.time() - start_time
start_time = time.time()
decryptor_tripledes = cipher_tripledes.decryptor()
plaintext_tripledes = decryptor_tripledes.update(ciphertext_tripledes) + decryptor_tripledes.finalize()
decryption_times['TripleDES'] = time.time() - start_time
metrics['TripleDES'] = {
    'KGT': 0,  # Key generation time is negligible
    'TKL': len(tripledes_key),
    'ET': encryption_times['TripleDES'],
    'DT': decryption_times['TripleDES'],
    'TP': data_length_bits / encryption_times['TripleDES']
}

# Store TripleDES encrypted data in blockchain
token_tripledes = generate_token(ciphertext_tripledes)
block_data_tripledes = {'token': token_tripledes, 'encrypted_data': ciphertext_tripledes}
blockchain.add_block(block_data_tripledes)

# --- RSA Key Generation ---
rsa_start_time = time.time()
rsa_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
rsa_public_key = rsa_private_key.public_key()
rsa_end_time = time.time()
metrics['RSA'] = {
    'KGT': rsa_end_time - rsa_start_time,
    'TKL': 0,  # RSA doesn't use a symmetric key
    'ET': 0,  # RSA encryption time is not measured here
    'DT': 0,  # RSA decryption time is not measured here
    'TP': 0  # RSA throughput is not measured here
}

# --- RSA Encryption for AES Key ---
rsa_start_time = time.time()
aes_key_encrypted = rsa_public_key.encrypt(
    aes_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
rsa_end_time = time.time()
metrics['RSA']['ET'] = rsa_end_time - rsa_start_time
# --- AES Encryption with Encrypted AES Key (Hybrid) ---
iv_rsa_aes = os.urandom(16)  # AES IV size 16 bytes for the encrypted AES key
cipher_rsa_aes = Cipher(algorithms.AES(aes_key), modes.CFB(iv_rsa_aes), backend=default_backend())
start_time = time.time()
encryptor_rsa_aes = cipher_rsa_aes.encryptor()
ciphertext_rsa_aes = encryptor_rsa_aes.update(genomic_data) + encryptor_rsa_aes.finalize()
encryption_times['AES/RSA'] = time.time() - start_time


# Decrypt the RSA-encrypted AES key before using it
aes_key_decrypted = rsa_private_key.decrypt(
    aes_key_encrypted,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Debug: Compare the decrypted AES key with the original
print("Original AES Key: ", aes_key)
print("Decrypted AES Key: ", aes_key_decrypted)


cipher_rsa_aes_dec = Cipher(algorithms.AES(aes_key_decrypted), modes.CFB(iv_rsa_aes), backend=default_backend())
decryptor_rsa_aes = cipher_rsa_aes_dec.decryptor()
plaintext_rsa_aes = decryptor_rsa_aes.update(ciphertext_rsa_aes) + decryptor_rsa_aes.finalize()
decryption_times['AES/RSA'] = time.time() - start_time
metrics['AES/RSA'] = {
    'KGT': 0,  # Key generation time is negligible
    'TKL': len(aes_key_encrypted),  # Encrypted AES key length
    'ET': encryption_times['AES/RSA'],
    'DT': decryption_times['AES/RSA'],
    'TP': data_length_bits / encryption_times['AES/RSA']
}  

if plaintext_rsa_aes == genomic_data:
    print("AES/RSA decryption successful")
else:
    print("AES/RSA decryption failed")

# Store AES/RSA encrypted data in blockchain
token_aes_rsa = generate_token(ciphertext_rsa_aes)
block_data_aes_rsa = {'token': token_aes_rsa, 'encrypted_data': ciphertext_rsa_aes}
blockchain.add_block(block_data_aes_rsa)


# Verification process
# Function to verify the existence of a block in the blockchain by token
def verify_block_existence(blockchain, token):
    block = blockchain.retrieve_block(token)
    return block is not None
# Verification process
for method in ['AES', 'ECC/AES', 'Blowfish', 'TripleDES']:
    token_var_name = f"token_{method.replace('/', '_').lower()}"
    token = locals().get(token_var_name)
    block_exists = verify_block_existence(blockchain, token)
    if block_exists:
        retrieved_block = blockchain.retrieve_block(token)
        decrypted_data_var_name = f"plaintext_{method.replace('/', '_').lower()}"
        decrypted_data = locals().get(decrypted_data_var_name)
        if compare_data(genomic_data, decrypted_data):
            print(f"Data integrity verified for method {method}")
        else:
            print(f"Data integrity check failed for method {method}")
    else:
        print(f"Block not found for method {method}")

# Graph the results
methods = ['AES', 'ECC/AES', 'Blowfish', 'TripleDES', 'AES/RSA']
kgt_vals = [metrics[method]['KGT'] for method in methods]
tkl_vals = [metrics[method]['TKL'] for method in methods]
et_vals = [metrics[method]['ET'] for method in methods]
dt_vals = [metrics[method]['DT'] for method in methods]
tp_vals = [metrics[method]['TP'] for method in methods]

# Plotting the Key Generation Time
plt.figure(figsize=(10, 5))
plt.bar(methods, kgt_vals, color='blue', width=0.4)
plt.title('Key Generation Time Comparison')
plt.xlabel('Encryption Method')
plt.ylabel('Time (seconds)')
for i, v in enumerate(kgt_vals):
    plt.text(i, v + 0.05, f"{v:.2f}", ha='center', color='blue')
plt.show()

# Plotting the Total Key Length
plt.figure(figsize=(10, 5))
plt.bar(methods, tkl_vals, color='green', width=0.4)
plt.title('Total Key Length Comparison')
plt.xlabel('Encryption Method')
plt.ylabel('Key Length (bytes)')
for i, v in enumerate(tkl_vals):
    plt.text(i, v + 0.05, f"{v:.2f}", ha='center', color='green')
plt.show()

# Plotting the Encryption Time
plt.figure(figsize=(10, 5))
plt.bar(methods, et_vals, color='orange', width=0.4)
plt.title('Encryption Time Comparison of hg38 reference genome')
plt.xlabel('Encryption Method')
plt.ylabel('Time (seconds)')
for i, v in enumerate(et_vals):
    plt.text(i, v, f"{v:.2f}", ha='center', color='orange')
plt.show()

# Plotting the Decryption Time
plt.figure(figsize=(10, 5))
plt.bar(methods, dt_vals, color='red', width=0.4)
plt.title('Dencryption Time Comparison of hg38 reference genome')
plt.xlabel('Encryption Method')
plt.ylabel('Time (seconds)')
for i, v in enumerate(dt_vals):
    plt.text(i, v + 0.0, f"{v:.2f}", ha='center', color='red')
plt.show()

# Plotting the Throughput
plt.figure(figsize=(10, 5))
plt.bar(methods, tp_vals, color='purple', width=0.4)
plt.title('Throughput Comparison')
plt.xlabel('Encryption Method')
plt.ylabel('Throughput (bits/sec)')
for i, v in enumerate(tp_vals):
    plt.text(i, v + 0, f"{v:.2f}", ha='center', color='purple')
plt.show()



# Print metrics
for algo, metric in metrics.items():
    print(f"{algo}:")
    for key, value in metric.items():
        print(f"  {key}: {value}")
    print()

is_valid = blockchain.validate_chain()  # Make sure this line has correct indentation
if is_valid:
    print("The blockchain is working correctly and is valid.")
else:
    print("The blockchain has issues and may not be valid.")
