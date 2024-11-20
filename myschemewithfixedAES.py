import os
import timeit
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding as asym_padding
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES




def generate_valid_aes256_key():
    # Fixed 256-bit key
    key = b'\x00' * 32
    return key

def generate_private_key_via_aes_sha():
    # Generate a valid AES256 key
    key = generate_valid_aes256_key()
    iv = os.urandom(16)   # Generate a random initialization vector (IV)
    
    # Create Cipher object using AES-256 and CBC mode with the valid key
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Generate random plaintext data
    plaintext = os.urandom(16)
    
    # Apply PKCS7 padding to plaintext
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    
    # Encrypt the padded data
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    # Concatenate plaintext and ciphertext
    combined_data = plaintext + ciphertext
    
    # Hash the combined data using SHA-256
    hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
    hasher.update(combined_data)
    hash_value = hasher.finalize()
    
    # Convert hash to integer
    private_key_int = int.from_bytes(hash_value, 'big')
    
    # Generate an ECDSA private key using the elliptic curve SECP256R1
    curve = ec.SECP256R1()
    private_key_int %= curve.key_size
    private_key = ec.derive_private_key(private_key_int, curve, default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def sign_message(private_key, message):
    signature = private_key.sign(
        message,
        ec.ECDSA(hashes.SHA256())
    )
    return signature

def verify_signature(public_key, signature, message):
    try:
        public_key.verify(
            signature,
            message,
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except Exception as e:
        return False

# Generate key pair, and time tests for signing and verification
number_of_tests = 100
generate_time = timeit.timeit('generate_private_key_via_aes_sha()', globals=globals(), number=number_of_tests)
private_key, public_key = generate_private_key_via_aes_sha()  # Generate key pair for signing and verification tests
message = b"This is a secure message."
signature = sign_message(private_key, message)

sign_time = timeit.timeit(lambda: sign_message(private_key, message), number=number_of_tests)
verify_time = timeit.timeit(lambda: verify_signature(public_key, signature, message), number=number_of_tests)

print(f"Average time to generate keys: {generate_time / number_of_tests:.6f} seconds")
print(f"Average time to sign a message: {sign_time / number_of_tests:.6f} seconds")
print(f"Average time to verify a signature: {verify_time / number_of_tests:.6f} seconds")
