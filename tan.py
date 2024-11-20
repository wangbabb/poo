from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os
import timeit

def generate_keys():
    # Generate a random byte sequence
    bk = os.urandom(32)  # 256 bits

    # Create a hash object and update it with the random bytes
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(bk)
    hashed_bytes = digest.finalize()

    # Convert the hash to an integer
    private_key_int = int.from_bytes(hashed_bytes, byteorder='big')

    # Get the curve
    curve = ec.SECP256R1()

    # Reduce this integer to fit within the curve's order
    private_key_int = private_key_int % curve.key_size

    

    # Create a private key from the integer
    private_key = ec.derive_private_key(private_key_int, curve, default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

# Test key generation, signing, and verification times
number_of_runs = 100

# Generate keys
generate_key_time = timeit.timeit('generate_keys()', globals=globals(), number=number_of_runs)
print(f"Average time to generate keys: {generate_key_time / number_of_runs:.6f} seconds")



