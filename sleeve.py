import os
import hashlib
import time


def generate_random_string(length):
    """Generate a random string of given length."""
    return os.urandom(length)

def hash_function(data):
    """Hash the given data using SHA-256."""
    return hashlib.sha256(data).hexdigest()

def gen_key_updated(l, w):
    # Parameter initialization
    n = 256  # Assuming n-bit masks are 256 bits (SHA-256 hash size)
    
    # Generate ri with each being 256 bytes long and (l + w - 1) such strings in total
    ri = [generate_random_string(256) for _ in range(l + w - 1)]
    
    masks = [[generate_random_string(n // 8), generate_random_string(n // 8)] for _ in range(l)]
    
    # Generate bk and initial vk
    bk = [b''.join([masks[i][0], masks[i][1]]) for i in range(l)]
    r = generate_random_string(l + w - 1)
    
    # Compute the vk using a correct XOR operation for bytes
    vk = [hash_function(bytes([bk[i][j] ^ r[j % len(r)] for j in range(len(bk[i]))])) for i in range(l)]
    
    # Example hash chain computations (simplified)
    nodes = [hash_function(vk[i].encode()) for i in range(l)]
    L = nodes[0]  # Example, taking the first node as L
    
    # Final sk and vk preparation
    sk = (vk[0], L, bk[0])
    vk_final = hash_function((vk[0].encode() + L.encode() + bk[0]))

    return sk, vk_final, bk
def test_average_execution_time(l, w, iterations=1000):
    total_time = 0
    for _ in range(iterations):
        start_time = time.time()
        sk, vk, bk = gen_key_updated(l, w)
        end_time = time.time()
        total_time += (end_time - start_time)
    average_time = total_time / iterations
    return average_time

# Time the key generation with the modified ri
start_time = time.time()
l = 256
w = 256
sk, vk, bk = gen_key_updated(l, w)
end_time = time.time()

# Calculate execution time for new parameters
average_execution_time = test_average_execution_time(256, 256)
print(average_execution_time)
