from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import timeit
import os

def generate_keys():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key



# 测试生成密钥、签名和验证的时间
number_of_runs = 100

# 生成密钥
generate_key_time = timeit.timeit('generate_keys()', globals=globals(), number=number_of_runs)
print(f"Average time to generate keys: {generate_key_time / number_of_runs:.6f} seconds")

