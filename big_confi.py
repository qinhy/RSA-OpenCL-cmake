import random
from sympy import nextprime

def generate_large_prime(bits):
    """Generate a large prime number of the specified bit size."""
    # Generate a random number with the specified number of bits
    random_number = random.getrandbits(bits)
    # Ensure it's odd (primes > 2 are odd)
    random_number |= 1
    # Use sympy's nextprime to ensure the number is prime
    return nextprime(random_number)

def modular_inverse(a, m):
    """Compute the modular multiplicative inverse of a modulo m."""
    m0, x0, x1 = m, 0, 1
    if m == 1:
        return 0
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

def generate_rsa_config(bits, message, filename):
    """Generate RSA configuration with p, q, e, and message."""
    # Generate two large prime numbers of 'bits' size
    p = generate_large_prime(bits)
    q = generate_large_prime(bits)
    
    # Ensure p and q are distinct
    while q == p:
        q = generate_large_prime(bits)
    
    # Compute N and phi(N)
    n = p * q
    phi_n = (p - 1) * (q - 1)
    
    # Choose e (public exponent)
    e = 65537  # Commonly used public exponent
    if phi_n % e == 0:
        raise ValueError("Chosen e is not coprime with phi(N).")
    
    # Compute d (private key)
    d = modular_inverse(e, phi_n)
    
    # Write to configuration file
    with open(filename, 'w') as f:
        f.write(f"{p} {q} {e} {message}\n")
    print(f"Configuration file '{filename}' generated successfully.")
    print(f"p = {p}")
    print(f"q = {q}")
    print(f"e = {e}")
    print(f"Message = {message}")
    print(f"N = {n}")
    print(f"phi(N) = {phi_n}")
    print(f"d (private key) = {d}")

# Usage example
if __name__ == "__main__":
    generate_rsa_config(256, 35, "conf_file.txt")
