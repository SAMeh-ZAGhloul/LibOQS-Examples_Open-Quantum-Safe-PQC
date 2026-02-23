# LibOQS - Open Quantum Safe PQC

This project provides **examples** on using Python bindings for **liboqs**, a C library for quantum-resistant cryptographic algorithms from the [Open Quantum Safe](https://openquantumsafe.org/) project.

---

## About

The **Open Quantum Safe (OQS) project** aims to develop and prototype quantum-resistant cryptography. As quantum computers advance, traditional cryptographic algorithms like RSA and ECC will become vulnerable to attacks. This project provides post-quantum cryptographic algorithms that are secure against both classical and quantum computers.

**liboqs-python** offers Python 3 bindings for the [liboqs](https://github.com/open-quantum-safe/liboqs/) C library, enabling easy integration of quantum-resistant cryptography into Python applications.

---
## Notebook Demo

This project includes an interactive Jupyter notebook demonstrating all features:

**File:** `LIBOQS2.ipynb`

The notebook covers:
1. Installation of liboqs-python
2. Running KEM examples
3. Running signature examples
4. Running stateful signature examples
5. Running random number generation examples

To run the notebook:
```bash
jupyter notebook LIBOQS2.ipynb
```

## PQC Recommendation: Hybrid Mode

For production use, combine classical and post-quantum algorithms:

```python
# Example: Hybrid key encapsulation
import oqs

# Generate classical keypair (e.g., X25519)
classical_kem = oqs.KeyEncapsulation("X25519")
classical_public = classical_kem.generate_keypair()

# Generate post-quantum keypair
pq_kem = oqs.KeyEncapsulation("ML-KEM-512")
pq_public = pq_kem.generate_keypair()

# Combine both public keys
combined_public = classical_public + pq_public
```

---

## Installation

```bash
# Clone and install liboqs-python
git clone --depth=1 https://github.com/open-quantum-safe/liboqs-python
cd liboqs-python
pip install .
```

### Automatic liboqs Installation

If liboqs is not detected at runtime, it will be downloaded, configured, and installed automatically as a shared library. This happens only once when loading the liboqs-python wrapper.

### Using Docker

```bash
docker build -t oqs-python .
docker run -it oqs-python sh -c ". venv/bin/activate && python liboqs-python/examples/kem.py"
```

---

## Quick Start

```python
import oqs

# Key Encapsulation Example
with oqs.KeyEncapsulation("ML-KEM-512") as kem:
    public_key = kem.generate_keypair()
    ciphertext, shared_secret = kem.encap_secret(public_key)
    decrypted_secret = kem.decap_secret(ciphertext)

# Signature Example
with oqs.Signature("ML-DSA-44") as sig:
    public_key = sig.generate_keypair()
    signature = sig.sign(b"Hello, Quantum World!")
    is_valid = sig.verify(b"Hello, Quantum World!", signature, public_key)
```

---

## Examples

The following examples demonstrate the core functionality of liboqs-python. All examples can be found in the `liboqs-python/examples/` directory.

### Key Encapsulation (KEM)

Key encapsulation mechanisms (KEMs) are used to establish shared secrets between parties. This example demonstrates ML-KEM-512:

```python
import oqs

kemalg = "ML-KEM-512"
with oqs.KeyEncapsulation(kemalg) as client:
    with oqs.KeyEncapsulation(kemalg) as server:
        # Client generates keypair
        public_key_client = client.generate_keypair()
        
        # Server encapsulates secret using client's public key
        ciphertext, shared_secret_server = server.encap_secret(public_key_client)
        
        # Client decapsulates to obtain shared secret
        shared_secret_client = client.decap_secret(ciphertext)

# Verify both secrets match
print(shared_secret_client == shared_secret_server)  # True
```

**Run the example:**
```bash
python3 liboqs-python/examples/kem.py
```

**Sample Output:**
```
liboqs version: X.XX.X
liboqs-python version: X.XX.X
Enabled KEM mechanisms:
['Kyber512', 'Kyber768', 'Kyber1024', 'ML-KEM-512', 'ML-KEM-768', 'ML-KEM-1024', ...]
Key encapsulation details:
{'name': 'ML-KEM-512', 'alg_version': 'https://github.com/open-quantum-safe/liboqs/releases/download/v0.XX.0/liboqs-v0.XX.0', ...}
Shared secretes coincide: True
```

### Signatures

Digital signatures provide authentication and integrity. This example uses ML-DSA-44:

```python
import oqs

message = b"This is the message to sign"
sigalg = "ML-DSA-44"

with oqs.Signature(sigalg) as signer, oqs.Signature(sigalg) as verifier:
    # Generate keypair
    signer_public_key = signer.generate_keypair()
    
    # Sign the message
    signature = signer.sign(message)
    
    # Verify the signature
    is_valid = verifier.verify(message, signature, signer_public_key)
    
print(f"Valid signature? {is_valid}")  # True
```

**Run the example:**
```bash
python3 liboqs-python/examples/sig.py
```

**Sample Output:**
```
liboqs version: X.XX.X
liboqs-python version: X.XX.X
Enabled signature mechanisms:
['Dilithium2', 'Dilithium3', 'Dilithium5', 'ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87', ...]
Signature details:
{'name': 'ML-DSA-44', 'alg_version': 'https://github.com/open-quantum-safe/liboqs/releases/download/v0.XX.0/liboqs-v0.XX.0', ...}
Valid signature? True
```

### Stateful Signatures

Stateful signature schemes like XMSS provide forward security through one-time signatures:

```python
import oqs
from oqs import StatefulSignature

message = b"This is the message to sign"
stfl_sigalg = "XMSS-SHA2_10_256"

with StatefulSignature(stfl_sigalg) as signer, StatefulSignature(stfl_sigalg) as verifier:
    # Generate keypair
    signer_public_key = signer.generate_keypair()
    
    # Sign the message (stateful - limited number of signatures)
    signature = signer.sign(message)
    
    # Verify the signature
    is_valid = verifier.verify(message, signature, signer_public_key)
    
print(f"Valid signature? {is_valid}")  # True
```

**Run the example:**
```
python3 liboqs-python/examples/stfl_sig.py
```

**Sample Output:**
```
liboqs version: X.XX.X
liboqs-python version: X.XX.X
Enabled stateful signature mechanisms:
['XMSS-SHA2_10_256', 'XMSS-SHA2_16_256', 'XMSS-SHA2_20_256', 'XMSS-SHA2_40_256', 'XMSS-SHA2_10_512', ...]
Signature details:
{'name': 'XMSS-SHA2_10_256', 'alg_version': 'https://github.com/open-quantum-safe/liboqs/releases/download/v0.XX.0/liboqs-v0.XX.0', ...}
Valid signature? True
```

### Random Number Generation

liboqs-python supports multiple random number generators:

```python
import oqs.rand as oqsrand
from oqs import oqs_version, oqs_python_version

print(f"liboqs version: {oqs_version()}")
print(f"liboqs-python version: {oqs_python_version()}")

# System random (default)
oqsrand.randombytes_switch_algorithm("system")
system_bytes = oqsrand.randombytes(32)
print(f"System RNG: {system_bytes.hex()}")

# OpenSSL random (not available on Windows)
import platform
if platform.system() != "Windows":
    oqsrand.randombytes_switch_algorithm("OpenSSL")
    openssl_bytes = oqsrand.randombytes(32)
    print(f"OpenSSL RNG: {openssl_bytes.hex()}")
```

**Run the example:**
```bash
python3 liboqs-python/examples/rand.py
```

---

## Supported Algorithms

### Key Encapsulation Mechanisms (KEM)

| Algorithm | Security Level | Description |
|-----------|----------------|-------------|
| ML-KEM-512 | Level 1 | Module-Lattice-based KEM (NIST Level 1) |
| ML-KEM-768 | Level 3 | Module-Lattice-based KEM (NIST Level 3) |
| ML-KEM-1024 | Level 5 | Module-Lattice-based KEM (NIST Level 5) |
| Kyber512 | Level 1 | Classic Kyber KEM |
| Kyber768 | Level 3 | Classic Kyber KEM |
| Kyber1024 | Level 5 | Classic Kyber KEM |

### Signature Algorithms

| Algorithm | Security Level | Description |
|-----------|----------------|-------------|
| ML-DSA-44 | Level 2 | Module-Lattice-based Signature (NIST Level 2) |
| ML-DSA-65 | Level 3 | Module-Lattice-based Signature (NIST Level 3) |
| ML-DSA-87 | Level 5 | Module-Lattice-based Signature (NIST Level 5) |
| ML-DSA-44-Python | Level 2 | Pure Python implementation |
| FN-DSA-512 | Level 1 | Fast Fourier-based Signature |
| FN-DSA-1024 | Level 5 | Fast Fourier-based Signature |

### Stateful Signature Algorithms

| Algorithm | Description |
|-----------|-------------|
| XMSS-SHA2_10_256 | eXtended Merkle Signature Scheme |
| XMSS-SHA2_16_256 | eXtended Merkle Signature Scheme |
| XMSS-SHA2_20_256 | eXtended Merkle Signature Scheme |
| XMSSMT-SHA2_40_2_256 | Multi-Tree XMSS |

---



---


