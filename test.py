# quick test (run from repo root)
from app.crypto import aes, dh, sign, pki
from cryptography import x509
from cryptography.hazmat.primitives import serialization
import base64, os

# 1) AES roundtrip
key = b"\x01"*16
pt = b"hello world"
ct = aes.encrypt_aes_ecb(key, pt)
pt2 = aes.decrypt_aes_ecb(key, ct)
assert pt == pt2

# 2) DH pair derive same key
# Use a small safe prime for dev; in real use load p,g from a known group
p = 0xE95E4A5F737059DC60DF5991D45029409E60FC09  # example small int (dev only)
g = 2
a = dh.generate_private_key(256)
b = dh.generate_private_key(256)
A = dh.compute_public(p, g, a)
B = dh.compute_public(p, g, b)
s1 = dh.compute_shared(p, B, a)
s2 = dh.compute_shared(p, A, b)
assert s1 == s2
K1 = dh.derive_aes_key_from_shared(s1)
K2 = dh.derive_aes_key_from_shared(s2)
assert K1 == K2

# 3) load CA and certs (after running gen_ca/gen_cert)
ca = pki.load_certificate("certs/ca.crt")
cert = pki.load_certificate("certs/client.crt")
ok, reason = pki.validate_certificate(cert, ca, expected_cn="client.local")
print("cert ok:", ok, reason)

