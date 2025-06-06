import base64
import secrets
import hmac
import hashlib
import struct
import time

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

PBKDF2_ITERATIONS = 600_000
PBKDF2_SALT_SIZE = 16
AES_KEY_SIZE = 32
AES_GCM_IV_SIZE = 12
RSA_KEY_SIZE = 2048
# Внешнее шифрование
EXT_RSA_KEY_SIZE = 1024
EXT_AES_KEY_SIZE = 16  # 128 бит
EXT_AES_GCM_IV_SIZE = 12

def generate_salt(size=PBKDF2_SALT_SIZE):
    return secrets.token_bytes(size)

def derive_key(password: str, salt: bytes, length=AES_KEY_SIZE, iterations=PBKDF2_ITERATIONS) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode())

def aes_encrypt(plaintext: bytes, key: bytes, iv=None) -> dict:
    if not iv:
        iv = secrets.token_bytes(AES_GCM_IV_SIZE)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, plaintext, None)
    tag = ciphertext[-16:]
    enc = {
        "iv": base64.b64encode(iv).decode(),
        "data": base64.b64encode(ciphertext[:-16]).decode(),
        "tag": base64.b64encode(tag).decode(),
    }
    return enc

def aes_decrypt(enc: dict, key: bytes) -> bytes:
    iv = base64.b64decode(enc["iv"])
    data = base64.b64decode(enc["data"])
    tag = base64.b64decode(enc["tag"])
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(iv, data + tag, None)

def generate_rsa_keypair(bits=RSA_KEY_SIZE):
    priv_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=bits,
        backend=default_backend()
    )
    pub_key = priv_key.public_key()
    return priv_key, pub_key

def rsa_encrypt(pub_key, data: bytes) -> str:
    ciphertext = pub_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return base64.b64encode(ciphertext).decode()

def rsa_decrypt(priv_key, ciphertext_b64: str) -> bytes:
    ciphertext = base64.b64decode(ciphertext_b64)
    return priv_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

def serialize_private_key(priv_key):
    return priv_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

def serialize_public_key(pub_key):
    return pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

def deserialize_private_key(priv_bytes):
    return serialization.load_pem_private_key(priv_bytes, password=None, backend=default_backend())

def deserialize_public_key(pub_bytes):
    return serialization.load_pem_public_key(pub_bytes, backend=default_backend())

def secure_zero(byte_array):
    # Обнуляет содержимое bytearray или bytes (mutable only)
    if isinstance(byte_array, bytearray):
        for i in range(len(byte_array)):
            byte_array[i] = 0
    elif isinstance(byte_array, bytes):
        ba = bytearray(byte_array)
        for i in range(len(ba)):
            ba[i] = 0

# ---------- EXTERNAL ENCRYPTION LAYER ----------

def ext_generate_rsa_keypair():
    return generate_rsa_keypair(bits=EXT_RSA_KEY_SIZE)

def ext_generate_aes_key():
    return secrets.token_bytes(EXT_AES_KEY_SIZE)

def ext_aes_encrypt(data: bytes, key: bytes, iv=None):
    if not iv:
        iv = secrets.token_bytes(EXT_AES_GCM_IV_SIZE)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, data, None)
    tag = ciphertext[-16:]
    enc = {
        "iv": base64.b64encode(iv).decode(),
        "data": base64.b64encode(ciphertext[:-16]).decode(),
        "tag": base64.b64encode(tag).decode(),
    }
    return enc

def ext_aes_decrypt(enc: dict, key: bytes) -> bytes:
    iv = base64.b64decode(enc["iv"])
    data = base64.b64decode(enc["data"])
    tag = base64.b64decode(enc["tag"])
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(iv, data + tag, None)

# ---------- TOTP (2FA) TOOLS ----------

def generate_totp_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode('utf-8').replace('=', '')

def totp_code(secret, interval=30, digits=6):
    # RFC 6238 TOTP (default HMAC-SHA1)
    secret = base64.b32decode(secret.upper() + '=' * ((8 - len(secret) % 8) % 8))
    T = int(time.time()) // interval
    msg = struct.pack(">Q", T)
    h = hmac.new(secret, msg, hashlib.sha1).digest()
    o = h[19] & 0xf
    code = (struct.unpack(">I", h[o:o+4])[0] & 0x7fffffff) % (10 ** digits)
    return str(code).zfill(digits)