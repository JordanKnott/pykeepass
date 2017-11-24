
import hashlib

def get_sha256_hash(message):
    m = hashlib.sha256()
    m.update(message.encoded())
    return m.digest()

def get_sha256_hash_hex(message):
    m = hashlib.sha256()
    m.update(message.encoded())
    return m.hexdigest()
