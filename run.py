from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import algorithms, modes, Cipher

from keepass.keepass import KeePassHeader
import hashlib

keepassheader = KeePassHeader()
keepass = open('testDatabase.kdbx', 'rb').read()
keepassheader.check_version_support(keepass)
keepassheader.read(keepass)

m = hashlib.sha256()

m.update(b'Password01')
pwd_hash = m.digest()

m = hashlib.sha256()
m.update(pwd_hash)

composite_key = m.digest()

backend = default_backend()

cipher = Cipher(algorithms.AES(keepassheader.transform_seed), modes.ECB(), backend)
encryptor = cipher.encryptor()

transformed_key = composite_key
for round in range(0, keepassheader.transform_rounds):
    transformed_key = encryptor.update(transformed_key)
m = hashlib.sha256()
m.update(transformed_key)
transformed_key = m.digest()
masterkey = keepassheader.master_seed + transformed_key

cipher = Cipher(algorithms.AES(masterkey), modes.CBC(keepassheader.encryption_iv), backend)
encryptor = cipher.encryptor()
