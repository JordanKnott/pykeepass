import io
import random
import struct

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import algorithms, modes, Cipher

from keepass.crypto import cryptutil
from keepass.domain import crsalgorithm, compalgorithm
from keepass.utils import byteutils

SIZE_OF_FIELD_LENGTH_BUFFER = 3

CIPHER = 2
COMPRESSION = 3
MASTER_SEED = 4
TRANSFORM_SEED = 5
TRANSFORM_ROUNDS = 6
ENCRYPTION_IV = 7
PROTECTED_STREAM_KEY = 8
STREAM_START_BYTES = 9
INNER_RANDOM_STREAM_ID = 10
KDF_PARAMETERS = 11
PUBLIC_CUSTOM_DATA = 12

DATABASE_V2_FILE_SIGNATURE_1 = bytearray.fromhex("03d9a29a")
DATABASE_V2_FILE_SIGNATURE_2 = bytearray.fromhex("67fb4bb5")

DATABASE_V2_FILE_VERSION_MAJOR = 3

DATABASE_V2_FILE_VERSION_MINOR_ONE = 0
DATABASE_V2_FILE_VERSION_MINOR_ZERO = 1


FILE_VERSION_CRITICAL_MASK = 0xFFFF0000

DATABASE_V3_FILE_VERSION_INT = 0x00030001
DATABASE_V4_FILE_VERSION_INT = 0x00040000

# KeePass Magic Bytes for AES Cipher
DATABASE_V2_AES_CIPHER = bytearray.fromhex("31C1F2E6BF714350BE5805216AFC5AFF")

# KeePass version signature length in bytes
VERSION_SIGNATURE_LENGTH = 12

# KeePass 2.x signature
DATABASE_V2_FILE_SIGNATURE_1_INT = 0x03d9a29a
DATABASE_V2_FILE_SIGNATURE_2_INT = 0x67fb4bb5


class KeePassHeader:
    def __init__(self):
        self.compression = 1  # Gzip
        self.crs = 2  # Salsa20
        self.transform_rounds = 8000  # default value?
        self.master_seed = random.getrandbits(32)
        self.transform_seed = random.getrandbits(32)
        self.encryption_iv = random.getrandbits(16)
        self.protected_stream_key = random.getrandbits(32)
        self.stream_start_bytes = random.getrandbits(32)
        self.cipher = DATABASE_V2_AES_CIPHER
        self.file_format_version = None

    def check_version_support(self, keepass):
        print("checking version support")
        input_stream = io.BytesIO(keepass)

        signature = input_stream.read(VERSION_SIGNATURE_LENGTH)

        sig_p1 = struct.unpack('>I', bytes(signature[:4]))[0]
        sig_p2 = struct.unpack('>I', bytes(signature[4:8]))[0]

        version_minor = struct.unpack('<H', bytes(signature[8:10]))[0]
        version_major = struct.unpack('<H', bytes(signature[10:12]))[0]

        self.file_format_version_minor = version_minor
        self.file_format_version_major = version_major

        print("{}.{}".format(version_major, version_minor))

        if version_major == DATABASE_V2_FILE_VERSION_MAJOR:
            if version_minor == DATABASE_V2_FILE_VERSION_MINOR_ONE or version_minor == DATABASE_V2_FILE_VERSION_MINOR_ZERO:
                pass
            else:
                raise AssertionError("Not a valid version or keepass database!")




    def is_version_supported(self, version):
        if (version & FILE_VERSION_CRITICAL_MASK) > (DATABASE_V4_FILE_VERSION_INT & FILE_VERSION_CRITICAL_MASK):
            return False

        return True

    def set_inner_random_stream_id(self, value):
        self.crs_algorithm = crsalgorithm.get_algorithm_from_value(byteutils.convert_bytes_to_uint(value))

    def get_inner_random_stream_id(self):
        return self.convert_to_bytes(crsalgorithm.get_value_from_algorithm(self.crs_algorithm))

    def set_stream_start_bytes(self, value):
        self.stream_start_bytes = value

    def set_protected_stream_key(self, value):
        self.protected_stream_key = value

    def set_encryption_iv(self, value):
        self.encryption_iv = value

    def set_transform_rounds(self, value):
        self.transform_rounds = struct.unpack('<q', value)[0]

    def set_transform_seed(self, value):
        self.transform_seed = value

    def set_master_seed(self, value):
        self.master_seed = value

    def set_compression_flag(self, value):
        i_value = byteutils.convert_bytes_to_uint(value)
        print(i_value)
        self.compression = compalgorithm.get_algorithm_from_value(i_value)

    def set_cipher(self, value):
        if value == None or len(value) != 16:
            raise Exception("The encryption cipher must contain 16 bytes!")
        self.cipher = value

    def convert_to_bytes(self, value):
        if isinstance(value, int):
            return byteutils.convert_int_to_bytes(value)
        elif isinstance(value, float):
            return byteutils.convert_float_to_bytes(value)

    def set_value(self, id, value):
        if id == CIPHER:
            print("Setting cipher!")
            self.set_cipher(value)
        elif id == COMPRESSION:
            print("Setting compression!")
            self.set_compression_flag(value)
        elif id == MASTER_SEED:
            print("Setting master seed!")
            self.set_master_seed(value)
        elif id == TRANSFORM_SEED:
            print("Setting transform seed!")
            self.set_transform_seed(value)
        elif id == TRANSFORM_ROUNDS:
            print("Setting transform rounds!")
            self.set_transform_rounds(value)
        elif id == ENCRYPTION_IV:
            print("Setting encryption iv!")
            self.set_encryption_iv(value)
        elif id == PROTECTED_STREAM_KEY:
            print("Setting protected stream key!")
            self.set_protected_stream_key(value)
        elif id == STREAM_START_BYTES:
            print("Setting stream start bytes!")
            self.set_stream_start_bytes(value)
        elif id == INNER_RANDOM_STREAM_ID:
            print("Setting inner random stream id!")
            self.set_inner_random_stream_id(value)
        elif id == KDF_PARAMETERS:
            print("Setting pdf parameters!")
            pass



    def read(self, keepass):
        input_stream = io.BytesIO(keepass)
        input_stream.read(VERSION_SIGNATURE_LENGTH)

        while True:
            fieldId = input_stream.read(1)[0]

            if self.file_format_version_major == 4:
                field_length = 2
            else:
                field_length = 4

            print("Field ID: {}".format(fieldId))

            field_length_int = struct.unpack("<H", input_stream.read(2))[0]
            print("Field Length: {}".format(field_length_int))

            if field_length_int > 0:
                data = input_stream.read(field_length_int)
                print("Field Data: {}".format(data))
                self.set_value(fieldId, data)

            if fieldId == 0:
                print("End Found")
                break

        self.header_end_position = input_stream.tell()

class CryptoInformation:

    def __init__(self, version_sig_length, master_seed, transform_seed, transform_rounds, header_size, encryption_iv):
        self.version_sig_length = version_sig_length
        self.master_seed = master_seed
        self.transform_seed = transform_seed
        self.transform_rounds = transform_rounds
        self.header_size = header_size
        self.encryption_iv = encryption_iv

class Aes:

    def transform_key(self, key, data, rounds):
        backend = default_backend()
        cipher = Cipher(algorithms.AES(key), modes.ECB, backend=backend)
        encryptor = cipher.encryptor()

        for i in range(0, rounds):
            encryptor.update(data, )


class Decrypter:

    def decrypt_database(self, password, crypto_information, database):

        aes_key = self.create_aes_key(password, crypto_information)

    def create_aes_key(self, password, crypto_information):
        hashed_password = cryptutil.get_sha256_hash(password)




class KeePassDatabase:

    def open_database(self, password, keepassfile):
        password_hash = cryptutil.get_sha256_hash(password)

        aes_decrypted_db_file = self.decrypt_stream(password_hash, keepassfile)
        hashed_block_bytes = self.skip_metadata(aes_decrypted_db_file)
        protected_string_crypto = self.get_protected_string_crypto()

        decompressed = self.decompress_stream(hashed_block_bytes)
        self.parse_database(decompressed, protected_string_crypto)


        # https://github.com/cternes/openkeepass/blob/master/src/main/java/de/slackspace/openkeepass/KeePassDatabase.java
        # https://github.com/cternes/openkeepass/blob/master/src/main/java/de/slackspace/openkeepass/api/KeePassDatabaseReader.java
        # https://gist.github.com/msmuenchen/9318327

    def decrypt_stream(self, key, keepass):

        pass

    def parse_database(self, decompressed, protected_string_crypto):
        pass

    def get_protected_string_crypto(self):
        pass

    def skip_metadata(self, aes_decrypted_db_file):
        pass

    def decompress_stream(self, hashed_block_bytes):
        pass
