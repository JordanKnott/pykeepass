import struct


def convert_bytes_to_uint(data):
    return struct.unpack('<I', bytes(data))[0]

def convert_int_to_bytes(data):
    return (data).to_bytes(4, byteorder='little')

def convert_float_to_bytes(data):
    return struct.pack('d', data)

