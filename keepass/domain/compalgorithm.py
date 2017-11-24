class CompressionAlgorithm(object): pass

class NoCompression(CompressionAlgorithm): pass

class GzipCompression(CompressionAlgorithm): pass

def get_algorithm_from_value(value):
    if value == 0:
        return NoCompression
    elif value == 1:
        return GzipCompression
    else:
        raise LookupError('No compression algorithm with that key exists!')

def get_value_from_algorithm(algorithm):
    if algorithm == NoCompression:
        return 0
    elif algorithm == GzipCompression:
        return 1
    else:
        raise LookupError("No value with that compression algorithm exists!")
