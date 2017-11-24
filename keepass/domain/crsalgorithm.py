class CrsAlgorithm(object): pass

class NoAlgorithm(CrsAlgorithm): pass


class Salsa20(CrsAlgorithm): pass

class ArcFourVariant(CrsAlgorithm): pass


def get_algorithm_from_value(value):
    if value == 0:
        return NoAlgorithm
    elif value == 1:
        return ArcFourVariant
    elif value == 2:
        return Salsa20
    else:
        raise LookupError('No algorithm with that key exists!')

def get_value_from_algorithm(algorithm):
    if algorithm == NoAlgorithm:
        return 0
    elif algorithm == ArcFourVariant:
        return 1
    elif algorithm == Salsa20:
        return 2
    else:
        raise LookupError("No value with that algorithm exists!")
