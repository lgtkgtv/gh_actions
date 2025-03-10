"""
Calculator Library

Provides good and bad implementations of two sample APIs for educational purposes.
"""

# API 1: Addition Operation
def API_1_good(x, y):
    try:
        return x + y
    except TypeError:
        raise ValueError("Invalid input: Expected numbers.")

def API_1_bad(x, y):
    return eval(f"{x} + {y}")  # ⚠️ Vulnerable to code injection

# API 2: Complex Calculation (3 parameters)
def API_2_good(x: int, y: float, z: str):
    try:
        if not z.isdigit():
            raise ValueError("Invalid string input for number conversion.")
        return x * y + int(z)
    except TypeError:
        raise ValueError("Invalid input types provided.")

def API_2_bad(x, y, z):
    return eval(f"{x} * {y} + {z}")  # ⚠️ High-risk security vulnerability
