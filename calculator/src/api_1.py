def API_1_good(a: int, b: int) -> int:
    """Secure implementation of API_1."""
    return a + b

def API_1_bad(a, b):
    """Insecure implementation of API_1."""
    return eval(f"{a} + {b}")  # ⚠️ Vulnerable to code injection
