def API_2_good(a: int, b: float, c: str) -> float:
    """Secure implementation of API_2."""
    return a * b + len(c)

def API_2_bad(a, b, c):
    """Insecure implementation of API_2."""
    return eval(f"{a} * {b} + len({c})")  # ⚠️ Vulnerable to code injection
