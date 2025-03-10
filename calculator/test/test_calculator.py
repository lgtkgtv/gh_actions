import pytest
from calculator import API_1_good, API_1_bad, API_2_good, API_2_bad
from hypothesis import given, strategies as st

# API_1 Tests
def test_API_1_good():
    assert API_1_good(2, 3) == 5
    assert API_1_good(-1, 1) == 0
    assert API_1_good(0, 0) == 0

def test_API_1_bad():
    assert API_1_bad(2, 3) == 5
    assert API_1_bad(-1, 1) == 0
    assert API_1_bad(0, 0) == 0

# API_2 Tests
def test_API_2_good():
    assert API_2_good(2, 3.5, "4") == 11
    assert API_2_good(0, 1.5, "0") == 0
    assert API_2_good(10, 0.1, "10") == 11

def test_API_2_bad():
    assert API_2_bad(2, 3.5, "4") == 11
    with pytest.raises(Exception):
        API_2_bad(5, 0, "invalid")
