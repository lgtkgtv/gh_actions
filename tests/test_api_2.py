from calculator.src import API_2_good, API_2_bad
import pytest
from hypothesis import given, strategies as st

@given(a=st.integers(), b=st.floats(allow_infinity=False, allow_nan=False), c=st.text())
def test_api_2_good(a, b, c):
    assert API_2_good(a, b, c) == a * b + len(c)

@given(a=st.text(), b=st.text(), c=st.text())
def test_api_2_bad(a, b, c):
    with pytest.raises(Exception):
        API_2_bad(a, b, c)
        
from calculator.src.api_2 import API_2_good
from hypothesis import given, strategies as st

        
