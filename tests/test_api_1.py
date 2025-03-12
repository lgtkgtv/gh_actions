from calculator.src.api_1 import API_1_good, API_1_bad

from hypothesis import given, strategies as st, assume
from hypothesis import HealthCheck, settings
import pytest

@given(a=st.integers(), b=st.integers())
def test_api_1_good(a, b):
    assert API_1_good(a, b) == a + b

# @settings(suppress_health_check=[HealthCheck.filter_too_much])
# @given(a=st.text(), b=st.text())
# def test_api_1_bad(a, b):
#    # Assuming API_1_bad should only fail for numeric strings
#    assume(a.isnumeric() and b.isnumeric())  # Keep only cases that should fail
#
#    with pytest.raises(Exception):
#        API_1_bad(a, b)

@given(a=st.text(alphabet="0123456789", min_size=1), b=st.text(alphabet="0123456789", min_size=1))
def test_api_1_bad(a, b):
    with pytest.raises(Exception):
        API_1_bad(a, b)

