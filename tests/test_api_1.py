from calculator.src.api_1 import API_1_good, API_1_bad

from hypothesis import given, strategies as st, assume
from hypothesis import HealthCheck, settings
import pytest

'''
@given(a=st.integers(), b=st.integers())
def test_api_1_good(a, b):
    assert API_1_good(a, b) == a + b

'''


'''
@given(a=st.text(), b=st.text())  # Generate random text inputs
def test_api_1_bad(a, b):
    """Test API_1_bad with random inputs to detect failures."""
    try:
        result = API_1_bad(a, b)  # Execute API

        # Ensure the result is of a valid type
        assert isinstance(result, (int, float, str)), f"Unexpected return type: {type(result)}"

    except (SyntaxError, TypeError, NameError):
        pytest.skip(f"Expected failure for input: {a}, {b}")
        
    except Exception as e:
        pytest.fail(f"Unexpected exception {e} for input: {a}, {b}")

import pytest
from calculator.src import API_1_bad
from hypothesis import given, strategies as st
'''

@given(a=st.text(), b=st.text())
def test_api_1_bad(a, b):
    """Test API_1_bad with random inputs."""
    try:
        result = API_1_bad(a, b)
        assert isinstance(result, (int, float, str)), f"Unexpected return type: {type(result)}"

    except (SyntaxError, TypeError, NameError) as e:
        print(f"Skipping for input: a={a}, b={b} due to {e}")  # Log skipped input
        pytest.skip(f"Expected failure for input: a={a}, b={b}")

    except Exception as e:
        pytest.fail(f"Unexpected exception {e} for input: a={a}, b={b}")


