# Calculator Library
This library implements two sample APIs for learning DevSecOps best practices.

```sh    

 <workdir>   
    │
    ├── init_github_repo.sh                 # script to clone the project template from github repo
    ├── project_setup.sh                    # script to setup the project template 
    ├── setup_pyenv_virtualenv_to_311.sh    # script to setup the python virtualenv for development on local host
    │
    └── gh_actions                          # repo contents (in the gitHub)
        │
        ├── README.md                       # This file
        │
        ├── requirements.txt                # for project setup
        ├── pyproject.toml                  #
        ├── setup.py                        #
        │
        ├── .gitignore                      # git ignore list for python projects 
        │
        ├── .github                         # github actions! Main purpose of this template project   
        │   └── workflows
        │       ├── ci.yml
        │       └── <more...>        
        │    
        ├── calculator                      # source code for an example python library package - 
        │   ├── __init__.py
        │   └── src
        │       ├── api_1.py                # api_1 - good and bad versions
        │       ├── api_2.py                # api_2 - good and bad versions
        │       └── __init__.py
        │    
        ├── tests
        │   ├── __init__.py
        │   ├── test_api_1.py               # unit tests using pytest and hypothesis
        │   ├── test_api_2.py
        │
        └── fuzz
            ├── __init__.py               
            ├── fuzz_api_1.py               # fuzz tests using atheris 
            └── fuzz_api_2.py
         
```

##  `calculator/src/api_1.py`      

```sh
def API_1_good(a: int, b: int) -> int:
    """Secure implementation of API_1."""
    return a + b

def API_1_bad(a, b):
    """Insecure implementation of API_1."""
    return eval(f"{a} + {b}")  # ⚠️ Vulnerable to code injection
```

##  `calculator/src/api_2.py`      

```py
def API_2_good(a: int, b: float, c: str) -> float:
    """Secure implementation of API_2."""
    return a * b + len(c)

def API_2_bad(a, b, c):
    """Insecure implementation of API_2."""
    return eval(f"{a} * {b} + len({c})")  # ⚠️ Vulnerable to code injection
```    

##  `tests/api_1.py`

```py
from calculator.src.api_1 import API_1_good, API_1_bad

from hypothesis import given, strategies as st, assume
from hypothesis import HealthCheck, settings
import pytest


@given(a=st.integers(), b=st.integers())
def test_api_1_good(a, b):
    assert API_1_good(a, b) == a + b


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
```

## `fuzz/fuzz_api_1.py`

```
import atheris
import sys
from calculator.src import API_1_good

def TestOneInput(data):
    try:
        API_1_good(int(data), int(data))
    except:
        pass

atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()
```
