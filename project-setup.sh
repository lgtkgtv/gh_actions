#!/bin/bash

# Idempotent script to set up the project structure and dependencies
set -e  # Exit on error

# Install pyenv if not present
if ! command -v pyenv &> /dev/null; then
  curl https://pyenv.run | bash
  echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.bashrc
  echo 'export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.bashrc
  echo 'eval "$(pyenv init --path)"' >> ~/.bashrc
  source ~/.bashrc
fi

# Install virtualenv if not present
if ! command -v virtualenv &> /dev/null; then
  pip install virtualenv
fi

# Install Docker if not present
if ! command -v docker &> /dev/null; then
  sudo apt-get update && sudo apt-get install -y docker.io
fi

# Create project structure
cd ..
mkdir -p gh_actions/calculator/src
mkdir -p gh_actions/calculator/test
mkdir -p gh_actions/calculator/fuzz
mkdir -p gh_actions/.github/workflows

# Add calculator library
cat << 'EOF' > gh_actions/calculator/src/calculator.py
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
EOF

# Add unit tests
cat << 'EOF' > gh_actions/calculator/test/test_calculator.py
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
EOF

# Add fuzz test for API_1
cat << 'EOF' > gh_actions/calculator/fuzz/fuzz_API_1.py
import atheris
import sys
from calculator import API_1_good, API_1_bad

@atheris.instrument_func
def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    x = fdp.ConsumeInt(4)
    y = fdp.ConsumeInt(4)
    
    try:
        API_1_good(x, y)
        API_1_bad(x, y)
    except Exception as e:
        print(f"Exception caught in API_1: {e}")

def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
EOF

# Add fuzz test for API_2
cat << 'EOF' > gh_actions/calculator/fuzz/fuzz_API_2.py
import atheris
import sys
from calculator import API_2_good, API_2_bad

@atheris.instrument_func
def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    x = fdp.ConsumeInt(4)
    y = fdp.ConsumeFloat()
    z = fdp.ConsumeString(4)
    
    try:
        API_2_good(x, y, z)
        API_2_bad(x, y, z)
    except Exception as e:
        print(f"Exception caught in API_2: {e}")

def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
EOF

# Add .gitignore
cat << EOF > gh_actions/.gitignore
__pycache__/
*.pyc
*.pyo
*.pyd
.Python
*.db
*.sqlite3
.vscode/
.DS_Store
EOF

# Success message
echo "✅ Project setup, calculator code, unit tests, and fuzz tests are complete."
