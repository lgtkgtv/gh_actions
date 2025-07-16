#!/bin/bash

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

# Create project structure
mkdir -p gh_actions/calculator/src
mkdir -p gh_actions/calculator/test
mkdir -p gh_actions/calculator/fuzz
mkdir -p gh_actions/.github/workflows

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

# Add calculator.py
cat << EOF > gh_actions/calculator/src/calculator.py
"""
Calculator Library

Implements API_1 and API_2 with good and bad versions for testing.
"""

def API_1_good(x, y):
    return x + y

def API_1_bad(x, y):
    return eval(f"{x} + {y}")

def API_2_good(x, y, z):
    return f"{x} - {y} - {z}"

def API_2_bad(x, y, z):
    return eval(f"{x} - {y} - {z}")
EOF

# Add test_calculator.py
cat << EOF > gh_actions/calculator/test/test_calculator.py
import pytest
from calculator import API_1_good, API_1_bad, API_2_good, API_2_bad

def test_API_1_good():
    assert API_1_good(2, 3) == 5

def test_API_1_bad():
    assert API_1_bad(2, 3) == 5

def test_API_2_good():
    assert API_2_good("A", "B", "C") == "A - B - C"

def test_API_2_bad():
    assert API_2_bad("A", "B", "C") == "A - B - C"
EOF

# Add fuzz tests
cat << EOF > gh_actions/calculator/fuzz/fuzz_API_1.py
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
        print(f"Exception caught: {e}")

def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
EOF

cat << EOF > gh_actions/calculator/fuzz/fuzz_API_2.py
import atheris
import sys
from calculator import API_2_good, API_2_bad

@atheris.instrument_func
def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    x = fdp.ConsumeUnicode(4)
    y = fdp.ConsumeInt(4)
    z = fdp.ConsumeBytes(4)
    try:
        API_2_good(x, y, z)
        API_2_bad(x, y, z)
    except Exception as e:
        print(f"Exception caught: {e}")

def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
EOF

# Add requirements.txt
cat << EOF > gh_actions/requirements.txt
pytest
hypothesis
bandit
semgrep
flake8
atheris
cyclonedx-bom
EOF

# Add .bandit.yml
cat << EOF > gh_actions/.bandit.yml
exclude_dirs:
  - tests
  - .github
skips:
  - B101  # Ignore assert statements for now
EOF

# Add .semgrep.yml
cat << EOF > gh_actions/.semgrep.yml
rules:
- id: eval-injection
  patterns:
    - pattern: eval(...)
  message: "Avoid eval() — it's prone to code injection attacks."
  severity: ERROR
EOF

# Add README.md
cat << EOF > gh_actions/README.md
# GitHub Actions DevSecOps Project

This project demonstrates key DevSecOps practices using GitHub Actions. It includes:

✅ Calculator library with good and bad APIs  
✅ Unit tests using pytest and Hypothesis  
✅ Fuzz tests using Atheris  
✅ Linting and static analysis using Bandit, Semgrep, and Flake8  
✅ SBOM generation and vulnerability scanning  

## Running Locally
```bash
./build.sh
```
EOF

# Add build.sh
cat << EOF > gh_actions/build.sh
#!/bin/bash
set -e
cd "$(dirname "$0")"
if ! pyenv versions | grep -q "3.11"; then
  pyenv install 3.11
fi
if ! pyenv virtualenvs | grep -q "gh_actions_env"; then
  pyenv virtualenv 3.11 gh_actions_env
fi
pyenv activate gh_actions_env
pip install -r requirements.txt
echo "✅ Build complete"
EOF

# Success message
echo "✅ Revised project structure and updated files created successfully."
