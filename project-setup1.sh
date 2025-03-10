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

# Add initial files
touch gh_actions/README.md
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
echo "✅ Project setup completed successfully."

