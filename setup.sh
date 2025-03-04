#!/bin/bash

set -e  # Stop script on first error

echo "[+] Updating system..."
sudo apt-get update -qq
sudo apt-get upgrade -y -qq
sudo apt-get install -y -qq python3 python3-pip python3-venv python3-dev git

echo "[+] Creating virtual environment..."
python3 -m venv venv || { echo "Virtual environment creation failed"; exit 1; }
source venv/bin/activate

echo "[+] Cloning and installing Volatility3..."
mkdir -p tools
git clone https://github.com/volatilityfoundation/volatility3.git tools/volatility3 || { echo "Cloning failed"; exit 1; }
cd tools/volatility3
pip install --quiet -e .[dev] || { echo "Volatility3 installation failed"; exit 1; }
cd ../..

echo "[+] Installing project dependencies..."
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt || { echo "Dependency installation failed"; exit 1; }

echo -e "\n[+] Setup completed successfully!"