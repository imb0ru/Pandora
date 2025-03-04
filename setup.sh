#!/bin/bash

set -e  # Stop script on first error

echo "[+] Updating system..."
sudo apt-get update -qq
sudo apt-get upgrade -y -qq
sudo apt-get install -y -qq python3 python3-pip python3-venv python3-dev git yara

echo "[+] Creating virtual environment..."
python3 -m venv venv || { echo "Virtual environment creation failed"; exit 1; }
source venv/bin/activate

echo "[+] Cloning and installing Volatility3..."
mkdir -p tools
git clone https://github.com/volatilityfoundation/volatility3.git tools/volatility3 || { echo "Cloning failed"; exit 1; }
cd tools/volatility3
pip install --quiet -e .[dev] || { echo "Volatility3 installation failed"; exit 1; }
cd ../..

echo "[+] Downloading YARA rules repositories..."
declare -A YARA_REPOS=(
    ["Yara-Rules"]="https://github.com/Yara-Rules/rules.git"
    ["Neo23x0"]="https://github.com/Neo23x0/signature-base.git"
    ["Elastic"]="https://github.com/elastic/protections-artifacts.git"
)

for repo in "${!YARA_REPOS[@]}"; do
    echo "  - Cloning ${repo} rules..."
    git clone --depth 1 "${YARA_REPOS[$repo]}" "tools/yara/rules/${repo}" || echo "Warning: Failed to clone ${repo}"
done

echo "[+] Compiling YARA rules..."
find tools/yara/rules -name "*.yar*" -exec cat {} + > tools/yara/rules/combined_rules.yar 2>/dev/null || true

if [ -s analysis/yara/rules/combined_rules.yar ]; then
    yarac tools/yara/rules/combined_rules.yar tools/yara/rules/compiled_rules.yarc || { echo "YARA compilation failed"; exit 1; }
else
    echo "Warning: No YARA rules found for compilation"
fi

echo "[+] Installing project dependencies..."
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt || { echo "Dependency installation failed"; exit 1; }

echo -e "\n[+] Setup completed successfully!"
echo -e "\nUse 'utils/yara-rules/compiled_rules.yarc' for YaraScanner initialization"