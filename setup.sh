#!/bin/bash
set -e

# Path configuration
YARA_RULES_DIR="tools/yara/rules"
YARA_TMP_DIR="${YARA_RULES_DIR}/processing_tmp"
VENV_DIR="venv"

# System updates
echo -e "\n[1/6] Updating system packages..."
sudo apt-get update -qq
sudo apt-get upgrade -y -qq
sudo apt-get install -y -qq \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    git \
    yara \
    curl \
    libcurl4-openssl-dev \
    libssl-dev \
    upx

# Python virtual environment management
echo -e "\n[2/5] Managing Python environment..."
if [[ -d "$VENV_DIR" ]]; then
    echo "Reusing existing virtual environment..."
else
    echo "Creating new virtual environment..."
    python3 -m venv "$VENV_DIR"
fi
source "$VENV_DIR/bin/activate"
pip install --quiet --upgrade pip wheel

# Install Volatility3 inside the virtual environment
echo -e "\n[3/5] Installing Volatility3..."
pip install --quiet --force-reinstall volatility3

# Check if Volatility 3 is correctly installed
if python -c "import volatility3" &> /dev/null; then
    echo "[+] Volatility 3 installed successfully!"
else
    echo "[-] Volatility 3 installation failed. Check dependencies."
    exit 1
fi

# YARA rules management
#echo -e "\n[5/6] Handling YARA rules..."
#declare -A YARA_REPOS=(
#    ["Yara-Rules"]="https://github.com/Yara-Rules/rules.git --branch master"
#
#
#mkdir -p "$YARA_RULES_DIR" "$YARA_TMP_DIR"

# Clone/update YARA repositories
#for repo in "${!YARA_REPOS[@]}"; do
#    repo_dir="${YARA_RULES_DIR}/${repo}"
#    repo_url=${YARA_REPOS[$repo]}
#    
#    echo "Processing ${repo} repository..."
#    if [[ -d "$repo_dir" ]]; then
#        echo "Updating existing repository..."
#        cd "$repo_dir"
#        git pull -q 2>/dev/null || true
#        cd - > /dev/null
#    else
#        git clone -q --depth 1 $repo_url "$repo_dir" 2>/dev/null || {
#            echo "Error cloning ${repo}"
#            exit 1
#        }
#    fi
#done
#
## Validate and copy rules with error suppression
#echo "Validating YARA rules..."
#find "${YARA_RULES_DIR}" -type f \( -name "*.yar" -o -name "*.yara" \) \
#    -not -path "*test*" -not -path "*example*" \
#    -exec sh -c '
#        for file; do
#            if yara -n "$file" /dev/null >/dev/null 2>&1; then
#                cp "$file" "'"$YARA_TMP_DIR/"'$(basename "$file")"
#            fi
#        done' sh {} +
#
## Create mock includes for missing dependencies
#echo "Creating missing includes..."
#echo 'global rule hash { condition = false }' > "${YARA_TMP_DIR}/includes.yar"
#echo 'global rule antidebug_antivm { condition = false }' >> "${YARA_TMP_DIR}/includes.yar"
#
## Process rules with advanced filtering
#echo "Processing valid rules..."
#awk '
#BEGIN {
#    RS = "\n}\n";
#    FS = "\n";
#    include_added = 0;
#}
#
#/^include / {
#    gsub(/"/, "", $0);
#    if (!includes_seen[$0]++) {
#        includes = includes $0 "\n";
#    }
#    next;
#}
#
#/^rule / {
#    rule_name = $2;
#    gsub(/[^a-zA-Z0-9_]/, "_", rule_name);
#    rule_name = substr(rule_name, 1, 120);
#    
#    if (!rules_seen[rule_name]++) {
#        if (!include_added) {
#            print includes;
#            include_added = 1;
#        }
#        print $0 RT;
#    }
#    next;
#}
#
#{ print }
#' "${YARA_TMP_DIR}"/*.yar > "${YARA_RULES_DIR}/combined_rules.yar"
#
## Compile final ruleset
#echo "Compiling YARA rules..."
#(
#    cd "$YARA_RULES_DIR"
#    yarac -w combined_rules.yar compiled_rules.yarc 2>/dev/null
#)
#
## Cleanup temporary files
#rm -rf "$YARA_TMP_DIR"

# Install Python requirements
echo -e "\n[6/6] Installing Python requirements..."
pip install --quiet -r requirements.txt

# Final cleanup and permissions
#echo -e "\n[7/7] Finalizing setup..."
#find "$YARA_RULES_DIR" -type f -name "*.yar" -exec chmod 644 {} \;

echo -e "\n[+] Installation completed successfully!"
