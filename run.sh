#!/bin/bash

# Function to display the help menu
function show_help() {
    echo "Usage: ./run.sh [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --memdump <path>    Path to the memory dump file to analyze (required)"
    echo "  --output <path>     Path to save the analysis report (optional)"
    echo "  --config <path>     Path to the configuration file for Volatility plugins (optional)"
    echo "  --help              Show this help message and exit"
    echo ""
    echo "Example:"
    echo "  ./run.sh --memdump /path/to/memdump.raw --output /path/to/report.json --config /path/to/config.json"
}

# Check if the first argument is --help
if [[ "$1" == "--help" ]]; then
    show_help
    exit 0
fi

# Parse command-line arguments
MEMDUMP_PATH=""
OUTPUT_PATH=""
CONFIG_PATH=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --memdump)
            MEMDUMP_PATH="$2"
            shift 2
            ;;
        --output)
            OUTPUT_PATH="$2"
            shift 2
            ;;
        --config)
            CONFIG_PATH="$2"
            shift 2
            ;;
        *)
            echo "Error: Unknown option $1"
            show_help
            exit 1
            ;;
    esac
done

# Validate the memory dump path
if [[ -z "$MEMDUMP_PATH" ]]; then
    echo "Error: --memdump <path> is required"
    show_help
    exit 1
fi

if [[ ! -f "$MEMDUMP_PATH" ]]; then
    echo "Error: Memory dump file not found: $MEMDUMP_PATH"
    exit 1
fi

# Activate the virtual environment
if [[ ! -f "venv/bin/activate" ]]; then
    echo "Error: Virtual environment not found. Please ensure 'venv/bin/activate' exists."
    exit 1
fi
source venv/bin/activate

# Run the Python application
echo "Starting memory dump analysis..."
if [[ -n "$OUTPUT_PATH" && -n "$CONFIG_PATH" ]]; then
    python3 app.py --memdump "$MEMDUMP_PATH" --output "$OUTPUT_PATH" --config "$CONFIG_PATH"
elif [[ -n "$OUTPUT_PATH" ]]; then
    python3 app.py --memdump "$MEMDUMP_PATH" --output "$OUTPUT_PATH"
elif [[ -n "$CONFIG_PATH" ]]; then
    python3 app.py --memdump "$MEMDUMP_PATH" --config "$CONFIG_PATH"
else
    python3 app.py --memdump "$MEMDUMP_PATH"
fi

# Deactivate the virtual environment
deactivate