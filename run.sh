#!/bin/bash

# Funzione per visualizzare il menu di help
function show_help() {
    echo "Usage: ./run.sh [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --memdump <path>    Path to the memory dump file to analyze (required)"
    echo "  --output <path>     Path to save the analysis report (optional)"
    echo "  --help              Show this help message and exit"
    echo ""
    echo "Example:"
    echo "  ./run.sh --memdump /path/to/memdump.raw --output /path/to/report.json"
}

# Verifica se il primo parametro è --help
if [[ "$1" == "--help" ]]; then
    show_help
    exit 0
fi

# Verifica se il file di dump della memoria è stato fornito
if [[ -z "$1" || "$1" != "--memdump" || -z "$2" ]]; then
    echo "Error: --memdump <path> is required"
    show_help
    exit 1
fi

# Verifica se il file di dump della memoria esiste
MEMDUMP_PATH="$2"
if [[ ! -f "$MEMDUMP_PATH" ]]; then
    echo "Error: Memory dump file not found: $MEMDUMP_PATH"
    exit 1
fi

# Verifica se il flag --output è stato fornito
if [[ "$3" == "--output" && -n "$4" ]]; then
    OUTPUT_PATH="$4"
else
    OUTPUT_PATH=""  # Non viene passato nessun percorso di output
fi

# Attiva l'ambiente virtuale
source venv/bin/activate

# Esegui l'applicazione Python
echo "Starting memory dump analysis..."
python3 app.py --memdump "$MEMDUMP_PATH" --output "$OUTPUT_PATH"

# Disattiva l'ambiente virtuale
deactivate
