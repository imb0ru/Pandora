import yara
import os
from loguru import logger as l

class YaraScanner:
    def __init__(self, rules_path: str = None):
        """Initialize YARA scanner with default compiled rules"""
        # Set default compiled rules path
        self.default_rules = os.path.abspath(
            os.path.join(
                os.path.dirname(__file__),  # This file's directory
                'rules',
                'compiled_rules.yarc'
            )
        )
        
        # Use custom path if provided
        self.rules_path = rules_path or self.default_rules

        # Validate rules file exists
        if not os.path.isfile(self.rules_path):
            raise FileNotFoundError(
                f"YARA rules file missing at: {self.rules_path}\n"
                "Run setup.sh to download and compile rules"
            )

        # Load compiled rules
        try:
            self.rules = yara.load(self.rules_path)
            l.success(f"Loaded YARA rules from {self.rules_path}")
        except yara.Error as e:
            l.error(f"YARA rules loading failed: {str(e)}")
            raise RuntimeError("Failed to load YARA rules") from e

    def scan(self, dump_path: str) -> list:
        """Scan a memory dump file"""
        l.info(f"Starting YARA scan on: {dump_path}")
        
        if not os.path.isfile(dump_path):
            l.error(f"File not found: {dump_path}")
            raise FileNotFoundError(f"Invalid dump file: {dump_path}")

        try:
            matches = self.rules.match(dump_path)
            
            if matches:
                l.warning(f"YARA matches found: {len(matches)}")
                return [str(m) for m in matches]
            
            l.info("No YARA matches found")
            return []

        except yara.Error as e:
            l.error(f"YARA scan failed: {str(e)}")
            raise RuntimeError("YARA scan execution error") from e