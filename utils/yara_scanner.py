import yara
import os
from loguru import logger as l

class YaraScanner:
    def __init__(self, rules_path):
        if not os.path.exists(rules_path):
            raise FileNotFoundError(f"YARA rules file not found: {rules_path}")

        self.rules = yara.compile(filepath=rules_path)

    def scan(self, dump_path):
        l.info(f"YARA scan in progress on {dump_path}...")
        matches = self.rules.match(dump_path)

        if matches:
            l.warning(f"Threat detected: {matches}")
            return matches
        else:
            l.info("No threats detected.")
            return None
