import os
import json
from typing import Dict, Any
from tools.yara.scanner import YaraScanner
from controllers.volatility_controller import VolatilityFeatureExtractor
from loguru import logger as l

class MemoryAnalyzer:
    def __init__(self):
        """
        Initialize memory analysis components.
        """
        # Initialize YARA scanner with default rules if needed
        # self.yara_scanner = YaraScanner()
        
        # Initialize Volatility feature extractor with config_path
        self.feature_extractor = VolatilityFeatureExtractor(config_path)
        
        # Configure paths
        self.base_dir = os.path.abspath(os.path.dirname(__file__))

    def analyze(self, memdump_path: str) -> Dict[str, Any]:
        """
        Perform a complete analysis workflow on the memory dump.

        :param memdump_path: Path to the memory dump file.
        :return: A dictionary containing the analysis report.
        """
        if not os.path.isfile(memdump_path):
            l.error(f"Memory dump not found: {memdump_path}")
            raise FileNotFoundError(f"Invalid file: {memdump_path}")

        # Initialize the report structure
        report = {
            'filename': os.path.basename(memdump_path),
            'analysis': {
                'yara': {'matches': None, 'error': None},
                'volatility': {'features': None, 'error': None},
            }
        }

        # Execute YARA scan if needed
        # try:
        #     yara_results = self.yara_scanner.scan(memdump_path)
        #     report['analysis']['yara']['matches'] = yara_results
        #     report['analysis']['threat_detected'] = len(yara_results) > 0
        # except Exception as e:
        #     report['analysis']['yara']['error'] = str(e)
        #     l.error(f"YARA analysis failed: {str(e)}")

        # Extract Volatility features
        try:
            volatility_features = self.feature_extractor.extract_features(memdump_path)
            report['analysis']['volatility']['features'] = volatility_features
        except Exception as e:
            report['analysis']['volatility']['error'] = str(e)
            l.error(f"Volatility analysis failed: {str(e)}")

        return report

    def save_report(self, report: Dict, output_path: str = None) -> str:
        """
        Save the analysis report to a JSON file.

        :param report: The analysis report to save.
        :param output_path: The path to save the JSON file. If not provided, a default path is used.
        :return: The path where the report was saved.
        """
        if not output_path:
            output_path = os.path.join(
                self.base_dir,
                'analysis',
                f"{report['filename']}_analysis.json"
            )
            
        # Ensure the output directory exists
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        # Save the report to a JSON file
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)
            
        l.info(f"Report saved to: {output_path}")
        return output_path