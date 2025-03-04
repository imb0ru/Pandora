"""
volatility_feature_extractor.py
Automatic feature extraction from memory dumps using Volatility 3
"""

import json
import logging
import os
import subprocess
import tempfile
from typing import Dict, Any, List

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class VolatilityFeatureExtractor:
    def __init__(self, volatility_path: str):
        """
        Initialize the extractor with Volatility 3 path
        
        :param volatility_path: Path to volatility3's vol.py
        """
        self.volatility_path = volatility_path
        self.available_plugins = self._discover_plugins()
        
    def _discover_plugins(self) -> List[str]:
        """Discover all available Windows plugins"""
        try:
            result = subprocess.run(
                ['python3', self.volatility_path, '-h'],
                capture_output=True,
                text=True,
                check=True
            )
            return [
                line.split()[0] 
                for line in result.stdout.split('\n') 
                if line.strip().startswith('windows.')
            ]
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to discover plugins: {e.stderr}")
            return []

    def _execute_plugin(self, memdump_path: str, plugin: str) -> Dict:
        """Execute a single Volatility plugin and return parsed results"""
        with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tmpfile:
            try:
                result = subprocess.run(
                    ['python3', self.volatility_path, '-f', memdump_path, '-r=json', plugin],
                    stdout=tmpfile,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=True,
                    timeout=300
                )
                tmpfile.seek(0)
                return json.load(tmpfile)
            except subprocess.CalledProcessError as e:
                logger.error(f"Plugin {plugin} failed: {e.stderr}")
            except subprocess.TimeoutExpired:
                logger.error(f"Plugin {plugin} timed out")
            except json.JSONDecodeError:
                logger.error(f"Invalid JSON output from {plugin}")
            finally:
                os.unlink(tmpfile.name)
        return {}

    def _flatten_data(self, data: Any, prefix: str = '') -> Dict[str, Any]:
        """Recursively flatten nested structures"""
        flattened = {}
        if isinstance(data, dict):
            for key, value in data.items():
                new_key = f"{prefix}.{key}" if prefix else key
                flattened.update(self._flatten_data(value, new_key))
        elif isinstance(data, list):
            for i, item in enumerate(data):
                new_key = f"{prefix}[{i}]" if prefix else str(i)
                flattened.update(self._flatten_data(item, new_key))
        else:
            flattened[prefix] = data
        return flattened

    def extract_features(self, memdump_path: str) -> Dict[str, Any]:
        """
        Extract features from a memory dump using all available plugins
        
        :param memdump_path: Path to memory dump file
        :return: Dictionary of flattened features
        """
        features = {
            'metadata.filename': os.path.basename(memdump_path),
            'metadata.plugins_processed': 0
        }
        
        total_plugins = len(self.available_plugins)
        for i, plugin in enumerate(self.available_plugins, 1):
            logger.info(f"Processing plugin {i}/{total_plugins}: {plugin}")
            plugin_data = self._execute_plugin(memdump_path, plugin)
            if plugin_data:
                features.update(self._flatten_data(plugin_data, plugin))
                features['metadata.plugins_processed'] += 1
                
        features['metadata.success_rate'] = \
            features['metadata.plugins_processed'] / total_plugins if total_plugins > 0 else 0
            
        return features

    def save_features(self, features: Dict, output_path: str):
        """Save features to JSON file"""
        with open(output_path, 'w') as f:
            json.dump(features, f, indent=2)
        logger.info(f"Features saved to {output_path}")