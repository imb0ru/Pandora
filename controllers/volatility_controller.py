import json
import logging
import os
from typing import Dict, Any, List, Type
from volatility3.framework import contexts, exceptions, interfaces
from volatility3 import plugins  # Correct import

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

class VolatilityFeatureExtractor:
    def __init__(self):
        """
        Initializes the feature extractor and discovers available plugins.
        """
        self.context = contexts.Context()
        self.available_plugins = self._discover_plugins()  # List of plugin classes

    def _discover_plugins(self) -> List[Type[interfaces.plugins.PluginInterface]]:
        """
        Uses Volatility3's built-in list_plugins function to retrieve available plugins.
        
        :return: A list of plugin classes.
        """
        try:
            # list_plugins() returns a dictionary {plugin_name: plugin_class}
            plugin_dict = plugins.list_plugins()
            plugin_classes = list(plugin_dict.values())
            logger.info(f"Total plugins found: {len(plugin_classes)}")
            return plugin_classes
        except Exception as e:
            logger.error(f"Error discovering plugins: {e}")
            return []

    def _execute_plugin(self, memdump_path: str, plugin_class: Type[interfaces.plugins.PluginInterface]) -> Dict:
        """
        Executes a Volatility plugin on the memory dump and returns the results.

        :param memdump_path: Path to the memory dump file.
        :param plugin_class: The plugin class to execute.
        :return: A dictionary containing the plugin's output.
        """
        try:
            logger.info(f"Executing plugin: {plugin_class.__name__}")
            plugin = plugin_class(self.context)
            # Assumes the run method accepts the memory dump path.
            result = plugin.run(memdump_path)
            logger.debug(f"Plugin {plugin_class.__name__} executed successfully.")
            return self._flatten_data(result)
        except exceptions.VolatilityException as e:
            logger.error(f"Error executing plugin {plugin_class.__name__}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error in plugin {plugin_class.__name__}: {e}")
        return {}

    def _flatten_data(self, data: Any, prefix: str = '') -> Dict[str, Any]:
        """
        Flattens nested structures (dicts, lists) into a simplified dictionary.

        :param data: The data to flatten.
        :param prefix: The prefix for nested keys (used internally for recursion).
        :return: A flattened dictionary.
        """
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
        Extracts features from a memory dump using all available plugins.

        :param memdump_path: Path to the memory dump file.
        :return: A dictionary containing the extracted features.
        """
        features = {
            "metadata.filename": os.path.basename(memdump_path),
            "metadata.plugins_processed": 0
        }
        total_plugins = len(self.available_plugins)
        for i, plugin_class in enumerate(self.available_plugins, 1):
            logger.info(f"Running plugin {i}/{total_plugins}: {plugin_class.__name__}")
            plugin_data = self._execute_plugin(memdump_path, plugin_class)
            if plugin_data:
                features.update(plugin_data)
                features["metadata.plugins_processed"] += 1
        features["metadata.success_rate"] = (
            features["metadata.plugins_processed"] / total_plugins if total_plugins > 0 else 0
        )
        return features

    def save_features(self, features: Dict, output_path: str):
        """
        Saves the extracted features to a JSON file.

        :param features: The features dictionary to save.
        :param output_path: The path to save the JSON file.
        """
        with open(output_path, "w") as f:
            json.dump(features, f, indent=2)
        logger.info(f"Features saved to {output_path}")

if __name__ == "__main__":
    # Example usage
    memdump = "memdump.mem"  # Replace with the actual memory dump path
    output_json = "features.json"

    extractor = VolatilityFeatureExtractor()
    features = extractor.extract_features(memdump)
    print("Analysis report:")
    print(json.dumps(features, indent=2))
    extractor.save_features(features, output_json)
