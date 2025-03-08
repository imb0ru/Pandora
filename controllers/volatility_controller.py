import json
import logging
import os
from typing import Dict, Any, List, Type
import importlib
import importlib.resources
from volatility3.framework import contexts, exceptions, interfaces
from volatility3 import plugins  # Correct import

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

class VolatilityFeatureExtractor:
    def __init__(self, config_path: str = ""):
        """
        Initializes the feature extractor and discovers available plugins.

        :param config_path: Path to the configuration file (if required by plugins).
        """
        # Create the Volatility context
        self.context = contexts.Context()
        
        # Set the config_path attribute
        self.config_path = config_path
        
        # Configure automagic to use the provided memory dump path
        self.context.config['automagic.LayerStacker.single_location'] = "file://" + config_path
        
        # Discover plugins
        self.available_plugins = self._discover_plugins()

    def _discover_plugins(self) -> List[Type[interfaces.plugins.PluginInterface]]:
        """
        Discovers available plugins in the Volatility framework, including Windows plugins.
        """
        plugin_classes = []
        try:
            # Explicitly import the windows subpackage to trigger plugin registration
            import volatility3.plugins.windows
            logger.info("Windows plugins imported successfully.")
        except Exception as e:
            logger.error(f"Error importing Windows plugins: {e}")

        try:
            # Get a directory-like object for the volatility3.plugins package
            plugin_dir = importlib.resources.files(plugins)
            # Recursively search for all .py files
            for file in plugin_dir.rglob("*.py"):
                if file.name == "__init__.py":
                    continue  # Skip __init__.py files
                # Derive the module name relative to the volatility3.plugins package
                relative_path = file.relative_to(plugin_dir)
                module_name = relative_path.with_suffix("")  # Remove the .py suffix
                module_name_str = f"{plugins.__name__}." + ".".join(module_name.parts)
                try:
                    mod = importlib.import_module(module_name_str)
                    # Inspect the module for plugin classes
                    for attr_name in dir(mod):
                        attr = getattr(mod, attr_name)
                        if (isinstance(attr, type) and 
                            issubclass(attr, interfaces.plugins.PluginInterface) and 
                            attr.__name__ != "PluginInterface"):
                            plugin_classes.append(attr)
                            logger.info(f"Found plugin: {attr.__name__}")
                except Exception as e:
                    logger.error(f"Error importing module {module_name_str}: {e}")
        except Exception as e:
            logger.error(f"Error discovering plugins: {e}")
        logger.info(f"Total plugins found: {len(plugin_classes)}")
        return plugin_classes

    def _execute_plugin(self, memdump_path: str, plugin_class: Type[interfaces.plugins.PluginInterface]) -> Dict:
        """
        Executes a Volatility plugin on the memory dump and returns the results.

        :param memdump_path: Path to the memory dump file.
        :param plugin_class: The plugin class to execute.
        :return: A dictionary containing the plugin's output.
        """
        try:
            logger.info(f"Executing plugin: {plugin_class.__name__}")
            # Instantiate the plugin with context and config_path
            plugin = plugin_class(self.context, self.config_path)
            # Run the plugin on the memory dump
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