from controllers.volatility_controller import VolatilityController
from extraction.feature_extractor import FeatureExtractor
from loguru import logger as l

class Pipeline:
    def __init__(self, dump_path):
        self.dump_path = dump_path
        self.volatility = VolatilityController()

    def run(self):
        extracted_data = {}

        for plugin in self.volatility.VOLATILITY_PLUGINS.keys():
            l.info(f"Executing plugin {plugin}...")
            result = self.volatility.run_plugin(self.dump_path, plugin)

            if result:
                df = FeatureExtractor.convert_to_dataframe(result)
                extracted_data[plugin] = df
                FeatureExtractor.save_to_csv(df, f"output/{plugin}.csv")
                FeatureExtractor.save_to_json(df, f"output/{plugin}.json")

        return extracted_data
