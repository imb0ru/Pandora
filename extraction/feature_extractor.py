import pandas as pd

class FeatureExtractor:
    @staticmethod
    def convert_to_dataframe(data):
        if data is None or len(data) == 0:
            return pd.DataFrame()

        return pd.DataFrame(data)

    @staticmethod
    def save_to_csv(df, output_file):
        df.to_csv(output_file, index=False)

    @staticmethod
    def save_to_json(df, output_file):
        df.to_json(output_file, orient="records", indent=4)
