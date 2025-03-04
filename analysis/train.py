from analysis.anomaly_detection import AnomalyDetection

dataset_path = "dataset/memory_analysis.csv"

model = AnomalyDetection(model_type="isolation_forest")
model.train(dataset_path)

model_supervised = AnomalyDetection(model_type="random_forest")
model_supervised.train(dataset_path)
