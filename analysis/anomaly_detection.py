import os
import pickle
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import precision_score, recall_score, f1_score
from loguru import logger as l

MODEL_PATH = "models/"

class AnomalyDetection:
    def __init__(self, model_type="isolation_forest"):
        """
        Inizializza il modello di anomaly detection.
        """
        self.model_type = model_type
        self.model = None
        self.scaler = StandardScaler()

        if model_type == "isolation_forest":
            self.model = IsolationForest(contamination=0.05, random_state=42)
        elif model_type == "random_forest":
            self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        else:
            raise ValueError("Modello non supportato. Usa 'isolation_forest' o 'random_forest'.")

    def load_dataset(self, dataset_path):
        """
        Carica il dataset per il training.
        """
        if not os.path.exists(dataset_path):
            raise FileNotFoundError(f"Dataset {dataset_path} non trovato.")

        df = pd.read_csv(dataset_path)
        if "label" not in df.columns:
            raise ValueError("Il dataset deve contenere una colonna 'label'.")

        X = df.drop(columns=["label"])
        y = df["label"]

        return X, y

    def train(self, dataset_path):
        """
        Allena il modello di anomaly detection.
        """
        l.info("Caricamento dataset...")
        X, y = self.load_dataset(dataset_path)

        # Normalizzazione dei dati
        X = self.scaler.fit_transform(X)

        if self.model_type == "isolation_forest":
            l.info("Training Isolation Forest...")
            self.model.fit(X)
        else:
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
            l.info("Training Random Forest...")
            self.model.fit(X_train, y_train)

            # Valutazione
            y_pred = self.model.predict(X_test)
            precision = precision_score(y_test, y_pred, average="binary")
            recall = recall_score(y_test, y_pred, average="binary")
            f1 = f1_score(y_test, y_pred, average="binary")

            l.info(f"Precisione: {precision:.4f}, Recall: {recall:.4f}, F1-score: {f1:.4f}")

        self.save_model()

    def save_model(self):
        """
        Salva il modello addestrato.
        """
        os.makedirs(MODEL_PATH, exist_ok=True)
        model_filename = f"{MODEL_PATH}{self.model_type}.pkl"

        with open(model_filename, "wb") as file:
            pickle.dump((self.model, self.scaler), file)

        l.info(f"Modello salvato in {model_filename}")

    def load_model(self):
        """
        Carica il modello salvato.
        """
        model_filename = f"{MODEL_PATH}{self.model_type}.pkl"
        if not os.path.exists(model_filename):
            raise FileNotFoundError("Modello non addestrato. Esegui il training prima.")

        with open(model_filename, "rb") as file:
            self.model, self.scaler = pickle.load(file)

        l.info(f"Modello {self.model_type} caricato.")

    def predict(self, X):
        """
        Predice se un sample è anomalo o meno.
        """
        X_scaled = self.scaler.transform(X)

        if self.model_type == "isolation_forest":
            return self.model.predict(X_scaled)  # -1 = anomalia, 1 = normale
        else:
            return self.model.predict(X_scaled)  # 0 = normale, 1 = anomalia
