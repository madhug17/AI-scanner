from pathlib import Path
from typing import Any
import joblib
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.model_selection import train_test_split

from scanner.core.finding import Finding
from scanner.ml.dataset import extract_finding_features, get_labeled_dataset


class FindingPrioritizer:
    """ML-based finding prioritization component that predicts the likelihood
    of a finding being a true positive to rank triage queues.
    """

    def __init__(self, model_path: Path | str | None = None):
        self.model_path = Path(model_path) if model_path else Path("prioritizer_model.joblib")
        self.pipeline: Pipeline | None = None
        self.metrics: dict[str, float] = {}

    def build_pipeline(self) -> Pipeline:
        cat_features = ["rule_id", "category", "severity", "status"]
        num_features = ["snippet_len", "in_test", "has_sanitizer"]

        preprocessor = ColumnTransformer(
            transformers=[
                ("cat", OneHotEncoder(handle_unknown="ignore"), cat_features),
                ("num", StandardScaler(), num_features),
            ]
        )

        pipeline = Pipeline(
            steps=[
                ("preprocessor", preprocessor),
                ("classifier", LogisticRegression(random_state=42, max_iter=200)),
            ]
        )
        return pipeline

    def train_and_evaluate(self, test_size: float = 0.25) -> dict[str, float]:
        df = get_labeled_dataset()
        X = df.drop(columns=["label"])
        y = df["label"]

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y
        )

        self.pipeline = self.build_pipeline()
        self.pipeline.fit(X_train, y_train)

        y_pred = self.pipeline.predict(X_test)

        self.metrics = {
            "accuracy": round(float(accuracy_score(y_test, y_pred)), 4),
            "precision": round(float(precision_score(y_test, y_pred, zero_division=0)), 4),
            "recall": round(float(recall_score(y_test, y_pred, zero_division=0)), 4),
            "f1_score": round(float(f1_score(y_test, y_pred, zero_division=0)), 4),
        }

        # Save model
        joblib.dump(self.pipeline, self.model_path)
        return self.metrics

    def predict_priority(self, finding: Finding) -> float:
        """Predict the probability (0.0 to 1.0) that this finding is a true positive."""
        if self.pipeline is None:
            if self.model_path.exists():
                self.pipeline = joblib.load(self.model_path)
            else:
                self.train_and_evaluate()

        features = extract_finding_features(finding)
        df_feat = pd.DataFrame([features])
        probs = self.pipeline.predict_proba(df_feat)
        # Class 1 is true positive
        return round(float(probs[0][1]), 3)


prioritizer = FindingPrioritizer()

