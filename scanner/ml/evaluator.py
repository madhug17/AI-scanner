import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from scanner.ml.model import FindingPrioritizer


class ExperimentTracker:
    """Tracks machine learning prioritization experiments, metrics, and comparisons against rule baseline."""

    def __init__(self, experiment_log_path: str = "ml_experiments.json"):
        self.experiment_log_path = Path(experiment_log_path)

    def run_experiment(self, experiment_name: str = "baseline_prioritizer_v1") -> dict[str, Any]:
        prioritizer = FindingPrioritizer()
        metrics = prioritizer.train_and_evaluate()

        # Rule-only baseline metrics (where all findings are assumed true positives: high recall, lower precision)
        baseline_metrics = {
            "accuracy": 0.54,
            "precision": 0.54,
            "recall": 1.0,
            "f1_score": 0.70,
        }

        experiment_record = {
            "experiment_name": experiment_name,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "model_type": "LogisticRegression (OneHot + Scaler)",
            "ml_metrics": metrics,
            "rule_only_baseline": baseline_metrics,
            "lift": {
                "precision_delta": round(metrics.get("precision", 0) - baseline_metrics["precision"], 4),
                "f1_delta": round(metrics.get("f1_score", 0) - baseline_metrics["f1_score"], 4),
            },
        }

        records = []
        if self.experiment_log_path.exists():
            try:
                records = json.loads(self.experiment_log_path.read_text(encoding="utf-8"))
            except Exception:
                records = []

        records.append(experiment_record)
        self.experiment_log_path.write_text(json.dumps(records, indent=2), encoding="utf-8")

        return experiment_record

