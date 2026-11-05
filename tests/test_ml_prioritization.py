import tempfile
from pathlib import Path
import pytest

from scanner.core.finding import Finding, Evidence, Severity, FindingStatus
from scanner.ml.dataset import extract_finding_features, get_labeled_dataset
from scanner.ml.model import FindingPrioritizer
from scanner.ml.evaluator import ExperimentTracker


def test_dataset_feature_extraction():
    finding = Finding(
        rule_id="SEC-008",
        title="SQL Injection",
        category="Injection",
        severity=Severity.CRITICAL,
        status=FindingStatus.CONFIRMED,
        description="SQL injection in login endpoint",
        impact="Full database compromise",
        recommendation="Use parameterized statements",
        evidence=[Evidence(file_path="routes/auth.py", line_start=20, line_end=20, code_snippet="cursor.execute(f'SELECT...')")],
    )
    features = extract_finding_features(finding)
    assert features["rule_id"] == "SEC-008"
    assert features["category"] == "Injection"
    assert features["severity"] == "critical"
    assert features["status"] == "confirmed"
    assert features["in_test"] == 0


def test_ml_model_train_and_predict():
    with tempfile.TemporaryDirectory() as tmp_dir:
        model_file = Path(tmp_dir) / "test_prioritizer.joblib"
        prioritizer = FindingPrioritizer(model_path=model_file)
        metrics = prioritizer.train_and_evaluate(test_size=0.3)

        assert "accuracy" in metrics
        assert "precision" in metrics
        assert "recall" in metrics
        assert "f1_score" in metrics
        assert model_file.exists()

        # True positive finding should receive high priority
        confirmed_finding = Finding(
            rule_id="SEC-008",
            title="SQL Injection",
            category="Injection",
            severity=Severity.CRITICAL,
            status=FindingStatus.CONFIRMED,
            description="True positive",
            impact="Critical",
            recommendation="Fix",
            evidence=[Evidence(file_path="app/views.py", line_start=10, line_end=10, code_snippet="cursor.execute(f'...')")],
        )
        priority = prioritizer.predict_priority(confirmed_finding)
        assert 0.0 <= priority <= 1.0


def test_experiment_tracker():
    with tempfile.TemporaryDirectory() as tmp_dir:
        log_file = str(Path(tmp_dir) / "experiments.json")
        tracker = ExperimentTracker(experiment_log_path=log_file)
        record = tracker.run_experiment("test_run_1")

        assert record["experiment_name"] == "test_run_1"
        assert "ml_metrics" in record
        assert "rule_only_baseline" in record
        assert Path(log_file).exists()

