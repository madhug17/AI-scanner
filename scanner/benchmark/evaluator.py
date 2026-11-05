import time
from pathlib import Path
from pydantic import BaseModel
from scanner.core.engine import SecurityEngine


class BenchmarkMetrics(BaseModel):
    files_scanned: int
    scan_duration_sec: float
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    recall: float
    precision: float
    false_positive_rate: float
    false_negative_rate: float
    rule_execution_failures: int
    analyzer_failures: int


class BenchmarkEvaluator:
    """Evaluates scanner performance on labeled clean and vulnerable benchmark code."""

    def __init__(self, engine: SecurityEngine | None = None):
        self.engine = engine or SecurityEngine()

    def evaluate_benchmark(
        self,
        vulnerable_dir: Path,
        clean_dir: Path,
        expected_vulnerable_rules: set[str],
    ) -> BenchmarkMetrics:
        start_time = time.perf_counter()

        # 1. Scan vulnerable files
        vuln_res = self.engine.execute_scan(vulnerable_dir, run_external_tools=False)
        detected_rule_ids = {f.rule_id for f in vuln_res.findings}

        # 2. Scan clean files
        clean_res = self.engine.execute_scan(clean_dir, run_external_tools=False)
        clean_findings = clean_res.findings

        duration = round(time.perf_counter() - start_time, 4)
        total_files = vuln_res.scanned_files_count + clean_res.scanned_files_count

        # Metrics computation
        tp = len(detected_rule_ids.intersection(expected_vulnerable_rules))
        fn = len(expected_vulnerable_rules.difference(detected_rule_ids))
        fp = len(clean_findings)
        tn = clean_res.scanned_files_count  # clean files correctly without findings

        recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 0.0
        precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 0.0
        fpr = round(fp / (fp + tn), 4) if (fp + tn) > 0 else 0.0
        fnr = round(fn / (fn + tp), 4) if (fn + tp) > 0 else 0.0

        rule_failures = len(vuln_res.rules_failed) + len(clean_res.rules_failed)
        tool_failures = len(vuln_res.tool_errors) + len(clean_res.tool_errors)

        return BenchmarkMetrics(
            files_scanned=total_files,
            scan_duration_sec=duration,
            true_positives=tp,
            false_positives=fp,
            true_negatives=tn,
            false_negatives=fn,
            recall=recall,
            precision=precision,
            false_positive_rate=fpr,
            false_negative_rate=fnr,
            rule_execution_failures=rule_failures,
            analyzer_failures=tool_failures,
        )

