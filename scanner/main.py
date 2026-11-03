import json
import argparse
from scanner.core.engine import SecurityEngine
from scanner.rules.authentication.secrets import HardcodedSecretRule
def main():
    parser = argparse.ArgumentParser(
        description="AI Application Security Scanner"
    )
    parser.add_argument(
        "repository",
        help="Path to the repository to scan"
    )
    args= parser.parse_args()
    rules = [
        HardcodedSecretRule()
    ]
    engine =  SecurityEngine(rules)
    findings = engine.scan_repository(args.repository)
    report = [
        finding.model_dump(mode="json")
        for finding in findings
    ]
    print(json.dumps(report, indent=4))
    print(f"\nTotal findings: {len(findings)}")
if __name__ =="__main__":
    main()
