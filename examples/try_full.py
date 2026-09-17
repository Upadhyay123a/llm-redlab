"""Full slice: attack -> finding -> score -> remediation, printed plainly."""
from core.engine import run_all
from core.target import MockTarget


def main() -> None:
    findings = run_all(MockTarget())
    for f in findings:
        if not f.succeeded:
            continue
        print("=" * 60)
        print(f"[{f.severity}] risk {f.risk_score}/10  {f.category}")
        print(f"payload: {f.payload}")
        print(f"evidence: {f.evidence}")
        print("\nREMEDIATION:")
        print(f.remediation)
        print()


if __name__ == "__main__":
    main()
