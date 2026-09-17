"""Run the attack engine against the vulnerable MockTarget and print results."""
from core.engine import run_all
from core.target import MockTarget


def main() -> None:
    findings = run_all(MockTarget())
    for f in findings:
        status = "SUCCEEDED" if f.succeeded else "blocked/failed"
        print(f"[{status:14}] {f.payload_id:16} {f.evidence}")
    succeeded = sum(1 for f in findings if f.succeeded)
    print(f"\n{succeeded}/{len(findings)} attacks succeeded against {MockTarget().name}")


if __name__ == "__main__":
    main()
