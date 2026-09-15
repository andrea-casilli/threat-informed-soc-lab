from pathlib import Path

from soc_lab.validation import run_validation, write_coverage

if __name__ == "__main__":
    results, _ = run_validation()
    print(write_coverage(results, Path("reports"), Path("mitre")))
