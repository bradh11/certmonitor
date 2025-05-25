#!/usr/bin/env python3
"""
CertMonitor Test Coverage and Modularization Report Generator

This script generates a comprehensive report on test organization, coverage,
and code quality metrics to ensure the codebase remains modular and maintainable.
"""

import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Tuple, Any
import ast


def run_command(cmd: str) -> Tuple[str, int]:
    """Run a shell command and return output and exit code."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, cwd=Path.cwd()
        )
        return result.stdout.strip(), result.returncode
    except Exception as e:
        return f"Error running command: {e}", 1


def get_file_stats(file_path: Path) -> Dict[str, Any]:
    """Get statistics for a Python file."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        lines = content.split("\n")
        total_lines = len(lines)
        code_lines = len(
            [
                line
                for line in lines
                if line.strip() and not line.strip().startswith("#")
            ]
        )

        # Count functions and classes
        tree = ast.parse(content)
        functions = len(
            [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)]
        )
        classes = len(
            [node for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]
        )

        return {
            "total_lines": total_lines,
            "code_lines": code_lines,
            "functions": functions,
            "classes": classes,
            "path": str(file_path),
        }
    except Exception as e:
        return {
            "total_lines": 0,
            "code_lines": 0,
            "functions": 0,
            "classes": 0,
            "path": str(file_path),
            "error": str(e),
        }


def analyze_test_modularization() -> Dict[str, Any]:
    """Analyze the test file organization and modularization."""
    test_core_dir = Path("tests/test_core")
    main_test_file = Path("tests/test_core.py")

    results = {
        "modular_files": [],
        "main_test_file": None,
        "total_test_files": 0,
        "total_lines": 0,
        "average_file_size": 0,
    }

    # Analyze main test file
    if main_test_file.exists():
        results["main_test_file"] = get_file_stats(main_test_file)

    # Analyze modular test files
    if test_core_dir.exists():
        for test_file in test_core_dir.glob("test_*.py"):
            stats = get_file_stats(test_file)
            results["modular_files"].append(stats)

    # Calculate totals
    results["total_test_files"] = len(results["modular_files"])
    results["total_lines"] = sum(f["total_lines"] for f in results["modular_files"])
    if results["total_test_files"] > 0:
        results["average_file_size"] = (
            results["total_lines"] // results["total_test_files"]
        )

    return results


def get_test_coverage() -> Dict[str, Any]:
    """Get test coverage information."""
    # Run pytest with coverage
    coverage_cmd = (
        "uv run pytest --cov=certmonitor --cov-report=json --cov-report=term-missing -q"
    )
    output, exit_code = run_command(coverage_cmd)

    coverage_data = {"coverage_available": False}

    # Try to read coverage.json if it exists
    coverage_file = Path("coverage.json")
    if coverage_file.exists():
        try:
            with open(coverage_file, "r") as f:
                coverage_json = json.load(f)

            coverage_data = {
                "coverage_available": True,
                "total_coverage": coverage_json.get("totals", {}).get(
                    "percent_covered", 0
                ),
                "total_statements": coverage_json.get("totals", {}).get(
                    "num_statements", 0
                ),
                "covered_statements": coverage_json.get("totals", {}).get(
                    "covered_lines", 0
                ),
                "missing_statements": coverage_json.get("totals", {}).get(
                    "missing_lines", 0
                ),
                "files_covered": len(coverage_json.get("files", {})),
            }
        except Exception as e:
            coverage_data["error"] = str(e)

    # Get test count
    test_cmd = "uv run pytest --collect-only -q | grep -c '<Function'"
    test_output, _ = run_command(test_cmd)
    try:
        coverage_data["total_tests"] = int(test_output)
    except ValueError:
        coverage_data["total_tests"] = "Unknown"

    return coverage_data


def analyze_type_hints() -> Dict[str, Any]:
    """Analyze type hint coverage across the codebase."""
    certmonitor_dir = Path("certmonitor")
    results = {
        "files_analyzed": [],
        "total_files": 0,
        "files_with_hints": 0,
        "coverage_percentage": 0,
    }

    if not certmonitor_dir.exists():
        return results

    for py_file in certmonitor_dir.rglob("*.py"):
        if py_file.name == "__init__.py":
            continue

        try:
            with open(py_file, "r", encoding="utf-8") as f:
                content = f.read()

            # Check for type hints
            has_typing_import = (
                "from typing import" in content or "import typing" in content
            )
            has_type_annotations = "->" in content or ": " in content

            file_info = {
                "file": str(py_file.relative_to(certmonitor_dir)),
                "has_typing_import": has_typing_import,
                "has_annotations": has_type_annotations,
                "lines": len(content.split("\n")),
            }

            results["files_analyzed"].append(file_info)
            if has_typing_import or has_type_annotations:
                results["files_with_hints"] += 1

        except Exception as e:
            results["files_analyzed"].append(
                {"file": str(py_file.relative_to(certmonitor_dir)), "error": str(e)}
            )

    results["total_files"] = len(results["files_analyzed"])
    if results["total_files"] > 0:
        results["coverage_percentage"] = (
            results["files_with_hints"] / results["total_files"]
        ) * 100

    return results


def get_code_quality_metrics() -> Dict[str, Any]:
    """Get code quality metrics from ruff and other tools."""
    results = {}

    # Run ruff check
    ruff_cmd = "uv run ruff check . --output-format=json"
    ruff_output, ruff_exit = run_command(ruff_cmd)

    if ruff_exit == 0 and ruff_output:
        try:
            ruff_data = json.loads(ruff_output) if ruff_output else []
            results["ruff_issues"] = len(ruff_data)
            results["ruff_files_with_issues"] = len(
                set(issue.get("filename", "") for issue in ruff_data)
            )
        except json.JSONDecodeError:
            results["ruff_issues"] = 0
            results["ruff_files_with_issues"] = 0
    else:
        results["ruff_issues"] = 0
        results["ruff_files_with_issues"] = 0

    # Check formatting
    format_cmd = "uv run ruff format --check ."
    _, format_exit = run_command(format_cmd)
    results["formatting_compliant"] = format_exit == 0

    return results


def generate_report() -> str:
    """Generate the complete modularization and coverage report."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

    # Gather all data
    test_analysis = analyze_test_modularization()
    coverage_data = get_test_coverage()
    type_hint_analysis = analyze_type_hints()
    quality_metrics = get_code_quality_metrics()

    # Generate report
    report = f"""# CertMonitor Modularization & Quality Report

**Generated on:** {timestamp}

## 📊 Executive Summary

### Test Modularization Status
- **Modular test files:** {test_analysis["total_test_files"]} files
- **Total test lines:** {test_analysis["total_lines"]:,} lines
- **Average file size:** {test_analysis["average_file_size"]} lines
- **Main test file:** {test_analysis["main_test_file"]["total_lines"] if test_analysis["main_test_file"] else 0} lines

### Test Coverage
"""

    if coverage_data["coverage_available"]:
        report += f"""- **Overall coverage:** {coverage_data["total_coverage"]:.1f}%
- **Total tests:** {coverage_data["total_tests"]}
- **Statements covered:** {coverage_data["covered_statements"]:,}/{coverage_data["total_statements"]:,}
- **Files with coverage:** {coverage_data["files_covered"]}
"""
    else:
        report += "- **Coverage data:** Not available (run with coverage enabled)\n"

    report += f"""
### Type Hint Coverage
- **Files analyzed:** {type_hint_analysis["total_files"]}
- **Files with type hints:** {type_hint_analysis["files_with_hints"]}
- **Type hint coverage:** {type_hint_analysis["coverage_percentage"]:.1f}%

### Code Quality
- **Ruff issues:** {quality_metrics["ruff_issues"]}
- **Files with issues:** {quality_metrics["ruff_files_with_issues"]}
- **Formatting compliant:** {"✅ Yes" if quality_metrics["formatting_compliant"] else "❌ No"}

---

## 🏗️ Test File Organization

### Modular Test Files
"""

    for test_file in test_analysis["modular_files"]:
        file_name = Path(test_file["path"]).name
        report += f"- **{file_name}**: {test_file['total_lines']} lines, {test_file['functions']} functions\n"

    if test_analysis["main_test_file"]:
        main_file = test_analysis["main_test_file"]
        report += f"\n### Main Test File\n- **test_core.py**: {main_file['total_lines']} lines, {main_file['functions']} functions\n"

    report += """
---

## 🎯 Type Hint Analysis

### Files with Type Hints
"""

    for file_info in type_hint_analysis["files_analyzed"]:
        if "error" not in file_info:
            status = (
                "✅"
                if (file_info["has_typing_import"] or file_info["has_annotations"])
                else "❌"
            )
            report += (
                f"- **{file_info['file']}**: {status} ({file_info['lines']} lines)\n"
            )
        else:
            report += f"- **{file_info['file']}**: ❌ Error: {file_info['error']}\n"

    report += """
---

## 📈 Quality Metrics Over Time

### Recommendations
"""

    # Add recommendations based on analysis
    recommendations = []

    if test_analysis["average_file_size"] > 300:
        recommendations.append("⚠️ Consider splitting larger test files (>300 lines)")

    if coverage_data.get("total_coverage", 0) < 95:
        recommendations.append("🎯 Increase test coverage to ≥95%")

    if type_hint_analysis["coverage_percentage"] < 90:
        recommendations.append("🔤 Add type hints to remaining files")

    if quality_metrics["ruff_issues"] > 0:
        recommendations.append(
            f"🔧 Fix {quality_metrics['ruff_issues']} code quality issues"
        )

    if not quality_metrics["formatting_compliant"]:
        recommendations.append("🎨 Run `make format` to fix formatting issues")

    if not recommendations:
        recommendations.append("🎉 Excellent! All quality metrics are meeting targets")

    for rec in recommendations:
        report += f"{rec}\n"

    report += """
---

## 🛠️ Development Workflow

### Regenerate This Report
```bash
make report
```

### Quality Checks
```bash
make lint          # Check code quality
make format        # Fix formatting
make test          # Run all tests
make verify-wheel  # Verify build artifacts
```

---

*Report generated by `scripts/generate_report.py`*
"""

    return report


def main():
    """Main entry point."""
    print("🔍 Generating CertMonitor modularization and quality report...")

    try:
        report = generate_report()

        # Write to file
        output_file = Path("MODULARIZATION_REPORT.md")
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(report)

        print(f"✅ Report generated: {output_file}")
        print("📊 Use 'make report' to regenerate this report")

    except Exception as e:
        print(f"❌ Error generating report: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
