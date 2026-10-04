import re
import sys
import subprocess
import urllib.request
import json
import tempfile
import os


def parse_requirements(file_path):
    """
    Read requirements.txt and extract package names and
    declared versions.
    """

    dependencies = []
    malformed = []

    with open(file_path, "r", encoding="utf-8") as file:

        for line_number, raw_line in enumerate(file, start=1):

            line = raw_line.strip()

            # Ignore empty lines and comments
            if not line or line.startswith("#"):
                continue

            # Ignore common pip options
            if line.startswith(("-", "--")):
                continue

            match = re.match(
                r"^([A-Za-z0-9_.-]+)\s*"
                r"(==|>=|<=|~=|!=|>|<)?\s*"
                r"([A-Za-z0-9_.+-]+)?",
                line
            )

            if not match:
                malformed.append({
                    "line": line_number,
                    "value": line
                })
                continue

            package = match.group(1)
            operator = match.group(2)
            version = match.group(3)

            dependencies.append({
                "package": package,
                "operator": operator,
                "version": version,
                "line": line_number
            })

    return dependencies, malformed


def get_pypi_info(package):

    url = f"https://pypi.org/pypi/{package}/json"

    try:

        request = urllib.request.Request(
            url,
            headers={
                "User-Agent":
                "Universal-Vulnerability-Assessment-Platform"
            }
        )

        with urllib.request.urlopen(
            request,
            timeout=10
        ) as response:

            return json.loads(
                response.read().decode("utf-8")
            )

    except Exception:
        return None

def check_dependency_conflicts(file_path):
    """
    Ask pip's dependency resolver whether the
    requirements can be resolved consistently.
    """

    try:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                "--dry-run",
                "--ignore-installed",
                "-r",
                file_path
            ],
            capture_output=True,
            text=True,
            timeout=60
        )

        if result.returncode == 0:
            return {
                "conflict": False,
                "message": "No dependency resolution conflict detected."
            }

        output = (
            result.stdout + "\n" +
            result.stderr
        ).strip()

        return {
            "conflict": True,
            "message": "Dependency resolution conflict detected.",
            "details": output[-3000:]
        }

    except subprocess.TimeoutExpired:

        return {
            "conflict": True,
            "message":
                "Dependency resolution timed out.",
            "details":
                "The dependency resolver did not complete within 60 seconds."
        }

    except Exception as e:

        return {
            "conflict": True,
            "message":
                "Dependency resolution could not be completed.",
            "details": str(e)
        }

def check_python_runtime_compatibility(dependencies):
    """
    Check whether dependency metadata declares Python
    requirements that are incompatible with the runtime
    performing the scan.
    """

    findings = []

    current_python = (
        f"{sys.version_info.major}."
        f"{sys.version_info.minor}."
        f"{sys.version_info.micro}"
    )

    for dependency in dependencies:

        package = dependency["package"]

        pypi_data = get_pypi_info(package)

        if not pypi_data:
            continue

        releases = pypi_data.get("releases", {})

        declared_version = dependency.get("version")

        if not declared_version:
            continue

        release_data = releases.get(
            declared_version,
            []
        )

        if not release_data:
            continue

        python_requirements = set()

        for release in release_data:

            requires_python = release.get(
                "requires_python"
            )

            if requires_python:
                python_requirements.add(
                    requires_python
                )

        if not python_requirements:
            continue

        # We don't guess compatibility from arbitrary
        # version strings. We report the package's
        # declared Python requirement for review.
        for requirement in python_requirements:

            findings.append({
                "type": "RUNTIME_COMPATIBILITY_CHECK",
                "severity": "INFO",
                "package": package,
                "package_version": declared_version,
                "runtime": f"Python {current_python}",
                "requires_python": requirement,
                "message":
                    f"{package} {declared_version} "
                    f"declares Python compatibility as "
                    f"'{requirement}'.",
                "recommendation":
                    "Verify that the deployment runtime "
                    "satisfies this Python requirement."
            })

    return findings


def analyze_requirements(file_path):

    dependencies, malformed = parse_requirements(
        file_path
    )

    findings = []

    # -----------------------------------------
    # MALFORMED DEPENDENCIES
    # -----------------------------------------

    for item in malformed:

        findings.append({
            "type": "MALFORMED_DEPENDENCY",
            "severity": "MEDIUM",
            "package": "Unknown",
            "message":
                f"Invalid dependency specification "
                f"on line {item['line']}: "
                f"{item['value']}",
            "recommendation":
                "Correct the dependency specification."
        })

    # -----------------------------------------
    # PACKAGE ANALYSIS
    # -----------------------------------------

    for dependency in dependencies:

        package = dependency["package"]
        declared_version = dependency["version"]

        pypi_data = get_pypi_info(package)

        if not pypi_data:
            findings.append({
                "type": "PACKAGE_NOT_FOUND",
                "severity": "HIGH",
                "package": package,
                "message":
                    f"Package '{package}' could not be "
                    f"resolved from PyPI.",
                "recommendation":
                    "Verify the package name and package source."
            })

            continue

        latest_version = pypi_data.get(
            "info",
            {}
        ).get(
            "version"
        )

        # -----------------------------------------
        # NO VERSION SPECIFIED
        # -----------------------------------------

        if not declared_version:

            findings.append({
                "type": "UNPINNED_DEPENDENCY",
                "severity": "LOW",
                "package": package,
                "declared_version": "Not specified",
                "latest_version": latest_version,
                "message":
                    f"Package '{package}' does not "
                    f"specify a version.",
                "recommendation":
                    "Pin dependencies to known compatible "
                    "versions for reproducible builds."
            })

            continue

        # -----------------------------------------
        # OUTDATED EXACT VERSION
        # -----------------------------------------

        if (
            dependency["operator"] == "=="
            and latest_version
            and declared_version != latest_version
        ):

            findings.append({
                "type": "OUTDATED_DEPENDENCY",
                "severity": "LOW",
                "package": package,
                "declared_version":
                    declared_version,
                "latest_version":
                    latest_version,
                "message":
                    f"{package} is pinned to "
                    f"{declared_version}, while the "
                    f"latest PyPI release is "
                    f"{latest_version}.",
                "recommendation":
                    "Review compatibility and upgrade "
                    "to a newer supported version."
            })

        # -----------------------------------------
    # PYTHON RUNTIME COMPATIBILITY
    # -----------------------------------------

    runtime_findings = (
        check_python_runtime_compatibility(
            dependencies
        )
    )

    findings.extend(runtime_findings)


        # -----------------------------------------
    # DEPENDENCY CONFLICT ANALYSIS
    # -----------------------------------------

    conflict_result = check_dependency_conflicts(
        file_path
    )

    if conflict_result["conflict"]:

        findings.append({
            "type": "DEPENDENCY_CONFLICT",
            "severity": "HIGH",
            "package": "Multiple dependencies",
            "message":
                conflict_result["message"],
            "details":
                conflict_result.get("details", ""),
            "recommendation":
                "Review dependency version constraints "
                "and update conflicting packages."
        })

    return {
        "success": True,
        "dependencies": dependencies,
        "findings": findings,
        "dependency_resolution": conflict_result,
        "total_dependencies": len(dependencies),
        "total_findings": len(findings)
    }


if __name__ == "__main__":

    if len(sys.argv) != 2:

        print(
            "Usage: python toolchain_analyzer.py "
            "<requirements.txt>"
        )

        sys.exit(1)

    requirements_file = sys.argv[1]

    result = analyze_requirements(
        requirements_file
    )

    print(
        json.dumps(
            result,
            indent=4
        )
    )