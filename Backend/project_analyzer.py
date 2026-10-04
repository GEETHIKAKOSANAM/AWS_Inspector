import os
import json
import re
import sys
import urllib.request
import xml.etree.ElementTree as ET


# ============================================================
# GENERIC HELPERS
# ============================================================

def read_text(file_path):
    try:
        with open(
            file_path,
            "r",
            encoding="utf-8",
            errors="ignore"
        ) as file:
            return file.read()
    except Exception:
        return ""


def get_json(file_path):
    try:
        with open(
            file_path,
            "r",
            encoding="utf-8"
        ) as file:
            return json.load(file)
    except Exception:
        return None


# ============================================================
# PYPI
# ============================================================

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


# ============================================================
# NPM
# ============================================================

def get_npm_info(package):

    url = f"https://registry.npmjs.org/{package}"

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


# ============================================================
# PYTHON ANALYZER
# ============================================================

def analyze_requirements(file_path):

    content = read_text(file_path)

    dependencies = []

    for line_number, raw_line in enumerate(
        content.splitlines(),
        start=1
    ):

        line = raw_line.strip()

        if not line or line.startswith("#"):
            continue

        if line.startswith("-"):
            continue

        match = re.match(
            r"^([A-Za-z0-9_.-]+)"
            r"\s*(==|>=|<=|~=|!=|>|<)?"
            r"\s*([A-Za-z0-9_.+-]+)?",
            line
        )

        if match:

            dependencies.append({
                "package": match.group(1),
                "operator": match.group(2),
                "version": match.group(3),
                "line": line_number
            })

    findings = []

    for dependency in dependencies:

        package = dependency["package"]
        version = dependency["version"]

        data = get_pypi_info(package)

        if not data:

            findings.append({
                "type": "PACKAGE_NOT_FOUND",
                "severity": "HIGH",
                "ecosystem": "Python",
                "package": package
            })

            continue

        latest = (
            data
            .get("info", {})
            .get("version")
        )

        if (
            version
            and dependency["operator"] == "=="
            and latest
            and version != latest
        ):

            findings.append({
                "type": "OUTDATED_DEPENDENCY",
                "severity": "LOW",
                "ecosystem": "Python",
                "package": package,
                "installed_version": version,
                "latest_version": latest,
                "recommendation":
                    "Review compatibility and upgrade."
            })

    return {
        "ecosystem": "Python",
        "manifest": os.path.basename(file_path),
        "dependencies": dependencies,
        "findings": findings
    }


# ============================================================
# NODE.JS ANALYZER
# ============================================================

def analyze_package_json(file_path):

    data = get_json(file_path)

    if not data:

        return {
            "ecosystem": "Node.js",
            "manifest": "package.json",
            "dependencies": [],
            "findings": [{
                "type": "INVALID_MANIFEST",
                "severity": "HIGH",
                "message":
                    "Invalid package.json file."
            }]
        }

    dependencies = {}

    dependencies.update(
        data.get("dependencies", {})
    )

    dependencies.update(
        data.get("devDependencies", {})
    )

    findings = []

    for package, version in dependencies.items():

        npm_data = get_npm_info(package)

        if not npm_data:

            findings.append({
                "type": "PACKAGE_NOT_FOUND",
                "severity": "HIGH",
                "ecosystem": "Node.js",
                "package": package
            })

            continue

        latest = (
            npm_data
            .get("dist-tags", {})
            .get("latest")
        )

        if (
            latest
            and version
            and version not in (
                latest,
                f"^{latest}",
                f"~{latest}"
            )
        ):

            findings.append({
                "type": "OUTDATED_DEPENDENCY",
                "severity": "LOW",
                "ecosystem": "Node.js",
                "package": package,
                "declared_version": version,
                "latest_version": latest,
                "recommendation":
                    "Review compatibility and upgrade."
            })

    return {
        "ecosystem": "Node.js",
        "manifest": "package.json",
        "dependencies": dependencies,
        "findings": findings
    }


# ============================================================
# JAVA / MAVEN
# ============================================================

def analyze_pom(file_path):

    content = read_text(file_path)

    dependencies = []

    artifact_matches = re.findall(
        r"<groupId>\s*([^<]+)"
        r"</groupId>.*?"
        r"<artifactId>\s*([^<]+)"
        r"</artifactId>",
        content,
        re.DOTALL
    )

    for group_id, artifact_id in artifact_matches:

        dependencies.append({
            "group": group_id.strip(),
            "artifact": artifact_id.strip()
        })

    findings = []

    if not dependencies:

        findings.append({
            "type": "NO_DEPENDENCIES_DETECTED",
            "severity": "INFO",
            "ecosystem": "Java"
        })

    return {
        "ecosystem": "Java",
        "manifest": "pom.xml",
        "dependencies": dependencies,
        "findings": findings
    }


# ============================================================
# .NET
# ============================================================

def analyze_csproj(file_path):

    content = read_text(file_path)

    dependencies = []

    matches = re.findall(
        r'PackageReference\s+'
        r'Include="([^"]+)"'
        r'(?:\s+Version="([^"]+)")?',
        content,
        re.IGNORECASE
    )

    for package, version in matches:

        dependencies.append({
            "package": package,
            "version": version
        })

    return {
        "ecosystem": ".NET",
        "manifest": os.path.basename(file_path),
        "dependencies": dependencies,
        "findings": []
    }


# ============================================================
# GO
# ============================================================

def analyze_go_mod(file_path):

    content = read_text(file_path)

    dependencies = []

    for line in content.splitlines():

        line = line.strip()

        if line.startswith("require "):

            parts = line.split()

            if len(parts) >= 3:

                dependencies.append({
                    "package": parts[1],
                    "version": parts[2]
                })

        elif line and not line.startswith("("):

            parts = line.split()

            if (
                len(parts) >= 2
                and "/" in parts[0]
                and parts[1].startswith("v")
            ):

                dependencies.append({
                    "package": parts[0],
                    "version": parts[1]
                })

    return {
        "ecosystem": "Go",
        "manifest": "go.mod",
        "dependencies": dependencies,
        "findings": []
    }


# ============================================================
# RUST
# ============================================================

def analyze_cargo(file_path):

    content = read_text(file_path)

    dependencies = []

    inside_dependencies = False

    for line in content.splitlines():

        line = line.strip()

        if line == "[dependencies]":

            inside_dependencies = True
            continue

        if (
            line.startswith("[")
            and line != "[dependencies]"
        ):

            inside_dependencies = False

        if inside_dependencies and "=" in line:

            package, version = line.split(
                "=",
                1
            )

            dependencies.append({
                "package": package.strip(),
                "version": version.strip()
            })

    return {
        "ecosystem": "Rust",
        "manifest": "Cargo.toml",
        "dependencies": dependencies,
        "findings": []
    }


# ============================================================
# DOCKERFILE
# ============================================================

def analyze_dockerfile(file_path):

    content = read_text(file_path)

    findings = []

    if re.search(
        r"^\s*USER\s+root",
        content,
        re.MULTILINE | re.IGNORECASE
    ):

        findings.append({
            "type": "CONTAINER_ROOT_USER",
            "severity": "MEDIUM",
            "ecosystem": "Docker",
            "message":
                "Container explicitly runs as root.",
            "recommendation":
                "Use a non-root user where possible."
        })

    if re.search(
        r"^\s*FROM\s+[^:\s]+\s*$",
        content,
        re.MULTILINE | re.IGNORECASE
    ):

        findings.append({
            "type": "UNPINNED_BASE_IMAGE",
            "severity": "LOW",
            "ecosystem": "Docker",
            "message":
                "Base image does not specify a tag.",
            "recommendation":
                "Pin the base image to a known version."
        })

    return {
        "ecosystem": "Docker",
        "manifest": "Dockerfile",
        "dependencies": [],
        "findings": findings
    }


# ============================================================
# TERRAFORM
# ============================================================

def analyze_terraform(file_path):

    content = read_text(file_path)

    findings = []

    if re.search(
        r'0\.0\.0\.0/0',
        content
    ):

        findings.append({
            "type": "OPEN_NETWORK_ACCESS",
            "severity": "HIGH",
            "ecosystem": "Terraform",
            "message":
                "Terraform configuration contains "
                "0.0.0.0/0 network access.",
            "recommendation":
                "Restrict network access to trusted ranges."
        })

    return {
        "ecosystem": "Terraform",
        "manifest": os.path.basename(file_path),
        "dependencies": [],
        "findings": findings
    }


# ============================================================
# KUBERNETES
# ============================================================

def analyze_kubernetes(file_path):

    content = read_text(file_path)

    findings = []

    if re.search(
        r'privileged:\s*true',
        content,
        re.IGNORECASE
    ):

        findings.append({
            "type": "PRIVILEGED_CONTAINER",
            "severity": "HIGH",
            "ecosystem": "Kubernetes",
            "message":
                "Kubernetes workload requests "
                "privileged container execution.",
            "recommendation":
                "Avoid privileged containers unless required."
        })

    return {
        "ecosystem": "Kubernetes",
        "manifest": os.path.basename(file_path),
        "dependencies": [],
        "findings": findings
    }


# ============================================================
# PROJECT DETECTOR
# ============================================================

def detect_project_files(project_path):

    detected = []

    for root, dirs, files in os.walk(project_path):

        # Ignore virtual environments and common build folders
        dirs[:] = [
            d for d in dirs
            if d not in {
                "venv",
                ".venv",
                "node_modules",
                ".git",
                "target",
                "bin",
                "obj"
            }
        ]

        for file in files:

            lower = file.lower()

            full_path = os.path.join(
                root,
                file
            )

            if lower == "requirements.txt":
                detected.append(
                    ("python", full_path)
                )

            elif lower == "pyproject.toml":
                detected.append(
                    ("python", full_path)
                )

            elif lower == "package.json":
                detected.append(
                    ("node", full_path)
                )

            elif lower == "pom.xml":
                detected.append(
                    ("java", full_path)
                )

            elif lower.endswith(".csproj"):
                detected.append(
                    ("dotnet", full_path)
                )

            elif lower == "packages.config":
                detected.append(
                    ("dotnet", full_path)
                )

            elif lower == "go.mod":
                detected.append(
                    ("go", full_path)
                )

            elif lower == "cargo.toml":
                detected.append(
                    ("rust", full_path)
                )

            elif lower == "dockerfile":
                detected.append(
                    ("docker", full_path)
                )

            elif lower.endswith(".tf"):
                detected.append(
                    ("terraform", full_path)
                )

            elif lower.endswith(".yaml") or \
                 lower.endswith(".yml"):

                content = read_text(full_path)

                if (
                    "apiVersion:" in content
                    and "kind:" in content
                ):

                    detected.append(
                        ("kubernetes", full_path)
                    )

    return detected


# ============================================================
# UNIFIED ANALYZER
# ============================================================

def analyze_project(project_path):

    detected = detect_project_files(
        project_path
    )

    results = []

    for ecosystem, file_path in detected:

        if ecosystem == "python":

            result = analyze_requirements(
                file_path
            )

        elif ecosystem == "node":

            result = analyze_package_json(
                file_path
            )

        elif ecosystem == "java":

            result = analyze_pom(
                file_path
            )

        elif ecosystem == "dotnet":

            result = analyze_csproj(
                file_path
            )

        elif ecosystem == "go":

            result = analyze_go_mod(
                file_path
            )

        elif ecosystem == "rust":

            result = analyze_cargo(
                file_path
            )

        elif ecosystem == "docker":

            result = analyze_dockerfile(
                file_path
            )

        elif ecosystem == "terraform":

            result = analyze_terraform(
                file_path
            )

        elif ecosystem == "kubernetes":

            result = analyze_kubernetes(
                file_path
            )

        else:
            continue

        result["file"] = file_path

        results.append(result)

    all_findings = []

    for result in results:

        all_findings.extend(
            result.get(
                "findings",
                []
            )
        )

    return {
        "success": True,
        "project": os.path.abspath(
            project_path
        ),
        "detected_files": len(detected),
        "ecosystems": sorted(
            list(
                set(
                    result["ecosystem"]
                    for result in results
                )
            )
        ),
        "results": results,
        "findings": all_findings,
        "total_findings": len(all_findings)
    }


# ============================================================
# COMMAND LINE
# ============================================================

if __name__ == "__main__":

    if len(sys.argv) != 2:

        print(
            "Usage: python project_analyzer.py "
            "<project-folder>"
        )

        sys.exit(1)

    project = sys.argv[1]

    result = analyze_project(
        project
    )

    print(
        json.dumps(
            result,
            indent=4
        )
    )