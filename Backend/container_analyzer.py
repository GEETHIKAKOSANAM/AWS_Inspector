import os
import re
import json
import sys
from pathlib import Path


SKIP_DIRS = {
    ".git",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    "env",
    ".idea",
    ".vscode",
    "dist",
    "build"
}

MAX_FILE_SIZE = 2 * 1024 * 1024


def make_finding(
    finding_type,
    severity,
    file_path,
    message,
    recommendation,
    line=None
):
    result = {
        "type": finding_type,
        "severity": severity,
        "file": str(file_path),
        "message": message,
        "recommendation": recommendation
    }

    if line is not None:
        result["line"] = line

    return result


def read_file(path):
    try:
        if path.stat().st_size > MAX_FILE_SIZE:
            return None

        return path.read_text(
            encoding="utf-8",
            errors="ignore"
        )

    except Exception:
        return None


# =========================================================
# DOCKERFILE ANALYSIS
# =========================================================

def analyze_dockerfile(path, findings):

    content = read_file(path)

    if content is None:
        return

    lines = content.splitlines()
    has_user_instruction = False

    for line_number, line in enumerate(lines, start=1):

        stripped = line.strip()

        if not stripped or stripped.startswith("#"):
            continue

        # -------------------------------------------------
        # FROM image analysis
        # -------------------------------------------------

        if re.match(r"(?i)^FROM\s+", stripped):

            parts = stripped.split()

            if len(parts) < 2:
                continue

            image = parts[1]

            if image.lower() != "scratch":

                image_without_digest = image.split("@")[0]
                image_name = image_without_digest.split("/")[-1]

                # latest tag
                if image_name.lower().endswith(":latest"):

                    findings.append(
                        make_finding(
                            "DOCKER_LATEST_TAG",
                            "MEDIUM",
                            path,
                            "Docker image explicitly uses the mutable 'latest' tag.",
                            "Use a fixed image version or immutable digest.",
                            line_number
                        )
                    )

                # No tag
                elif ":" not in image_name:

                    findings.append(
                        make_finding(
                            "DOCKER_UNPINNED_IMAGE",
                            "LOW",
                            path,
                            "Docker base image does not specify a version.",
                            "Pin the image to a supported version or digest.",
                            line_number
                        )
                    )

        # -------------------------------------------------
        # USER analysis
        # -------------------------------------------------

        if re.match(r"(?i)^USER\s+", stripped):

            has_user_instruction = True

            user = stripped.split(None, 1)[1].strip()

            if user.lower() == "root" or user == "0":

                findings.append(
                    make_finding(
                        "DOCKER_ROOT_USER",
                        "HIGH",
                        path,
                        "Container explicitly runs as root.",
                        "Create and use a dedicated non-root user.",
                        line_number
                    )
                )

        # -------------------------------------------------
        # Dangerous permissions
        # -------------------------------------------------

        if re.search(
            r"(?i)\b(chmod\s+777|chmod\s+-R\s+777)\b",
            stripped
        ):

            findings.append(
                make_finding(
                    "DANGEROUS_FILE_PERMISSIONS",
                    "HIGH",
                    path,
                    "Dockerfile assigns overly permissive 777 file permissions.",
                    "Use the minimum permissions required.",
                    line_number
                )
            )

        # -------------------------------------------------
        # Remote shell execution
        # -------------------------------------------------

        if re.search(
            r"(?i)(curl|wget).*(\||\s)(sh|bash)",
            stripped
        ):

            findings.append(
                make_finding(
                    "REMOTE_SCRIPT_EXECUTION",
                    "HIGH",
                    path,
                    "Dockerfile directly executes a remotely downloaded script.",
                    "Download and verify the script before execution.",
                    line_number
                )
            )

        # -------------------------------------------------
        # Sensitive environment variables
        # -------------------------------------------------

        if re.match(r"(?i)^ENV\s+", stripped):

            if re.search(
                r"(?i)(password|passwd|secret|api[_-]?key|token|access[_-]?key)",
                stripped
            ):

                findings.append(
                    make_finding(
                        "DOCKER_SECRET_IN_ENV",
                        "HIGH",
                        path,
                        "Dockerfile may place a secret directly into an environment variable.",
                        "Use runtime secret injection instead of embedding secrets in the image.",
                        line_number
                    )
                )

    # -----------------------------------------------------
    # Missing USER instruction
    # -----------------------------------------------------

    if not has_user_instruction:

        findings.append(
            make_finding(
                "DOCKER_MISSING_USER",
                "MEDIUM",
                path,
                "Dockerfile does not specify a USER instruction.",
                "Explicitly configure a non-root runtime user."
            )
        )


# =========================================================
# DOCKER COMPOSE ANALYSIS
# =========================================================

def analyze_compose(path, findings):

    content = read_file(path)

    if content is None:
        return

    lines = content.splitlines()

    for line_number, line in enumerate(lines, start=1):

        stripped = line.strip()

        # privileged: true
        if re.search(
            r"(?i)^privileged\s*:\s*true",
            stripped
        ):

            findings.append(
                make_finding(
                    "COMPOSE_PRIVILEGED",
                    "HIGH",
                    path,
                    "Docker Compose service runs in privileged mode.",
                    "Disable privileged mode unless strictly required.",
                    line_number
                )
            )

        # network_mode: host
        if re.search(
            r'''(?i)^network_mode\s*:\s*['"]?host''',
            stripped
        ):

            findings.append(
                make_finding(
                    "COMPOSE_HOST_NETWORK",
                    "HIGH",
                    path,
                    "Docker Compose service uses the host network.",
                    "Use an isolated Docker network instead.",
                    line_number
                )
            )

        # pid: host
        if re.search(
            r'''(?i)^pid\s*:\s*['"]?host''',
            stripped
        ):

            findings.append(
                make_finding(
                    "COMPOSE_HOST_PID",
                    "HIGH",
                    path,
                    "Docker Compose service shares the host PID namespace.",
                    "Avoid host PID mode unless explicitly required.",
                    line_number
                )
            )

        # 0.0.0.0 binding
        if "0.0.0.0:" in stripped:

            findings.append(
                make_finding(
                    "COMPOSE_PUBLIC_PORT",
                    "MEDIUM",
                    path,
                    "Container port is exposed on all host interfaces.",
                    "Restrict exposure to trusted interfaces or networks.",
                    line_number
                )
            )

        # latest image
        if re.search(
            r"(?i)^image\s*:\s*.*:latest",
            stripped
        ):

            findings.append(
                make_finding(
                    "COMPOSE_LATEST_IMAGE",
                    "MEDIUM",
                    path,
                    "Docker Compose uses the mutable latest image tag.",
                    "Pin the image to a fixed version or digest.",
                    line_number
                )
            )


# =========================================================
# KUBERNETES ANALYSIS
# =========================================================

def analyze_kubernetes(path, findings):

    content = read_file(path)

    if content is None:
        return

    lines = content.splitlines()

    for line_number, line in enumerate(lines, start=1):

        stripped = line.strip()

        # -------------------------------------------------
        # Privileged container
        # -------------------------------------------------

        if re.search(
            r"(?i)privileged\s*:\s*true",
            stripped
        ):

            findings.append(
                make_finding(
                    "K8S_PRIVILEGED_CONTAINER",
                    "CRITICAL",
                    path,
                    "Kubernetes container requests privileged execution.",
                    "Set privileged to false unless absolutely required.",
                    line_number
                )
            )

        # -------------------------------------------------
        # Host network
        # -------------------------------------------------

        if re.search(
            r"(?i)hostNetwork\s*:\s*true",
            stripped
        ):

            findings.append(
                make_finding(
                    "K8S_HOST_NETWORK",
                    "HIGH",
                    path,
                    "Pod uses the host network namespace.",
                    "Disable hostNetwork unless explicitly required.",
                    line_number
                )
            )

        # -------------------------------------------------
        # Host PID
        # -------------------------------------------------

        if re.search(
            r"(?i)hostPID\s*:\s*true",
            stripped
        ):

            findings.append(
                make_finding(
                    "K8S_HOST_PID",
                    "HIGH",
                    path,
                    "Pod shares the host PID namespace.",
                    "Disable hostPID unless explicitly required.",
                    line_number
                )
            )

        # -------------------------------------------------
        # Host IPC
        # -------------------------------------------------

        if re.search(
            r"(?i)hostIPC\s*:\s*true",
            stripped
        ):

            findings.append(
                make_finding(
                    "K8S_HOST_IPC",
                    "HIGH",
                    path,
                    "Pod shares the host IPC namespace.",
                    "Disable hostIPC unless explicitly required.",
                    line_number
                )
            )

        # -------------------------------------------------
        # Host path
        # -------------------------------------------------

        if re.search(
            r"(?i)hostPath\s*:",
            stripped
        ):

            findings.append(
                make_finding(
                    "K8S_HOST_PATH",
                    "HIGH",
                    path,
                    "Pod mounts a directory from the host filesystem.",
                    "Avoid hostPath volumes unless absolutely necessary.",
                    line_number
                )
            )

        # -------------------------------------------------
        # Privilege escalation
        # -------------------------------------------------

        if re.search(
            r"(?i)allowPrivilegeEscalation\s*:\s*true",
            stripped
        ):

            findings.append(
                make_finding(
                    "K8S_PRIVILEGE_ESCALATION",
                    "HIGH",
                    path,
                    "Container allows privilege escalation.",
                    "Set allowPrivilegeEscalation to false.",
                    line_number
                )
            )

        # -------------------------------------------------
        # Root user
        # -------------------------------------------------

        if re.search(
            r"(?i)runAsUser\s*:\s*0",
            stripped
        ):

            findings.append(
                make_finding(
                    "K8S_ROOT_USER",
                    "HIGH",
                    path,
                    "Container is configured to run as UID 0.",
                    "Use a non-root UID.",
                    line_number
                )
            )

        # -------------------------------------------------
        # Dangerous capabilities
        # -------------------------------------------------

        if re.search(
            r"(?i)capabilities\s*:",
            stripped
        ):

            if re.search(
                r"(?i)(SYS_ADMIN|NET_ADMIN|SYS_PTRACE|ALL)",
                stripped
            ):

                findings.append(
                    make_finding(
                        "K8S_DANGEROUS_CAPABILITY",
                        "HIGH",
                        path,
                        "Container requests a potentially dangerous Linux capability.",
                        "Remove unnecessary capabilities and follow least privilege.",
                        line_number
                    )
                )

        # -------------------------------------------------
        # NodePort
        # -------------------------------------------------

        if re.search(
            r"(?i)^\s*type\s*:\s*NodePort",
            stripped
        ):

            findings.append(
                make_finding(
                    "K8S_NODEPORT",
                    "MEDIUM",
                    path,
                    "Kubernetes service is exposed using NodePort.",
                    "Restrict external exposure and prefer controlled ingress where appropriate.",
                    line_number
                )
            )

        # -------------------------------------------------
        # LoadBalancer
        # -------------------------------------------------

        if re.search(
            r"(?i)^\s*type\s*:\s*LoadBalancer",
            stripped
        ):

            findings.append(
                make_finding(
                    "K8S_LOADBALANCER",
                    "LOW",
                    path,
                    "Kubernetes service requests external LoadBalancer exposure.",
                    "Verify that public exposure is intentional.",
                    line_number
                )
            )

        # -------------------------------------------------
        # Latest image
        # -------------------------------------------------

        if re.search(
            r"(?i)^\s*image\s*:\s*[^:\s]+:latest\s*$",
            stripped
        ):

            findings.append(
                make_finding(
                    "LATEST_IMAGE",
                    "MEDIUM",
                    path,
                    "Container image uses the mutable 'latest' tag.",
                    "Pin the image to a specific version or immutable digest.",
                    line_number
                )
            )


# =========================================================
# FILE DISCOVERY
# =========================================================

def analyze_project(project_path):

    project = Path(project_path)

    if not project.exists():

        return {
            "success": False,
            "error": "Project path does not exist."
        }

    if not project.is_dir():

        return {
            "success": False,
            "error": "Project path is not a directory."
        }

    findings = []

    docker_files = []
    compose_files = []
    kubernetes_files = []

    scanned_files = 0

    for root, dirs, files in os.walk(project):

        dirs[:] = [
            directory
            for directory in dirs
            if directory not in SKIP_DIRS
        ]

        for filename in files:

            path = Path(root) / filename

            try:
                if path.stat().st_size > MAX_FILE_SIZE:
                    continue
            except Exception:
                continue

            scanned_files += 1

            lower = filename.lower()

            # Dockerfile
            if lower == "dockerfile" or lower.startswith("dockerfile."):

                docker_files.append(str(path))

                analyze_dockerfile(
                    path,
                    findings
                )

            # Docker Compose
            elif lower in {
                "docker-compose.yml",
                "docker-compose.yaml",
                "compose.yml",
                "compose.yaml"
            }:

                compose_files.append(str(path))

                analyze_compose(
                    path,
                    findings
                )

            # Kubernetes
            elif lower.endswith(".yaml") or lower.endswith(".yml"):

                kubernetes_files.append(str(path))

                analyze_kubernetes(
                    path,
                    findings
                )

    summary = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    for item in findings:

        severity = item["severity"]

        if severity in summary:
            summary[severity] += 1

    return {
        "success": True,
        "project": str(project),
        "scanned_files": scanned_files,
        "dockerfiles": docker_files,
        "compose_files": compose_files,
        "kubernetes_files": kubernetes_files,
        "summary": summary,
        "total_findings": len(findings),
        "findings": findings
    }


# =========================================================
# COMMAND LINE
# =========================================================

if __name__ == "__main__":

    if len(sys.argv) != 2:

        print(
            "Usage: python container_analyzer.py <project_path>"
        )

        sys.exit(1)

    target = sys.argv[1]

    result = analyze_project(target)

    print(
        json.dumps(
            result,
            indent=4
        )
    )