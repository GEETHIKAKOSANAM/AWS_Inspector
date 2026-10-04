import os
import re
import json
import sys
from pathlib import Path


# ---------------------------------------------------------
# Configuration
# ---------------------------------------------------------

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

SKIP_EXTENSIONS = {
    ".exe",
    ".dll",
    ".so",
    ".zip",
    ".tar",
    ".gz",
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".mp4",
    ".pdf",
    ".pyc"
}

MAX_FILE_SIZE = 2 * 1024 * 1024


# ---------------------------------------------------------
# Finding helper
# ---------------------------------------------------------

def finding(
    finding_type,
    severity,
    file_path,
    message,
    recommendation,
    line=None,
    secret_type=None
):
    result = {
        "type": finding_type,
        "severity": severity,
        "file": file_path,
        "message": message,
        "recommendation": recommendation
    }

    if line is not None:
        result["line"] = line

    if secret_type:
        result["secret_type"] = secret_type

    return result


# ---------------------------------------------------------
# File reader
# ---------------------------------------------------------

def read_text_file(path):
    try:
        if path.stat().st_size > MAX_FILE_SIZE:
            return None

        return path.read_text(
            encoding="utf-8",
            errors="ignore"
        )

    except Exception:
        return None


# ---------------------------------------------------------
# Secret detection
# ---------------------------------------------------------

SECRET_PATTERNS = [

    (
        "AWS_ACCESS_KEY",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "CRITICAL",
        "Possible AWS access key detected.",
        "Remove the credential and rotate it immediately."
    ),

    (
        "AWS_SECRET_KEY",
        re.compile(
            r"(?i)(aws_secret_access_key|aws_secret_key)"
            r"\s*[:=]\s*[\"']?[A-Za-z0-9/+=]{30,}[\"']?"
        ),
        "CRITICAL",
        "Possible AWS secret access key detected.",
        "Remove the credential and rotate it immediately."
    ),

    (
        "PRIVATE_KEY",
        re.compile(
            r"-----BEGIN (RSA|OPENSSH|EC|DSA|PGP) PRIVATE KEY-----"
        ),
        "CRITICAL",
        "Private cryptographic key detected.",
        "Remove the private key from the project and rotate it."
    ),

    (
        "GITHUB_TOKEN",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
        "CRITICAL",
        "Possible GitHub access token detected.",
        "Revoke the token and store credentials securely."
    ),

    (
        "GENERIC_API_KEY",
        re.compile(
            r"(?i)(api[_-]?key|apikey)"
            r"\s*[:=]\s*[\"'][A-Za-z0-9_\-]{16,}[\"']"
        ),
        "HIGH",
        "Possible API key detected.",
        "Remove the API key and use a secure secret manager."
    ),

    (
        "PASSWORD",
        re.compile(
            r"(?i)(password|passwd|pwd)"
            r"\s*[:=]\s*[\"'][^\"']{6,}[\"']"
        ),
        "HIGH",
        "Possible hard-coded password detected.",
        "Remove the password and use environment variables or a secret manager."
    ),

    (
        "JWT_SECRET",
        re.compile(
            r"(?i)(jwt[_-]?secret|secret[_-]?key)"
            r"\s*[:=]\s*[\"'][^\"']{12,}[\"']"
        ),
        "HIGH",
        "Possible hard-coded application secret detected.",
        "Move the secret to a secure secret-management mechanism."
    )
]


def scan_secrets(path, findings):
    content = read_text_file(path)

    if content is None:
        return

    lines = content.splitlines()

    for line_number, line in enumerate(lines, start=1):

        # Avoid reporting obvious comments as secrets.
        stripped = line.strip()

        if stripped.startswith("#"):
            continue

        for (
            secret_type,
            pattern,
            severity,
            message,
            recommendation
        ) in SECRET_PATTERNS:

            if pattern.search(line):

                findings.append(
                    finding(
                        "SECRET_EXPOSURE",
                        severity,
                        str(path),
                        message,
                        recommendation,
                        line_number,
                        secret_type
                    )
                )


# ---------------------------------------------------------
# Docker analysis
# ---------------------------------------------------------

def scan_docker(path, findings):

    content = read_text_file(path)

    if content is None:
        return

    lines = content.splitlines()

    for line_number, line in enumerate(lines, start=1):

        stripped = line.strip()

        # Root user
        if re.match(r"(?i)^USER\s+root\s*$", stripped):

            findings.append(
                finding(
                    "CONTAINER_ROOT_USER",
                    "MEDIUM",
                    str(path),
                    "Docker container explicitly runs as root.",
                    "Use a dedicated non-root user where possible.",
                    line_number
                )
            )

        # Unpinned image
        if re.match(r"(?i)^FROM\s+", stripped):

            parts = stripped.split()

            if len(parts) >= 2:

                image = parts[1]

                # Ignore scratch
                if image.lower() != "scratch":

                    # Remove platform syntax if present
                    image_without_platform = image.split("@")[0]

                    # Check whether a tag exists
                    image_name = image_without_platform.split("/")[-1]

                    if ":" not in image_name:

                        findings.append(
                            finding(
                                "UNPINNED_BASE_IMAGE",
                                "LOW",
                                str(path),
                                "Docker base image does not specify a version tag.",
                                "Pin the base image to a known supported version.",
                                line_number
                            )
                        )

        # Dangerous curl pipe shell
        if re.search(
            r"curl\s+.*\|\s*(sh|bash)",
            stripped,
            re.IGNORECASE
        ):

            findings.append(
                finding(
                    "REMOTE_SCRIPT_EXECUTION",
                    "HIGH",
                    str(path),
                    "Dockerfile downloads and directly executes a remote script.",
                    "Download, verify, and execute trusted artifacts separately.",
                    line_number
                )
            )


# ---------------------------------------------------------
# Kubernetes analysis
# ---------------------------------------------------------

def scan_kubernetes(path, findings):

    content = read_text_file(path)

    if content is None:
        return

    lines = content.splitlines()

    for line_number, line in enumerate(lines, start=1):

        stripped = line.strip()

        # Privileged container
        if re.search(
            r"(?i)privileged\s*:\s*true",
            stripped
        ):

            findings.append(
                finding(
                    "PRIVILEGED_CONTAINER",
                    "HIGH",
                    str(path),
                    "Kubernetes workload requests privileged container execution.",
                    "Avoid privileged containers unless absolutely required.",
                    line_number
                )
            )

        # Host network
        if re.search(
            r"(?i)hostNetwork\s*:\s*true",
            stripped
        ):

            findings.append(
                finding(
                    "HOST_NETWORK",
                    "HIGH",
                    str(path),
                    "Kubernetes workload uses the host network.",
                    "Avoid host networking unless there is a documented requirement.",
                    line_number
                )
            )

        # Host PID
        if re.search(
            r"(?i)hostPID\s*:\s*true",
            stripped
        ):

            findings.append(
                finding(
                    "HOST_PID",
                    "HIGH",
                    str(path),
                    "Kubernetes workload shares the host PID namespace.",
                    "Disable host PID unless explicitly required.",
                    line_number
                )
            )

        # Host filesystem mount
        if re.search(
            r"(?i)hostPath\s*:",
            stripped
        ):

            findings.append(
                finding(
                    "HOST_PATH_MOUNT",
                    "MEDIUM",
                    str(path),
                    "Kubernetes workload uses a hostPath volume.",
                    "Avoid host filesystem mounts unless necessary.",
                    line_number
                )
            )

        # Privilege escalation
        if re.search(
            r"(?i)allowPrivilegeEscalation\s*:\s*true",
            stripped
        ):

            findings.append(
                finding(
                    "PRIVILEGE_ESCALATION",
                    "HIGH",
                    str(path),
                    "Container allows privilege escalation.",
                    "Set allowPrivilegeEscalation to false.",
                    line_number
                )
            )


# ---------------------------------------------------------
# Terraform analysis
# ---------------------------------------------------------

def scan_terraform(path, findings):

    content = read_text_file(path)

    if content is None:
        return

    lines = content.splitlines()

    for line_number, line in enumerate(lines, start=1):

        stripped = line.strip()

        # Public internet access
        if "0.0.0.0/0" in stripped:

            findings.append(
                finding(
                    "OPEN_NETWORK_ACCESS",
                    "HIGH",
                    str(path),
                    "Terraform configuration allows access from 0.0.0.0/0.",
                    "Restrict network access to trusted CIDR ranges.",
                    line_number
                )
            )

        # Public IPv6
        if "::/0" in stripped:

            findings.append(
                finding(
                    "OPEN_IPV6_ACCESS",
                    "HIGH",
                    str(path),
                    "Terraform configuration allows access from the entire IPv6 internet.",
                    "Restrict IPv6 access to trusted networks.",
                    line_number
                )
            )

        # Public S3 ACL
        if re.search(
            r"(?i)acl\s*=\s*[\"']public",
            stripped
        ):

            findings.append(
                finding(
                    "PUBLIC_STORAGE",
                    "HIGH",
                    str(path),
                    "Terraform configuration may expose storage publicly.",
                    "Use private storage and explicit access policies.",
                    line_number
                )
            )


# ---------------------------------------------------------
# Generic configuration analysis
# ---------------------------------------------------------

def scan_generic_config(path, findings):

    content = read_text_file(path)

    if content is None:
        return

    lines = content.splitlines()

    for line_number, line in enumerate(lines, start=1):

        stripped = line.strip()

        # HTTP URLs in configuration
        if re.search(
            r"https?://",
            stripped,
            re.IGNORECASE
        ):

            if not re.search(
                r"https://",
                stripped,
                re.IGNORECASE
            ):

                findings.append(
                    finding(
                        "INSECURE_HTTP",
                        "MEDIUM",
                        str(path),
                        "Configuration contains an unencrypted HTTP URL.",
                        "Use HTTPS instead of HTTP for sensitive communication.",
                        line_number
                    )
                )


# ---------------------------------------------------------
# Main scanner
# ---------------------------------------------------------

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
            "error": "Provided path is not a directory."
        }

    findings = []

    scanned_files = 0

    for root, dirs, files in os.walk(project):

        # Prevent scanning unwanted directories
        dirs[:] = [
            d for d in dirs
            if d not in SKIP_DIRS
        ]

        for filename in files:

            path = Path(root) / filename

            if path.suffix.lower() in SKIP_EXTENSIONS:
                continue

            try:
                if path.stat().st_size > MAX_FILE_SIZE:
                    continue
            except Exception:
                continue

            scanned_files += 1

            lower_name = filename.lower()

            # Secret detection on source/config files
            scan_secrets(path, findings)

            # Docker
            if lower_name == "dockerfile" or lower_name.startswith(
                "dockerfile."
            ):
                scan_docker(path, findings)

            # Kubernetes
            elif (
                lower_name.endswith(".yaml")
                or lower_name.endswith(".yml")
            ):
                scan_kubernetes(path, findings)

            # Terraform
            elif lower_name.endswith(".tf"):
                scan_terraform(path, findings)

            # Generic configuration
            elif lower_name.endswith(
                (
                    ".env",
                    ".ini",
                    ".conf",
                    ".cfg",
                    ".properties",
                    ".json"
                )
            ):
                scan_generic_config(path, findings)

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
        "summary": summary,
        "total_findings": len(findings),
        "findings": findings
    }


# ---------------------------------------------------------
# Command line interface
# ---------------------------------------------------------

if __name__ == "__main__":

    if len(sys.argv) != 2:

        print(
            "Usage: python security_analyzer.py <project_path>"
        )

        sys.exit(1)

    project_path = sys.argv[1]

    result = analyze_project(project_path)

    print(
        json.dumps(
            result,
            indent=4
        )
    )