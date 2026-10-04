from flask import Flask, jsonify, request
from flask_cors import CORS
from datetime import datetime
import subprocess
import sys
import os
import json
import tempfile
import shutil
import zipfile

app = Flask(__name__)
CORS(app)

app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024

BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))


def run_analyzer(script_name, target):
    script_path = os.path.join(BACKEND_DIR, script_name)

    try:
        result = subprocess.run(
            [sys.executable, script_path, target],
            capture_output=True,
            text=True,
            timeout=120
        )

        if result.returncode != 0:
            return {
                "success": False,
                "analyzer": script_name,
                "error": result.stderr.strip()
            }

        output = result.stdout.strip()

        return json.loads(output)

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "analyzer": script_name,
            "error": "Analyzer timed out."
        }

    except json.JSONDecodeError:
        return {
            "success": False,
            "analyzer": script_name,
            "error": "Analyzer did not return valid JSON.",
            "raw_output": output if "output" in locals() else ""
        }

    except Exception as e:
        return {
            "success": False,
            "analyzer": script_name,
            "error": str(e)
        }


def calculate_summary(findings):
    summary = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    for finding in findings:
        severity = str(
            finding.get("severity", "")
        ).upper()

        if severity in summary:
            summary[severity] += 1

    return summary


def run_complete_scan(target):
    project = run_analyzer(
        "project_analyzer.py",
        target
    )

    security = run_analyzer(
        "security_analyzer.py",
        target
    )

    container = run_analyzer(
        "container_analyzer.py",
        target
    )

    requirements_file = None

    for root, dirs, files in os.walk(target):
        if "requirements.txt" in files:
            requirements_file = os.path.join(
                root,
                "requirements.txt"
            )
            break

    if requirements_file:
        toolchain = run_analyzer(
            "toolchain_analyzer.py",
            requirements_file
        )
    else:
        toolchain = {
            "success": True,
            "dependencies": [],
            "findings": [],
            "total_dependencies": 0,
            "total_findings": 0,
            "message": "No requirements.txt found."
        }

    all_findings = []

    analyzer_results = [
        toolchain,
        project,
        security,
        container
    ]

    for result in analyzer_results:
        if result.get("success", False):
            findings = result.get("findings", [])

            if isinstance(findings, list):
                all_findings.extend(findings)

    return {
        "success": True,
        "project": target,
        "timestamp": datetime.now().isoformat(),
        "summary": calculate_summary(all_findings),
        "total_findings": len(all_findings),
        "findings": all_findings,
        "analyzers": {
            "toolchain": toolchain,
            "project": project,
            "security": security,
            "container": container
        }
    }


@app.route("/")
def home():
    return jsonify({
        "project": "Amazon Inspector Vulnerability Scanner",
        "status": "running",
        "message": "Security analysis backend is active."
    })


@app.route("/api/scan", methods=["POST"])
def scan_project():
    data = request.get_json(silent=True) or {}

    target = data.get("target")

    if not target:
        return jsonify({
            "success": False,
            "error": "Target project path is required."
        }), 400

    target = os.path.abspath(target)

    if not os.path.exists(target):
        return jsonify({
            "success": False,
            "error": f"Target does not exist: {target}"
        }), 400

    if not os.path.isdir(target):
        return jsonify({
            "success": False,
            "error": "Target must be a directory."
        }), 400

    return jsonify(run_complete_scan(target))


@app.route("/api/upload-scan", methods=["POST"])
def upload_scan():
    uploaded = request.files.get("file")

    if uploaded is None:
        return jsonify({
            "success": False,
            "error": "Please select a file or ZIP project."
        }), 400

    if not uploaded.filename:
        return jsonify({
            "success": False,
            "error": "Invalid file name."
        }), 400

    original_name = os.path.basename(uploaded.filename)

    temp_dir = tempfile.mkdtemp(
        prefix="inspector_scan_"
    )

    try:
        lower_name = original_name.lower()

        # ----------------------------------------------------
        # ZIP PROJECT
        # ----------------------------------------------------

        if lower_name.endswith(".zip"):

            zip_path = os.path.join(
                temp_dir,
                "project.zip"
            )

            uploaded.save(zip_path)

            extract_dir = os.path.join(
                temp_dir,
                "project"
            )

            os.makedirs(
                extract_dir,
                exist_ok=True
            )

            with zipfile.ZipFile(
                zip_path,
                "r"
            ) as archive:

                for member in archive.infolist():

                    member_path = os.path.abspath(
                        os.path.join(
                            extract_dir,
                            member.filename
                        )
                    )

                    if not member_path.startswith(
                        os.path.abspath(extract_dir)
                        + os.sep
                    ):
                        return jsonify({
                            "success": False,
                            "error":
                                "Unsafe ZIP file detected."
                        }), 400

                archive.extractall(
                    extract_dir
                )

            target = extract_dir

        # ----------------------------------------------------
        # SINGLE FILE
        # ----------------------------------------------------

        else:

            target = os.path.join(
                temp_dir,
                original_name
            )

            uploaded.save(target)

            # Put single file inside a directory
            # because the analyzers operate on projects.
            project_dir = os.path.join(
                temp_dir,
                "project"
            )

            os.makedirs(
                project_dir,
                exist_ok=True
            )

            new_target = os.path.join(
                project_dir,
                original_name
            )

            shutil.move(
                target,
                new_target
            )

            target = project_dir

        result = run_complete_scan(target)

        result["uploaded_file"] = original_name
        result["scan_type"] = (
            "ZIP_PROJECT"
            if lower_name.endswith(".zip")
            else "SINGLE_FILE"
        )

        return jsonify(result)

    except zipfile.BadZipFile:
        return jsonify({
            "success": False,
            "error": "The uploaded ZIP file is invalid."
        }), 400

    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

    finally:
        shutil.rmtree(
            temp_dir,
            ignore_errors=True
        )


@app.route("/api/summary")
def summary():
    return jsonify({
        "message":
            "Use POST /api/scan for local projects or "
            "POST /api/upload-scan for uploaded files."
    })


if __name__ == "__main__":
    app.run(
        debug=True,
        port=5000
    )