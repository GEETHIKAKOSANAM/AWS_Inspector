
from flask import Flask, jsonify, request
from flask_cors import CORS
from datetime import datetime
import subprocess
import sys
import os
import json


app = Flask(__name__)
CORS(app)


# ============================================================
# Configuration
# ============================================================

BACKEND_DIR = os.path.dirname(
    os.path.abspath(__file__)
)


# ============================================================
# Run Analyzer
# ============================================================

def run_analyzer(script_name, target):

    script_path = os.path.join(
        BACKEND_DIR,
        script_name
    )

    try:

        result = subprocess.run(
            [
                sys.executable,
                script_path,
                target
            ],
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
            "raw_output": output
        }

    except Exception as e:

        return {
            "success": False,
            "analyzer": script_name,
            "error": str(e)
        }


# ============================================================
# Calculate Severity Summary
# ============================================================

def calculate_summary(findings):

    summary = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    for finding in findings:

        severity = finding.get(
            "severity",
            ""
        ).upper()

        if severity in summary:

            summary[severity] += 1

    return summary


# ============================================================
# Home
# ============================================================

@app.route("/")
def home():

    return jsonify({

        "project":
            "Amazon Inspector Vulnerability Scanner",

        "status":
            "running",

        "message":
            "Security analysis backend is active."

    })


# ============================================================
# Complete Project Scan
# ============================================================

@app.route("/api/scan", methods=["POST"])
def scan_project():

    data = request.get_json(
        silent=True
    ) or {}

    target = data.get(
        "target"
    )

    # --------------------------------------------------------
    # Validate target
    # --------------------------------------------------------

    if not target:

        return jsonify({

            "success": False,

            "error":
                "Target project path is required."

        }), 400


    target = os.path.abspath(
        target
    )


    if not os.path.exists(target):

        return jsonify({

            "success": False,

            "error":
                f"Target does not exist: {target}"

        }), 400


    if not os.path.isdir(target):

        return jsonify({

            "success": False,

            "error":
                "Target must be a directory."

        }), 400


    # ========================================================
    # 1. Project Analyzer
    # ========================================================

    project = run_analyzer(

        "project_analyzer.py",

        target

    )


    # ========================================================
    # 2. Security Analyzer
    # ========================================================

    security = run_analyzer(

        "security_analyzer.py",

        target

    )


    # ========================================================
    # 3. Container Analyzer
    # ========================================================

    container = run_analyzer(

        "container_analyzer.py",

        target

    )


    # ========================================================
    # 4. Toolchain Analyzer
    # ========================================================

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

            "message":
                "No requirements.txt found."

        }


    # ========================================================
    # Combine All Findings
    # ========================================================

    all_findings = []


    analyzer_results = [

        toolchain,

        project,

        security,

        container

    ]


    for result in analyzer_results:

        if result.get(
            "success",
            False
        ):

            findings = result.get(
                "findings",
                []
            )


            if isinstance(
                findings,
                list
            ):

                all_findings.extend(
                    findings
                )


    # ========================================================
    # Calculate Final Summary
    # ========================================================

    summary = calculate_summary(
        all_findings
    )


    # ========================================================
    # Return Complete Scan
    # ========================================================

    return jsonify({

        "success": True,

        "project": target,

        "timestamp":
            datetime.now().isoformat(),

        "summary": summary,

        "total_findings":
            len(all_findings),

        "findings":
            all_findings,

        "analyzers": {

            "toolchain":
                toolchain,

            "project":
                project,

            "security":
                security,

            "container":
                container

        }

    })


# ============================================================
# Summary Endpoint
# ============================================================

@app.route("/api/summary")
def summary():

    return jsonify({

        "message":
            "Use POST /api/scan with a project directory."

    })


# ============================================================
# Run Flask
# ============================================================

if __name__ == "__main__":

    app.run(

        debug=True,

        port=5000

    )