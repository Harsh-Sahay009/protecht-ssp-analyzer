#!/usr/bin/env python3
"""
proTecht - Cybersecurity Compliance Automation Platform
=======================================================

Entry point for the Flask application. Analyzes a System Security Plan (SSP)
against FedRAMP Moderate, NIST 800-53 Rev. 4, ISO 27001:2013, or PCI DSS v4.0
controls, scores each control against a cloud (AWS) security posture snapshot,
and generates remediation recommendations (OpenAI, with a rule-based fallback).

Author: Harsh Sahay
Version: 1.0.0
License: MIT
"""

import sys
import os

# Add src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from protecht import app

if __name__ == '__main__':
    host = os.environ.get('HOST', '127.0.0.1')
    port = int(os.environ.get('PORT', '5000'))
    # Debug mode exposes the Werkzeug debugger; only enable it explicitly for local development.
    debug = os.environ.get('FLASK_DEBUG', '0') == '1'

    print("Starting proTecht - Cybersecurity Compliance Automation Platform")
    print(f"Server will be available at http://{host}:{port}")
    print("=" * 60)

    app.run(
        host=host,
        port=port,
        debug=debug,
        use_reloader=debug
    )
