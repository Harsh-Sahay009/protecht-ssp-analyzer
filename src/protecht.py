#!/usr/bin/env python3
"""
Simple proTecht MVP
Analyzes SSP against endpoints and checks compliance
"""

import re
import json
from datetime import datetime
from flask import Flask, request, jsonify, render_template_string
from werkzeug.utils import secure_filename
import os
import requests

# Load environment variables from .env file if it exists
try:
    from dotenv import load_dotenv
    load_dotenv()
    print("Loaded environment variables from .env file")
except ImportError:
    print("python-dotenv not installed, using system environment variables")

# Configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'doc', 'docx', 'md'}
AI_API_KEY = os.environ.get('OPENAI_API_KEY', '')

# Debug API key status
if AI_API_KEY:
    print("OpenAI API key found in environment")
else:
    print("OpenAI API key not found in environment variables")

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Create uploads directory if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def extract_text_from_file(file_path):
    """Extract text from uploaded file with proper handling for different file types"""
    file_extension = file_path.lower().split('.')[-1]
    
    try:
        if file_extension == 'txt' or file_extension == 'md':
            # Plain text files
            with open(file_path, 'r', encoding='utf-8') as f:
                return f.read()
        elif file_extension == 'pdf':
            # PDF files - try to extract text
            try:
                import PyPDF2
                with open(file_path, 'rb') as f:
                    pdf_reader = PyPDF2.PdfReader(f)
                    text = ""
                    for page in pdf_reader.pages:
                        text += page.extract_text() + "\n"
                    return text
            except ImportError:
                return "PDF text extraction requires PyPDF2 library. Please install: pip install PyPDF2"
            except Exception as e:
                return f"Error extracting PDF text: {str(e)}"
        elif file_extension in ['doc', 'docx']:
            # Word documents - try to extract text
            try:
                import docx
                doc = docx.Document(file_path)
                text = ""
                for paragraph in doc.paragraphs:
                    text += paragraph.text + "\n"
                return text
            except ImportError:
                return "Word document text extraction requires python-docx library. Please install: pip install python-docx"
            except Exception as e:
                return f"Error extracting Word document text: {str(e)}"
        else:
            # Try as plain text with different encodings
            encodings = ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1']
            for encoding in encodings:
                try:
                    with open(file_path, 'r', encoding=encoding) as f:
                        content = f.read()
                        # Check if content looks like text (not binary)
                        if len(content) > 0 and not any(ord(char) < 32 and char not in '\n\r\t' for char in content[:100]):
                            return content
                except (UnicodeDecodeError, UnicodeError):
                    continue
            
            return "Unable to extract text from file. Please ensure it's a text file or install required libraries for PDF/DOC files."
            
    except Exception as e:
        return f"Error reading file: {str(e)}"

def get_aws_data():
    """Get AWS data from database or fallback"""
    if db:
        try:
            return db.get_aws_data()
        except Exception as e:
            print(f"Database error, using fallback data: {e}")
            return FALLBACK_AWS_DATA
    else:
        return FALLBACK_AWS_DATA

# Database integration
try:
    from database import ProTechtDatabase
    db = ProTechtDatabase()
    print("Database connection established")
except ImportError:
    print("Database module not found, using fallback data")
    db = None

# Fallback AWS data (used if database is not available)
FALLBACK_AWS_DATA = {
    "account_metadata": {
        "org_id": "o-abc123xyz",
        "master_payer_id": "123456789012",
        "regions": ["us-gov-west-1", "us-gov-east-1"]
    },
    "control_tower": {
        "version": "3.4",
        "enabled_guardrails": 42,
        "accounts_managed": 12
    },
    "iam": {
        "password_policy": {
            "MinimumPasswordLength": 14,
            "RequireSymbols": True,
            "RequireNumbers": True,
            "RequireUppercaseCharacters": True,
            "RequireLowercaseCharacters": True,
            "MaxPasswordAge": 60,
            "PasswordReusePrevention": 5
        },
        "users": [
            {"UserName": "alice", "MFA": True, "LastLogin": "2025-08-28"},
            {"UserName": "bob", "MFA": False, "LastLogin": "2025-06-01"},
            {"UserName": "charlie", "MFA": True, "LastLogin": "2025-08-15"},
            {"UserName": "david", "MFA": True, "LastLogin": "2025-08-20"},
            {"UserName": "root", "MFA": True, "LastLogin": "2025-07-30"}
        ],
        "inactive_user_disable_days": 30,
        "roles": [
            {"RoleName": "DevOps", "Permissions": ["EC2","S3"], "Boundary": "arn:aws:iam::aws:policy/PowerUserAccess"},
            {"RoleName": "SecurityAdmin", "Permissions": ["IAM","Config","SecurityHub"], "Boundary": None}
        ]
    },
    "sso": {
        "application_count": 8,
        "mfa_types": ["Virtual","Hardware","WebAuthn"],
        "federation": "Okta"
    },
    "s3": [
        {"Bucket": "central-logs", "Encryption": "AES256", "ObjectLockMode": "GOVERNANCE", "RetentionDays": 365, "PublicAccessBlock": True},
        {"Bucket": "tenant-artifacts", "Encryption": "aws:kms", "KmsKeyId": "alias/tenant-key", "PublicAccessBlock": True},
        {"Bucket": "dev-test-binaries", "Encryption": None, "PublicAccessBlock": False},
        {"Bucket": "pii-archive", "Encryption": "aws:kms", "KmsKeyId": "alias/pii-archive", "ObjectLockMode": "COMPLIANCE", "RetentionDays": 730, "PublicAccessBlock": True}
    ],
    "kms": [
        {"KeyId": "key-1111", "RotationEnabled": True, "Alias": "alias/prod-master"},
        {"KeyId": "key-2222", "RotationEnabled": False, "Alias": "alias/dev-nokeyrotate"},
        {"KeyId": "key-3333", "RotationEnabled": True, "Alias": "alias/pii-archive"}
    ],
    "cloudtrail": {
        "trails": [
            {"Name": "orgTrail", "MultiRegion": True, "LogFileValidation": True, "InsightSelectors": ["ApiCallRateInsight","ErrorRateInsight"]}
        ]
    },
    "config": {
        "rules": [
            {"Name": "phoenix-ac2-inactive", "ComplianceType": "COMPLIANT"},
            {"Name": "phoenix-s3-encryption", "ComplianceType": "NON_COMPLIANT"},
            {"Name": "phoenix-ssh-restricted", "ComplianceType": "COMPLIANT"}
        ],
        "conformance_packs": [
            {"Name": "CIS-1.4", "Status": "NON_COMPLIANT", "FailingRules": 6},
            {"Name": "NIST-800-53", "Status": "NON_COMPLIANT", "FailingRules": 12}
        ]
    },
    "guardduty": {
        "detector_count": 1,
        "findings": {"Critical": 0, "High": 2, "Medium": 7, "Low": 15}
    },
    "security_hub": {
        "standards": {
            "CIS AWS Foundations v1.4.0": "FAILED",
            "AWS Best Practices": "FAILED"
        },
        "open_findings": 22
    },
    "macie": {
        "jobs": [
            {"JobId": "j-abcd", "Status": "RUNNING", "S3BucketsScanned": 14},
            {"JobId": "j-efgh", "Status": "COMPLETE", "SensitiveFindings": 5}
        ]
    },
    "inspector2": {
        "last_run": "2025-08-29",
        "findings": {"Critical": 6, "High": 14, "Medium": 37, "Low": 120}
    },
    "eks": [
        {"Cluster": "gov-prod-eks", "OIDC": True, "IRSA": True, "K8sVersion": "1.29", "PublicAccess": False},
        {"Cluster": "gov-dev-eks", "OIDC": True, "IRSA": False, "K8sVersion": "1.27", "PublicAccess": True}
    ],
    "rds": [
        {"DBInstance": "prod-aurora-global", "Engine": "aurora-postgresql", "Encrypted": True, "MultiAZ": True},
        {"DBInstance": "dev-mysql", "Engine": "mysql", "Encrypted": False, "MultiAZ": False}
    ],
    "backup": {
        "vault_name": "phoenix-backup-vault", "resources_protected": 128, "cross_region_copy": True, "vault_lock": "ON"
    },
    "vpc": {
        "flow_logs": True,
        "security_groups": [
            {"GroupId":"sg-aaa111","OpenPorts":[22],"AllowedCidrs":["10.0.0.0/16"]},
            {"GroupId":"sg-bbb222","OpenPorts":[22,3389],"AllowedCidrs":["0.0.0.0/0"]}
        ],
        "nat_gateways": 4,
        "transit_gateway": {"attachments":3}
    },
    "waf": {
        "web_acls":[{"Name":"phoenix-waf","Rules":15,"BlockedCount7d":12000}]
    },
    "cloudfront": {
        "distributions":[
            {"Id":"E111AAA","TLSPolicy":"TLSv1.2_2021","WAFEnabled":True},
            {"Id":"E222BBB","TLSPolicy":"TLSv1.2_2021","WAFEnabled":False}
        ]
    },
    "ssm_patch": {
        "last_scan":"2025-08-28","pending_critical":5,"pending_high":11
    }
}

# FedRAMP control patterns
CONTROL_PATTERNS = {
    "AC-1": r"AC-1.*Access Control Policy",
    "AC-2": r"AC-2.*Account Management",
    "AC-3": r"AC-3.*Access Enforcement",
    "AC-4": r"AC-4.*Information Flow Enforcement",
    "AC-5": r"AC-5.*Separation of Duties",
    "AC-6": r"AC-6.*Least Privilege",
    "AC-7": r"AC-7.*Unsuccessful Logon Attempts",
    "AC-17": r"AC-17.*Remote Access",
    "AC-19": r"AC-19.*Access Control for Mobile Devices",
    "AC-20": r"AC-20.*Use of External Systems",
    "AU-2": r"AU-2.*Audit Events",
    "AU-3": r"AU-3.*Content of Audit Records",
    "AU-6": r"AU-6.*Audit Review",
    "AU-8": r"AU-8.*Time Stamps",
    "AU-12": r"AU-12.*Log Retention",
    "CA-2": r"CA-2.*Security Assessments",
    "CA-7": r"CA-7.*Continuous Monitoring",
    "CM-2": r"CM-2.*Baseline Configuration",
    "CM-3": r"CM-3.*Configuration Change Control",
    "CM-6": r"CM-6.*Configuration Settings",
    "CP-2": r"CP-2.*Contingency Plan",
    "CP-4": r"CP-4.*Contingency Testing",
    "CP-7": r"CP-7.*Alternate Processing Site",
    "CP-9": r"CP-9.*System Backup",
    "IA-2": r"IA-2.*Identification.*Authentication",
    "IA-5": r"IA-5.*Authenticator Management",
    "IR-2": r"IR-2.*Incident Response Training",
    "IR-4": r"IR-4.*Incident Handling",
    "IR-6": r"IR-6.*Incident Reporting",
    "MA-2": r"MA-2.*Controlled Maintenance",
    "MP-2": r"MP-2.*Media Access",
    "MP-4": r"MP-4.*Media Storage",
    "PE-2": r"PE-2.*Physical Access Authorizations",
    "PL-2": r"PL-2.*System.*Communications Protection Policy",
    "PM-10": r"PM-10.*Security Authorization Process",
    "PM-11": r"PM-11.*Mission.*Business Impact Analysis",
    "RA-5": r"RA-5.*Vulnerability Scanning",
    "RA-7": r"RA-7.*Threat Intelligence",
    "SA-11": r"SA-11.*Developer Security Testing",
    "SA-22": r"SA-22.*Unsupported System Components",
    "SC-7": r"SC-7.*Boundary Protection",
    "SC-8": r"SC-8.*Transmission Confidentiality",
    "SC-12": r"SC-12.*Cryptographic Key Establishment",
    "SC-13": r"SC-13.*Cryptographic Protection",
    "SC-28": r"SC-28.*Protection of Information at Rest",
    "SI-2": r"SI-2.*Flaw Remediation",
    "SI-4": r"SI-4.*System Monitoring",
    "SI-7": r"SI-7.*Software.*Firmware.*Information Integrity",
    "SI-10": r"SI-10.*Information Input Validation",
    "SR-1": r"SR-1.*Supply Chain Risk Management Policy"
}

# FedRAMP compliance rules
COMPLIANCE_RULES = {
    "AC-1": {
        "description": "Access Control Policy & Procedures",
        "requirements": ["policy", "procedures", "access", "control"]
    },
    "AC-2": {
        "description": "Account Management",
        "requirements": ["account", "management", "iam", "aws", "sso", "okta"]
    },
    "AC-3": {
        "description": "Access Enforcement",
        "requirements": ["permission", "boundary", "rbac", "scp", "eks", "irsa"]
    },
    "AC-4": {
        "description": "Information Flow Enforcement",
        "requirements": ["vpc", "peering", "transit", "gateway", "security", "groups", "nacl"]
    },
    "AC-5": {
        "description": "Separation of Duties",
        "requirements": ["roles", "duties", "devops", "security", "auditor"]
    },
    "AC-6": {
        "description": "Least Privilege",
        "requirements": ["session", "duration", "guardrails", "privilege"]
    },
    "AC-7": {
        "description": "Unsuccessful Logon Attempts",
        "requirements": ["lockout", "attempts", "sso", "cloudwatch", "alarms"]
    },
    "AC-17": {
        "description": "Remote Access",
        "requirements": ["ssm", "session", "manager", "vpn", "mfa", "cert"]
    },
    "AC-19": {
        "description": "Access Control for Mobile Devices",
        "requirements": ["mdm", "flare", "mobile", "device"]
    },
    "AC-20": {
        "description": "Use of External Systems",
        "requirements": ["ssh", "rdp", "bastion", "private", "subnets"]
    },
    "AU-2": {
        "description": "Audit Events",
        "requirements": ["cloudtrail", "govcloud", "validation", "vpc", "flow", "alb", "macie"]
    },
    "AU-3": {
        "description": "Content of Audit Records",
        "requirements": ["useridentity", "eventname", "sourceip", "requestparameters", "responseelements"]
    },
    "AU-6": {
        "description": "Audit Review, Analysis, & Reporting",
        "requirements": ["guardduty", "security", "hub", "jira", "eventbridge", "soc"]
    },
    "AU-8": {
        "description": "Time Stamps",
        "requirements": ["time", "sync", "ntp", "amazon"]
    },
    "AU-12": {
        "description": "Log Retention",
        "requirements": ["object", "lock", "governance", "glacier", "retention"]
    },
    "CA-2": {
        "description": "Security Assessments",
        "requirements": ["pentest", "secrets", "manager", "encrypted"]
    },
    "CA-7": {
        "description": "Continuous Monitoring",
        "requirements": ["config", "conformance", "cis", "pci", "nist"]
    },
    "CM-2": {
        "description": "Baseline Configuration",
        "requirements": ["terraform", "codeartifact", "ami", "cis", "hardened"]
    },
    "CM-3": {
        "description": "Configuration Change Control",
        "requirements": ["gitops", "pr", "approvals", "security", "team"]
    },
    "CM-6": {
        "description": "Configuration Settings",
        "requirements": ["ssm", "state", "manager", "cis", "benchmarks"]
    },
    "CP-2": {
        "description": "Contingency Plan",
        "requirements": ["backup", "vault", "dr", "tabletop"]
    },
    "CP-4": {
        "description": "Contingency Testing",
        "requirements": ["failover", "rto", "rpo", "testing"]
    },
    "CP-7": {
        "description": "Alternate Processing Site",
        "requirements": ["aurora", "global", "route53", "health", "failover", "lambda"]
    },
    "CP-9": {
        "description": "System Backup",
        "requirements": ["aws", "backup", "rds", "dynamodb", "efs", "ec2", "retention", "cross", "region"]
    },
    "IA-2": {
        "description": "Identification & Authentication",
        "requirements": ["mfa", "enforced", "users", "root", "federation", "okta", "webauthn"]
    },
    "IA-5": {
        "description": "Authenticator Management",
        "requirements": ["password", "policy", "rotation", "reuse", "cmk", "auto", "rotation"]
    },
    "IR-2": {
        "description": "Incident Response Training",
        "requirements": ["tabletop", "phishing", "simulations", "security", "hub"]
    },
    "IR-4": {
        "description": "Incident Handling",
        "requirements": ["eventbridge", "guardduty", "pagerduty", "runbook"]
    },
    "IR-6": {
        "description": "Incident Reporting",
        "requirements": ["incidents", "p1", "p2", "fedramp", "pmo", "emass"]
    },
    "MA-2": {
        "description": "Controlled Maintenance",
        "requirements": ["maintenance", "windows", "systems", "manager", "pl", "labels"]
    },
    "MP-2": {
        "description": "Media Access",
        "requirements": ["local", "storage", "pii", "backups", "encrypted", "removable"]
    },
    "MP-4": {
        "description": "Media Storage",
        "requirements": ["s3", "buckets", "pii", "tagged", "encrypted", "endpoints"]
    },
    "PE-2": {
        "description": "Physical Access Authorizations",
        "requirements": ["govcloud", "dc", "physical", "controls", "soc1", "soc2"]
    },
    "PL-2": {
        "description": "System & Communications Protection Policy",
        "requirements": ["policy", "spl", "reviewed", "annually"]
    },
    "PM-10": {
        "description": "Security Authorization Process",
        "requirements": ["continuous", "authorization", "emass", "artifacts", "monthly"]
    },
    "PM-11": {
        "description": "Mission & Business Impact Analysis",
        "requirements": ["bia", "annually", "confluence"]
    },
    "RA-5": {
        "description": "Vulnerability Scanning",
        "requirements": ["nessus", "gov", "inspector2", "critical", "jira"]
    },
    "RA-7": {
        "description": "Threat Intelligence",
        "requirements": ["guardduty", "threat", "lists", "toxic", "ip", "marketplace"]
    },
    "SA-11": {
        "description": "Developer Security Testing",
        "requirements": ["checkov", "tfsec", "semgrep", "zap", "api", "fuzzing", "codebuild"]
    },
    "SA-22": {
        "description": "Unsupported System Components",
        "requirements": ["security", "hub", "governance", "checks", "unsupported", "amis"]
    },
    "SC-7": {
        "description": "Boundary Protection",
        "requirements": ["alb", "cloudfront", "tls", "waf", "owasp", "top", "10"]
    },
    "SC-8": {
        "description": "Transmission Confidentiality",
        "requirements": ["tls", "elasticlb", "security", "policy"]
    },
    "SC-12": {
        "description": "Cryptographic Key Establishment",
        "requirements": ["kms", "cmks", "gov", "regions", "hsm", "policies", "audited"]
    },
    "SC-13": {
        "description": "Cryptographic Protection",
        "requirements": ["encrypted", "s3", "rds", "efs", "dynamo", "cmks", "secrets", "manager", "rotated"]
    },
    "SC-28": {
        "description": "Protection of Information at Rest",
        "requirements": ["parameter", "store", "encrypted", "rotation"]
    },
    "SI-2": {
        "description": "Flaw Remediation",
        "requirements": ["patch", "manager", "critical", "patches", "inspector2", "container"]
    },
    "SI-4": {
        "description": "System Monitoring",
        "requirements": ["guardduty", "detective", "security", "hub", "cloudwatch", "contributor", "insights"]
    },
    "SI-7": {
        "description": "Software, Firmware, & Information Integrity",
        "requirements": ["codesigning", "lambda", "ecr", "images", "integrity", "pipeline"]
    },
    "SI-10": {
        "description": "Information Input Validation",
        "requirements": ["api", "gateway", "waf", "json", "schemas", "lambda", "authorizers"]
    },
    "SR-1": {
        "description": "Supply Chain Risk Management Policy",
        "requirements": ["policy", "updated", "vendor", "assessments", "artifact"]
    }
}

# Framework definitions
FRAMEWORKS = {
    "fedramp": {
        "name": "FedRAMP Moderate",
        "description": "Federal Risk and Authorization Management Program",
        "controls": CONTROL_PATTERNS,
        "rules": COMPLIANCE_RULES
    },
    "nist": {
        "name": "NIST 800-53 Rev. 4",
        "description": "National Institute of Standards and Technology",
        "controls": {
            "AC-1": r"AC-1.*Access Control Policy",
            "AC-2": r"AC-2.*Account Management",
            "AC-3": r"AC-3.*Access Enforcement",
            "AC-4": r"AC-4.*Information Flow Enforcement",
            "AC-5": r"AC-5.*Separation of Duties",
            "AC-6": r"AC-6.*Least Privilege",
            "AC-7": r"AC-7.*Unsuccessful Logon Attempts",
            "IA-2": r"IA-2.*Identification.*Authentication",
            "IA-5": r"IA-5.*Authenticator Management",
            "SC-7": r"SC-7.*Boundary Protection",
            "SC-8": r"SC-8.*Transmission Confidentiality",
            "SC-13": r"SC-13.*Cryptographic Protection",
            "SI-4": r"SI-4.*System Monitoring",
            "AU-2": r"AU-2.*Audit Events",
            "AU-12": r"AU-12.*Log Retention",
            "CP-7": r"CP-7.*Alternate Processing Site",
            "CP-9": r"CP-9.*System Backup",
            "RA-5": r"RA-5.*Vulnerability Scanning",
            "CM-6": r"CM-6.*Configuration Settings"
        },
        "rules": {
            "AC-1": {"description": "Access Control Policy", "requirements": ["policy", "procedures", "access", "control"]},
            "AC-2": {"description": "Account Management", "requirements": ["account", "management", "iam", "aws"]},
            "AC-3": {"description": "Access Enforcement", "requirements": ["permission", "boundary", "rbac", "access"]},
            "AC-4": {"description": "Information Flow Enforcement", "requirements": ["vpc", "security", "groups", "network"]},
            "AC-5": {"description": "Separation of Duties", "requirements": ["roles", "duties", "separation"]},
            "AC-6": {"description": "Least Privilege", "requirements": ["privilege", "minimal", "access"]},
            "AC-7": {"description": "Unsuccessful Logon Attempts", "requirements": ["lockout", "attempts", "authentication"]},
            "IA-2": {"description": "Identification & Authentication", "requirements": ["mfa", "authentication", "identity"]},
            "IA-5": {"description": "Authenticator Management", "requirements": ["password", "policy", "rotation"]},
            "SC-7": {"description": "Boundary Protection", "requirements": ["network", "boundary", "firewall"]},
            "SC-8": {"description": "Transmission Confidentiality", "requirements": ["tls", "encryption", "transmission"]},
            "SC-13": {"description": "Cryptographic Protection", "requirements": ["encryption", "cryptographic", "protection"]},
            "SI-4": {"description": "System Monitoring", "requirements": ["monitor", "logging", "detection"]},
            "AU-2": {"description": "Audit Events", "requirements": ["audit", "logging", "events"]},
            "AU-12": {"description": "Log Retention", "requirements": ["retention", "logs", "storage"]},
            "CP-7": {"description": "Alternate Processing Site", "requirements": ["backup", "disaster", "recovery"]},
            "CP-9": {"description": "System Backup", "requirements": ["backup", "system", "recovery"]},
            "RA-5": {"description": "Vulnerability Scanning", "requirements": ["vulnerability", "scanning", "assessment"]},
            "CM-6": {"description": "Configuration Settings", "requirements": ["configuration", "settings", "management"]}
        }
    },
    "iso27001": {
        "name": "ISO 27001:2013",
        "description": "Information Security Management System",
        "controls": {
            "A.6.1": r"A\.6\.1.*Internal Organization",
            "A.6.2": r"A\.6\.2.*Mobile Devices",
            "A.7.1": r"A\.7\.1.*Human Resource Security",
            "A.8.1": r"A\.8\.1.*Asset Management",
            "A.9.1": r"A\.9\.1.*Access Control",
            "A.9.2": r"A\.9\.2.*User Access Management",
            "A.9.3": r"A\.9\.3.*User Responsibilities",
            "A.9.4": r"A\.9\.4.*System and Application Access Control",
            "A.10.1": r"A\.10\.1.*Cryptographic Controls",
            "A.11.1": r"A\.11\.1.*Physical and Environmental Security",
            "A.12.1": r"A\.12\.1.*Operational Security",
            "A.12.2": r"A\.12\.2.*Protection from Malware",
            "A.12.3": r"A\.12\.3.*Backup",
            "A.12.4": r"A\.12\.4.*Logging and Monitoring",
            "A.12.6": r"A\.12\.6.*Technical Vulnerability Management",
            "A.13.1": r"A\.13\.1.*Network Security Management",
            "A.13.2": r"A\.13\.2.*Information Transfer",
            "A.14.1": r"A\.14\.1.*Security Requirements",
            "A.15.1": r"A\.15\.1.*Supplier Relationships",
            "A.16.1": r"A\.16\.1.*Incident Management"
        },
        "rules": {
            "A.6.1": {"description": "Internal Organization", "requirements": ["organization", "structure", "roles"]},
            "A.6.2": {"description": "Mobile Devices", "requirements": ["mobile", "devices", "management"]},
            "A.7.1": {"description": "Human Resource Security", "requirements": ["hr", "security", "personnel"]},
            "A.8.1": {"description": "Asset Management", "requirements": ["assets", "inventory", "management"]},
            "A.9.1": {"description": "Access Control", "requirements": ["access", "control", "policy"]},
            "A.9.2": {"description": "User Access Management", "requirements": ["user", "access", "management"]},
            "A.9.3": {"description": "User Responsibilities", "requirements": ["user", "responsibilities", "training"]},
            "A.9.4": {"description": "System and Application Access Control", "requirements": ["system", "application", "access"]},
            "A.10.1": {"description": "Cryptographic Controls", "requirements": ["cryptographic", "encryption", "controls"]},
            "A.11.1": {"description": "Physical and Environmental Security", "requirements": ["physical", "environmental", "security"]},
            "A.12.1": {"description": "Operational Security", "requirements": ["operational", "procedures", "security"]},
            "A.12.2": {"description": "Protection from Malware", "requirements": ["malware", "protection", "antivirus"]},
            "A.12.3": {"description": "Backup", "requirements": ["backup", "recovery", "data"]},
            "A.12.4": {"description": "Logging and Monitoring", "requirements": ["logging", "monitoring", "audit"]},
            "A.12.6": {"description": "Technical Vulnerability Management", "requirements": ["vulnerability", "management", "patching"]},
            "A.13.1": {"description": "Network Security Management", "requirements": ["network", "security", "management"]},
            "A.13.2": {"description": "Information Transfer", "requirements": ["information", "transfer", "communication"]},
            "A.14.1": {"description": "Security Requirements", "requirements": ["security", "requirements", "development"]},
            "A.15.1": {"description": "Supplier Relationships", "requirements": ["supplier", "relationships", "third-party"]},
            "A.16.1": {"description": "Incident Management", "requirements": ["incident", "management", "response"]}
        }
    },
    "pci": {
        "name": "PCI DSS v4.0",
        "description": "Payment Card Industry Data Security Standard",
        "controls": {
            "Req-1": r"Req-1.*Install and Maintain Network Security Controls",
            "Req-2": r"Req-2.*Apply Secure Configurations",
            "Req-3": r"Req-3.*Protect Stored Account Data",
            "Req-4": r"Req-4.*Protect Cardholder Data",
            "Req-5": r"Req-5.*Protect All Systems and Networks",
            "Req-6": r"Req-6.*Develop and Maintain Secure Systems",
            "Req-7": r"Req-7.*Restrict Access to System Components",
            "Req-8": r"Req-8.*Identify Users and Authenticate Access",
            "Req-9": r"Req-9.*Restrict Physical Access",
            "Req-10": r"Req-10.*Log and Monitor All Access",
            "Req-11": r"Req-11.*Test Security of Systems and Networks",
            "Req-12": r"Req-12.*Support Information Security"
        },
        "rules": {
            "Req-1": {"description": "Network Security Controls", "requirements": ["network", "security", "firewall"]},
            "Req-2": {"description": "Secure Configurations", "requirements": ["configuration", "secure", "settings"]},
            "Req-3": {"description": "Protect Stored Data", "requirements": ["data", "protection", "storage"]},
            "Req-4": {"description": "Protect Cardholder Data", "requirements": ["cardholder", "data", "encryption"]},
            "Req-5": {"description": "Protect Systems and Networks", "requirements": ["systems", "networks", "protection"]},
            "Req-6": {"description": "Secure Systems", "requirements": ["secure", "systems", "development"]},
            "Req-7": {"description": "Restrict Access", "requirements": ["access", "restriction", "control"]},
            "Req-8": {"description": "User Authentication", "requirements": ["authentication", "users", "access"]},
            "Req-9": {"description": "Physical Access", "requirements": ["physical", "access", "security"]},
            "Req-10": {"description": "Logging and Monitoring", "requirements": ["logging", "monitoring", "audit"]},
            "Req-11": {"description": "Security Testing", "requirements": ["testing", "security", "vulnerability"]},
            "Req-12": {"description": "Information Security", "requirements": ["information", "security", "policy"]}
        }
    }
}

def parse_ssp(ssp_text, framework_controls):
    """Parse SSP text and extract controls for the selected framework using intelligent pattern matching"""
    controls = {}
    
    # Normalize text for better matching
    ssp_text_normalized = ssp_text.replace('\r', '\n').replace('\t', ' ')
    
    # Multiple extraction strategies
    extracted_controls = {}
    
    # Strategy 1: Direct pattern matching (original method)
    for control_id, pattern in framework_controls.items():
        match = re.search(pattern, ssp_text_normalized, re.IGNORECASE | re.MULTILINE)
        if match:
            extracted_controls[control_id] = extract_control_content(ssp_text_normalized, control_id, match.start())
    
    # Strategy 2: Flexible control ID matching
    if not extracted_controls:
        extracted_controls = extract_controls_by_id(ssp_text_normalized, framework_controls)
    
    # Strategy 3: Semantic matching based on control descriptions
    if not extracted_controls:
        extracted_controls = extract_controls_by_semantics(ssp_text_normalized, framework_controls)
    
    # Strategy 4: Keyword-based extraction
    if not extracted_controls:
        extracted_controls = extract_controls_by_keywords(ssp_text_normalized, framework_controls)
    
    return extracted_controls

def extract_control_content(ssp_text, control_id, start_pos):
    """Extract control content from a specific position"""
    lines = ssp_text.split('\n')
    content_lines = []
    
    # Find the line containing the control
    control_line = ""
    for line in lines:
        if control_id in line:
            control_line = line.strip()
            break
    
    # start_pos is a character offset; convert it to the line it falls on
    start_line = ssp_text.count('\n', 0, start_pos)
    end_line = min(len(lines), start_line + 10)

    # Take the control's own block: stop at a blank line or the next control heading
    for i in range(start_line, end_line):
        line = lines[i].strip()
        if not line:
            if content_lines:
                break
            continue
        if i > start_line and re.match(r'^([A-Z]{2}-\d+|[A-Z]\.\d+|Req-\d+)\b', line, re.IGNORECASE):
            break
        content_lines.append(line)
    
    description = ' '.join(content_lines)
    
    return {
        'description': description,
        'raw_text': control_line,
        'confidence': 0.9
    }

def extract_controls_by_id(ssp_text, framework_controls):
    """Extract controls using flexible control ID patterns"""
    controls = {}
    
    # Multiple control ID patterns to try
    control_patterns = [
        r'([A-Z]+-\d+)[:\s]+([^.\n]+)',  # AC-2: Account Management
        r'([A-Z]+-\d+)\s*[-–]\s*([^.\n]+)',  # AC-2 - Account Management
        r'([A-Z]+-\d+)\s+([^.\n]+)',  # AC-2 Account Management
        r'([A-Z]+\.\d+)[:\s]+([^.\n]+)',  # A.9.1: Access Control
        r'(Req-\d+)[:\s]+([^.\n]+)',  # Req-8: Identify Users
    ]
    
    for pattern in control_patterns:
        matches = re.finditer(pattern, ssp_text, re.IGNORECASE | re.MULTILINE)
        for match in matches:
            control_id = match.group(1).upper()
            control_title = match.group(2).strip()
            
            # Try to match with framework controls
            for framework_id, framework_pattern in framework_controls.items():
                if control_id == framework_id or control_id.replace('.', '-') == framework_id:
                    # Extract content around this control
                    start_pos = match.start()
                    controls[framework_id] = extract_control_content(ssp_text, framework_id, start_pos)
                    controls[framework_id]['confidence'] = 0.8
                    break
    
    return controls

def extract_controls_by_semantics(ssp_text, framework_controls):
    """Extract controls using semantic matching based on descriptions"""
    controls = {}
    
    # Define semantic keywords for each control family
    semantic_keywords = {
        'AC': ['access', 'account', 'authentication', 'authorization', 'identity', 'user', 'login', 'password', 'mfa', 'sso'],
        'AU': ['audit', 'logging', 'trail', 'monitor', 'record', 'log', 'cloudtrail'],
        'SC': ['security', 'boundary', 'network', 'encryption', 'cryptographic', 'transmission', 'protection', 'vpc', 'firewall'],
        'SI': ['system', 'monitoring', 'integrity', 'software', 'firmware', 'input', 'validation'],
        'CP': ['contingency', 'backup', 'recovery', 'disaster', 'alternate', 'site', 'business', 'continuity'],
        'RA': ['risk', 'assessment', 'vulnerability', 'scanning', 'threat', 'intelligence'],
        'CM': ['configuration', 'change', 'management', 'baseline', 'settings'],
        'IA': ['identification', 'authentication', 'credential', 'token', 'certificate'],
        'IR': ['incident', 'response', 'handling', 'reporting', 'training'],
        'MA': ['maintenance', 'controlled', 'scheduled'],
        'MP': ['media', 'protection', 'storage', 'access'],
        'PE': ['physical', 'environment', 'access', 'authorization'],
        'PL': ['planning', 'policy', 'procedure', 'standard'],
        'PM': ['program', 'management', 'authorization', 'assessment'],
        'SA': ['system', 'acquisition', 'development', 'testing'],
        'SR': ['supply', 'chain', 'risk', 'management']
    }
    
    # Split text into sections
    sections = re.split(r'\n\s*\n', ssp_text)
    
    for section in sections:
        section_lower = section.lower()
        
        # Determine control family based on keywords
        best_match = None
        best_score = 0
        
        for family, keywords in semantic_keywords.items():
            score = sum(1 for keyword in keywords if keyword in section_lower)
            if score > best_score:
                best_score = score
                best_match = family
        
        if best_match and best_score >= 2:  # At least 2 keywords match
            # Try to find specific control numbers in this section
            control_matches = re.findall(r'([A-Z]+-\d+)', section, re.IGNORECASE)
            
            for control_match in control_matches:
                if control_match in framework_controls:
                    controls[control_match] = {
                        'description': section.strip(),
                        'raw_text': control_match,
                        'confidence': min(0.7, best_score * 0.1)
                    }
    
    return controls

def extract_controls_by_keywords(ssp_text, framework_controls):
    """Extract controls using keyword-based matching"""
    controls = {}
    
    # Define control-specific keywords
    control_keywords = {
        'AC-2': ['account', 'management', 'user', 'iam', 'aws', 'sso', 'okta', 'password', 'policy'],
        'SC-7': ['boundary', 'protection', 'network', 'vpc', 'security', 'groups', 'firewall', 'nacl'],
        'SC-13': ['cryptographic', 'encryption', 'kms', 'key', 'rotation', 'aes', 'ssl', 'tls'],
        'SI-4': ['monitoring', 'system', 'guardduty', 'security', 'hub', 'cloudwatch', 'alarm'],
        'AU-2': ['audit', 'events', 'cloudtrail', 'logging', 'validation', 'insight'],
        'AU-12': ['log', 'retention', 's3', 'object', 'lock', 'glacier', 'archive'],
        'CM-6': ['configuration', 'settings', 'config', 'rules', 'compliance', 'conformance'],
        'RA-5': ['vulnerability', 'scanning', 'inspector', 'macie', 'findings', 'critical', 'high'],
        'CP-7': ['alternate', 'processing', 'site', 'aurora', 'global', 'failover', 'lambda'],
        'CP-9': ['backup', 'system', 'vault', 'resources', 'protected', 'cross', 'region'],
        'SC-8': ['transmission', 'protection', 'tls', 'ssl', 'cloudfront', 'waf', 'alb'],
        'SC-12': ['cryptographic', 'key', 'establishment', 'management', 'rotation', 'alias'],
        'SC-28': ['protection', 'information', 'rest', 'encryption', 's3', 'rds', 'efs', 'dynamodb'],
        'SI-7': ['software', 'integrity', 'codebuild', 'codepipeline', 'ssm', 'patch', 'pending']
    }
    
    # Split text into paragraphs
    paragraphs = re.split(r'\n\s*\n', ssp_text)
    
    for paragraph in paragraphs:
        paragraph_lower = paragraph.lower()
        
        # Score each control based on keyword matches
        control_scores = {}
        
        for control_id, keywords in control_keywords.items():
            if control_id in framework_controls:
                score = sum(1 for keyword in keywords if keyword in paragraph_lower)
                if score >= 2:  # At least 2 keywords must match
                    control_scores[control_id] = score
        
        # Select the best matching control for this paragraph
        if control_scores:
            best_control = max(control_scores, key=control_scores.get)
            if control_scores[best_control] >= 2:
                controls[best_control] = {
                    'description': paragraph.strip(),
                    'raw_text': best_control,
                    'confidence': min(0.6, control_scores[best_control] * 0.1)
                }
    
    return controls

def check_compliance(control_id, ssp_description, aws_data, framework_rules):
    """Check compliance for a specific control"""
    rule = framework_rules.get(control_id, {})
    requirements = rule.get('requirements', [])
    
    # Check if SSP description meets requirements
    ssp_lower = ssp_description.lower()
    requirements_met = sum(1 for req in requirements if req.lower() in ssp_lower)
    requirement_score = requirements_met / len(requirements) if requirements else 0
    
    # Check AWS data
    aws_score = 0
    findings = []
    recommendations = []
    
    # AC-2: Account Management
    if control_id == "AC-2":
        users_without_mfa = [u for u in aws_data['iam']['users'] if not u['MFA']]
        if users_without_mfa:
            findings.append(f"Users without MFA: {', '.join([u['UserName'] for u in users_without_mfa])}")
            recommendations.append("Enable MFA for all users")
            aws_score = 0.3
        else:
            aws_score = 1.0
            
        if aws_data['iam']['password_policy']['MinimumPasswordLength'] >= 12:
            aws_score += 0.2
        else:
            findings.append("Password policy too weak")
            recommendations.append("Increase minimum password length to 12+ characters")
    
    # IA-2: Identification & Authentication
    elif control_id == "IA-2":
        users_without_mfa = [u for u in aws_data['iam']['users'] if not u['MFA']]
        if users_without_mfa:
            findings.append(f"Users without MFA: {', '.join([u['UserName'] for u in users_without_mfa])}")
            recommendations.append("Enable MFA for all users")
            aws_score = 0.2
        else:
            aws_score = 1.0
    
    # CP-7: Alternate Processing Site
    elif control_id == "CP-7":
        if "aurora" in ssp_lower and "global" in ssp_lower:
            aws_score = 0.9
        else:
            findings.append("SSP doesn't clearly describe alternate processing site")
            recommendations.append("Document Aurora Global Database configuration")
            aws_score = 0.4
    
    # CP-9: System Backup
    elif control_id == "CP-9":
        if aws_data['backup']['resources_protected'] > 0:
            aws_score = 0.8
        else:
            findings.append("No backup resources configured")
            recommendations.append("Configure AWS Backup for critical resources")
            aws_score = 0.2
    
    # SC-7: Boundary Protection
    elif control_id == "SC-7":
        public_buckets = [b for b in aws_data['s3'] if not b['PublicAccessBlock']]
        if not public_buckets:
            aws_score = 1.0
        else:
            findings.append(f"Public buckets found: {', '.join([b['Bucket'] for b in public_buckets])}")
            recommendations.append("Block public access on all S3 buckets")
            aws_score = 0.4
    
    # SI-4: System Monitoring
    elif control_id == "SI-4":
        if aws_data['guardduty']['findings']['Critical'] == 0:
            aws_score = 0.8
        else:
            findings.append("Critical security findings detected")
            recommendations.append("Address critical GuardDuty findings")
            aws_score = 0.5
    
    # AU-2: Audit Events
    elif control_id == "AU-2":
        if aws_data['cloudtrail']['trails']:
            aws_score = 0.9
        else:
            findings.append("No CloudTrail configured")
            recommendations.append("Enable CloudTrail for audit logging")
            aws_score = 0.1
    
    # AU-12: Log Retention
    elif control_id == "AU-12":
        retention_buckets = [b for b in aws_data['s3'] if b.get('RetentionDays', 0) >= 365]
        if retention_buckets:
            aws_score = 0.8
        else:
            findings.append("Insufficient log retention configured")
            recommendations.append("Configure S3 Object Lock for 365+ day retention")
            aws_score = 0.3
    
    # CM-6: Configuration Settings
    elif control_id == "CM-6":
        compliant_rules = [r for r in aws_data['config']['rules'] if r['ComplianceType'] == 'COMPLIANT']
        if len(compliant_rules) >= 2:
            aws_score = 0.7
        else:
            findings.append("Insufficient Config rules compliance")
            recommendations.append("Address non-compliant Config rules")
            aws_score = 0.3
    
    # RA-5: Vulnerability Scanning
    elif control_id == "RA-5":
        if aws_data['inspector2']['findings']['Critical'] == 0:
            aws_score = 0.8
        else:
            findings.append(f"Critical vulnerabilities found: {aws_data['inspector2']['findings']['Critical']}")
            recommendations.append("Address critical Inspector2 findings")
            aws_score = 0.4
    
    # SC-13: Cryptographic Protection
    elif control_id == "SC-13":
        encrypted_services = 0
        if any(b['Encryption'] for b in aws_data['s3']):
            encrypted_services += 1
        if aws_data['rds'][0]['Encrypted']:
            encrypted_services += 1
        if aws_data['kms']:
            encrypted_services += 1
        
        if encrypted_services >= 2:
            aws_score = 0.8
        else:
            findings.append("Insufficient encryption coverage")
            recommendations.append("Enable encryption for all data at rest")
            aws_score = 0.4
    
    # Default scoring for other controls
    else:
        # Base score on SSP description quality
        if requirement_score > 0.7:
            aws_score = 0.8
        elif requirement_score > 0.4:
            aws_score = 0.5
        else:
            aws_score = 0.2
            findings.append("SSP description lacks sufficient detail")
            recommendations.append("Provide more detailed implementation description")
    
    # Calculate overall score
    overall_score = (requirement_score + aws_score) / 2
    
    # Determine status
    if overall_score >= 0.8:
        status = "PASS"
    elif overall_score >= 0.5:
        status = "PARTIAL"
    else:
        status = "FAIL"
    
    return {
        'control_id': control_id,
        'control_title': rule.get('description', 'Unknown Control'),
        'status': status,
        'confidence': round(overall_score * 100, 1),
        'findings': findings,
        'recommendations': recommendations,
        'evidence': {
            'ssp_description': ssp_description,
            'requirement_score': round(requirement_score * 100, 1),
            'aws_score': round(aws_score * 100, 1)
        }
    }

@app.route('/')
def index():
    """Futuristic web interface"""
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>proTecht - Cybersecurity Compliance Automation</title>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }

            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #0c0c0c 0%, #1a1a2e 50%, #16213e 100%);
                color: #ffffff;
                min-height: 100vh;
                overflow-x: hidden;
            }

            .container {
                max-width: 1200px;
                margin: 0 auto;
                padding: 20px;
            }

            .header {
                text-align: center;
                margin-bottom: 40px;
                position: relative;
            }

            .header h1 {
                font-size: 3.5rem;
                font-weight: 700;
                background: linear-gradient(45deg, #00d4ff, #ff6b6b, #4ecdc4);
                background-size: 200% 200%;
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
                animation: gradientShift 3s ease-in-out infinite;
                margin-bottom: 10px;
            }

            @keyframes gradientShift {
                0%, 100% { background-position: 0% 50%; }
                50% { background-position: 100% 50%; }
            }

            .header p {
                font-size: 1.2rem;
                color: #b0b0b0;
                margin-bottom: 20px;
            }

            .stats-bar {
                display: flex;
                justify-content: center;
                gap: 40px;
                margin-top: 30px;
                flex-wrap: wrap;
            }

            .stat-item {
                text-align: center;
                background: rgba(0, 212, 255, 0.1);
                border: 1px solid rgba(0, 212, 255, 0.3);
                border-radius: 15px;
                padding: 20px;
                min-width: 150px;
                transition: all 0.3s ease;
            }

            .stat-item:hover {
                transform: translateY(-5px);
                box-shadow: 0 10px 25px rgba(0, 212, 255, 0.3);
                background: rgba(0, 212, 255, 0.15);
            }

            .stat-number {
                font-size: 2.5rem;
                font-weight: bold;
                color: #00d4ff;
                margin-bottom: 8px;
                text-shadow: 0 0 10px rgba(0, 212, 255, 0.5);
            }

            .stat-label {
                color: #b0b0b0;
                font-size: 0.9rem;
                font-weight: 600;
            }

            /* Rotating Framework Animation */
            .rotating-framework {
                position: relative;
                height: 20px;
                overflow: hidden;
            }

            .framework-text {
                position: absolute;
                top: 0;
                left: 0;
                width: 100%;
                opacity: 0;
                transform: translateY(20px);
                transition: all 0.5s ease;
                color: #b0b0b0;
                font-size: 0.9rem;
                font-weight: 600;
            }

            .framework-text.active {
                opacity: 1;
                transform: translateY(0);
            }

            .framework-text.sliding-out {
                opacity: 0;
                transform: translateY(-20px);
            }

            .main-content {
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 30px;
                margin-bottom: 40px;
            }

            .input-section, .results-section {
                background: rgba(255, 255, 255, 0.05);
                backdrop-filter: blur(15px);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 20px;
                padding: 30px;
                transition: transform 0.3s ease;
            }

            .input-section:hover, .results-section:hover {
                transform: translateY(-2px);
                box-shadow: 0 15px 40px rgba(0, 212, 255, 0.1);
            }

            .section-title {
                font-size: 1.5rem;
                font-weight: 600;
                margin-bottom: 20px;
                color: #00d4ff;
                display: flex;
                align-items: center;
                gap: 10px;
            }

            .section-title::before {
                content: '';
                width: 4px;
                height: 20px;
                background: linear-gradient(45deg, #00d4ff, #ff6b6b);
                border-radius: 2px;
            }

            textarea {
                width: 100%;
                height: 300px;
                background: rgba(0, 0, 0, 0.3);
                border: 1px solid rgba(255, 255, 255, 0.2);
                border-radius: 15px;
                padding: 20px;
                color: #ffffff;
                font-size: 14px;
                line-height: 1.6;
                resize: vertical;
                transition: border-color 0.3s ease, box-shadow 0.3s ease;
            }

            textarea:focus {
                outline: none;
                border-color: #00d4ff;
                box-shadow: 0 0 20px rgba(0, 212, 255, 0.3);
            }

            .btn {
                padding: 15px 30px;
                border: none;
                border-radius: 12px;
                font-size: 1rem;
                font-weight: 600;
                cursor: pointer;
                transition: all 0.3s ease;
                position: relative;
                overflow: hidden;
                min-width: 150px;
            }

            .btn-primary {
                background: linear-gradient(45deg, #00d4ff, #0099cc);
                color: white;
            }

            .btn-primary:hover {
                transform: translateY(-2px);
                box-shadow: 0 10px 25px rgba(0, 212, 255, 0.4);
            }

            .btn-ai {
                background: linear-gradient(45deg, #ff6b6b, #ee5a24);
                color: white;
            }

            .btn-ai:hover {
                transform: translateY(-2px);
                box-shadow: 0 10px 25px rgba(255, 107, 107, 0.4);
            }

            .btn-secondary {
                background: linear-gradient(45deg, #6c757d, #495057);
                color: white;
            }

            .btn-secondary:hover {
                transform: translateY(-2px);
                box-shadow: 0 10px 25px rgba(108, 117, 125, 0.4);
            }

            .btn:disabled {
                opacity: 0.6;
                cursor: not-allowed;
                transform: none !important;
            }

            .loading {
                display: none;
                text-align: center;
                padding: 40px;
            }

            .spinner {
                width: 50px;
                height: 50px;
                border: 4px solid rgba(255, 255, 255, 0.1);
                border-left: 4px solid #00d4ff;
                border-radius: 50%;
                animation: spin 1s linear infinite;
                margin: 0 auto 20px;
            }

            @keyframes spin {
                0% { transform: rotate(0deg); }
                100% { transform: rotate(360deg); }
            }

            .compliance-summary {
                background: rgba(0, 0, 0, 0.2);
                border-radius: 15px;
                padding: 25px;
                margin-bottom: 30px;
                border: 1px solid rgba(255, 255, 255, 0.1);
            }

            .compliance-score {
                text-align: center;
                margin-bottom: 20px;
            }

            .score-circle {
                width: 120px;
                height: 120px;
                border-radius: 50%;
                margin: 0 auto 15px;
                display: flex;
                align-items: center;
                justify-content: center;
                font-size: 2rem;
                font-weight: bold;
                position: relative;
            }

            .score-pass { background: linear-gradient(45deg, #4ecdc4, #44a08d); }
            .score-partial { background: linear-gradient(45deg, #ffd93d, #ff6b6b); }
            .score-fail { background: linear-gradient(45deg, #ff6b6b, #ee5a24); }

            .control-results {
                max-height: 500px;
                overflow-y: auto;
                padding-right: 10px;
            }

            .control-item {
                background: rgba(255, 255, 255, 0.05);
                border-radius: 12px;
                padding: 20px;
                margin-bottom: 15px;
                border-left: 4px solid;
                transition: all 0.3s ease;
                position: relative;
                cursor: pointer;
            }

            .control-item:hover {
                background: rgba(255, 255, 255, 0.08);
                border-color: rgba(0, 212, 255, 0.3);
                transform: translateY(-2px);
                box-shadow: 0 8px 25px rgba(0, 212, 255, 0.15);
            }

            .control-item.expanded {
                background: rgba(0, 212, 255, 0.1);
                border-color: rgba(0, 212, 255, 0.5);
                box-shadow: 0 8px 25px rgba(0, 212, 255, 0.2);
            }

            .control-item::after {
                content: '▼';
                position: absolute;
                right: 20px;
                top: 20px;
                color: #00d4ff;
                font-size: 12px;
                transition: transform 0.3s ease;
            }

            .control-item.expanded::after {
                transform: rotate(180deg);
            }

            .control-item.pass { border-left-color: #4ecdc4; }
            .control-item.partial { border-left-color: #ffd93d; }
            .control-item.fail { border-left-color: #ff6b6b; }

            .control-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 10px;
            }

            .control-title {
                font-weight: 600;
                font-size: 1.1rem;
            }

            .control-status {
                padding: 5px 12px;
                border-radius: 20px;
                font-size: 0.8rem;
                font-weight: 600;
                text-transform: uppercase;
            }

            .status-pass { background: rgba(78, 205, 196, 0.2); color: #4ecdc4; }
            .status-partial { background: rgba(255, 217, 61, 0.2); color: #ffd93d; }
            .status-fail { background: rgba(255, 107, 107, 0.2); color: #ff6b6b; }

            .control-summary {
                font-size: 0.9rem;
                color: #b0b0b0;
                margin-bottom: 10px;
            }

            .control-details {
                font-size: 0.9rem;
                color: #b0b0b0;
                margin-top: 15px;
                padding-top: 15px;
                border-top: 1px solid rgba(255, 255, 255, 0.1);
                animation: slideDown 0.3s ease;
            }

            @keyframes slideDown {
                from {
                    opacity: 0;
                    transform: translateY(-10px);
                }
                to {
                    opacity: 1;
                    transform: translateY(0);
                }
            }

            .findings-list, .recommendations-list {
                margin-top: 10px;
            }

            .findings-list li, .recommendations-list li {
                margin-bottom: 5px;
                padding-left: 20px;
                position: relative;
            }

            .findings-list li::before {
                content: '⚠️';
                position: absolute;
                left: 0;
            }

            .recommendations-list li::before {
                content: '💡';
                position: absolute;
                left: 0;
            }

            /* AI Recommendations specific styles - Futuristic Dark Theme */
            .ai-recommendations {
                background: linear-gradient(135deg, rgba(0, 0, 0, 0.8), rgba(20, 20, 40, 0.9));
                border: 1px solid rgba(0, 212, 255, 0.3);
                border-radius: 20px;
                padding: 30px;
                margin: 20px 0;
                box-shadow: 0 0 30px rgba(0, 212, 255, 0.2);
                backdrop-filter: blur(10px);
                position: relative;
                overflow: hidden;
            }

            .ai-recommendations::before {
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                height: 2px;
                background: linear-gradient(90deg, #00d4ff, #ff6b6b, #00d4ff);
                animation: shimmer 3s ease-in-out infinite;
            }

            @keyframes shimmer {
                0%, 100% { transform: translateX(-100%); }
                50% { transform: translateX(100%); }
            }

            .ai-header {
                display: flex;
                align-items: center;
                gap: 15px;
                font-size: 20px;
                font-weight: bold;
                color: #00d4ff;
                margin-bottom: 25px;
                text-shadow: 0 0 10px rgba(0, 212, 255, 0.5);
            }

            .ai-header span:first-child {
                font-size: 28px;
                animation: pulse 2s ease-in-out infinite;
            }

            @keyframes pulse {
                0%, 100% { transform: scale(1); }
                50% { transform: scale(1.1); }
            }

            .ai-content {
                background: linear-gradient(135deg, rgba(0, 0, 0, 0.6), rgba(20, 20, 40, 0.7));
                border-radius: 15px;
                padding: 25px;
                border: 1px solid rgba(0, 212, 255, 0.2);
                min-height: 300px;
                overflow-y: auto;
                max-height: 700px;
                color: #e0e0e0;
                line-height: 1.7;
                position: relative;
            }

            .ai-content::-webkit-scrollbar {
                width: 8px;
            }

            .ai-content::-webkit-scrollbar-track {
                background: rgba(0, 0, 0, 0.3);
                border-radius: 4px;
            }

            .ai-content::-webkit-scrollbar-thumb {
                background: linear-gradient(45deg, #00d4ff, #0099cc);
                border-radius: 4px;
            }

            .ai-content::-webkit-scrollbar-thumb:hover {
                background: linear-gradient(45deg, #0099cc, #00d4ff);
            }

            /* AI Content Typography */
            .ai-content h1 {
                color: #00d4ff;
                font-size: 28px;
                margin: 25px 0 15px 0;
                text-shadow: 0 0 15px rgba(0, 212, 255, 0.3);
                border-bottom: 2px solid rgba(0, 212, 255, 0.3);
                padding-bottom: 10px;
            }

            .ai-content h2 {
                color: #ff6b6b;
                font-size: 22px;
                margin: 20px 0 12px 0;
                text-shadow: 0 0 10px rgba(255, 107, 107, 0.3);
            }

            .ai-content h3 {
                color: #ffd93d;
                font-size: 18px;
                margin: 15px 0 10px 0;
                text-shadow: 0 0 8px rgba(255, 217, 61, 0.3);
            }

            .ai-content p {
                color: #b0b0b0;
                line-height: 1.8;
                margin-bottom: 15px;
                text-shadow: 0 1px 2px rgba(0, 0, 0, 0.5);
            }

            .ai-content ul, .ai-content ol {
                margin: 15px 0 15px 25px;
                color: #b0b0b0;
            }

            .ai-content li {
                margin-bottom: 10px;
                color: #b0b0b0;
                position: relative;
                padding-left: 5px;
            }

            .ai-content li::before {
                content: '▶';
                color: #00d4ff;
                font-weight: bold;
                position: absolute;
                left: -15px;
                animation: blink 2s ease-in-out infinite;
            }

            @keyframes blink {
                0%, 100% { opacity: 1; }
                50% { opacity: 0.5; }
            }

            .ai-content strong {
                color: #00d4ff;
                text-shadow: 0 0 5px rgba(0, 212, 255, 0.3);
            }

            .ai-content .critical {
                color: #ff6b6b;
                text-shadow: 0 0 5px rgba(255, 107, 107, 0.3);
            }

            .ai-content .medium {
                color: #ffd93d;
                text-shadow: 0 0 5px rgba(255, 217, 61, 0.3);
            }

            .ai-content .strategic {
                color: #00d4ff;
                text-shadow: 0 0 5px rgba(0, 212, 255, 0.3);
            }

            .ai-content .actionable {
                color: #00ff88;
                text-shadow: 0 0 5px rgba(0, 255, 136, 0.3);
            }

            /* Loading state */
            .ai-content .loading {
                text-align: center;
                padding: 40px;
                color: #00d4ff;
                font-size: 18px;
                text-shadow: 0 0 10px rgba(0, 212, 255, 0.5);
            }

            .ai-content .loading::after {
                content: '';
                display: inline-block;
                width: 20px;
                height: 20px;
                border: 2px solid #00d4ff;
                border-radius: 50%;
                border-top-color: transparent;
                animation: spin 1s linear infinite;
                margin-left: 10px;
            }

            @keyframes spin {
                to { transform: rotate(360deg); }
            }

            .framework-selector {
                margin-bottom: 20px;
            }

            .framework-selector label {
                display: block;
                margin-bottom: 8px;
                color: #00d4ff;
                font-weight: 600;
            }

            .framework-select {
                width: 100%;
                padding: 12px 15px;
                background: rgba(0, 0, 0, 0.3);
                border: 1px solid rgba(255, 255, 255, 0.2);
                border-radius: 12px;
                color: #ffffff;
                font-size: 14px;
                transition: border-color 0.3s ease, box-shadow 0.3s ease;
            }

            .framework-select:focus {
                outline: none;
                border-color: #00d4ff;
                box-shadow: 0 0 20px rgba(0, 212, 255, 0.3);
            }

            .framework-select option {
                background: #1a1a2e;
                color: #ffffff;
            }

            .framework-info {
                background: rgba(0, 212, 255, 0.1);
                border: 1px solid rgba(0, 212, 255, 0.3);
                border-radius: 10px;
                padding: 15px;
                margin-bottom: 20px;
                display: none;
            }

            .framework-info h4 {
                color: #00d4ff;
                margin-bottom: 8px;
            }

            .framework-info p {
                color: #b0b0b0;
                font-size: 0.9rem;
                margin-bottom: 5px;
            }

            .file-upload-section {
                margin-bottom: 20px;
            }

            .file-upload-area {
                border: 2px dashed rgba(0, 212, 255, 0.5);
                border-radius: 12px;
                padding: 30px;
                text-align: center;
                background: rgba(0, 212, 255, 0.05);
                transition: all 0.3s ease;
                cursor: pointer;
                position: relative;
                overflow: hidden;
            }

            .file-upload-area:hover {
                border-color: #00d4ff;
                background: rgba(0, 212, 255, 0.1);
                transform: translateY(-2px);
            }

            .file-upload-area.dragover {
                border-color: #00d4ff;
                background: rgba(0, 212, 255, 0.15);
                transform: scale(1.02);
            }

            .file-upload-icon {
                font-size: 48px;
                color: #00d4ff;
                margin-bottom: 15px;
            }

            .file-upload-text {
                color: #ffffff;
                font-size: 16px;
                margin-bottom: 10px;
            }

            .file-upload-subtext {
                color: #b0b0b0;
                font-size: 14px;
                margin-bottom: 15px;
            }

            .file-input {
                position: absolute;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                opacity: 0;
                cursor: pointer;
                z-index: 10;
            }

            .uploaded-file-info {
                background: rgba(0, 255, 0, 0.1);
                border: 1px solid rgba(0, 255, 0, 0.3);
                border-radius: 10px;
                padding: 15px;
                margin-bottom: 20px;
                display: none;
            }

            .uploaded-file-info h4 {
                color: #00ff00;
                margin-bottom: 8px;
            }

            .uploaded-file-info p {
                color: #b0b0b0;
                font-size: 0.9rem;
                margin-bottom: 5px;
            }

            .or-divider {
                text-align: center;
                margin: 20px 0;
                position: relative;
            }

            .or-divider::before {
                content: '';
                position: absolute;
                top: 50%;
                left: 0;
                right: 0;
                height: 1px;
                background: rgba(255, 255, 255, 0.2);
            }

            .or-divider span {
                background: #1a1a2e;
                padding: 0 15px;
                color: #b0b0b0;
                font-size: 14px;
            }

            .analysis-actions-section {
                background: rgba(0, 212, 255, 0.05);
                border: 1px solid rgba(0, 212, 255, 0.2);
                border-radius: 15px;
                padding: 25px;
                margin: 30px 0;
                text-align: center;
            }

            .action-buttons {
                display: flex;
                justify-content: center;
                gap: 20px;
                margin-top: 20px;
                flex-wrap: wrap;
            }

            .action-buttons .btn {
                min-width: 200px;
                padding: 15px 25px;
                font-size: 16px;
                font-weight: 600;
                border-radius: 10px;
                border: none;
                cursor: pointer;
                transition: all 0.3s ease;
                box-shadow: 0 4px 15px rgba(0, 0, 0, 0.2);
            }

            .action-buttons .btn:hover {
                transform: translateY(-2px);
                box-shadow: 0 6px 20px rgba(0, 0, 0, 0.3);
            }

            .action-buttons .btn:disabled {
                opacity: 0.5;
                cursor: not-allowed;
                transform: none;
            }

            /* Tab Navigation Styles */
            .tab-navigation {
                display: flex;
                background: rgba(0, 0, 0, 0.2);
                border-radius: 10px;
                padding: 5px;
                margin-bottom: 20px;
                gap: 5px;
            }

            .tab-button {
                flex: 1;
                padding: 12px 20px;
                background: transparent;
                border: none;
                border-radius: 8px;
                color: #b0b0b0;
                font-size: 14px;
                font-weight: 600;
                cursor: pointer;
                transition: all 0.3s ease;
                text-align: center;
            }

            .tab-button:hover {
                background: rgba(0, 212, 255, 0.1);
                color: #ffffff;
            }

            .tab-button.active {
                background: linear-gradient(135deg, #00d4ff, #0099cc);
                color: white;
                box-shadow: 0 4px 15px rgba(0, 212, 255, 0.3);
            }

            /* Tab Content Styles */
            .tab-content {
                position: relative;
            }

            .tab-pane {
                display: none;
                animation: fadeIn 0.3s ease-in-out;
            }

            .tab-pane.active {
                display: block !important;
                visibility: visible !important;
                opacity: 1 !important;
            }

            @keyframes fadeIn {
                from { opacity: 0; transform: translateY(10px); }
                to { opacity: 1; transform: translateY(0); }
            }

            @media (max-width: 768px) {
                .main-content {
                    grid-template-columns: 1fr;
                }
                
                .header h1 {
                    font-size: 2.5rem;
                }
                
                .stats-bar {
                    gap: 15px;
                }
                
                .stat-item {
                    min-width: 120px;
                    padding: 15px;
                }
            }

            ::-webkit-scrollbar {
                width: 8px;
            }

            ::-webkit-scrollbar-track {
                background: rgba(255, 255, 255, 0.1);
                border-radius: 4px;
            }

            ::-webkit-scrollbar-thumb {
                background: rgba(0, 212, 255, 0.5);
                border-radius: 4px;
            }

            ::-webkit-scrollbar-thumb:hover {
                background: rgba(0, 212, 255, 0.7);
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>proTecht</h1>
                <p>Advanced Cybersecurity Compliance Automation Platform</p>
                <div class="stats-bar">
                    <div class="stat-item">
                        <div class="stat-number">50+</div>
                        <div class="stat-label rotating-framework">
                            <span class="framework-text active">FedRAMP Controls</span>
                            <span class="framework-text">NIST Controls</span>
                            <span class="framework-text">ISO Controls</span>
                            <span class="framework-text">PCI DSS Controls</span>
                        </div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-number">99%</div>
                        <div class="stat-label">Time Savings</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-number">AI</div>
                        <div class="stat-label">Powered Analysis</div>
                    </div>
                </div>
            </div>

            <div class="main-content">
                <div class="input-section">
                    <div class="section-title">System Security Plan (SSP)</div>
                    
                    <div class="framework-selector">
                        <label for="frameworkSelect">Compliance Framework</label>
                        <select id="frameworkSelect" class="framework-select" onchange="updateFrameworkInfo()">
                            <option value="fedramp">FedRAMP Moderate</option>
                            <option value="nist">NIST 800-53 Rev. 4</option>
                            <option value="iso27001">ISO 27001:2013</option>
                            <option value="pci">PCI DSS v4.0</option>
                        </select>
                    </div>
                    
                    <div class="framework-info" id="frameworkInfo">
                        <h4 id="frameworkName">FedRAMP Moderate</h4>
                        <p id="frameworkDescription">Federal Risk and Authorization Management Program</p>
                        <p><strong>Controls:</strong> <span id="controlCount">50+</span></p>
                    </div>
                    
                    <div class="file-upload-section">
                        <div class="section-title">Upload SSP File</div>
                        
                        <!-- Simple file input with label -->
                        <div style="text-align: center; margin: 20px 0;">
                            <label for="fileInput" style="display: inline-block; padding: 15px 30px; background: linear-gradient(135deg, #00d4ff, #0099cc); color: white; border-radius: 10px; cursor: pointer; font-size: 16px; transition: all 0.3s ease;">
                                Choose SSP File
                            </label>
                            <input type="file" id="fileInput" accept=".txt,.pdf,.doc,.docx,.md" style="display: none;">
                            <div style="margin-top: 10px; color: #b0b0b0; font-size: 14px;">
                                Supports: TXT, PDF, DOC, DOCX, MD (Max 16MB)
                            </div>
                        </div>
                        
                        <div class="uploaded-file-info" id="uploadedFileInfo" style="display: none;">
                            <h4 id="uploadedFileName">File Uploaded Successfully!</h4>
                            <p id="uploadedFileMessage">Your SSP file has been processed and loaded.</p>
                        </div>
                    </div>
                    
                    <div class="or-divider">
                        <span>OR</span>
                    </div>
                    
                    <div class="section-title">Paste SSP Text</div>
                    <textarea id="sspText" placeholder="Paste your SSP text here...">AC-2: Account Management
AWS IAM, AWS SSO, and Okta federated via SAML are authoritative.
Automated inactivation: Config rule \`phoenix-ac2-inactive\` disables after 30 days.

IA-2: Identification & Authentication
MFA enforced on all users and root.
Federation via Okta with WebAuthn.

CP-7: Alternate Processing Site
Active-Active Aurora Global DB; Route 53 health checks; automated failover Lambda.

CP-9: System Backup
AWS Backup protects RDS/DynamoDB/EFS/EC2 nightly; retention=35 days; cross-region copy enabled.

SC-7: Boundary Protection
All ingress via ALB/CloudFront TLS 1.2+; WAF rules block OWASP Top 10.

SI-4: System Monitoring
GuardDuty, Detective, Security Hub all ON; custom CloudWatch Contributor Insights.

AU-2: Audit Events
CloudTrail in all GovCloud regions with log validation.

AU-12: Log Retention
S3 Object Lock (GOVERNANCE, 365 days); Glacier Deep Archive after 180 days.

CM-6: Configuration Settings
SSM State Manager enforces CIS benchmarks every hour.

RA-5: Vulnerability Scanning
Nessus Gov external; Inspector2 internal weekly; critical auto-ticket via Jira.

SC-13: Cryptographic Protection
Data at rest: S3/RDS/EFS/Dynamo encrypted with CMKs.
Secrets in Secrets Manager rotated 30 days.</textarea>
                    
                    <!-- New Analysis Actions Section -->
                    <div class="analysis-actions-section">
                        <div class="section-title">Analysis Actions</div>
                        <div class="action-buttons">
                            <button class="btn btn-primary" onclick="analyzeSSP()">
                                Analyze SSP
                            </button>
                            <button class="btn btn-ai" onclick="getAIRecommendations()" id="aiBtn" disabled>
                                AI Recommendations
                            </button>
                        </div>
                    </div>
                </div>

                <div class="results-section">
                    <div class="section-title">Analysis Results</div>
                    
                    <!-- Tab Navigation -->
                    <div class="tab-navigation">
                        <button class="tab-button active" onclick="switchTab('compliance')" id="complianceTab">
                            Compliance Analysis
                        </button>
                        <button class="tab-button" onclick="switchTab('ai')" id="aiTab">
                            AI Recommendations
                        </button>
                    </div>
                    
                    <!-- Tab Content -->
                    <div class="tab-content">
                        <!-- Compliance Analysis Tab -->
                        <div class="tab-pane active" id="complianceTabContent">
                            <div class="loading" id="loading">
                                <div class="spinner"></div>
                                <p>Analyzing your SSP against AWS infrastructure...</p>
                            </div>
                            
                            <div id="results"></div>
                        </div>
                        
                        <!-- AI Recommendations Tab -->
                        <div class="tab-pane" id="aiTabContent">
                            <div class="ai-recommendations" id="aiRecommendations">
                                <div class="ai-header">
                                    <span>AI</span>
                                    <span>AI-Powered Recommendations</span>
                                </div>
                                <div class="ai-content" id="aiContent">
                                    Click "AI Recommendations" to get intelligent suggestions for improving your compliance posture.
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <script>
            // Test if JavaScript is loading
            console.log('JavaScript is loading...');
            
            // Global error handler to catch any JavaScript errors
            window.addEventListener('error', function(e) {
                console.error('JavaScript Error:', e.error);
                alert('JavaScript Error: ' + e.error.message);
            });
            
            let currentAnalysisData = null;
            let frameworksData = null;

            // Load frameworks on page load
            window.addEventListener('load', async function() {
                try {
                    const response = await fetch('/frameworks');
                    frameworksData = await response.json();
                    updateFrameworkInfo();
                } catch (error) {
                    console.error('Error loading frameworks:', error);
                }
                
                // Start the rotating framework animation
                startFrameworkRotation();
            });

            // Rotating framework animation
            function startFrameworkRotation() {
                const frameworkTexts = document.querySelectorAll('.framework-text');
                let currentIndex = 0;
                
                function rotateFramework() {
                    // Remove active class from current text
                    frameworkTexts[currentIndex].classList.remove('active');
                    frameworkTexts[currentIndex].classList.add('sliding-out');
                    
                    // Move to next framework
                    currentIndex = (currentIndex + 1) % frameworkTexts.length;
                    
                    // Add active class to new text
                    setTimeout(() => {
                        frameworkTexts[currentIndex].classList.remove('sliding-out');
                        frameworkTexts[currentIndex].classList.add('active');
                    }, 500);
                }
                
                // Rotate every 3 seconds
                setInterval(rotateFramework, 3000);
            }

            function updateFrameworkInfo() {
                const frameworkSelect = document.getElementById('frameworkSelect');
                const frameworkInfo = document.getElementById('frameworkInfo');
                const frameworkName = document.getElementById('frameworkName');
                const frameworkDescription = document.getElementById('frameworkDescription');
                const controlCount = document.getElementById('controlCount');
                const sspText = document.getElementById('sspText');
                
                if (frameworksData && frameworkSelect.value) {
                    const framework = frameworksData[frameworkSelect.value];
                    if (framework) {
                        frameworkName.textContent = framework.name;
                        frameworkDescription.textContent = framework.description;
                        controlCount.textContent = framework.control_count;
                        frameworkInfo.style.display = 'block';
                        
                        // Update sample text based on framework
                        updateSampleText(frameworkSelect.value);
                    }
                }
            }

            // Global flag to track if a file has been uploaded
            let fileUploaded = false;

            function updateSampleText(framework) {
                const sspText = document.getElementById('sspText');
                
                // Only update with sample text if no file has been uploaded
                if (!fileUploaded) {
                    const sampleTexts = {
                        'fedramp': `AC-2: Account Management
AWS IAM, AWS SSO, and Okta federated via SAML are authoritative.
Automated inactivation: Config rule \`phoenix-ac2-inactive\` disables after 30 days.

IA-2: Identification & Authentication
MFA enforced on all users and root.
Federation via Okta with WebAuthn.

CP-7: Alternate Processing Site
Active-Active Aurora Global DB; Route 53 health checks; automated failover Lambda.

SC-7: Boundary Protection
All ingress via ALB/CloudFront TLS 1.2+; WAF rules block OWASP Top 10.

SI-4: System Monitoring
GuardDuty, Detective, Security Hub all ON; custom CloudWatch Contributor Insights.`,
                        
                        'nist': `AC-2: Account Management
AWS IAM provides centralized account management with automated user lifecycle.

IA-2: Identification & Authentication
Multi-factor authentication is implemented for all administrative access.

SC-7: Boundary Protection
Network boundaries are enforced through VPC security groups and NACLs.

SC-13: Cryptographic Protection
All data at rest is encrypted using AWS KMS customer master keys.

SI-4: System Monitoring
Comprehensive monitoring through CloudWatch, GuardDuty, and Security Hub.`,
                        
                        'iso27001': `A.9.1: Access Control
Access control policy is implemented through AWS IAM with role-based permissions.

A.9.2: User Access Management
User access is managed through centralized identity provider with regular reviews.

A.10.1: Cryptographic Controls
Encryption is applied to all sensitive data using industry-standard algorithms.

A.12.4: Logging and Monitoring
Security events are logged and monitored through CloudTrail and CloudWatch.

A.12.6: Technical Vulnerability Management
Vulnerability scanning is performed regularly using AWS Inspector and third-party tools.`,
                        
                        'pci': `Req-8: Identify Users and Authenticate Access
All users are assigned unique IDs and MFA is required for all access.

Req-10: Log and Monitor All Access
All access to cardholder data is logged and monitored in real-time.

Req-3: Protect Stored Account Data
Cardholder data is encrypted at rest using AES-256 encryption.

Req-4: Protect Cardholder Data
Strong cryptography is used to protect cardholder data during transmission.

Req-11: Test Security of Systems and Networks
Regular security testing is performed including penetration testing and vulnerability scans.`
                    };
                    
                    sspText.value = sampleTexts[framework] || sampleTexts['fedramp'];
                }
            }

            async function handleFileUpload(event) {
                console.log('handleFileUpload called with event:', event);
                const file = event.target.files[0];
                if (!file) {
                    console.error('No file selected');
                    return;
                }

                console.log('Processing file:', file.name, 'Size:', file.size, 'Type:', file.type);

                const uploadedFileInfo = document.getElementById('uploadedFileInfo');
                const uploadedFileName = document.getElementById('uploadedFileName');
                const uploadedFileMessage = document.getElementById('uploadedFileMessage');
                const sspText = document.getElementById('sspText');

                // Check file size (16MB limit)
                if (file.size > 16 * 1024 * 1024) {
                    console.error('File too large:', file.size);
                    alert('File size exceeds 16MB limit');
                    return;
                }

                // Check file type
                const allowedTypes = ['.txt', '.pdf', '.doc', '.docx', '.md'];
                const fileName = file.name.toLowerCase();
                const isValidType = allowedTypes.some(type => fileName.endsWith(type));
                
                if (!isValidType) {
                    console.error('Invalid file type:', fileName);
                    alert('Invalid file type. Please upload TXT, PDF, DOC, DOCX, or MD files.');
                    return;
                }

                console.log('File validation passed, starting upload...');

                // Show loading state
                const uploadLabel = document.querySelector('label[for="fileInput"]');
                if (uploadLabel) {
                    uploadLabel.textContent = '⏳ Processing...';
                    uploadLabel.style.background = 'linear-gradient(135deg, #ffaa00, #ff8800)';
                }

                try {
                    const formData = new FormData();
                    formData.append('file', file);
                    console.log('FormData created, sending to server...');

                    const response = await fetch('/upload', {
                        method: 'POST',
                        body: formData
                    });

                    console.log('Server response received:', response.status);
                    const result = await response.json();
                    console.log('Response data:', result);

                    if (result.success) {
                        // Check if the extracted text looks valid
                        if (result.ssp_text && result.ssp_text.length > 10 && !result.ssp_text.includes('Error extracting')) {
                            console.log('Text extraction successful, updating UI...');
                            // Update textarea with uploaded content
                            sspText.value = result.ssp_text;
                            
                            // Set flag to indicate file has been uploaded
                            fileUploaded = true;
                            
                            // Show success message
                            uploadedFileName.textContent = `File uploaded: ${result.filename}`;
                            uploadedFileMessage.textContent = result.message;
                            uploadedFileInfo.style.display = 'block';
                            
                            // Show success state
                            if (uploadLabel) {
                                uploadLabel.textContent = 'File Uploaded Successfully!';
                                uploadLabel.style.background = 'linear-gradient(135deg, #00ff00, #00cc00)';
                            }
                            
                            // Reset after 3 seconds
                            setTimeout(() => {
                                if (uploadLabel) {
                                    uploadLabel.textContent = 'Choose SSP File';
                                    uploadLabel.style.background = 'linear-gradient(135deg, #00d4ff, #0099cc)';
                                }
                            }, 3000);
                        } else {
                            console.error('Text extraction failed:', result.ssp_text);
                            throw new Error('Unable to extract readable text from file. Please ensure it contains text content.');
                        }
                    } else {
                        console.error('Server returned error:', result.error);
                        throw new Error(result.error || 'Upload failed');
                    }
                } catch (error) {
                    console.error('Upload error:', error);
                    alert('Upload failed: ' + error.message);
                    
                    // Reset label on error
                    if (uploadLabel) {
                        uploadLabel.textContent = 'Choose SSP File';
                        uploadLabel.style.background = 'linear-gradient(135deg, #00d4ff, #0099cc)';
                    }
                }
            }

            // Function to reset file upload state and allow sample text again
            function resetFileUploadState() {
                fileUploaded = false;
                const uploadedFileInfo = document.getElementById('uploadedFileInfo');
                uploadedFileInfo.style.display = 'none';
            }

            // Tab switching functionality
            function switchTab(tabName) {
                console.log('switchTab called with:', tabName);
                
                // Remove active class from all tabs and content
                const tabButtons = document.querySelectorAll('.tab-button');
                const tabPanes = document.querySelectorAll('.tab-pane');
                
                console.log('Found tab buttons:', tabButtons.length);
                console.log('Found tab panes:', tabPanes.length);
                
                tabButtons.forEach(btn => btn.classList.remove('active'));
                tabPanes.forEach(pane => pane.classList.remove('active'));
                
                // Add active class to selected tab and content
                const selectedTab = document.getElementById(tabName + 'Tab');
                const selectedPane = document.getElementById(tabName + 'TabContent');
                
                console.log('Selected tab element:', selectedTab);
                console.log('Selected pane element:', selectedPane);
                
                if (selectedTab) selectedTab.classList.add('active');
                if (selectedPane) selectedPane.classList.add('active');
                
                console.log('Tab switching complete');
            }

            // Test function to verify tab content is working
            function testTabContent() {
                console.log('testTabContent called');
                switchTab('ai');
                
                const aiContent = document.getElementById('aiContent');
                console.log('AI content element in test:', aiContent);
                
                if (aiContent) {
                    aiContent.innerHTML = '<div style="color: #00ff00; text-align: center; padding: 20px; font-size: 18px;">Tab content is working! This is a test message.</div>';
                    console.log('Test content set successfully');
                } else {
                    console.error('AI content element not found!');
                }
            }

            // Update AI recommendations function to switch to AI tab
            async function getAIRecommendations() {
                console.log('=== AI RECOMMENDATIONS DEBUG START ===');
                console.log('getAIRecommendations called');
                
                if (!currentAnalysisData) {
                    console.error('No currentAnalysisData found');
                    alert('Please analyze your SSP first to get AI recommendations.');
                    return;
                }
                
                console.log('Current analysis data found:', currentAnalysisData);
                
                // Switch to AI tab
                console.log('Switching to AI tab...');
                switchTab('ai');
                console.log('Switched to AI tab');
                
                // Wait a moment for tab switch to complete
                await new Promise(resolve => setTimeout(resolve, 100));
                
                const aiContent = document.getElementById('aiContent');
                console.log('AI content element:', aiContent);
                
                if (!aiContent) {
                    console.error('AI content element not found!');
                    alert('Error: AI content element not found. Please refresh the page.');
                    return;
                }
                
                // Set loading content
                console.log('Setting loading content...');
                aiContent.innerHTML = '<div style="color: #00ff00; text-align: center; padding: 20px; font-size: 18px;">Loading AI recommendations...</div>';
                console.log('Set loading content');
                
                try {
                    const requestData = {
                        audit_results: currentAnalysisData.audit_results,
                        compliance_summary: currentAnalysisData.compliance_summary
                    };
                    
                    console.log('Sending request with data:', requestData);
                    
                    const response = await fetch('/ai-recommendations', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(requestData)
                    });
                    
                    console.log('Response status:', response.status);
                    const data = await response.json();
                    console.log('Response data:', data);
                    
                    if (data.success) {
                        console.log('Setting AI content, length:', data.recommendations.length);
                        console.log('Content preview:', data.recommendations.substring(0, 200) + '...');
                        
                        // Set the AI recommendations content
                        aiContent.innerHTML = data.recommendations;
                        
                        console.log('AI content set successfully');
                        
                        // Force a repaint to ensure visibility
                        aiContent.style.display = 'none';
                        aiContent.offsetHeight;
                        aiContent.style.display = 'block';
                        
                        console.log('Final AI content innerHTML length:', aiContent.innerHTML.length);
                    } else {
                        console.error('AI recommendations error:', data.error);
                        aiContent.innerHTML = '<div style="color: #ff6b6b; text-align: center; padding: 20px;">Error: ' + data.error + '</div>';
                    }
                } catch (error) {
                    console.error('AI recommendations fetch error:', error);
                    aiContent.innerHTML = '<div style="color: #ff6b6b; text-align: center; padding: 20px;">Error: ' + error.message + '</div>';
                }
                
                console.log('=== AI RECOMMENDATIONS DEBUG END ===');
            }

            // Simplified file upload functionality
            document.addEventListener('DOMContentLoaded', function() {
                console.log('DOM loaded, setting up simplified file upload...');
                const fileInput = document.getElementById('fileInput');
                const sspText = document.getElementById('sspText');

                if (!fileInput) {
                    console.error('fileInput not found!');
                    return;
                }

                console.log('File input found, adding change handler...');

                // Simple change handler for file input
                fileInput.addEventListener('change', function(e) {
                    console.log('File input changed, files:', e.target.files);
                    if (e.target.files.length > 0) {
                        console.log('Processing file:', e.target.files[0].name);
                        handleFileUpload(e);
                    }
                });

                // Listen for changes to SSP textarea to reset file upload state
                if (sspText) {
                    sspText.addEventListener('input', function() {
                        if (this.value.trim() === '') {
                            resetFileUploadState();
                        }
                    });
                }

                console.log('Simplified file upload setup complete');
            });

            async function analyzeSSP() {
                const sspText = document.getElementById('sspText').value;
                const framework = document.getElementById('frameworkSelect').value;
                const resultsDiv = document.getElementById('results');
                const loadingDiv = document.getElementById('loading');
                const aiBtn = document.getElementById('aiBtn');
                
                if (!sspText.trim()) {
                    alert('Please paste your SSP text first.');
                    return;
                }
                
                // Switch to compliance tab and show loading
                switchTab('compliance');
                loadingDiv.style.display = 'block';
                resultsDiv.innerHTML = '';
                aiBtn.disabled = true;
                
                try {
                    const response = await fetch('/analyze', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ 
                            ssp_text: sspText,
                            framework: framework
                        })
                    });
                    
                    const data = await response.json();
                    
                    if (data.success) {
                        currentAnalysisData = data;
                        displayResults(data);
                        aiBtn.disabled = false;
                    } else {
                        resultsDiv.innerHTML = '<div style="color: #ff6b6b; text-align: center; padding: 20px;">Error: ' + data.error + '</div>';
                    }
                } catch (error) {
                    resultsDiv.innerHTML = '<div style="color: #ff6b6b; text-align: center; padding: 20px;">Error: ' + error.message + '</div>';
                } finally {
                    loadingDiv.style.display = 'none';
                }
            }

            function displayResults(data) {
                const resultsDiv = document.getElementById('results');
                const summary = data.compliance_summary;
                
                let html = `
                    <div class="compliance-summary">
                        <div class="compliance-score">
                            <div class="score-circle ${getScoreClass(summary.compliance_percentage)}">
                                ${summary.compliance_percentage}%
                            </div>
                            <h3>Overall Compliance Score</h3>
                            <p>Confidence: ${summary.average_confidence}%</p>
                        </div>
                        
                        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; text-align: center;">
                            <div class="stat-item">
                                <div class="stat-number" style="color: #4ecdc4;">${summary.passed_controls}</div>
                                <div class="stat-label">Passed</div>
                            </div>
                            <div class="stat-item">
                                <div class="stat-number" style="color: #ffd93d;">${summary.partial_controls}</div>
                                <div class="stat-label">Partial</div>
                            </div>
                            <div class="stat-item">
                                <div class="stat-number" style="color: #ff6b6b;">${summary.failed_controls}</div>
                                <div class="stat-label">Failed</div>
                            </div>
                            <div class="stat-item">
                                <div class="stat-number" style="color: #00d4ff;">${summary.total_controls}</div>
                                <div class="stat-label">Total</div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="control-results">
                        <h3 style="margin-bottom: 20px; color: #00d4ff;">Control Analysis</h3>
                `;
                
                for (const [controlId, result] of Object.entries(data.audit_results)) {
                    const statusClass = result.status.toLowerCase();
                    html += `
                        <div class="control-item ${statusClass}" onclick="toggleControlDetails('${controlId}')" style="cursor: pointer;">
                            <div class="control-header">
                                <div class="control-title">${controlId}: ${result.control_title}</div>
                                <div class="control-status status-${statusClass}">${result.status}</div>
                            </div>
                            <div class="control-summary">
                                <strong>Confidence:</strong> ${result.confidence}% | 
                                <strong>SSP Score:</strong> ${result.evidence.requirement_score}% | 
                                <strong>AWS Score:</strong> ${result.evidence.aws_score}%
                            </div>
                            <div class="control-details" id="details-${controlId}" style="display: none;">
                    `;
                    
                    if (result.findings.length > 0) {
                        html += '<div class="findings-list"><strong>Findings:</strong><ul>';
                        result.findings.forEach(finding => html += '<li>' + finding + '</li>');
                        html += '</ul></div>';
                    }
                    
                    if (result.recommendations.length > 0) {
                        html += '<div class="recommendations-list"><strong>Recommendations:</strong><ul>';
                        result.recommendations.forEach(rec => html += '<li>' + rec + '</li>');
                        html += '</ul></div>';
                    }
                    
                    html += '</div></div>';
                }
                
                html += '</div>';
                resultsDiv.innerHTML = html;
            }

            function getScoreClass(percentage) {
                if (percentage >= 80) return 'score-pass';
                if (percentage >= 50) return 'score-partial';
                return 'score-fail';
            }

            function toggleControlDetails(controlId) {
                const detailsDiv = document.getElementById('details-' + controlId);
                const controlItem = detailsDiv.parentElement;
                
                if (detailsDiv.style.display === 'none') {
                    detailsDiv.style.display = 'block';
                    controlItem.classList.add('expanded');
                } else {
                    detailsDiv.style.display = 'none';
                    controlItem.classList.remove('expanded');
                }
            }
        </script>
    </body>
    </html>
    """
    return html

@app.route('/analyze', methods=['POST'])
def analyze():
    """Analyze SSP for compliance"""
    try:
        data = request.get_json()
        ssp_text = data.get('ssp_text', '')
        framework_name = data.get('framework', 'fedramp') # Default to FedRAMP
        
        if not ssp_text:
            return jsonify({'error': 'No SSP text provided'}), 400
        
        # Get framework data
        framework_data = FRAMEWORKS.get(framework_name)
        if not framework_data:
            return jsonify({'error': f'Framework "{framework_name}" not found'}), 400
        
        # Parse SSP
        controls = parse_ssp(ssp_text, framework_data['controls'])
        
        if not controls:
            return jsonify({'error': 'No controls found in SSP text'}), 400
        
        # Check compliance for each control
        audit_results = {}
        for control_id, control_info in controls.items():
            result = check_compliance(control_id, control_info['description'], get_aws_data(), framework_data['rules'])
            audit_results[control_id] = result
        
        # Calculate summary
        total_controls = len(audit_results)
        passed = sum(1 for r in audit_results.values() if r['status'] == 'PASS')
        failed = sum(1 for r in audit_results.values() if r['status'] == 'FAIL')
        partial = sum(1 for r in audit_results.values() if r['status'] == 'PARTIAL')
        
        compliance_percentage = (passed / total_controls * 100) if total_controls > 0 else 0
        average_confidence = sum(r['confidence'] for r in audit_results.values()) / total_controls if total_controls > 0 else 0
        
        compliance_summary = {
            'total_controls': total_controls,
            'passed_controls': passed,
            'failed_controls': failed,
            'partial_controls': partial,
            'compliance_percentage': round(compliance_percentage, 1),
            'average_confidence': round(average_confidence, 1)
        }
        
        return jsonify({
            'success': True,
            'audit_results': audit_results,
            'compliance_summary': compliance_summary
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/ai-recommendations', methods=['POST'])
def ai_recommendations():
    """Generate AI-powered compliance recommendations"""
    try:
        data = request.get_json()
        audit_results = data.get('audit_results', {})
        
        if not audit_results:
            return jsonify({'error': 'No audit results provided'}), 400
        
        # Analyze the audit results and generate recommendations
        recommendations = generate_ai_recommendations(audit_results)
        
        return jsonify({
            'success': True,
            'recommendations': recommendations
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def generate_ai_recommendations(audit_results):
    """Generate intelligent recommendations based on audit results using AI"""
    print(f"🔍 AI Recommendations Debug: Starting with {len(audit_results)} controls")
    
    try:
        # Check if API key is available
        if not AI_API_KEY:
            print("AI API key not found, using fallback")
            return generate_basic_recommendations(audit_results)
        
        print("OpenAI API key found in environment")
        
        # Prepare the audit data for AI analysis
        audit_summary = {
            'total_controls': len(audit_results),
            'failed_controls': [r for r in audit_results.values() if r.get('status') == 'FAIL'],
            'partial_controls': [r for r in audit_results.values() if r.get('status') == 'PARTIAL'],
            'passed_controls': [r for r in audit_results.values() if r.get('status') == 'PASS'],
            'compliance_rate': len([r for r in audit_results.values() if r.get('status') == 'PASS']) / len(audit_results) * 100 if audit_results else 0
        }
        
        print(f"Audit Summary: {audit_summary}")
        
        # Create a detailed prompt for AI analysis
        prompt = f"""
        As a cybersecurity compliance expert, analyze the following audit results and provide comprehensive recommendations:

        AUDIT SUMMARY:
        - Total Controls: {audit_summary['total_controls']}
        - Failed Controls: {len(audit_summary['failed_controls'])}
        - Partial Controls: {len(audit_summary['partial_controls'])}
        - Passed Controls: {len(audit_summary['passed_controls'])}
        - Compliance Rate: {audit_summary['compliance_rate']:.1f}%

        AUDIT RESULTS:
        {json.dumps(audit_results, indent=2)}

        Please provide:
        1. Executive Summary with compliance assessment
        2. Critical issues requiring immediate attention
        3. Medium priority issues to address
        4. Strategic recommendations for improvement
        5. Actionable next steps with timelines
        6. Best practices for maintaining compliance

        Format the response in HTML with proper styling, emojis, and clear sections.
        """

        print("Sending request to OpenAI API...")
        
        # Call AI API for enhanced recommendations
        headers = {
            'Authorization': f'Bearer {AI_API_KEY}',
            'Content-Type': 'application/json'
        }
        
        data = {
            'model': 'gpt-3.5-turbo',
            'messages': [
                {
                    'role': 'system',
                    'content': 'You are a cybersecurity compliance expert specializing in FedRAMP, NIST, and AWS security frameworks. Provide detailed, actionable recommendations with clear priorities and timelines.'
                },
                {
                    'role': 'user',
                    'content': prompt
                }
            ],
            'max_tokens': 2000,
            'temperature': 0.7
        }
        
        print(f"API Request Data: {json.dumps(data, indent=2)}")
        
        response = requests.post('https://api.openai.com/v1/chat/completions', headers=headers, json=data, timeout=30)
        
        print(f"API Response Status: {response.status_code}")
        print(f"API Response Headers: {dict(response.headers)}")
        
        if response.status_code == 200:
            ai_response = response.json()
            print(f"AI Response received: {ai_response}")
            recommendations = ai_response['choices'][0]['message']['content']
            print(f"Recommendations generated: {len(recommendations)} characters")
            return recommendations
        else:
            print(f"AI API call failed with status {response.status_code}")
            print(f"Error response: {response.text}")
            # Fallback to basic recommendations if AI call fails
            return generate_basic_recommendations(audit_results)
            
    except Exception as e:
        print(f"AI API call failed with exception: {e}")
        import traceback
        traceback.print_exc()
        # Fallback to basic recommendations
        return generate_basic_recommendations(audit_results)

def generate_basic_recommendations(audit_results):
    """Generate basic recommendations as fallback"""
    recommendations = []
    
    # Count issues by severity
    failed_controls = [r for r in audit_results.values() if r.get('status') == 'FAIL']
    partial_controls = [r for r in audit_results.values() if r.get('status') == 'PARTIAL']
    passed_controls = [r for r in audit_results.values() if r.get('status') == 'PASS']
    
    # Overall assessment
    total_controls = len(audit_results)
    compliance_rate = len(passed_controls) / total_controls * 100 if total_controls > 0 else 0
    
    recommendations.append("**AI-Powered Compliance Analysis**\n")
    recommendations.append(f"Based on analysis of {total_controls} controls, your overall compliance rate is {compliance_rate:.1f}%.\n")
    
    # Critical issues (FAIL controls)
    if failed_controls:
        recommendations.append("**CRITICAL ISSUES - Immediate Action Required:**\n")
        for control_id, control in audit_results.items():
            if control.get('status') == 'FAIL':
                title = control.get('control_title', 'Unknown Control')
                findings = control.get('findings', [])
                
                recommendations.append(f"• **{control_id} ({title})**:")
                if findings:
                    for finding in findings:
                        recommendations.append(f"  - {finding}")
                recommendations.append("")
    
    # Medium priority issues (PARTIAL controls)
    if partial_controls:
        recommendations.append("**MEDIUM PRIORITY - Address Soon:**\n")
        for control_id, control in audit_results.items():
            if control.get('status') == 'PARTIAL':
                title = control.get('control_title', 'Unknown Control')
                recommendations_list = control.get('recommendations', [])
                
                recommendations.append(f"• **{control_id} ({title})**:")
                if recommendations_list:
                    for rec in recommendations_list:
                        recommendations.append(f"  - {rec}")
                recommendations.append("")
    
    # Strategic recommendations
    recommendations.append("**STRATEGIC RECOMMENDATIONS:**\n")
    
    # MFA issues
    mfa_issues = [r for r in audit_results.values() if 'MFA' in str(r.get('findings', []))]
    if mfa_issues:
        recommendations.append("• **Multi-Factor Authentication**: Implement MFA for all users immediately. This is a critical security control that affects multiple compliance areas.")
    
    # Vulnerability issues
    vuln_issues = [r for r in audit_results.values() if 'vulnerability' in str(r.get('findings', [])).lower()]
    if vuln_issues:
        recommendations.append("• **Vulnerability Management**: Establish a formal vulnerability management program with regular scanning and remediation timelines.")
    
    # Encryption issues
    encryption_issues = [r for r in audit_results.values() if 'encryption' in str(r.get('findings', [])).lower()]
    if encryption_issues:
        recommendations.append("• **Data Encryption**: Ensure all data at rest and in transit is properly encrypted using AWS KMS or equivalent.")
    
    # Monitoring issues
    monitoring_issues = [r for r in audit_results.values() if 'monitor' in str(r.get('findings', [])).lower()]
    if monitoring_issues:
        recommendations.append("• **Security Monitoring**: Implement comprehensive security monitoring with GuardDuty, CloudTrail, and Security Hub.")
    
    # General recommendations
    if compliance_rate < 50:
        recommendations.append("• **Compliance Program**: Consider implementing a formal compliance management program with regular assessments.")
    elif compliance_rate < 80:
        recommendations.append("• **Continuous Improvement**: Focus on addressing partial controls to achieve higher compliance levels.")
    else:
        recommendations.append("• **Maintenance**: Excellent compliance posture! Focus on maintaining and monitoring existing controls.")
    
    # Next steps
    recommendations.append("\n**NEXT STEPS:**\n")
    recommendations.append("1. **Prioritize Critical Issues**: Address all FAIL controls immediately")
    recommendations.append("2. **Review Partial Controls**: Implement recommendations for PARTIAL controls")
    recommendations.append("3. **Document Remediation**: Keep records of all changes made")
    recommendations.append("4. **Schedule Follow-up**: Plan for regular compliance assessments")
    
    return "<br>".join(recommendations)

@app.route('/frameworks')
def get_frameworks():
    """Get available frameworks"""
    frameworks = {}
    for key, framework in FRAMEWORKS.items():
        frameworks[key] = {
            'name': framework['name'],
            'description': framework['description'],
            'control_count': len(framework['controls'])
        }
    return jsonify(frameworks)

@app.route('/upload', methods=['POST'])
def upload_file():
    """Upload SSP file"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            
            # Extract text from file
            ssp_text = extract_text_from_file(file_path)
            
            # Clean up the uploaded file
            os.remove(file_path)
            
            return jsonify({
                'success': True,
                'filename': filename,
                'ssp_text': ssp_text,
                'message': f'Successfully uploaded {filename}'
            })
        else:
            return jsonify({'error': 'Invalid file type. Allowed: txt, pdf, doc, docx, md'}), 400
            
    except Exception as e:
        return jsonify({'error': f'Upload failed: {str(e)}'}), 500

@app.route('/health')
def health():
    """Health check"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0'
    })

@app.route('/debug-extraction', methods=['POST'])
def debug_extraction():
    """Debug endpoint to test control extraction"""
    try:
        data = request.get_json()
        ssp_text = data.get('ssp_text', '')
        framework_name = data.get('framework', 'fedramp')
        
        if not ssp_text:
            return jsonify({'error': 'No SSP text provided'}), 400
        
        # Get framework data
        framework_data = FRAMEWORKS.get(framework_name)
        if not framework_data:
            return jsonify({'error': f'Framework "{framework_name}" not found'}), 400
        
        # Test each extraction strategy
        debug_results = {
            'ssp_text_length': len(ssp_text),
            'framework': framework_name,
            'extraction_results': {}
        }
        
        # Strategy 1: Direct pattern matching
        controls_direct = {}
        for control_id, pattern in framework_data['controls'].items():
            match = re.search(pattern, ssp_text, re.IGNORECASE | re.MULTILINE)
            if match:
                controls_direct[control_id] = {
                    'matched_text': ssp_text[match.start():match.end()],
                    'position': match.start()
                }
        debug_results['extraction_results']['direct_pattern'] = controls_direct
        
        # Strategy 2: Flexible control ID matching
        controls_flexible = extract_controls_by_id(ssp_text, framework_data['controls'])
        debug_results['extraction_results']['flexible_id'] = controls_flexible
        
        # Strategy 3: Semantic matching
        controls_semantic = extract_controls_by_semantics(ssp_text, framework_data['controls'])
        debug_results['extraction_results']['semantic'] = controls_semantic
        
        # Strategy 4: Keyword-based
        controls_keywords = extract_controls_by_keywords(ssp_text, framework_data['controls'])
        debug_results['extraction_results']['keywords'] = controls_keywords
        
        # Final result using the main parse_ssp function
        final_controls = parse_ssp(ssp_text, framework_data['controls'])
        debug_results['final_extracted_controls'] = final_controls
        
        return jsonify({
            'success': True,
            'debug_info': debug_results
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print("Starting proTecht Simple MVP...")
    print("Server will be available at http://localhost:5000")
    print("No authentication required!")
    app.run(host='0.0.0.0', port=5000, debug=True) 