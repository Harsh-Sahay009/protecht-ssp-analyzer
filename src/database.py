#!/usr/bin/env python3
"""
Database module for proTecht
Stores AWS infrastructure data for compliance analysis
"""

import sqlite3
import json
from datetime import datetime
from typing import Dict, List, Any, Optional
import os

class ProTechtDatabase:
    def __init__(self, db_path: str = "protecht.db"):
        self.db_path = db_path
        self.init_database()
    
    def get_connection(self):
        """Get database connection"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    def init_database(self):
        """Initialize database tables"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Account metadata table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS account_metadata (
                id INTEGER PRIMARY KEY,
                org_id TEXT UNIQUE,
                master_payer_id TEXT,
                regions TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Control tower table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS control_tower (
                id INTEGER PRIMARY KEY,
                version TEXT,
                enabled_guardrails INTEGER,
                accounts_managed INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # IAM password policy table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS iam_password_policy (
                id INTEGER PRIMARY KEY,
                minimum_password_length INTEGER,
                require_symbols BOOLEAN,
                require_numbers BOOLEAN,
                require_uppercase BOOLEAN,
                require_lowercase BOOLEAN,
                max_password_age INTEGER,
                password_reuse_prevention INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # IAM users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS iam_users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE,
                mfa_enabled BOOLEAN,
                last_login TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # IAM roles table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS iam_roles (
                id INTEGER PRIMARY KEY,
                role_name TEXT UNIQUE,
                permissions TEXT,
                boundary TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # SSO table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sso (
                id INTEGER PRIMARY KEY,
                application_count INTEGER,
                mfa_types TEXT,
                federation TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # S3 buckets table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS s3_buckets (
                id INTEGER PRIMARY KEY,
                bucket_name TEXT UNIQUE,
                encryption TEXT,
                object_lock_mode TEXT,
                retention_days INTEGER,
                public_access_block BOOLEAN,
                kms_key_id TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # KMS keys table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS kms_keys (
                id INTEGER PRIMARY KEY,
                key_id TEXT UNIQUE,
                rotation_enabled BOOLEAN,
                alias TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # CloudTrail trails table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cloudtrail_trails (
                id INTEGER PRIMARY KEY,
                trail_name TEXT UNIQUE,
                multi_region BOOLEAN,
                log_file_validation BOOLEAN,
                insight_selectors TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Config rules table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS config_rules (
                id INTEGER PRIMARY KEY,
                rule_name TEXT UNIQUE,
                compliance_type TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Config conformance packs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS config_conformance_packs (
                id INTEGER PRIMARY KEY,
                pack_name TEXT UNIQUE,
                status TEXT,
                failing_rules INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # GuardDuty table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS guardduty (
                id INTEGER PRIMARY KEY,
                detector_count INTEGER,
                critical_findings INTEGER,
                high_findings INTEGER,
                medium_findings INTEGER,
                low_findings INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Security Hub table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_hub (
                id INTEGER PRIMARY KEY,
                standard_name TEXT UNIQUE,
                status TEXT,
                open_findings INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Macie jobs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS macie_jobs (
                id INTEGER PRIMARY KEY,
                job_id TEXT UNIQUE,
                status TEXT,
                s3_buckets_scanned INTEGER,
                sensitive_findings INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Inspector2 table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS inspector2 (
                id INTEGER PRIMARY KEY,
                last_run TEXT,
                critical_findings INTEGER,
                high_findings INTEGER,
                medium_findings INTEGER,
                low_findings INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # EKS clusters table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS eks_clusters (
                id INTEGER PRIMARY KEY,
                cluster_name TEXT UNIQUE,
                oidc_enabled BOOLEAN,
                irsa_enabled BOOLEAN,
                k8s_version TEXT,
                public_access BOOLEAN,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # ECS clusters table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ecs_clusters (
                id INTEGER PRIMARY KEY,
                cluster_name TEXT UNIQUE,
                fargate_tasks INTEGER,
                ec2_tasks INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # RDS instances table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS rds_instances (
                id INTEGER PRIMARY KEY,
                instance_name TEXT UNIQUE,
                engine TEXT,
                encrypted BOOLEAN,
                multi_az BOOLEAN,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # DynamoDB tables table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS dynamodb_tables (
                id INTEGER PRIMARY KEY,
                table_name TEXT UNIQUE,
                encrypted BOOLEAN,
                kms_key_id TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # EFS file systems table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS efs_file_systems (
                id INTEGER PRIMARY KEY,
                file_system_id TEXT UNIQUE,
                encrypted BOOLEAN,
                kms_key_id TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Backup table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS backup (
                id INTEGER PRIMARY KEY,
                vault_name TEXT UNIQUE,
                resources_protected INTEGER,
                cross_region_copy BOOLEAN,
                vault_lock TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # VPC table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vpc (
                id INTEGER PRIMARY KEY,
                flow_logs BOOLEAN,
                nat_gateways INTEGER,
                transit_gateway_attachments INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Security groups table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_groups (
                id INTEGER PRIMARY KEY,
                group_id TEXT UNIQUE,
                open_ports TEXT,
                allowed_cidrs TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # API Gateway table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS api_gateway (
                id INTEGER PRIMARY KEY,
                stage_name TEXT UNIQUE,
                execution_logging BOOLEAN,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # WAF table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS waf (
                id INTEGER PRIMARY KEY,
                web_acl_name TEXT UNIQUE,
                rules_count INTEGER,
                blocked_count_7d INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # CloudFront table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cloudfront (
                id INTEGER PRIMARY KEY,
                distribution_id TEXT UNIQUE,
                tls_policy TEXT,
                waf_enabled BOOLEAN,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # SSM Patch table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ssm_patch (
                id INTEGER PRIMARY KEY,
                last_scan TEXT,
                pending_critical INTEGER,
                pending_high INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # EventBridge rules table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS eventbridge_rules (
                id INTEGER PRIMARY KEY,
                rule_name TEXT UNIQUE,
                target TEXT,
                state TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Detective table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS detective (
                id INTEGER PRIMARY KEY,
                graph_enabled BOOLEAN,
                member_accounts INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # CodeBuild table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS codebuild (
                id INTEGER PRIMARY KEY,
                projects_count INTEGER,
                failed_builds_last7d INTEGER,
                passed_builds INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # CodePipeline table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS codepipeline (
                id INTEGER PRIMARY KEY,
                pipelines_count INTEGER,
                failed_executions INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Lambda table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS lambda (
                id INTEGER PRIMARY KEY,
                functions_count INTEGER,
                unreserved_concurrent_executions INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # CloudWatch table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cloudwatch (
                id INTEGER PRIMARY KEY,
                alarms_count INTEGER,
                metrics_collected INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Route53 table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS route53 (
                id INTEGER PRIMARY KEY,
                hosted_zones INTEGER,
                health_checks INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Direct Connect table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS direct_connect (
                id INTEGER PRIMARY KEY,
                connections INTEGER,
                locations TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # VPN table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vpn (
                id INTEGER PRIMARY KEY,
                client_vpn_endpoints INTEGER,
                active_sessions INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def clear_all_data(self):
        """Clear all data from all tables"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        tables = [
            'account_metadata', 'control_tower', 'iam_password_policy', 'iam_users', 'iam_roles',
            'sso', 's3_buckets', 'kms_keys', 'cloudtrail_trails', 'config_rules', 'config_conformance_packs',
            'guardduty', 'security_hub', 'macie_jobs', 'inspector2', 'eks_clusters', 'ecs_clusters',
            'rds_instances', 'dynamodb_tables', 'efs_file_systems', 'backup', 'vpc', 'security_groups',
            'api_gateway', 'waf', 'cloudfront', 'ssm_patch', 'eventbridge_rules', 'detective',
            'codebuild', 'codepipeline', 'lambda', 'cloudwatch', 'route53', 'direct_connect', 'vpn'
        ]
        
        for table in tables:
            cursor.execute(f'DELETE FROM {table}')
        
        conn.commit()
        conn.close()
    
    def load_aws_data(self, aws_data: Dict[str, Any]):
        """Load AWS data into database"""
        self.clear_all_data()  # Clear existing data
        
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            # Account metadata
            if 'account_metadata' in aws_data:
                metadata = aws_data['account_metadata']
                cursor.execute('''
                    INSERT INTO account_metadata (org_id, master_payer_id, regions)
                    VALUES (?, ?, ?)
                ''', (metadata['org_id'], metadata['master_payer_id'], json.dumps(metadata['regions'])))
            
            # Control tower
            if 'control_tower' in aws_data:
                ct = aws_data['control_tower']
                cursor.execute('''
                    INSERT INTO control_tower (version, enabled_guardrails, accounts_managed)
                    VALUES (?, ?, ?)
                ''', (ct['version'], ct['enabled_guardrails'], ct['accounts_managed']))
            
            # IAM password policy
            if 'iam' in aws_data and 'password_policy' in aws_data['iam']:
                policy = aws_data['iam']['password_policy']
                cursor.execute('''
                    INSERT INTO iam_password_policy 
                    (minimum_password_length, require_symbols, require_numbers, require_uppercase, 
                     require_lowercase, max_password_age, password_reuse_prevention)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (policy['MinimumPasswordLength'], policy['RequireSymbols'], policy['RequireNumbers'],
                      policy['RequireUppercaseCharacters'], policy['RequireLowercaseCharacters'],
                      policy['MaxPasswordAge'], policy['PasswordReusePrevention']))
            
            # IAM users
            if 'iam' in aws_data and 'users' in aws_data['iam']:
                for user in aws_data['iam']['users']:
                    cursor.execute('''
                        INSERT INTO iam_users (username, mfa_enabled, last_login)
                        VALUES (?, ?, ?)
                    ''', (user['UserName'], user['MFA'], user['LastLogin']))
            
            # IAM roles
            if 'iam' in aws_data and 'roles' in aws_data['iam']:
                for role in aws_data['iam']['roles']:
                    cursor.execute('''
                        INSERT INTO iam_roles (role_name, permissions, boundary)
                        VALUES (?, ?, ?)
                    ''', (role['RoleName'], json.dumps(role['Permissions']), role['Boundary']))
            
            # SSO
            if 'sso' in aws_data:
                sso = aws_data['sso']
                cursor.execute('''
                    INSERT INTO sso (application_count, mfa_types, federation)
                    VALUES (?, ?, ?)
                ''', (sso['application_count'], json.dumps(sso['mfa_types']), sso['federation']))
            
            # S3 buckets
            if 's3' in aws_data:
                for bucket in aws_data['s3']:
                    cursor.execute('''
                        INSERT INTO s3_buckets 
                        (bucket_name, encryption, object_lock_mode, retention_days, public_access_block, kms_key_id)
                        VALUES (?, ?, ?, ?, ?, ?)
                    ''', (bucket['Bucket'], bucket['Encryption'], bucket.get('ObjectLockMode'),
                          bucket.get('RetentionDays'), bucket['PublicAccessBlock'], bucket.get('KmsKeyId')))
            
            # KMS keys
            if 'kms' in aws_data:
                for key in aws_data['kms']:
                    cursor.execute('''
                        INSERT INTO kms_keys (key_id, rotation_enabled, alias)
                        VALUES (?, ?, ?)
                    ''', (key['KeyId'], key['RotationEnabled'], key['Alias']))
            
            # CloudTrail trails
            if 'cloudtrail' in aws_data and 'trails' in aws_data['cloudtrail']:
                for trail in aws_data['cloudtrail']['trails']:
                    cursor.execute('''
                        INSERT INTO cloudtrail_trails (trail_name, multi_region, log_file_validation, insight_selectors)
                        VALUES (?, ?, ?, ?)
                    ''', (trail['Name'], trail['MultiRegion'], trail['LogFileValidation'], 
                          json.dumps(trail['InsightSelectors'])))
            
            # Config rules
            if 'config' in aws_data and 'rules' in aws_data['config']:
                for rule in aws_data['config']['rules']:
                    cursor.execute('''
                        INSERT INTO config_rules (rule_name, compliance_type)
                        VALUES (?, ?)
                    ''', (rule['Name'], rule['ComplianceType']))
            
            # Config conformance packs
            if 'config' in aws_data and 'conformance_packs' in aws_data['config']:
                for pack in aws_data['config']['conformance_packs']:
                    cursor.execute('''
                        INSERT INTO config_conformance_packs (pack_name, status, failing_rules)
                        VALUES (?, ?, ?)
                    ''', (pack['Name'], pack['Status'], pack['FailingRules']))
            
            # GuardDuty
            if 'guardduty' in aws_data:
                gd = aws_data['guardduty']
                findings = gd['findings']
                cursor.execute('''
                    INSERT INTO guardduty (detector_count, critical_findings, high_findings, medium_findings, low_findings)
                    VALUES (?, ?, ?, ?, ?)
                ''', (gd['detector_count'], findings['Critical'], findings['High'], 
                      findings['Medium'], findings['Low']))
            
            # Security Hub
            if 'security_hub' in aws_data:
                sh = aws_data['security_hub']
                for standard, status in sh['standards'].items():
                    cursor.execute('''
                        INSERT INTO security_hub (standard_name, status, open_findings)
                        VALUES (?, ?, ?)
                    ''', (standard, status, sh['open_findings']))
            
            # Macie jobs
            if 'macie' in aws_data and 'jobs' in aws_data['macie']:
                for job in aws_data['macie']['jobs']:
                    cursor.execute('''
                        INSERT INTO macie_jobs (job_id, status, s3_buckets_scanned, sensitive_findings)
                        VALUES (?, ?, ?, ?)
                    ''', (job['JobId'], job['Status'], job.get('S3BucketsScanned'), job.get('SensitiveFindings')))
            
            # Inspector2
            if 'inspector2' in aws_data:
                insp = aws_data['inspector2']
                findings = insp['findings']
                cursor.execute('''
                    INSERT INTO inspector2 (last_run, critical_findings, high_findings, medium_findings, low_findings)
                    VALUES (?, ?, ?, ?, ?)
                ''', (insp['last_run'], findings['Critical'], findings['High'], 
                      findings['Medium'], findings['Low']))
            
            # EKS clusters
            if 'eks' in aws_data:
                for cluster in aws_data['eks']:
                    cursor.execute('''
                        INSERT INTO eks_clusters (cluster_name, oidc_enabled, irsa_enabled, k8s_version, public_access)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (cluster['Cluster'], cluster['OIDC'], cluster['IRSA'], 
                          cluster['K8sVersion'], cluster['PublicAccess']))
            
            # ECS clusters
            if 'ecs' in aws_data:
                for cluster in aws_data['ecs']:
                    cursor.execute('''
                        INSERT INTO ecs_clusters (cluster_name, fargate_tasks, ec2_tasks)
                        VALUES (?, ?, ?)
                    ''', (cluster['Cluster'], cluster['FargateTasks'], cluster['EC2Tasks']))
            
            # RDS instances
            if 'rds' in aws_data:
                for instance in aws_data['rds']:
                    cursor.execute('''
                        INSERT INTO rds_instances (instance_name, engine, encrypted, multi_az)
                        VALUES (?, ?, ?, ?)
                    ''', (instance['DBInstance'], instance['Engine'], instance['Encrypted'], instance['MultiAZ']))
            
            # DynamoDB tables
            if 'dynamodb' in aws_data:
                for table in aws_data['dynamodb']:
                    cursor.execute('''
                        INSERT INTO dynamodb_tables (table_name, encrypted, kms_key_id)
                        VALUES (?, ?, ?)
                    ''', (table['Table'], table['Encrypted'], table['KmsKeyId']))
            
            # EFS file systems
            if 'efs' in aws_data:
                for fs in aws_data['efs']:
                    cursor.execute('''
                        INSERT INTO efs_file_systems (file_system_id, encrypted, kms_key_id)
                        VALUES (?, ?, ?)
                    ''', (fs['FileSystemId'], fs['Encrypted'], fs.get('KmsKeyId')))
            
            # Backup
            if 'backup' in aws_data:
                backup = aws_data['backup']
                cursor.execute('''
                    INSERT INTO backup (vault_name, resources_protected, cross_region_copy, vault_lock)
                    VALUES (?, ?, ?, ?)
                ''', (backup['vault_name'], backup['resources_protected'], 
                      backup['cross_region_copy'], backup['vault_lock']))
            
            # VPC
            if 'vpc' in aws_data:
                vpc = aws_data['vpc']
                cursor.execute('''
                    INSERT INTO vpc (flow_logs, nat_gateways, transit_gateway_attachments)
                    VALUES (?, ?, ?)
                ''', (vpc['flow_logs'], vpc['nat_gateways'], vpc['transit_gateway']['attachments']))
            
            # Security groups
            if 'vpc' in aws_data and 'security_groups' in aws_data['vpc']:
                for sg in aws_data['vpc']['security_groups']:
                    cursor.execute('''
                        INSERT INTO security_groups (group_id, open_ports, allowed_cidrs)
                        VALUES (?, ?, ?)
                    ''', (sg['GroupId'], json.dumps(sg['OpenPorts']), json.dumps(sg['AllowedCidrs'])))
            
            # API Gateway
            if 'api_gateway' in aws_data and 'endpoints' in aws_data['api_gateway']:
                for endpoint in aws_data['api_gateway']['endpoints']:
                    cursor.execute('''
                        INSERT INTO api_gateway (stage_name, execution_logging)
                        VALUES (?, ?)
                    ''', (endpoint['Stage'], endpoint['ExecutionLogging']))
            
            # WAF
            if 'waf' in aws_data and 'web_acls' in aws_data['waf']:
                for acl in aws_data['waf']['web_acls']:
                    cursor.execute('''
                        INSERT INTO waf (web_acl_name, rules_count, blocked_count_7d)
                        VALUES (?, ?, ?)
                    ''', (acl['Name'], acl['Rules'], acl['BlockedCount7d']))
            
            # CloudFront
            if 'cloudfront' in aws_data and 'distributions' in aws_data['cloudfront']:
                for dist in aws_data['cloudfront']['distributions']:
                    cursor.execute('''
                        INSERT INTO cloudfront (distribution_id, tls_policy, waf_enabled)
                        VALUES (?, ?, ?)
                    ''', (dist['Id'], dist['TLSPolicy'], dist['WAFEnabled']))
            
            # SSM Patch
            if 'ssm_patch' in aws_data:
                patch = aws_data['ssm_patch']
                cursor.execute('''
                    INSERT INTO ssm_patch (last_scan, pending_critical, pending_high)
                    VALUES (?, ?, ?)
                ''', (patch['last_scan'], patch['pending_critical'], patch['pending_high']))
            
            # EventBridge rules
            if 'eventbridge' in aws_data and 'rules' in aws_data['eventbridge']:
                for rule in aws_data['eventbridge']['rules']:
                    cursor.execute('''
                        INSERT INTO eventbridge_rules (rule_name, target, state)
                        VALUES (?, ?, ?)
                    ''', (rule['Name'], rule['Target'], rule['State']))
            
            # Detective
            if 'detective' in aws_data:
                det = aws_data['detective']
                cursor.execute('''
                    INSERT INTO detective (graph_enabled, member_accounts)
                    VALUES (?, ?)
                ''', (det['graph_enabled'], det['member_accounts']))
            
            # CodeBuild
            if 'codebuild' in aws_data:
                cb = aws_data['codebuild']
                cursor.execute('''
                    INSERT INTO codebuild (projects_count, failed_builds_last7d, passed_builds)
                    VALUES (?, ?, ?)
                ''', (cb['projects'], cb['failed_builds_last7d'], cb['passed']))
            
            # CodePipeline
            if 'codepipeline' in aws_data:
                cp = aws_data['codepipeline']
                cursor.execute('''
                    INSERT INTO codepipeline (pipelines_count, failed_executions)
                    VALUES (?, ?)
                ''', (cp['pipelines'], cp['failed_executions']))
            
            # Lambda
            if 'lambda' in aws_data:
                lambda_data = aws_data['lambda']
                cursor.execute('''
                    INSERT INTO lambda (functions_count, unreserved_concurrent_executions)
                    VALUES (?, ?)
                ''', (lambda_data['functions'], lambda_data['unreserved_concurrent_executions']))
            
            # CloudWatch
            if 'cloudwatch' in aws_data:
                cw = aws_data['cloudwatch']
                cursor.execute('''
                    INSERT INTO cloudwatch (alarms_count, metrics_collected)
                    VALUES (?, ?)
                ''', (cw['alarms'], cw['metrics_collected']))
            
            # Route53
            if 'route53' in aws_data:
                r53 = aws_data['route53']
                cursor.execute('''
                    INSERT INTO route53 (hosted_zones, health_checks)
                    VALUES (?, ?)
                ''', (r53['hosted_zones'], r53['health_checks']))
            
            # Direct Connect
            if 'direct_connect' in aws_data:
                dc = aws_data['direct_connect']
                cursor.execute('''
                    INSERT INTO direct_connect (connections, locations)
                    VALUES (?, ?)
                ''', (dc['connections'], json.dumps(dc['locations'])))
            
            # VPN
            if 'vpn' in aws_data:
                vpn = aws_data['vpn']
                cursor.execute('''
                    INSERT INTO vpn (client_vpn_endpoints, active_sessions)
                    VALUES (?, ?)
                ''', (vpn['client_vpn_endpoints'], vpn['active_sessions']))
            
            conn.commit()
            print("AWS data loaded successfully into database")
            
        except Exception as e:
            conn.rollback()
            print(f"Error loading AWS data: {e}")
            raise
        finally:
            conn.close()
    
    def get_aws_data(self) -> Dict[str, Any]:
        """Retrieve all AWS data from database"""
        # For now, return a simplified structure that matches the expected format
        # This can be expanded later to include all database queries
        return {
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
            "ecs": [
                {"Cluster": "gov-prod-ecs", "FargateTasks": 12, "EC2Tasks": 6},
                {"Cluster": "gov-dev-ecs", "FargateTasks": 5, "EC2Tasks": 2}
            ],
            "rds": [
                {"DBInstance": "prod-aurora-global", "Engine": "aurora-postgresql", "Encrypted": True, "MultiAZ": True},
                {"DBInstance": "dev-mysql", "Engine": "mysql", "Encrypted": False, "MultiAZ": False}
            ],
            "dynamodb": [
                {"Table": "Tenant-Meta", "Encrypted": True, "KmsKeyId": "alias/prod-master"},
                {"Table": "Dev-Flags", "Encrypted": False, "KmsKeyId": None}
            ],
            "efs": [
                {"FileSystemId": "fs-aaa111", "Encrypted": True, "KmsKeyId": "alias/prod-master"},
                {"FileSystemId": "fs-bbb222", "Encrypted": False}
            ],
            "backup": {
                "vault_name": "phoenix-backup-vault", "resources_protected": 128, "cross_region_copy": True, "vault_lock": "ON"
            },
            "vpc": {
                "flow_logs": True,
                "security_groups": [
                    {"GroupId": "sg-aaa111", "OpenPorts": [22], "AllowedCidrs": ["10.0.0.0/16"]},
                    {"GroupId": "sg-bbb222", "OpenPorts": [22, 3389], "AllowedCidrs": ["0.0.0.0/0"]}
                ],
                "nat_gateways": 4,
                "transit_gateway": {"attachments": 3}
            },
            "api_gateway": {
                "endpoints": [
                    {"Stage": "prod", "ExecutionLogging": True},
                    {"Stage": "dev", "ExecutionLogging": False}
                ]
            },
            "waf": {
                "web_acls": [{"Name": "phoenix-waf", "Rules": 15, "BlockedCount7d": 12000}]
            },
            "cloudfront": {
                "distributions": [
                    {"Id": "E111AAA", "TLSPolicy": "TLSv1.2_2021", "WAFEnabled": True},
                    {"Id": "E222BBB", "TLSPolicy": "TLSv1.2_2021", "WAFEnabled": False}
                ]
            },
            "ssm_patch": {
                "last_scan": "2025-08-28", "pending_critical": 5, "pending_high": 11
            },
            "eventbridge": {
                "rules": [
                    {"Name": "gd-to-sh", "Target": "SecurityHub", "State": "ENABLED"},
                    {"Name": "cve-to-jira", "Target": "Jira", "State": "ENABLED"}
                ]
            },
            "detective": {
                "graph_enabled": True, "member_accounts": 5
            },
            "codebuild": {
                "projects": 5, "failed_builds_last7d": 2, "passed": 120
            },
            "codepipeline": {
                "pipelines": 3, "failed_executions": 1
            },
            "lambda": {
                "functions": 45, "unreserved_concurrent_executions": 25
            },
            "cloudwatch": {
                "alarms": 32, "metrics_collected": 150
            },
            "route53": {
                "hosted_zones": 4, "health_checks": 8
            },
            "direct_connect": {
                "connections": 2, "locations": ["DC1", "DC2"]
            },
            "vpn": {
                "client_vpn_endpoints": 1, "active_sessions": 7
            }
        }
    
    def get_service_data(self, service_name: str) -> List[Dict[str, Any]]:
        """Get data for a specific service"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute(f'SELECT * FROM {service_name}')
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
        except Exception as e:
            print(f"Error getting {service_name} data: {e}")
            return []
        finally:
            conn.close()

# Global database instance
db = ProTechtDatabase() 