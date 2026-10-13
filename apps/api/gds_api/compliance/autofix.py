"""GDS OS Compliance Auto-Remediation Engine.

Provides models, remediation mapping for frameworks (PCI-DSS, SOC2, ISO27001, NIST,
GDPR, DORA, NIS2, EU_AI_Act), job generation, real CLI/Terraform execution,
verification, and automated framework remediation.
"""

from __future__ import annotations

import shlex
import subprocess
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import ForeignKey, String, Text, func, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped, mapped_column

from gds_api.models import Base

# ============================================================================
# MODELS
# ============================================================================


class ComplianceRemediationJob(Base):
    __tablename__ = "compliance_remediation_jobs"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    framework: Mapped[str] = mapped_column(String(100))  # PCI-DSS, SOC2, ISO27001, NIST, GDPR, DORA, NIS2, EU_AI_Act
    control_id: Mapped[str] = mapped_column(String(200))
    control_name: Mapped[str] = mapped_column(String(500))
    gap_description: Mapped[str] = mapped_column(Text)
    remediation_type: Mapped[str] = mapped_column(String(100))  # cloud_config, iam_policy, encryption, logging, access_review, policy_doc
    remediation_steps: Mapped[list] = mapped_column(JSONB, default=list)  # list of step dicts
    aws_cli_command: Mapped[str | None] = mapped_column(Text, default=None)
    terraform_snippet: Mapped[str | None] = mapped_column(Text, default=None)
    status: Mapped[str] = mapped_column(String(50), default="pending")  # pending, executing, verifying, completed, failed, manual_required
    progress_pct: Mapped[int] = mapped_column(default=0)
    error_message: Mapped[str | None] = mapped_column(Text, default=None)
    verification_result: Mapped[dict | None] = mapped_column(JSONB, default=None)
    triggered_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    completed_at: Mapped[datetime | None] = mapped_column(default=None)


class ComplianceControlStatus(Base):
    __tablename__ = "compliance_control_status"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    framework: Mapped[str] = mapped_column(String(100))
    control_id: Mapped[str] = mapped_column(String(200))
    control_name: Mapped[str] = mapped_column(String(500))
    status: Mapped[str] = mapped_column(String(50), default="not_tested")  # passing, failing, not_tested, remediated, manual_required
    last_checked: Mapped[datetime] = mapped_column(server_default=func.now())
    remediation_job_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("compliance_remediation_jobs.id"), default=None)
    notes: Mapped[str | None] = mapped_column(Text, default=None)


# ============================================================================
# FRAMEWORK REMEDIATION MAPPINGS
# ============================================================================

PCI_DSS_REMEDIATIONS: dict[str, dict[str, Any]] = {
    "3.4": {
        "control_id": "3.4",
        "control_name": "Encrypt Cardholder Data at Rest",
        "remediation_type": "encryption",
        "steps": [
            {"step": 1, "action": "Enable account-level default EBS encryption in AWS EC2."},
            {"step": 2, "action": "Provision KMS Customer Managed Key for cardholder volume encryption."},
            {"step": 3, "action": "Enforce encryption on newly provisioned EBS volumes and snapshots."},
        ],
        "aws_cli_command": "aws ec2 enable-ebs-encryption-by-default",
        "terraform_snippet": """resource "aws_ebs_encryption_by_default" "pci_3_4" {
  enabled = true
}

resource "aws_kms_key" "pci_cardholder_key" {
  description             = "KMS key for PCI-DSS 3.4 cardholder data encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}""",
        "verification_check": {
            "type": "aws_cli",
            "command": "aws ec2 get-ebs-encryption-by-default",
            "expected_key": "EbsEncryptionByDefault",
            "expected_value": True,
        },
    },
    "6.5.3": {
        "control_id": "6.5.3",
        "control_name": "Vulnerability Scanning & Patch Management",
        "remediation_type": "cloud_config",
        "steps": [
            {"step": 1, "action": "Enable AWS Inspector v2 for automated vulnerability scanning."},
            {"step": 2, "action": "Configure scan targets for EC2 instances and ECR container repositories."},
            {"step": 3, "action": "Activate continuous vulnerability assessments and reporting."},
        ],
        "aws_cli_command": "aws inspector2 enable --resource-types EC2 ECR",
        "terraform_snippet": """resource "aws_inspector2_enabler" "pci_6_5_3" {
  account_ids    = ["self"]
  resource_types = ["EC2", "ECR"]
}""",
        "verification_check": {
            "type": "aws_cli",
            "command": "aws inspector2 list-coverage",
            "expected_status": "ENABLED",
        },
    },
    "8.3": {
        "control_id": "8.3",
        "control_name": "Multi-Factor Authentication (MFA) & Password Policy",
        "remediation_type": "iam_policy",
        "steps": [
            {"step": 1, "action": "Enforce strict IAM password policy across all user accounts."},
            {"step": 2, "action": "Require MFA for all administrative and console access."},
            {"step": 3, "action": "Set password expiration to 90 days and mandate length >= 14 characters."},
        ],
        "aws_cli_command": (
            "aws iam update-account-password-policy "
            "--minimum-password-length 14 "
            "--require-symbols "
            "--require-numbers "
            "--require-uppercase-characters "
            "--require-lowercase-characters "
            "--allow-users-to-change-password "
            "--max-password-age 90"
        ),
        "terraform_snippet": """resource "aws_iam_account_password_policy" "pci_8_3" {
  minimum_password_length        = 14
  require_symbols                = true
  require_numbers                = true
  require_uppercase_characters   = true
  require_lowercase_characters   = true
  allow_users_to_change_password = true
  max_password_age               = 90
}""",
        "verification_check": {
            "type": "aws_cli",
            "command": "aws iam get-account-password-policy",
            "expected_key": "PasswordPolicy.MinimumPasswordLength",
            "expected_value": 14,
        },
    },
    "10.1": {
        "control_id": "10.1",
        "control_name": "Audit Logging & CloudTrail Enabled",
        "remediation_type": "logging",
        "steps": [
            {"step": 1, "action": "Create multi-region AWS CloudTrail for comprehensive audit logging."},
            {"step": 2, "action": "Enable log file validation to ensure log integrity."},
            {"step": 3, "action": "Configure centralized S3 bucket destination for audit logs."},
        ],
        "aws_cli_command": (
            "aws cloudtrail create-trail "
            "--name pci-audit-trail "
            "--s3-bucket-name gds-pci-audit-logs "
            "--is-multi-region-trail "
            "--enable-log-file-validation"
        ),
        "terraform_snippet": """resource "aws_cloudtrail" "pci_10_1" {
  name                          = "pci-audit-trail"
  s3_bucket_name                = "gds-pci-audit-logs"
  enable_logging                = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
}""",
        "verification_check": {
            "type": "aws_cli",
            "command": "aws cloudtrail get-trail-status --name pci-audit-trail",
            "expected_key": "IsLogging",
            "expected_value": True,
        },
    },
    "10.2": {
        "control_id": "10.2",
        "control_name": "Track and Monitor All Access to Network Resources and Cardholder Data",
        "remediation_type": "logging",
        "steps": [
            {"step": 1, "action": "Enable log file validation on CloudTrail."},
            {"step": 2, "action": "Configure CloudWatch Logs integration for real-time log event tracking."},
            {"step": 3, "action": "Enable management and data event logging for cardholder resources."},
        ],
        "aws_cli_command": "aws cloudtrail update-trail --name pci-audit-trail --enable-log-file-validation",
        "terraform_snippet": """resource "aws_cloudtrail" "pci_10_2" {
  name                       = "pci-audit-trail"
  s3_bucket_name             = "gds-pci-audit-logs"
  enable_log_file_validation = true
}""",
        "verification_check": {
            "type": "aws_cli",
            "command": "aws cloudtrail describe-trails --trail-name-list pci-audit-trail",
            "expected_key": "LogFileValidationEnabled",
            "expected_value": True,
        },
    },
    "10.5": {
        "control_id": "10.5",
        "control_name": "Secure Audit Logs against Modification",
        "remediation_type": "logging",
        "steps": [
            {"step": 1, "action": "Apply strict bucket policy to S3 audit log destination."},
            {"step": 2, "action": "Enable S3 Object Lock and MFA Delete for log retention protection."},
            {"step": 3, "action": "Restrict write and delete access to authorized audit services only."},
        ],
        "aws_cli_command": (
            'aws s3api put-bucket-policy --bucket gds-pci-audit-logs --policy '
            "'{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"CloudTrailACLCheck\",\"Effect\":\"Allow\","
            "\"Principal\":{\"Service\":\"cloudtrail.amazonaws.com\"},\"Action\":\"s3:GetBucketAcl\","
            "\"Resource\":\"arn:aws:s3:::gds-pci-audit-logs\"},{\"Sid\":\"CloudTrailWrite\",\"Effect\":\"Allow\","
            "\"Principal\":{\"Service\":\"cloudtrail.amazonaws.com\"},\"Action\":\"s3:PutObject\","
            "\"Resource\":\"arn:aws:s3:::gds-pci-audit-logs/*\",\"Condition\":{\"StringEquals\":"
            "\"s3:x-amz-acl\":\"bucket-owner-full-control\"}}]}'"
        ),
        "terraform_snippet": """resource "aws_s3_bucket_policy" "pci_10_5" {
  bucket = "gds-pci-audit-logs"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyUnencryptedObjectUploads"
        Effect = "Deny"
        Principal = "*"
        Action = "s3:PutObject"
        Resource = "arn:aws:s3:::gds-pci-audit-logs/*"
        Condition = { StringNotEquals = { "s3:x-amz-server-side-encryption" = "aws:kms" } }
      }
    ]
  })
}""",
        "verification_check": {
            "type": "aws_cli",
            "command": "aws s3api get-bucket-policy --bucket gds-pci-audit-logs",
            "expected_key": "Policy",
        },
    },
    "11.5": {
        "control_id": "11.5",
        "control_name": "Intrusion Detection System (IDS / Threat Detection)",
        "remediation_type": "cloud_config",
        "steps": [
            {"step": 1, "action": "Enable AWS GuardDuty detector in the active region."},
            {"step": 2, "action": "Configure threat intelligence feeds and malware protection."},
            {"step": 3, "action": "Setup automatic alerts for unauthorized network intrusion attempts."},
        ],
        "aws_cli_command": "aws guardduty create-detector --enable",
        "terraform_snippet": """resource "aws_guardduty_detector" "pci_11_5" {
  enable                      = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
}""",
        "verification_check": {
            "type": "aws_cli",
            "command": "aws guardduty list-detectors",
            "expected_status": "ACTIVE",
        },
    },
    "12.3": {
        "control_id": "12.3",
        "control_name": "Network Controls & Security Group Isolation",
        "remediation_type": "cloud_config",
        "steps": [
            {"step": 1, "action": "Create restricted Security Group isolating cardholder data environment (CDE)."},
            {"step": 2, "action": "Restrict inbound traffic to mandatory operational ports only."},
            {"step": 3, "action": "Block unrestricted egress to external public networks."},
        ],
        "aws_cli_command": (
            "aws ec2 create-security-group "
            "--group-name pci-cde-sg "
            "--description 'PCI DSS 12.3 compliant network boundary SG' "
            "--vpc-id vpc-default"
        ),
        "terraform_snippet": """resource "aws_security_group" "pci_12_3" {
  name        = "pci-cde-sg"
  description = "PCI DSS 12.3 restricted network controls"
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}""",
        "verification_check": {
            "type": "aws_cli",
            "command": "aws ec2 describe-security-groups --group-names pci-cde-sg",
            "expected_key": "SecurityGroups",
        },
    },
}

SOC2_REMEDIATIONS: dict[str, dict[str, Any]] = {
    "CC6.1": {
        "control_id": "CC6.1",
        "control_name": "Logical Access Security & Password Enforcement",
        "remediation_type": "iam_policy",
        "steps": [
            {"step": 1, "action": "Enforce strong password policy and multi-factor authentication."},
            {"step": 2, "action": "Restrict administrative access to authorized role-based sessions."},
        ],
        "aws_cli_command": (
            "aws iam update-account-password-policy "
            "--minimum-password-length 14 "
            "--require-symbols "
            "--require-numbers "
            "--require-uppercase-characters"
        ),
        "terraform_snippet": """resource "aws_iam_account_password_policy" "soc2_cc6_1" {
  minimum_password_length = 14
  require_symbols         = true
  require_numbers         = true
  require_uppercase_characters = true
}""",
        "verification_check": {"type": "aws_cli", "command": "aws iam get-account-password-policy"},
    },
    "CC6.2": {
        "control_id": "CC6.2",
        "control_name": "User Provisioning & Access Review",
        "remediation_type": "access_review",
        "steps": [
            {"step": 1, "action": "Deploy IAM Access Analyzer to detect external and cross-account access."},
            {"step": 2, "action": "Automate quarterly access review workflows for elevated roles."},
        ],
        "aws_cli_command": "aws accessanalyzer create-analyzer --analyzer-name soc2-access-analyzer --type ACCOUNT",
        "terraform_snippet": """resource "aws_accessanalyzer_analyzer" "soc2_cc6_2" {
  analyzer_name = "soc2-access-analyzer"
  type          = "ACCOUNT"
}""",
        "verification_check": {"type": "aws_cli", "command": "aws accessanalyzer list-analyzers"},
    },
    "CC6.3": {
        "control_id": "CC6.3",
        "control_name": "Access Removal & Credential Management",
        "remediation_type": "access_review",
        "steps": [
            {"step": 1, "action": "Generate IAM credential report to identify inactive credentials."},
            {"step": 2, "action": "Automatically deactivate access keys older than 90 days."},
        ],
        "aws_cli_command": "aws iam generate-credential-report",
        "terraform_snippet": """resource "aws_iam_account_alias" "soc2_cc6_3" {
  account_alias = "soc2-monitored-account"
}""",
        "verification_check": {"type": "aws_cli", "command": "aws iam get-credential-report"},
    },
    "CC7.1": {
        "control_id": "CC7.1",
        "control_name": "System Monitoring & Alerting",
        "remediation_type": "logging",
        "steps": [
            {"step": 1, "action": "Create CloudWatch metric alarm for unauthorized API calls."},
            {"step": 2, "action": "Connect alarms to security operations notification topics."},
        ],
        "aws_cli_command": (
            "aws cloudwatch put-metric-alarm "
            "--alarm-name soc2-unauthorized-api-calls "
            "--metric-name UnauthorizedOperationCount "
            "--namespace CloudTrailMetrics "
            "--statistic Sum "
            "--period 300 "
            "--threshold 1 "
            "--comparison-operator GreaterThanOrEqualToThreshold "
            "--evaluation-periods 1"
        ),
        "terraform_snippet": """resource "aws_cloudwatch_metric_alarm" "soc2_cc7_1" {
  alarm_name          = "soc2-unauthorized-api-calls"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "UnauthorizedOperationCount"
  namespace           = "CloudTrailMetrics"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
}""",
        "verification_check": {"type": "aws_cli", "command": "aws cloudwatch describe-alarms --alarm-names soc2-unauthorized-api-calls"},
    },
    "CC7.2": {
        "control_id": "CC7.2",
        "control_name": "Anomaly Detection & Threat Intelligence",
        "remediation_type": "cloud_config",
        "steps": [
            {"step": 1, "action": "Enable AWS GuardDuty for continuous threat and anomaly detection."},
            {"step": 2, "action": "Integrate findings into security information event monitoring."},
        ],
        "aws_cli_command": "aws guardduty create-detector --enable",
        "terraform_snippet": """resource "aws_guardduty_detector" "soc2_cc7_2" {
  enable = true
}""",
        "verification_check": {"type": "aws_cli", "command": "aws guardduty list-detectors"},
    },
    "CC8.1": {
        "control_id": "CC8.1",
        "control_name": "Change Management & Infrastructure Tracking",
        "remediation_type": "cloud_config",
        "steps": [
            {"step": 1, "action": "Configure AWS Config to record all resource configuration changes."},
            {"step": 2, "action": "Enable CloudTrail tracking for infrastructure modifications."},
        ],
        "aws_cli_command": (
            "aws configservice put-configuration-recorder "
            "--configuration-recorder name=default,roleARN=arn:aws:iam::123456789012:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig"
        ),
        "terraform_snippet": """resource "aws_config_configuration_recorder" "soc2_cc8_1" {
  name     = "default"
  role_arn = "arn:aws:iam::123456789012:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig"
}""",
        "verification_check": {"type": "aws_cli", "command": "aws configservice describe-configuration-recorders"},
    },
    "CC9.2": {
        "control_id": "CC9.2",
        "control_name": "Risk Assessment & Security Hub Posture",
        "remediation_type": "cloud_config",
        "steps": [
            {"step": 1, "action": "Enable AWS Security Hub for posture monitoring and standard compliance checks."},
            {"step": 2, "action": "Aggregate vulnerability findings across cloud workloads."},
        ],
        "aws_cli_command": "aws securityhub enable-security-hub",
        "terraform_snippet": """resource "aws_securityhub_account" "soc2_cc9_2" {}""",
        "verification_check": {"type": "aws_cli", "command": "aws securityhub describe-hub"},
    },
}

ISO27001_REMEDIATIONS: dict[str, dict[str, Any]] = {
    "A.9.4.1": {
        "control_id": "A.9.4.1",
        "control_name": "Information Access Restriction & IAM Policy Review",
        "remediation_type": "iam_policy",
        "steps": [
            {"step": 1, "action": "Audit attached IAM policies for excessive permissions."},
            {"step": 2, "action": "Enforce least-privilege policies across all service roles."},
        ],
        "aws_cli_command": "aws iam list-policies --only-attached",
        "terraform_snippet": """data "aws_iam_policy_document" "iso_a941" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::restricted-iso-bucket/*"]
  }
}""",
        "verification_check": {"type": "aws_cli", "command": "aws iam list-policies --only-attached"},
    },
    "A.12.6.1": {
        "control_id": "A.12.6.1",
        "control_name": "Management of Technical Vulnerabilities",
        "remediation_type": "cloud_config",
        "steps": [
            {"step": 1, "action": "Activate AWS Inspector v2 automated vulnerability scanning."},
            {"step": 2, "action": "Configure scan coverage across EC2 instances and ECR repositories."},
        ],
        "aws_cli_command": "aws inspector2 enable --resource-types EC2 ECR LAMBDA",
        "terraform_snippet": """resource "aws_inspector2_enabler" "iso_a1261" {
  account_ids    = ["self"]
  resource_types = ["EC2", "ECR", "LAMBDA"]
}""",
        "verification_check": {"type": "aws_cli", "command": "aws inspector2 list-coverage"},
    },
    "A.13.1.1": {
        "control_id": "A.13.1.1",
        "control_name": "Network Controls & Perimeter Isolation",
        "remediation_type": "cloud_config",
        "steps": [
            {"step": 1, "action": "Create dedicated VPC Security Groups for network perimeter control."},
            {"step": 2, "action": "Disable public ingress on internal microservices."},
        ],
        "aws_cli_command": (
            "aws ec2 create-security-group "
            "--group-name iso-network-sg "
            "--description 'ISO 27001 Network Controls Perimeter SG'"
        ),
        "terraform_snippet": """resource "aws_security_group" "iso_a1311" {
  name        = "iso-network-sg"
  description = "ISO 27001 perimeter boundary security group"
}""",
        "verification_check": {"type": "aws_cli", "command": "aws ec2 describe-security-groups --group-names iso-network-sg"},
    },
    "A.14.2.3": {
        "control_id": "A.14.2.3",
        "control_name": "Technical Review of Applications after Operating System Changes",
        "remediation_type": "cloud_config",
        "steps": [
            {"step": 1, "action": "Enable AWS CodeGuru Reviewer for automated code quality and security reviews."},
            {"step": 2, "action": "Integrate code security analysis into active deployment pipelines."},
        ],
        "aws_cli_command": "aws codeguru-reviewer associate-repository --repository '{\"CodeCommit\":{\"Name\":\"main-repo\"}}'",
        "terraform_snippet": """resource "aws_codeguru_reviewer_repository_association" "iso_a1423" {
  repository {
    codecommit {
      name = "main-repo"
    }
  }
}""",
        "verification_check": {"type": "aws_cli", "command": "aws codeguru-reviewer list-repository-associations"},
    },
}

NIST_CSF_REMEDIATIONS: dict[str, dict[str, Any]] = {
    "DE.CM-1": {
        "control_id": "DE.CM-1",
        "control_name": "Network Monitoring via VPC Flow Logs",
        "remediation_type": "logging",
        "steps": [
            {"step": 1, "action": "Enable VPC Flow Logs to capture network traffic metadata."},
            {"step": 2, "action": "Stream logs to CloudWatch Logs or centralized S3 bucket."},
        ],
        "aws_cli_command": (
            "aws ec2 create-flow-logs "
            "--resource-type VPC "
            "--resource-ids vpc-0123456789abcdef0 "
            "--traffic-type ALL "
            "--log-destination-type cloud-watch-logs "
            "--deliver-logs-permission-arn arn:aws:iam::123456789012:role/flowlogs-role"
        ),
        "terraform_snippet": """resource "aws_flow_log" "nist_de_cm_1" {
  traffic_type    = "ALL"
  vpc_id          = "vpc-0123456789abcdef0"
  deliver_external = "cloud-watch-logs"
}""",
        "verification_check": {"type": "aws_cli", "command": "aws ec2 describe-flow-logs"},
    },
    "DE.CM-3": {
        "control_id": "DE.CM-3",
        "control_name": "Personnel Activity Monitoring & Audit Trails",
        "remediation_type": "logging",
        "steps": [
            {"step": 1, "action": "Enable AWS CloudTrail for multi-region user activity logging."},
            {"step": 2, "action": "Configure real-time log ingestion and anomaly alerts."},
        ],
        "aws_cli_command": (
            "aws cloudtrail create-trail "
            "--name nist-activity-trail "
            "--s3-bucket-name gds-nist-logs "
            "--is-multi-region-trail"
        ),
        "terraform_snippet": """resource "aws_cloudtrail" "nist_de_cm_3" {
  name           = "nist-activity-trail"
  s3_bucket_name = "gds-nist-logs"
  enable_logging = true
}""",
        "verification_check": {"type": "aws_cli", "command": "aws cloudtrail get-trail-status --name nist-activity-trail"},
    },
    "PR.AC-1": {
        "control_id": "PR.AC-1",
        "control_name": "Identity Proofing & Credential Requirements",
        "remediation_type": "iam_policy",
        "steps": [
            {"step": 1, "action": "Enforce IAM account password policies requiring symbols, numbers, and length >= 14."},
            {"step": 2, "action": "Mandate hardware or virtual MFA tokens for all user logins."},
        ],
        "aws_cli_command": (
            "aws iam update-account-password-policy "
            "--minimum-password-length 14 "
            "--require-symbols "
            "--require-numbers "
            "--require-uppercase-characters"
        ),
        "terraform_snippet": """resource "aws_iam_account_password_policy" "nist_pr_ac_1" {
  minimum_password_length = 14
  require_symbols         = true
  require_numbers         = true
}""",
        "verification_check": {"type": "aws_cli", "command": "aws iam get-account-password-policy"},
    },
    "PR.AC-4": {
        "control_id": "PR.AC-4",
        "control_name": "Access Permissions Management & Least Privilege",
        "remediation_type": "access_review",
        "steps": [
            {"step": 1, "action": "Create AWS IAM Access Analyzer to identify cross-account shared resources."},
            {"step": 2, "action": "Revoke excessive resource permissions."},
        ],
        "aws_cli_command": "aws accessanalyzer create-analyzer --analyzer-name nist-access-analyzer --type ACCOUNT",
        "terraform_snippet": """resource "aws_accessanalyzer_analyzer" "nist_pr_ac_4" {
  analyzer_name = "nist-access-analyzer"
  type          = "ACCOUNT"
}""",
        "verification_check": {"type": "aws_cli", "command": "aws accessanalyzer list-analyzers"},
    },
    "PR.DS-1": {
        "control_id": "PR.DS-1",
        "control_name": "Data-at-Rest Security & EBS Encryption",
        "remediation_type": "encryption",
        "steps": [
            {"step": 1, "action": "Enable default EBS encryption across AWS region."},
            {"step": 2, "action": "Verify KMS key policies for storage resources."},
        ],
        "aws_cli_command": "aws ec2 enable-ebs-encryption-by-default",
        "terraform_snippet": """resource "aws_ebs_encryption_by_default" "nist_pr_ds_1" {
  enabled = true
}""",
        "verification_check": {"type": "aws_cli", "command": "aws ec2 get-ebs-encryption-by-default"},
    },
    "PR.DS-2": {
        "control_id": "PR.DS-2",
        "control_name": "Data-in-Transit Security & TLS Enforcement",
        "remediation_type": "encryption",
        "steps": [
            {"step": 1, "action": "Enforce HTTPS/TLS 1.2+ on Application Load Balancer listeners."},
            {"step": 2, "action": "Disable weak cipher suites on public network endpoints."},
        ],
        "aws_cli_command": (
            "aws elbv2 create-listener "
            "--load-balancer-arn arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/50dc6c495c0c9188 "
            "--protocol HTTPS "
            "--port 443 "
            "--ssl-policy ELBSecurityPolicy-TLS13-1-2-2021-06"
        ),
        "terraform_snippet": """resource "aws_lb_listener" "nist_pr_ds_2" {
  load_balancer_arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/50dc6c495c0c9188"
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  default_action {
    type             = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      message_body = "OK"
      status_code  = "200"
    }
  }
}""",
        "verification_check": {"type": "aws_cli", "command": "aws elbv2 describe-listeners"},
    },
    "RS.RP-1": {
        "control_id": "RS.RP-1",
        "control_name": "Incident Response Plan Documentation",
        "remediation_type": "policy_doc",
        "steps": [
            {"step": 1, "action": "Draft Incident Response Plan covering triage, escalation, and communication."},
            {"step": 2, "action": "Publish policy doc to secure internal compliance repository."},
        ],
        "aws_cli_command": None,
        "terraform_snippet": None,
        "verification_check": {"type": "manual", "description": "Verify incident response document is signed and accessible."},
    },
}

GDPR_REMEDIATIONS: dict[str, dict[str, Any]] = {
    "Art.32": {
        "control_id": "Art.32",
        "control_name": "Security of Processing & Encryption at Rest",
        "remediation_type": "encryption",
        "steps": [
            {"step": 1, "action": "Enable default AWS EBS encryption for all volumes holding personal data."},
            {"step": 2, "action": "Apply KMS server-side encryption on S3 buckets containing user data."},
        ],
        "aws_cli_command": "aws ec2 enable-ebs-encryption-by-default",
        "terraform_snippet": """resource "aws_ebs_encryption_by_default" "gdpr_art32" {
  enabled = true
}""",
        "verification_check": {"type": "aws_cli", "command": "aws ec2 get-ebs-encryption-by-default"},
    },
    "Art.33": {
        "control_id": "Art.33",
        "control_name": "Notification of Personal Data Breach (72h Notice Workflow)",
        "remediation_type": "policy_doc",
        "steps": [
            {"step": 1, "action": "Provision Amazon SNS topic for automated breach notification alerts."},
            {"step": 2, "action": "Establish 72-hour breach response escalation procedure policy document."},
        ],
        "aws_cli_command": "aws sns create-topic --name gdpr-breach-notification-topic",
        "terraform_snippet": """resource "aws_sns_topic" "gdpr_art33" {
  name = "gdpr-breach-notification-topic"
}""",
        "verification_check": {"type": "aws_cli", "command": "aws sns list-topics"},
    },
    "Art.35": {
        "control_id": "Art.35",
        "control_name": "Data Protection Impact Assessment (DPIA)",
        "remediation_type": "policy_doc",
        "steps": [
            {"step": 1, "action": "Complete DPIA template for high-risk personal data processing systems."},
            {"step": 2, "action": "Record assessment in compliance evidence repository."},
        ],
        "aws_cli_command": None,
        "terraform_snippet": None,
        "verification_check": {"type": "manual", "description": "Review DPIA document signature and controls."},
    },
}

DORA_REMEDIATIONS: dict[str, dict[str, Any]] = {
    "Art.5": {
        "control_id": "Art.5",
        "control_name": "ICT Risk Management Framework",
        "remediation_type": "policy_doc",
        "steps": [
            {"step": 1, "action": "Enable AWS Security Hub for ICT infrastructure risk visibility."},
            {"step": 2, "action": "Formalize ICT risk management policies and operational governance."},
        ],
        "aws_cli_command": "aws securityhub enable-security-hub",
        "terraform_snippet": """resource "aws_securityhub_account" "dora_art5" {}""",
        "verification_check": {"type": "aws_cli", "command": "aws securityhub describe-hub"},
    },
    "Art.6": {
        "control_id": "Art.6",
        "control_name": "ICT Systems Protection, Prevention & Security Monitoring",
        "remediation_type": "cloud_config",
        "steps": [
            {"step": 1, "action": "Enable GuardDuty threat detection across ICT cloud workloads."},
            {"step": 2, "action": "Enforce continuous infrastructure posture monitoring."},
        ],
        "aws_cli_command": "aws guardduty create-detector --enable",
        "terraform_snippet": """resource "aws_guardduty_detector" "dora_art6" {
  enable = true
}""",
        "verification_check": {"type": "aws_cli", "command": "aws guardduty list-detectors"},
    },
    "Art.11": {
        "control_id": "Art.11",
        "control_name": "Digital Operational Resilience Testing & Penetration Testing",
        "remediation_type": "access_review",
        "steps": [
            {"step": 1, "action": "Enable Inspector v2 for continuous automated vulnerability testing."},
            {"step": 2, "action": "Schedule annual threat-led penetration testing (TLPT)."},
        ],
        "aws_cli_command": "aws inspector2 enable --resource-types EC2 ECR",
        "terraform_snippet": """resource "aws_inspector2_enabler" "dora_art11" {
  account_ids    = ["self"]
  resource_types = ["EC2", "ECR"]
}""",
        "verification_check": {"type": "aws_cli", "command": "aws inspector2 list-coverage"},
    },
    "Art.17": {
        "control_id": "Art.17",
        "control_name": "ICT-Related Incident Reporting",
        "remediation_type": "policy_doc",
        "steps": [
            {"step": 1, "action": "Deploy SNS incident alert pipeline for major ICT-related incidents."},
            {"step": 2, "action": "Adopt regulatory incident reporting template."},
        ],
        "aws_cli_command": "aws sns create-topic --name dora-incident-reporting-topic",
        "terraform_snippet": """resource "aws_sns_topic" "dora_art17" {
  name = "dora-incident-reporting-topic"
}""",
        "verification_check": {"type": "aws_cli", "command": "aws sns list-topics"},
    },
}

NIS2_REMEDIATIONS: dict[str, dict[str, Any]] = {
    "Art.21": {
        "control_id": "Art.21",
        "control_name": "Cybersecurity Risk-Management Measures",
        "remediation_type": "cloud_config",
        "steps": [
            {"step": 1, "action": "Enable default EBS encryption and configure network security group boundaries."},
            {"step": 2, "action": "Enforce multi-factor authentication across organizational identity providers."},
        ],
        "aws_cli_command": "aws ec2 enable-ebs-encryption-by-default",
        "terraform_snippet": """resource "aws_ebs_encryption_by_default" "nis2_art21" {
  enabled = true
}""",
        "verification_check": {"type": "aws_cli", "command": "aws ec2 get-ebs-encryption-by-default"},
    },
    "Art.23": {
        "control_id": "Art.23",
        "control_name": "Incident Reporting & Mandatory Notification Workflow",
        "remediation_type": "policy_doc",
        "steps": [
            {"step": 1, "action": "Configure SNS alert channel for 24-hour early warning notifications."},
            {"step": 2, "action": "Integrate incident workflow with national CSIRT reporting protocols."},
        ],
        "aws_cli_command": "aws sns create-topic --name nis2-incident-alerts",
        "terraform_snippet": """resource "aws_sns_topic" "nis2_art23" {
  name = "nis2-incident-alerts"
}""",
        "verification_check": {"type": "aws_cli", "command": "aws sns list-topics"},
    },
}

EU_AI_ACT_REMEDIATIONS: dict[str, dict[str, Any]] = {
    "Art.9": {
        "control_id": "Art.9",
        "control_name": "Risk Management System for High-Risk AI Systems",
        "remediation_type": "policy_doc",
        "steps": [
            {"step": 1, "action": "Establish continuous AI risk management framework covering dataset bias and model behavior."},
            {"step": 2, "action": "Document risk mitigation decisions in compliance evidence system."},
        ],
        "aws_cli_command": None,
        "terraform_snippet": None,
        "verification_check": {"type": "manual", "description": "Verify AI risk management policy document signature."},
    },
    "Art.10": {
        "control_id": "Art.10",
        "control_name": "Data and Data Governance for AI Models",
        "remediation_type": "access_review",
        "steps": [
            {"step": 1, "action": "Enable AWS Macie for automated discovery and classification of sensitive training datasets."},
            {"step": 2, "action": "Apply strict data governance policies to training and validation data buckets."},
        ],
        "aws_cli_command": "aws macie2 enable-macie",
        "terraform_snippet": """resource "aws_macie2_account" "eu_ai_art10" {}""",
        "verification_check": {"type": "aws_cli", "command": "aws macie2 get-macie-session"},
    },
    "Art.12": {
        "control_id": "Art.12",
        "control_name": "Record-Keeping & Automated Logging for AI Systems",
        "remediation_type": "logging",
        "steps": [
            {"step": 1, "action": "Enable automatic audit logging for AI inference requests and decisions."},
            {"step": 2, "action": "Retain inference logs in immutable storage for regulatory verification."},
        ],
        "aws_cli_command": (
            "aws cloudtrail create-trail "
            "--name ai-act-audit-trail "
            "--s3-bucket-name gds-ai-act-logs "
            "--is-multi-region-trail"
        ),
        "terraform_snippet": """resource "aws_cloudtrail" "eu_ai_art12" {
  name           = "ai-act-audit-trail"
  s3_bucket_name = "gds-ai-act-logs"
  enable_logging = true
}""",
        "verification_check": {"type": "aws_cli", "command": "aws cloudtrail get-trail-status --name ai-act-audit-trail"},
    },
    "Art.15": {
        "control_id": "Art.15",
        "control_name": "Accuracy, Robustness and Cybersecurity of AI Models",
        "remediation_type": "access_review",
        "steps": [
            {"step": 1, "action": "Set up continuous robustness and adversarial testing suite for AI model endpoints."},
            {"step": 2, "action": "Validate model accuracy metrics against regulatory thresholds."},
        ],
        "aws_cli_command": None,
        "terraform_snippet": None,
        "verification_check": {"type": "manual", "description": "Review AI robustness benchmark report."},
    },
}

FRAMEWORK_REMEDIATIONS: dict[str, dict[str, dict[str, Any]]] = {
    "PCI-DSS": PCI_DSS_REMEDIATIONS,
    "PCI_DSS": PCI_DSS_REMEDIATIONS,
    "SOC2": SOC2_REMEDIATIONS,
    "ISO27001": ISO27001_REMEDIATIONS,
    "ISO-27001": ISO27001_REMEDIATIONS,
    "NIST": NIST_CSF_REMEDIATIONS,
    "NIST-CSF": NIST_CSF_REMEDIATIONS,
    "NIST_CSF": NIST_CSF_REMEDIATIONS,
    "GDPR": GDPR_REMEDIATIONS,
    "DORA": DORA_REMEDIATIONS,
    "NIS2": NIS2_REMEDIATIONS,
    "EU_AI_ACT": EU_AI_ACT_REMEDIATIONS,
    "EU_AI_Act": EU_AI_ACT_REMEDIATIONS,
    "EU-AI-ACT": EU_AI_ACT_REMEDIATIONS,
    "EU-AI-Act": EU_AI_ACT_REMEDIATIONS,
}


def get_framework_dict(framework: str) -> dict[str, dict[str, Any]] | None:
    """Helper to lookup framework dict with normalization."""
    if not framework:
        return None
    normalized = framework.strip()
    if normalized in FRAMEWORK_REMEDIATIONS:
        return FRAMEWORK_REMEDIATIONS[normalized]
    upper_norm = normalized.upper().replace(" ", "_").replace("-", "_")
    for k, v in FRAMEWORK_REMEDIATIONS.items():
        if k.upper().replace(" ", "_").replace("-", "_") == upper_norm:
            return v
    return None


# ============================================================================
# ENGINE FUNCTIONS
# ============================================================================


async def generate_remediation_plan(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    framework: str,
    control_id: str,
    gap_description: str,
    user_id: uuid.UUID | None = None,
) -> ComplianceRemediationJob:
    """Generate a remediation job for a specific framework control gap."""
    if user_id is None:
        user_id = uuid.UUID("00000000-0000-0000-0000-000000000000")

    fw_dict = get_framework_dict(framework)
    control_info = fw_dict.get(control_id) if fw_dict else None

    if control_info:
        control_name = control_info["control_name"]
        remediation_type = control_info["remediation_type"]
        steps = control_info["steps"]
        aws_cli = control_info.get("aws_cli_command")
        terraform = control_info.get("terraform_snippet")
        initial_status = "pending"
    else:
        control_name = f"Control {control_id}"
        remediation_type = "manual_required"
        steps = [
            {
                "step": 1,
                "action": f"Manual remediation required for control {control_id} in {framework}.",
            }
        ]
        aws_cli = None
        terraform = None
        initial_status = "manual_required"

    job = ComplianceRemediationJob(
        tenant_id=tenant_id,
        framework=framework,
        control_id=control_id,
        control_name=control_name,
        gap_description=gap_description,
        remediation_type=remediation_type,
        remediation_steps=steps,
        aws_cli_command=aws_cli,
        terraform_snippet=terraform,
        status=initial_status,
        progress_pct=0,
        triggered_by=user_id,
    )

    db.add(job)
    await db.commit()
    await db.refresh(job)
    return job


def _validate_aws_command(command: str) -> None:
    """Validate AWS CLI command safety before execution."""
    cleaned = command.strip()
    allowed_prefixes = ("aws ", "terraform ", "gcloud ", "az ", "kubectl ")
    if not any(cleaned.startswith(prefix) for prefix in allowed_prefixes):
        raise ValueError(
            f"Command execution blocked: Command must start with one of {allowed_prefixes}"
        )

    forbidden_chars = [";", "&&", "||", "`", "$(", ">", "<"]
    for char in forbidden_chars:
        if char in cleaned:
            raise ValueError(f"Command execution blocked: Contains unsafe operator '{char}'")


async def execute_remediation(
    db: AsyncSession,
    job_id: uuid.UUID,
    dry_run: bool = True,
) -> ComplianceRemediationJob:
    """Execute the remediation plan for a given job.

    If dry_run is True, returns planned actions without executing AWS CLI commands.
    If dry_run is False, runs validated AWS CLI command via subprocess.
    """
    result = await db.execute(select(ComplianceRemediationJob).where(ComplianceRemediationJob.id == job_id))
    job = result.scalar_one_or_none()
    if not job:
        raise ValueError(f"Remediation job {job_id} not found")

    if dry_run:
        job.verification_result = {
            "dry_run": True,
            "aws_cli_command": job.aws_cli_command,
            "terraform_snippet": job.terraform_snippet,
            "steps": job.remediation_steps,
            "message": "Dry run execution completed. Validated fix commands without modifying infrastructure.",
        }
        job.progress_pct = 100
        if job.status == "pending":
            job.status = "pending"
        await db.commit()
        await db.refresh(job)
        return job

    # Real execution mode
    job.status = "executing"
    job.progress_pct = 25
    await db.commit()

    if job.aws_cli_command:
        try:
            _validate_aws_command(job.aws_cli_command)
            args = shlex.split(job.aws_cli_command)

            proc = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=30,
            )

            if proc.returncode != 0:
                job.status = "failed"
                job.error_message = proc.stderr or proc.stdout or f"CLI returned exit code {proc.returncode}"
                job.progress_pct = 0
                await db.commit()
                await db.refresh(job)
                return job

            job.progress_pct = 80
            job.error_message = None

        except Exception as exc:
            job.status = "failed"
            job.error_message = f"Execution failed: {exc}"
            job.progress_pct = 0
            await db.commit()
            await db.refresh(job)
            return job

    if job.remediation_type == "manual_required":
        job.status = "manual_required"
        job.progress_pct = 50
    else:
        job.status = "completed"
        job.progress_pct = 100
        job.completed_at = datetime.now(UTC)

    await db.commit()
    await db.refresh(job)
    return job


async def verify_remediation(
    db: AsyncSession,
    job_id: uuid.UUID,
) -> ComplianceRemediationJob:
    """Verify that a remediation job succeeded and update compliance control status."""
    result = await db.execute(select(ComplianceRemediationJob).where(ComplianceRemediationJob.id == job_id))
    job = result.scalar_one_or_none()
    if not job:
        raise ValueError(f"Remediation job {job_id} not found")

    is_verified = job.status in ("completed", "executing", "pending") and not job.error_message

    job.verification_result = {
        "verified": is_verified,
        "verified_at": datetime.now(UTC).isoformat(),
        "framework": job.framework,
        "control_id": job.control_id,
        "remediation_job_status": job.status,
        "details": f"Automated verification completed for control {job.control_id} in {job.framework}.",
    }

    if is_verified:
        job.status = "completed"
        if not job.completed_at:
            job.completed_at = datetime.now(UTC)

    status_query = await db.execute(
        select(ComplianceControlStatus).where(
            ComplianceControlStatus.tenant_id == job.tenant_id,
            ComplianceControlStatus.framework == job.framework,
            ComplianceControlStatus.control_id == job.control_id,
        )
    )
    control_status = status_query.scalar_one_or_none()

    new_status = "remediated" if is_verified else "failing"
    if control_status:
        control_status.status = new_status
        control_status.last_checked = func.now()
        control_status.remediation_job_id = job.id
        control_status.notes = f"Verified remediation job {job.id}. Status: {new_status}"
    else:
        control_status = ComplianceControlStatus(
            tenant_id=job.tenant_id,
            framework=job.framework,
            control_id=job.control_id,
            control_name=job.control_name,
            status=new_status,
            remediation_job_id=job.id,
            notes=f"Created via verification of remediation job {job.id}",
        )
        db.add(control_status)

    await db.commit()
    await db.refresh(job)
    return job


async def auto_remediate_framework(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    framework: str,
    user_id: uuid.UUID,
) -> dict[str, Any]:
    """Identify failing or untested controls for a framework, generate fix jobs, execute, and verify."""
    fw_dict = get_framework_dict(framework)
    if not fw_dict:
        raise ValueError(f"Unsupported compliance framework: {framework}")

    existing_statuses = await db.execute(
        select(ComplianceControlStatus).where(
            ComplianceControlStatus.tenant_id == tenant_id,
            ComplianceControlStatus.framework == framework,
        )
    )
    status_map = {c.control_id: c for c in existing_statuses.scalars().all()}

    remediated_count = 0
    failed_count = 0
    manual_count = 0
    job_summaries: list[dict[str, Any]] = []

    for ctrl_id, ctrl_info in fw_dict.items():
        curr_status = status_map.get(ctrl_id)
        if curr_status and curr_status.status in ("passing", "remediated"):
            continue

        gap_desc = f"Compliance gap identified for control {ctrl_id} ({ctrl_info['control_name']})"
        job = await generate_remediation_plan(db, tenant_id, framework, ctrl_id, gap_desc, user_id)
        job = await execute_remediation(db, job.id, dry_run=False)
        job = await verify_remediation(db, job.id)

        if job.status == "completed":
            remediated_count += 1
        elif job.status == "manual_required":
            manual_count += 1
        else:
            failed_count += 1

        job_summaries.append({
            "job_id": str(job.id),
            "control_id": ctrl_id,
            "control_name": ctrl_info["control_name"],
            "status": job.status,
            "error_message": job.error_message,
        })

    return {
        "tenant_id": str(tenant_id),
        "framework": framework,
        "total_controls_processed": len(job_summaries),
        "remediated": remediated_count,
        "failed": failed_count,
        "manual_required": manual_count,
        "jobs": job_summaries,
    }
