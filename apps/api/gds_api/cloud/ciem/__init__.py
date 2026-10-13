"""GDS OS CIEM (Cloud Infrastructure Entitlement Management) module.

Provides identity threat detection for AWS, Azure, and GCP:
- Overprivileged IAM users and roles
- Stale/inactive cloud identities (90+ days)
- Privilege escalation paths
- Unused permissions (granted but never used)
- MFA-disabled privileged accounts
- Access key age and rotation status
- Blast radius scoring
"""
