📖 Executive Summary
Modern cloud environments require more than passive alerting. This project demonstrates a fully functional, zero-touch Security Operations Center (SOC) built natively within AWS.

By engineering a custom telemetry pipeline across public and private subnets, I simulated a sophisticated 6-stage cloud intrusion. Rather than relying on third-party SIEMs, I built a custom EventBridge-to-Lambda SOAR pipeline to dynamically neutralize threats in real-time. Finally, I integrated Anthropic's Claude via the Model Context Protocol (MCP) to act as an automated Tier-2 analyst, reducing incident triage time from hours to seconds.

🏗️ Architecture & Telemetry Pipeline
The environment was engineered from scratch to ensure high-fidelity data capture across network and API layers.

Target Infrastructure: A custom VPC with segmented public and private subnets, housing an internet-facing web server, an isolated internal server, and an S3 honeypot.

Log Ingestion: AWS CloudTrail (capturing account-wide Management & Data events) and VPC Flow Logs (capturing 1-minute interval network traffic).

Detection Engine: AWS Config (for compliance drift) and Amazon CloudWatch (using custom metric filters to detect MITRE ATT&CK patterns).

Automated Remediation: Amazon EventBridge routes active CloudWatch alarms to a custom Python (boto3) Lambda function, which dynamically injects DENY rules into the VPC Network ACL.
