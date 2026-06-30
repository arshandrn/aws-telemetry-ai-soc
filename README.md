# High-Fidelity Cloud Telemetry Engineering & AI-Assisted Security Operations Center (SOC)

## Demo Video
Watch the full project demo: [Click here](https://1drv.ms/v/c/ca84ccba0e93da2d/IQCOaduqe4PkSbiTWT0drfRfAS1BpGq1HGq-RDu2ThfD-TA?e=G4TGam)

## 📖 Executive Summary

Modern cloud environments require more than passive alerting. This project demonstrates a fully functional, zero-touch Security Operations Center (SOC) built natively within AWS.

By engineering a custom telemetry pipeline across public and private subnets, I simulated a sophisticated 6-stage cloud intrusion. Rather than relying on third-party SIEMs, I built a custom EventBridge-to-Lambda SOAR pipeline to dynamically neutralize threats in real-time. Finally, I integrated Anthropic's Claude via the Model Context Protocol (MCP) to act as an automated Tier-2 analyst, reducing incident triage time from hours to seconds.

## 🏗️ Architecture & Telemetry Pipeline

The environment was engineered from scratch to ensure high-fidelity data capture across network and API layers.

- **Target Infrastructure:** A custom VPC with segmented public and private subnets, housing an internet-facing web server, an isolated internal server, and an S3 honeypot.
- **Log Ingestion:** `AWS CloudTrail` (capturing account-wide Management & Data events) and `VPC Flow Logs` (capturing 1-minute interval network traffic).
- **Detection Engine:** `AWS Config` (for compliance drift) and `Amazon CloudWatch` (using custom metric filters to detect MITRE ATT&CK patterns).
- **Automated Remediation:** `Amazon EventBridge` routes active CloudWatch alarms to a custom `Python (boto3) Lambda` function, which dynamically injects DENY rules into the VPC Network ACL.

## ⚔️ The Attack Kill Chain (6-Stage Simulation)

<details>
<summary><strong>Stage 1: Initial Exposure (T1530)</strong></summary>

- **Adversary Action:** Disabled "Block Public Access" on the honeypot bucket, exposing `credentials.txt` to the internet.
- **Detection:** AWS Config rule `s3-bucket-public-read-prohibited` flagged the resource as `NON_COMPLIANT`.

</details>

<details>
<summary><strong>Stage 2: Credential Abuse & Reconnaissance (T1078)</strong></summary>

- **Adversary Action:** Used the leaked keys from an external IP to enumerate account assets via the AWS CLI.
- **Detection & Response:** CloudWatch `IAMMisuse-Alarm` triggered. The automated Lambda script successfully extracted the unauthorized IP and injected Rule #90 into the Network ACL, dropping all traffic.

</details>

<details>
<summary><strong>Stage 3: Port Scanning (T1046)</strong></summary>

- **Adversary Action:** Executed an aggressive Nmap TCP scan against the public-facing EC2 instance.
- **Detection:** VPC Flow Logs recorded a massive spike in REJECT packets, triggering the `PortScan-Alarm` and dispatching an SNS alert to the security team.

</details>

<details>
<summary><strong>Stage 4: Privilege Escalation (T1098)</strong></summary>

- **Adversary Action:** Manipulated IAM policies to attach `AdministratorAccess` to the compromised dev user.
- **Detection:** CloudTrail captured the `AttachUserPolicy` event, triggering the `PrivEsc-Alarm` in seconds.

</details>

<details>
<summary><strong>Stage 5: API Discovery Burst (T1580)</strong></summary>

- **Adversary Action:** Executed 27 cross-service API discovery calls (EC2, RDS, Lambda, KMS) within a 35-second window using admin privileges.
- **Detection:** Custom CloudWatch metric filter detected the anomaly, firing the `APIBurst-Alarm`.

</details>

<details>
<summary><strong>Stage 6: Lateral Movement (T1021)</strong></summary>

- **Adversary Action:** Established an SSH session on the public web server and pivoted to scan the isolated private subnet (`10.0.2.0/24`).
- **Detection:** VPC Flow Logs flagged unauthorized `ACCEPT` traffic moving from the public subnet boundary into the private zone, triggering the `LateralMovement-Alarm`.

</details>

## 🤖 Highlight: AI-Assisted Triage via Claude MCP

To bridge the gap between automated containment and incident reporting, I deployed a local AI agent using the Model Context Protocol (MCP).

By granting Claude read-only programmatic access to my AWS APIs, I transformed the AI into a Tier-2 SOC Analyst. Instead of manually parsing thousands of JSON log lines, the AI was able to:

1. Automatically query CloudWatch alarm histories.
2. Cross-correlate unauthorized API bursts to specific access keys (`AKIA` vs `ASIA`).
3. Generate a complete, executive-ready Incident Report mapped to the MITRE ATT&CK framework in seconds.
