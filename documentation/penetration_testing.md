# Module 03: Penetration Testing Assessment Guide

## Purpose
Supports structured network and web application penetration tests, service inventories, CVSS v3 vulnerability documentation, and remediation retesting.

## Features

### 1. Pre-Engagement Verification
- Enforces scope authorization (IPs, subnets, domains, URLs).
- Logs testing window parameters and authorization contracts.

### 2. Network & Service Inventory
- **Network Inventory:** Records authorized IP targets, hostnames, OS fingerprints, and segment categories.
- **Service Inventory:** Records listening ports (validated 1-65535), protocols (`tcp`/`udp`), service versions, and banners.

### 3. Web Application Assessment
- Web surface cataloging with technology stack, authentication mechanisms, and OWASP WSTG test checklist records.

### 4. Vulnerability Management & Retesting
- Standardized severity ratings: `informational`, `low`, `medium`, `high`, `critical`.
- Optional CVSS v3 metrics (0.0 to 10.0).
- Detailed fields: description, business impact, reproduction steps, remediation guidance.
- Retesting workflow records whether an issue is resolved (`fixed`) or remains exploitable (`validated`).

### 5. Consulting-Grade Reporting
- Generates executive summaries, severity distribution tables, and technical finding sheets in HTML, Markdown, and JSON.
