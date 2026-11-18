# Module 01: Bug Bounty Research Guide

## Purpose
Supports authorized bug bounty research programs, scope boundary verification, asset discovery, HTTP security inspection, and structured vulnerability verification.

## Features & Commands

### 1. Program & Scope Management
- Every bug bounty program must define authorized domains and testing restrictions.
- Default Policy is **DENY**. Any target not listed in `scopes` table is blocked before network queries execute.
- Explicit exclusions prevent accidental scans of critical infrastructure or out-of-scope third-party services.

### 2. DNS Reconnaissance (`dns_recon.py`)
- Resolves IPv4 and IPv6 records for in-scope domains.
- Safely discovers CNAME aliases without aggressive brute-forcing.
- Discovered hosts and IPs are automatically linked to `assets` table.

### 3. HTTP Security Header Analysis (`http_analyzer.py`)
- Analyzes headers:
  - `Strict-Transport-Security` (HSTS)
  - `Content-Security-Policy` (CSP)
  - `X-Frame-Options`
  - `X-Content-Type-Options`
  - `Referrer-Policy`
  - `Permissions-Policy`
- Computes overall security score percentage.
- Flags information disclosures (`Server`, `X-Powered-By`).

### 4. Vulnerability Lifecycle Tracking
Every finding requires a strict validation status:
- `potential`: Raw scanner or automated detection; unverified.
- `suspected`: Preliminary manual confirmation.
- `validated`: Fully validated with deterministic reproduction steps.
- `false_positive`: Identified as non-exploitable or intended behavior.
- `fixed`: Verified resolved following remediation.

### 5. Report Compilation
Exports professional Markdown, HTML, and JSON reports summarizing all findings, scope boundaries, and executive impact.
