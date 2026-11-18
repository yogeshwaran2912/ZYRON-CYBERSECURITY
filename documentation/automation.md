# Module 04: Cybersecurity Automation Hub

## Purpose
Provides a deterministic Python execution engine, multi-format result parsing, duplicate finding suppression, lightweight task scheduling, and multi-step security workflows.

## Safety Architecture
- **No Arbitrary Shell Command Execution:** Shell commands from external sources are strictly disallowed.
- **Reviewed Python Callables:** All automation tasks run predefined, reviewed Python functions with explicit parameters.
- **Controlled Timeouts:** Prevents hanging tasks or CPU spinlocks.
- **Resource Conscious:** Zero background daemon processes required. Optimized for 8 GB RAM machines.

## Features

### 1. Task Runner (`task_runner.py`)
- Executes registered callables with start/completion timestamps, duration logging, and exception isolation.
- Pre-registered routines:
  - `database_optimization_vacuum`: Optimizes local SQLite database file.
  - `system_health_audit`: Gathers system metrics and entity counts.

### 2. Result Parser (`result_parser.py`)
- Safely parses JSON strings or files.
- Parses CSV files into structured dictionaries.
- `deduplicate_findings`: Filters duplicate findings based on `(affected_asset, title, severity)`.

### 3. Lightweight Job Scheduler (`scheduler.py`)
- Configures planned security checks (`daily`, `weekly`, `manual`) in SQLite.
- Executes jobs on-demand without spinning up memory-heavy cron daemons.

### 4. Workflow Manager (`workflow_manager.py`)
- Chains tasks into automated workflows:
  - **Evidence Integrity Verification Workflow:** Traverses all evidence files, calculates SHA-256 hashes, and reports any tampered or missing artifacts.
  - **Batch HTTP Security Header Workflow:** Analyzes header postures across multiple authorized web targets.
