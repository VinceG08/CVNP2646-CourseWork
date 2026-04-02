# User Account & Permissions Auditor

## Overview

This project implements an Identity and Access Management (IAM) auditing tool that analyzes user accounts and role assignments to detect security risks such as improper access, stale accounts, and policy violations.

## Data Relationship

Two datasets are used:

* Users: user_id (primary key), username, status, department, last_login
* Roles: user_id (foreign key), role, assigned_date

They are joined using a dictionary for O(1) lookup efficiency.

## Detection Rules

### Required Rules

* Disabled users with active roles (CRITICAL)
* Unauthorized admin access outside IT/Security (HIGH)
* Stale accounts (90+ days inactivity) (MEDIUM)

### Advanced / AI Rules

* Conflicting roles (admin + auditor) (CRITICAL)
* Orphaned roles (HIGH)
* Excessive permissions (LOW)

## AI-Assisted Development

**Prompt Used:**
"What additional IAM anomalies should I detect?"

**Implemented:**

* Conflicting roles
* Excessive permissions

**Rejected:**

* Time-based anomalies (not enough data)

## Results

* Total Violations: ~8
* CRITICAL: 6
* HIGH: 1
* MEDIUM: 1
* LOW: 0

## Key Concepts

* Dictionary joins (O(1) lookup)
* Set membership testing
* defaultdict grouping
* Structured reporting
* Risk scoring system

## Conclusion

This tool demonstrates real-world IAM auditing techniques used in cybersecurity to detect privilege misuse, stale accounts, and policy violations.
