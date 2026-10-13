# CGEP Capstone Write-up: Audit defense of ACME Health's Patient Intake API

## Primary Framework: HIPAA Security Rule
ACME Health’s primary compliance framework is the HIPAA Security Rule.  ACME Health was considering three compliance frameworks in order to fill eight compliance gaps in ACME Health's Patient Intake API.  If left unaddressed these gaps would lead to a failed audit.  The three choices were the HIPAA Security Rule, SOC 2 Type II, and CMMC Level 2.  When deciding between the three, SOC 2 Type II was not made a priority because only one customer was asking about it.  Also deprioritized was CMMC Level 2 because the federal pilot is on the table, but not confirmed.  The HIPAA Security Rule was selected because ACME Health is a telehealth company that handles data via a Patient Intake API.  The Patient Intake API handles Protected Health Information (PHI) and Electronic Protected Health Information (ePHI), and the HIPAA Security Rule's primary purpose is to establish a national set of security standards to protect the confidentiality, integrity, and availability of ePHI.  Finally when it comes to healthcare organizations that handle ePHI the HIPAA Security Rule isn't just a suggestion or set of guidelines it is a federal law and mandatory regulation.

## Control Coverage

| Gap | HIPAA control | Fix in Terraform | Detect with policy |
|---|---|---|---|
| GAP-01: SSE-S3 key controlled by AWS not ACME Health | HIPAA 164.312(a)(2)(iv) |  |  |
| GAP-02: DynamoDB table uses key owned by AWS | HIPAA 164.312(a)(2)(iv) |  |  |
| GAP-03: Uploads bucket allows non-TLS requests | HIPAA 164.312(e)(1) |  |  |
| GAP-04: No versioning on the uploads bucket | HIPAA 164.308(a)(7) |  |  |
| GAP-05: Lambda runs outside the VPC | HIPAA 164.312(e)(1) |  |  |
| GAP-06: No reserved concurrency, no DLQ, no X-ray |  |  |  |
| GAP-07: Lambda IAM role permissions too permissive | HIPAA 164.312(a)(1) |  |  |
| GAP-08: No access logging, throttling, or WAF on API G/W | HIPAA 164.312(b) |  |  |