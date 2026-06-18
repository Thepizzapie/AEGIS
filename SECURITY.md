# Security Policy

## Reporting a vulnerability

If you discover a security issue in Aegis, please report it responsibly:

**Email:** adrianmelendez2411@gmail.com  
**Subject line:** `[AEGIS SECURITY] <brief description>`

Please include:
- Description of the vulnerability
- Steps to reproduce
- Impact assessment (which guard/layer is affected)
- Any suggested fix

**Do not** open a public GitHub issue for security vulnerabilities.

## Response timeline

- **Acknowledgement:** within 48 hours
- **Initial assessment:** within 7 days
- **Fix or mitigation:** best effort, typically within 30 days for confirmed issues

## Scope

In scope:
- Built-in rule bypasses (evasion that defeats normalization)
- Self-protection circumvention (agent deleting/disabling Aegis)
- Identity forgery (minting valid tokens without the issuer key)
- Audit log tampering or suppression
- Policy engine evaluation-order violations (declarative rule overriding a built-in)

Out of scope (by design — see [Limitations](README.md#limitations)):
- OS-level escape from a process that already has shell access (Aegis is a policy layer, not a sandbox)
- Secret reads from paths not in the credential denylist (pair with least privilege)
- Novel obfuscation not yet covered by `normalize.scan_surface()` (report it — we'll add coverage)

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ Current |
