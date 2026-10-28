# Contributing to DriftGuard

DriftGuard is an AWS/Terraform drift-analysis project. Contributions that improve correctness, reproducibility, and the safety of its recommendations are particularly useful.

## Before opening a pull request

1. Read the [README](README.md), including documented limitations.
2. Search [existing issues](https://github.com/EdwinJdevops/driftguard/issues) and [pull requests](https://github.com/EdwinJdevops/driftguard/pulls).
3. For a bug, include a minimal reproduction, actual output, expected output, and the affected commit or version. **Remove account IDs, credentials, Terraform state secrets, customer data, and private infrastructure identifiers.**
4. Prefer a small change with a regression test over a broad refactor. Explain failure behavior and possible security implications.
5. Record commands you actually ran and their results. Do not claim a test passed if it was not executed.

## Review targets

The following questions are useful areas for independent review, not statements that they have been fully addressed:

- Can a partial or failed AWS inventory be misinterpreted as a resource deletion?
- Can one tenant retrieve another tenant's scan results? See [the existing access-control issue](https://github.com/EdwinJdevops/driftguard/issues/2).
- Are AWS permissions scoped, and are failure modes visible rather than silently ignored?
- Can generated remediation suggestions damage an existing Terraform configuration?
- Does logging or an API response expose credential material, Terraform state secrets, or infrastructure identifiers?

## Submitting a change

In the pull request, document:

- **Problem:** input and condition that triggers the behavior.
- **Change:** what the patch actually changes.
- **Evidence:** reproducible test or demonstration and exact commands executed.
- **Risk:** expected compatibility, authorization, or deployment impact.
- **Limits:** cases the change does not cover.

An external reproduction that disproves a documented assumption is a valuable contribution, even if it does not arrive with a patch.

## Security reports

**Do not publish exploitable vulnerabilities or secrets in public issues.** Before reporting a security-sensitive finding, check the repository's Security tab for a private vulnerability reporting option. If it is unavailable, do not post exploit details publicly.

## Licensing

Before copying, redistributing, or modifying this code, verify that the repository contains an applicable license. Public visibility alone does not grant reuse rights. This contribution guide does not grant a software license.

No one is expected to claim production qualification on behalf of this project. Review the exact scope of each test or experiment.
