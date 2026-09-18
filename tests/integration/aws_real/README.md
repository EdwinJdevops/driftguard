# Real AWS provider drift proof

This fixture is an intentionally small end-to-end validation of DriftGuard's
provider-native evidence path against a real AWS API.

The GitHub Actions workflow creates one **SSM Standard String parameter** under
`/driftguard/proof/`, mutates its value directly through AWS (outside
Terraform), runs a Terraform 1.16.2 refresh-only plan with AWS provider 6.65.0,
and converts the resulting `resource_drift` into DriftGuard Evidence Bundle
v1.

The proof is successful only when all of the following hold:

- GitHub authenticates to AWS through OIDC; no long-lived AWS access key is used.
- The assumed role is scoped to the proof parameter namespace.
- Terraform observes exactly one managed-resource drift record.
- DriftGuard preserves the Terraform resource identity and update action.
- The changed-value path is represented in the Evidence Bundle.
- Raw baseline and mutated parameter values occur in the ephemeral plan JSON
  but do **not** occur in the Evidence Bundle.
- Terraform destroy and a direct SSM fallback delete both run under `always()`.
- A final AWS API read proves the disposable parameter no longer exists.

The fixture intentionally uses local Terraform state because the resource exists
only for one workflow run. Raw plan JSON, plan files, state, and evidence output
are deleted from the runner and are not uploaded as artifacts.

This is an integration proof, not a production deployment topology. A failed
proof must be investigated; the test must not be weakened to accommodate a
provider or parser discrepancy.
