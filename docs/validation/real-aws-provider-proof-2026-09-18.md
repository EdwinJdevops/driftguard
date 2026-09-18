# Real AWS provider-native drift proof — 2026-09-18

## Scope

This record captures the first DriftGuard Evidence Core validation against a
real AWS API and a real HashiCorp AWS provider refresh.

It is evidence for one controlled resource type and one mutation path. It is
**not** evidence that every AWS provider resource or every drift shape is
correctly adjudicated.

## Source revision

- DriftGuard commit: `d7a00acffa18c43b75ce9c04575b6836f84c6a18`
- GitHub Actions run: `35342171422`
- Workflow: `Real AWS Provider Drift Proof`
- Region: `us-east-1`
- Terraform: `1.16.2`
- HashiCorp AWS provider: `6.65.0`

Authentication used GitHub Actions OIDC and the scoped
`DriftGuardGitHubProofRole`. No long-lived AWS access key was stored in the
repository or workflow.

## Experiment

The workflow created one Terraform-managed SSM Standard String parameter under
`/driftguard/proof/`.

The sequence was:

1. Terraform applied the baseline parameter.
2. A direct AWS API read verified the baseline state.
3. The parameter value was changed directly through AWS, outside Terraform.
4. A second AWS API read proved the out-of-band mutation occurred.
5. Terraform generated a refresh-only plan and detected the remote change.
6. `terraform show -json` produced ephemeral plan JSON.
7. DriftGuard converted `resource_drift` into Evidence Bundle v1.
8. The workflow asserted semantic identity and redaction.
9. Terraform destroy ran under `always()`.
10. A direct SSM fallback deletion ran under `always()`.
11. A final AWS read proved the parameter no longer existed.
12. A separate post-run AWS query found no parameters remaining under
    `/driftguard/proof/`.

## Observed provider-native evidence

DriftGuard emitted:

- resource address: `aws_ssm_parameter.proof`
- resource type: `aws_ssm_parameter`
- provider action: `update`
- changed paths:
  - `/value`
  - `/version`
- sensitive paths:
  - `/value`
  - `/value_wo`
- unknown paths: none

Evidence Bundle SHA-256:

`c0081f296855c3b42c882f8bc9bc17842dffacb68d362f958e19082f28d60d13`

Ephemeral raw-plan SHA-256:

`ee9689d70563f0b80fe662d7a5dd07ce678c7c971058d45ef30d234567f0a8f5`

The raw plan contained both the prior and out-of-band parameter values. The
Evidence Bundle contained neither value. The workflow asserted this directly
without printing the values.

## What this proves

This run proves that, for this fixture:

- GitHub OIDC can obtain short-lived AWS credentials with the scoped proof role.
- Terraform's AWS provider can observe the out-of-band mutation.
- Terraform emits the change through `resource_drift`.
- DriftGuard preserves the provider-native resource identity and action.
- DriftGuard derives changed-path metadata from the real provider plan.
- DriftGuard carries sensitive-path metadata without persisting the sensitive
  values.
- The proof resource is removed after the run.

## What this does not prove

This run does not prove:

- correctness for every AWS resource type;
- correctness for modules, `count`, or `for_each` on AWS specifically
  (those identity semantics are covered by the separate local-provider
  Terraform/OpenTofu contract);
- CloudTrail attribution;
- code remediation safety;
- cloud-to-code source rewriting;
- ingestion into a deployed DriftGuard API;
- multi-account role behavior;
- concurrent worker behavior;
- production readiness.

Those remain separate gates and must not be inferred from this result.

## Operational note

The AWS account was queried after the workflow completed. No SSM parameters
remained under the proof namespace. The workflow's own cleanup verification also
passed.
