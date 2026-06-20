"""
DriftGuard — Remote Terraform State Reader

Reads terraform.tfstate directly from an S3 backend, the way
real Terraform teams actually store state (with DynamoDB locking).
No more pasting state into a textarea.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

import boto3
import structlog
from botocore.exceptions import ClientError, NoCredentialsError

log = structlog.get_logger(__name__)


@dataclass
class StateReadResult:
    success: bool
    state: dict | None = None
    error: str | None = None
    version_id: str | None = None


class S3StateReader:
    """
    Reads Terraform state from an S3 backend.

    Standard Terraform S3 backend config looks like:

        terraform {
          backend "s3" {
            bucket = "my-terraform-state"
            key    = "prod/terraform.tfstate"
            region = "us-east-1"
          }
        }

    This reader pulls exactly that file using the same bucket/key/region.
    """

    def __init__(self, session: boto3.Session):
        self.session = session

    def read_state(self, bucket: str, key: str, region: str) -> StateReadResult:
        try:
            s3 = self.session.client("s3", region_name=region)
            response = s3.get_object(Bucket=bucket, Key=key)
            raw = response["Body"].read()
            state = json.loads(raw)
            version_id = response.get("VersionId")

            log.info(
                "Read Terraform state from S3",
                bucket=bucket,
                key=key,
                version_id=version_id,
                resource_count=len(state.get("resources", [])),
            )

            return StateReadResult(success=True, state=state, version_id=version_id)

        except NoCredentialsError:
            return StateReadResult(
                success=False,
                error="No AWS credentials available to read S3 state.",
            )
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            if error_code == "NoSuchKey":
                msg = f"State file not found at s3://{bucket}/{key}"
            elif error_code == "NoSuchBucket":
                msg = f"Bucket does not exist: {bucket}"
            elif error_code == "AccessDenied":
                msg = f"Access denied reading s3://{bucket}/{key} — check IAM permissions for s3:GetObject"
            else:
                msg = f"S3 error ({error_code}): {e.response.get('Error', {}).get('Message', str(e))}"
            log.error("S3 state read failed", bucket=bucket, key=key, error=msg)
            return StateReadResult(success=False, error=msg)
        except json.JSONDecodeError as e:
            return StateReadResult(success=False, error=f"State file is not valid JSON: {e}")
        except Exception as e:
            log.error("Unexpected error reading S3 state", error=str(e))
            return StateReadResult(success=False, error=f"Unexpected error: {e}")

    def check_lock(self, bucket: str, key: str, region: str, dynamodb_table: str | None) -> bool:
        """
        Checks if the state is currently locked via DynamoDB (standard Terraform
        S3 backend locking mechanism). Returns True if locked.
        DriftGuard reads state regardless of lock (read-only), but surfaces
        lock status so the UI can warn that a Terraform operation is in progress.
        """
        if not dynamodb_table:
            return False
        try:
            ddb = self.session.client("dynamodb", region_name=region)
            lock_id = f"{bucket}/{key}"
            response = ddb.get_item(
                TableName=dynamodb_table,
                Key={"LockID": {"S": lock_id}},
            )
            return "Item" in response
        except Exception as e:
            log.warning("Could not check state lock", error=str(e))
            return False
