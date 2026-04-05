"""
Handles AWS credential loading and validation.

Supports profile-based auth from ~/.aws/ and the full boto3 default chain
(env vars, default profile, instance metadata). Validates credentials
by calling STS GetCallerIdentity before any scan begins.
"""

import boto3
import botocore.exceptions


def load_session(profile=None, region=None):
    """
    Build a boto3 session. If profile is provided, load that specific profile.
    Otherwise fall back to the default boto3 credential chain.

    Returns the session on success, None on failure.
    """
    try:
        kwargs = {}
        if profile:
            kwargs["profile_name"] = profile
        if region:
            kwargs["region_name"] = region
        return boto3.Session(**kwargs)
    except botocore.exceptions.ProfileNotFound:
        return None
    except Exception:
        return None


def validate(session):
    """
    Confirm the session credentials are valid by calling STS GetCallerIdentity.
    Returns a dict with Account, Arn, and UserId on success, None otherwise.
    """
    try:
        sts = session.client("sts")
        resp = sts.get_caller_identity()
        return {
            "Account": resp.get("Account"),
            "Arn": resp.get("Arn"),
            "UserId": resp.get("UserId"),
        }
    except Exception:
        return None


def list_profiles():
    """Return all profile names found in ~/.aws/credentials and ~/.aws/config."""
    try:
        return boto3.Session().available_profiles
    except Exception:
        return []


def get_region(session):
    """Return the region this session is configured for, defaulting to us-east-1."""
    return session.region_name or "us-east-1"


def get_enabled_regions(session):
    """
    Query EC2 for all regions enabled on this account.
    Falls back to just the session region if the call fails.
    """
    try:
        ec2 = session.client("ec2")
        resp = ec2.describe_regions(AllRegions=False)
        return [r["RegionName"] for r in resp.get("Regions", [])]
    except Exception:
        return [get_region(session)]
