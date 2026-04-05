"""
Deep enumeration: second-pass resource chaining.

After the surface scan discovers resources, deep mode pulls their full
configurations. Each chain function takes the session and quick-scan results,
iterates over discovered resources, and pulls detailed data that the surface
scan cannot reach (bucket policies, IAM trust documents, Lambda env vars, etc).
"""

import json
import base64
import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

import botocore.exceptions


def _serial(obj):
    if isinstance(obj, (datetime.datetime, datetime.date)):
        return obj.isoformat()
    if isinstance(obj, bytes):
        try:
            return obj.decode("utf-8")
        except UnicodeDecodeError:
            return "<binary>"
    return str(obj)


def _safe(data):
    return json.loads(json.dumps(data, default=_serial))


def _get_call_data(svc_result, method_name):
    """Pull data from a specific method in a ServiceResult object."""
    for call in svc_result.calls:
        if call.method == method_name and call.status == "ok" and call.data:
            return call.data
    return None


def _try(func, default=None):
    """
    Run a callable and swallow any exception.
    Used for optional API calls where failure should not stop the chain.
    """
    try:
        result = func()
        if isinstance(result, dict):
            result.pop("ResponseMetadata", None)
        return _safe(result)
    except Exception:
        return default


# ---------------------------------------------------------------------------
# Chain: S3
# ---------------------------------------------------------------------------

def chain_s3(session, quick):
    """Pull ACL, policy, public access block, encryption, versioning, and website config for each bucket."""
    svc = quick.get("s3")
    if not svc:
        return None

    buckets = _get_call_data(svc, "list_buckets")
    if not buckets:
        return None

    s3 = session.client("s3")
    enriched = []

    for bucket in buckets:
        name = bucket.get("Name")
        if not name:
            continue

        entry = {"Name": name, "CreationDate": bucket.get("CreationDate")}
        entry["Acl"] = _try(lambda: s3.get_bucket_acl(Bucket=name))
        entry["Policy"] = _try(lambda: s3.get_bucket_policy(Bucket=name))
        entry["PublicAccessBlock"] = _try(lambda: s3.get_public_access_block(Bucket=name))
        entry["Encryption"] = _try(lambda: s3.get_bucket_encryption(Bucket=name))
        entry["Versioning"] = _try(lambda: s3.get_bucket_versioning(Bucket=name))
        entry["Logging"] = _try(lambda: s3.get_bucket_logging(Bucket=name))
        entry["Website"] = _try(lambda: s3.get_bucket_website(Bucket=name))
        enriched.append(entry)

    return enriched


# ---------------------------------------------------------------------------
# Shared: managed policy document fetcher
# ---------------------------------------------------------------------------

def _fetch_managed_policy_doc(iam, policy_arn):
    """Fetch the active version's policy document for a managed policy ARN."""
    try:
        meta = iam.get_policy(PolicyArn=policy_arn)
        version_id = meta["Policy"]["DefaultVersionId"]
        version = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
        doc = version.get("PolicyVersion", {}).get("Document")
        return _safe(doc) if doc else None
    except Exception:
        return None


def _fetch_policy_version_doc(iam, policy_arn, version_id):
    """Fetch a specific version's policy document."""
    try:
        resp = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
        doc = resp.get("PolicyVersion", {}).get("Document")
        return _safe(doc) if doc else None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Chain: IAM Users
# ---------------------------------------------------------------------------

def chain_iam_users(session, quick):
    """Pull access keys, MFA, policies, groups, login profile, and full policy documents for each IAM user."""
    svc = quick.get("iam")
    if not svc:
        return None

    users = _get_call_data(svc, "list_users")
    if not users:
        return None

    iam = session.client("iam")
    enriched = []

    for user in users:
        uname = user.get("UserName")
        if not uname:
            continue

        entry = dict(user)
        entry["AccessKeys"] = _try(lambda: iam.list_access_keys(UserName=uname).get("AccessKeyMetadata", []))
        entry["MFADevices"] = _try(lambda: iam.list_mfa_devices(UserName=uname).get("MFADevices", []))
        entry["InlinePolicies"] = _try(lambda: iam.list_user_policies(UserName=uname).get("PolicyNames", []))
        entry["AttachedPolicies"] = _try(lambda: iam.list_attached_user_policies(UserName=uname).get("AttachedPolicies", []))
        entry["Groups"] = _try(lambda: iam.list_groups_for_user(UserName=uname).get("Groups", []))
        entry["LoginProfile"] = _try(lambda: iam.get_login_profile(UserName=uname).get("LoginProfile"))

        # fetch inline policy documents
        inline_names = entry.get("InlinePolicies") or []
        entry["InlinePolicyDocuments"] = {}
        for pname in inline_names:
            doc = _try(lambda: iam.get_user_policy(UserName=uname, PolicyName=pname).get("PolicyDocument"))
            if doc:
                entry["InlinePolicyDocuments"][pname] = doc

        # fetch managed policy documents
        entry["AttachedPolicyDocuments"] = {}
        for pol in (entry.get("AttachedPolicies") or []):
            arn = pol.get("PolicyArn")
            if arn:
                doc = _fetch_managed_policy_doc(iam, arn)
                if doc:
                    entry["AttachedPolicyDocuments"][arn] = doc

        enriched.append(entry)

    return enriched


# ---------------------------------------------------------------------------
# Chain: IAM Roles
# ---------------------------------------------------------------------------

def chain_iam_roles(session, quick):
    """Pull trust policy, attached policies, inline policy documents, and managed policy documents for each role."""
    svc = quick.get("iam")
    if not svc:
        return None

    roles = _get_call_data(svc, "list_roles")
    if not roles:
        return None

    iam = session.client("iam")
    enriched = []

    for role in roles:
        rname = role.get("RoleName")
        if not rname:
            continue

        entry = dict(role)
        entry["TrustPolicy"] = role.get("AssumeRolePolicyDocument")
        entry["InlinePolicies"] = _try(lambda: iam.list_role_policies(RoleName=rname).get("PolicyNames", []))
        entry["AttachedPolicies"] = _try(lambda: iam.list_attached_role_policies(RoleName=rname).get("AttachedPolicies", []))

        # fetch the actual policy document for each inline policy
        inline_names = entry.get("InlinePolicies") or []
        entry["InlinePolicyDocuments"] = {}
        for pname in inline_names:
            doc = _try(lambda: iam.get_role_policy(RoleName=rname, PolicyName=pname).get("PolicyDocument"))
            if doc:
                entry["InlinePolicyDocuments"][pname] = doc

        # fetch managed policy documents
        entry["AttachedPolicyDocuments"] = {}
        for pol in (entry.get("AttachedPolicies") or []):
            arn = pol.get("PolicyArn")
            if arn:
                doc = _fetch_managed_policy_doc(iam, arn)
                if doc:
                    entry["AttachedPolicyDocuments"][arn] = doc

        enriched.append(entry)

    return enriched


# ---------------------------------------------------------------------------
# Chain: Lambda
# ---------------------------------------------------------------------------

def chain_lambda(session, quick):
    """Pull full function config (including env vars), resource policy, and tags."""
    svc = quick.get("lambda")
    if not svc:
        return None

    functions = _get_call_data(svc, "list_functions")
    if not functions:
        return None

    lmb = session.client("lambda")
    enriched = []

    for fn in functions:
        fname = fn.get("FunctionName")
        if not fname:
            continue

        entry = dict(fn)
        full = _try(lambda: lmb.get_function(FunctionName=fname))
        if full:
            entry["FullConfig"] = full.get("Configuration")
            entry["Tags"] = full.get("Tags")
            entry["CodeLocation"] = full.get("Code", {}).get("Location")

        entry["Policy"] = _try(lambda: json.loads(lmb.get_policy(FunctionName=fname).get("Policy", "{}")))
        enriched.append(entry)

    return enriched


# ---------------------------------------------------------------------------
# Chain: EC2 User Data
# ---------------------------------------------------------------------------

def chain_ec2_userdata(session, quick):
    """Pull instance user data, which frequently contains bootstrap secrets."""
    svc = quick.get("ec2")
    if not svc:
        return None

    reservations = _get_call_data(svc, "describe_instances")
    if not reservations:
        return None

    ec2 = session.client("ec2")
    enriched = []

    for res in reservations:
        instances = res.get("Instances", []) if isinstance(res, dict) else []
        for inst in instances:
            iid = inst.get("InstanceId")
            if not iid:
                continue

            entry = {
                "InstanceId": iid,
                "State": inst.get("State", {}).get("Name"),
                "PublicIp": inst.get("PublicIpAddress"),
                "PrivateIp": inst.get("PrivateIpAddress"),
                "SecurityGroups": inst.get("SecurityGroups"),
                "SubnetId": inst.get("SubnetId"),
                "VpcId": inst.get("VpcId"),
                "IamProfile": inst.get("IamInstanceProfile"),
            }

            ud = _try(lambda: ec2.describe_instance_attribute(InstanceId=iid, Attribute="userData"))
            if ud and ud.get("UserData", {}).get("Value"):
                try:
                    entry["UserData"] = base64.b64decode(ud["UserData"]["Value"]).decode("utf-8", errors="replace")
                except Exception:
                    entry["UserData"] = ud["UserData"]["Value"]
            else:
                entry["UserData"] = None

            enriched.append(entry)

    return enriched


# ---------------------------------------------------------------------------
# Chain: CloudTrail
# ---------------------------------------------------------------------------

def chain_cloudtrail(session, quick):
    """Pull trail status and event selectors for each trail."""
    svc = quick.get("cloudtrail")
    if not svc:
        return None

    trails = _get_call_data(svc, "describe_trails")
    if not trails:
        return None

    ct = session.client("cloudtrail")
    enriched = []

    for trail in trails:
        name = trail.get("Name") or trail.get("TrailARN")
        if not name:
            continue

        entry = dict(trail)
        entry["Status"] = _try(lambda: ct.get_trail_status(Name=name))
        entry["EventSelectors"] = _try(lambda: ct.get_event_selectors(TrailName=name).get("EventSelectors"))
        enriched.append(entry)

    return enriched


# ---------------------------------------------------------------------------
# Chain: KMS
# ---------------------------------------------------------------------------

def chain_kms(session, quick):
    """Pull key metadata, key policy, and rotation status for each KMS key."""
    svc = quick.get("kms")
    if not svc:
        return None

    keys = _get_call_data(svc, "list_keys")
    if not keys:
        return None

    kms_client = session.client("kms")
    enriched = []

    for key in keys:
        kid = key.get("KeyId")
        if not kid:
            continue

        entry = {"KeyId": kid, "KeyArn": key.get("KeyArn")}
        entry["Description"] = _try(lambda: kms_client.describe_key(KeyId=kid).get("KeyMetadata"))
        entry["Policy"] = _try(lambda: kms_client.get_key_policy(KeyId=kid, PolicyName="default").get("Policy"))
        entry["RotationEnabled"] = _try(lambda: kms_client.get_key_rotation_status(KeyId=kid).get("KeyRotationEnabled"))
        enriched.append(entry)

    return enriched


# ---------------------------------------------------------------------------
# Chain: ECS
# ---------------------------------------------------------------------------

def chain_ecs(session, quick):
    """Pull full task definitions, which may contain secrets and env vars."""
    svc = quick.get("ecs")
    if not svc:
        return None

    task_defs = _get_call_data(svc, "list_task_definitions")
    if not task_defs:
        return None

    ecs_client = session.client("ecs")
    enriched = []

    for arn in task_defs[:50]:  # cap to avoid hammering the API
        td = _try(lambda: ecs_client.describe_task_definition(taskDefinition=arn).get("taskDefinition"))
        if td:
            enriched.append(td)

    return enriched


# ---------------------------------------------------------------------------
# Chain: CloudFormation
# ---------------------------------------------------------------------------

def chain_cloudformation(session, quick):
    """Pull full stack details including outputs and parameters for active stacks."""
    svc = quick.get("cloudformation")
    if not svc:
        return None

    stacks = _get_call_data(svc, "list_stacks")
    if not stacks:
        return None

    cfn = session.client("cloudformation")
    active = [s for s in stacks if s.get("StackStatus") != "DELETE_COMPLETE"]
    enriched = []

    for stack in active[:50]:
        sname = stack.get("StackName")
        if not sname:
            continue
        detail = _try(lambda: cfn.describe_stacks(StackName=sname).get("Stacks", [None])[0])
        if detail:
            enriched.append(detail)

    return enriched


# ---------------------------------------------------------------------------
# Chain: RDS
# ---------------------------------------------------------------------------

def chain_rds(session, quick):
    """Extract security-relevant fields from RDS instance data."""
    svc = quick.get("rds")
    if not svc:
        return None

    instances = _get_call_data(svc, "describe_db_instances")
    if not instances:
        return None

    # describe_db_instances already returns full detail, just restructure for clarity
    enriched = []
    for inst in instances:
        enriched.append({
            "DBInstanceIdentifier": inst.get("DBInstanceIdentifier"),
            "Engine": inst.get("Engine"),
            "EngineVersion": inst.get("EngineVersion"),
            "PubliclyAccessible": inst.get("PubliclyAccessible"),
            "Endpoint": inst.get("Endpoint"),
            "StorageEncrypted": inst.get("StorageEncrypted"),
            "VpcSecurityGroups": inst.get("VpcSecurityGroups"),
            "DBSubnetGroup": inst.get("DBSubnetGroup", {}).get("DBSubnetGroupName"),
            "MasterUsername": inst.get("MasterUsername"),
            "MultiAZ": inst.get("MultiAZ"),
            "DeletionProtection": inst.get("DeletionProtection"),
            "IAMDatabaseAuthenticationEnabled": inst.get("IAMDatabaseAuthenticationEnabled"),
            "BackupRetentionPeriod": inst.get("BackupRetentionPeriod"),
        })
    return enriched


# ---------------------------------------------------------------------------
# Helpers: policy document analysis
# ---------------------------------------------------------------------------

def _extract_statements(doc):
    """Extract simplified statements from a policy document."""
    if not doc or not isinstance(doc, dict):
        return []
    stmts = []
    for stmt in doc.get("Statement", []):
        if not isinstance(stmt, dict):
            continue
        actions = stmt.get("Action", [])
        resources = stmt.get("Resource", [])
        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]
        entry = {"Effect": stmt.get("Effect", ""), "Actions": actions, "Resources": resources}
        if stmt.get("Condition"):
            entry["Condition"] = True
        stmts.append(entry)
    return stmts


def _identity_matches_trust(identity_arn, account, trust_doc):
    """Check if an identity ARN is allowed by a role's trust policy."""
    if not trust_doc or not isinstance(trust_doc, dict):
        return False
    for stmt in trust_doc.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        if not any(a in ("sts:AssumeRole", "sts:*", "*") for a in actions):
            continue
        principal = stmt.get("Principal", {})
        if principal == "*":
            return True
        if isinstance(principal, dict):
            aws_p = principal.get("AWS", [])
            if isinstance(aws_p, str):
                aws_p = [aws_p]
            for p in aws_p:
                if p == "*":
                    return True
                if p == identity_arn:
                    return True
                if p == f"arn:aws:iam::{account}:root":
                    return True
                # for assumed-role identities, also check the underlying role ARN
                if ":assumed-role/" in identity_arn:
                    rn = identity_arn.split(":assumed-role/")[-1].split("/")[0]
                    if p == f"arn:aws:iam::{account}:role/{rn}":
                        return True
    return False


# ---------------------------------------------------------------------------
# Chain: IAM Self (identity-aware recon)
# ---------------------------------------------------------------------------

def chain_iam_self(session, quick):
    """
    Full identity permission mapping: enumerate every policy on the current
    principal, parse their documents, discover assumable roles, and enumerate
    those roles' policies too. This is the core recon chain.
    """
    sts_svc = quick.get("sts")
    if not sts_svc:
        return None

    identity = None
    for c in sts_svc.calls:
        if c.method == "get_caller_identity" and c.status == "ok" and c.data:
            identity = c.data
            break
    if not identity:
        return None

    arn = identity.get("Arn", "")
    account = identity.get("Account", "")
    iam = session.client("iam")

    result = {
        "Arn": arn,
        "Account": account,
        "Type": "unknown",
        "Principal": "",
        "Groups": [],
        "Policies": [],
        "AssumableRoles": [],
    }

    if ":user/" in arn:
        username = arn.rsplit("/", 1)[-1]
        result["Type"] = "user"
        result["Principal"] = username
        _enum_self_user(iam, username, result)
    elif ":assumed-role/" in arn:
        role_name = arn.split(":assumed-role/")[-1].split("/")[0]
        result["Type"] = "assumed-role"
        result["Principal"] = role_name
        _enum_self_role(iam, role_name, result)
    elif ":role/" in arn:
        role_name = arn.rsplit("/", 1)[-1]
        result["Type"] = "role"
        result["Principal"] = role_name
        _enum_self_role(iam, role_name, result)
    else:
        return result

    _discover_assumable_roles(iam, arn, account, quick, result)
    result["PrivescPaths"] = _detect_privesc(result)
    return result


# ---------------------------------------------------------------------------
# Privilege escalation detection
# ---------------------------------------------------------------------------

_PRIVESC_TECHNIQUES = {
    "iam:SetDefaultPolicyVersion": {
        "name": "Policy Version Rollback",
        "desc": "Switch a managed policy to an older version that may grant more permissions",
        "severity": "HIGH",
    },
    "iam:CreatePolicyVersion": {
        "name": "Policy Version Injection",
        "desc": "Create a new policy version with arbitrary permissions",
        "severity": "CRITICAL",
    },
    "iam:AttachUserPolicy": {
        "name": "User Policy Attachment",
        "desc": "Attach any managed policy (e.g. AdministratorAccess) to a user",
        "severity": "CRITICAL",
    },
    "iam:AttachRolePolicy": {
        "name": "Role Policy Attachment",
        "desc": "Attach any managed policy to a role",
        "severity": "CRITICAL",
    },
    "iam:AttachGroupPolicy": {
        "name": "Group Policy Attachment",
        "desc": "Attach any managed policy to a group you belong to",
        "severity": "CRITICAL",
    },
    "iam:PutUserPolicy": {
        "name": "User Inline Policy Injection",
        "desc": "Create an inline policy with arbitrary permissions on a user",
        "severity": "CRITICAL",
    },
    "iam:PutRolePolicy": {
        "name": "Role Inline Policy Injection",
        "desc": "Create an inline policy with arbitrary permissions on a role",
        "severity": "CRITICAL",
    },
    "iam:PutGroupPolicy": {
        "name": "Group Inline Policy Injection",
        "desc": "Create an inline policy with arbitrary permissions on a group",
        "severity": "CRITICAL",
    },
    "iam:AddUserToGroup": {
        "name": "Group Membership Escalation",
        "desc": "Add a user to a group that may have higher privileges",
        "severity": "HIGH",
    },
    "iam:CreateLoginProfile": {
        "name": "Console Access Creation",
        "desc": "Create console login credentials for a user",
        "severity": "HIGH",
    },
    "iam:UpdateLoginProfile": {
        "name": "Console Password Change",
        "desc": "Change the console password for a user",
        "severity": "HIGH",
    },
    "iam:CreateAccessKey": {
        "name": "Access Key Creation",
        "desc": "Create programmatic access keys for a user",
        "severity": "HIGH",
    },
    "iam:UpdateAssumeRolePolicy": {
        "name": "Trust Policy Modification",
        "desc": "Modify a role's trust policy to allow your identity to assume it",
        "severity": "CRITICAL",
    },
    "iam:PassRole": {
        "name": "Role Passing",
        "desc": "Pass a role to an AWS service (Lambda, EC2, etc.) to execute as that role",
        "severity": "HIGH",
    },
}


def _action_matches(pattern, target):
    """Check if an IAM action pattern matches a specific action. Handles wildcards."""
    if pattern == "*" or pattern == target:
        return True
    if pattern.endswith(":*"):
        return target.startswith(pattern[:-1])
    if "*" in pattern:
        return target.startswith(pattern.replace("*", ""))
    return False


def _detect_privesc(result):
    """Scan effective policies for known privilege escalation paths."""
    paths = []
    seen = set()

    all_policies = list(result.get("Policies", []))
    for role in result.get("AssumableRoles", []):
        for rpol in role.get("Policies", []):
            all_policies.append({**rpol, "_via_role": role.get("RoleName", "")})

    for pol in all_policies:
        via_role = pol.get("_via_role", "")
        for stmt in pol.get("Statements", []):
            if stmt["Effect"] != "Allow":
                continue
            for action in stmt.get("Actions", []):
                for privesc_action, info in _PRIVESC_TECHNIQUES.items():
                    if not _action_matches(action, privesc_action):
                        continue
                    dedup_key = (privesc_action, pol["Name"], via_role)
                    if dedup_key in seen:
                        continue
                    seen.add(dedup_key)

                    path = {
                        "Action": privesc_action,
                        "Name": info["name"],
                        "Description": info["desc"],
                        "Severity": info["severity"],
                        "ViaPolicy": pol["Name"],
                        "ViaRole": via_role,
                        "Resources": stmt.get("Resources", []),
                    }

                    # for SetDefaultPolicyVersion, attach the alternate versions
                    if privesc_action == "iam:SetDefaultPolicyVersion":
                        path["AlternateVersions"] = _collect_alternate_versions(
                            result, stmt.get("Resources", []))

                    paths.append(path)

    paths.sort(key=lambda p: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}.get(p["Severity"], 9))
    return paths


def _collect_alternate_versions(result, resources):
    """Find alternate policy versions for policies matching the given resource ARNs."""
    alternates = []
    for pol in result.get("Policies", []):
        pol_arn = pol.get("Arn", "")
        if not pol_arn or not pol.get("AlternateVersions"):
            continue
        for res in resources:
            if res == "*" or pol_arn == res or (res.endswith("*") and pol_arn.startswith(res[:-1])):
                for ver in pol["AlternateVersions"]:
                    alternates.append({
                        "PolicyName": pol["Name"],
                        "PolicyArn": pol_arn,
                        "VersionId": ver["VersionId"],
                        "Statements": ver["Statements"],
                    })
                break
    return alternates


def _build_managed_policy_entry(iam, policy_name, policy_arn, attached_to):
    """Build a policy entry for a managed policy, including alternate versions."""
    doc = _fetch_managed_policy_doc(iam, policy_arn)
    entry = {
        "Name": policy_name, "Arn": policy_arn,
        "Type": "aws-managed" if "::aws:" in policy_arn else "customer-managed",
        "AttachedTo": attached_to,
        "Statements": _extract_statements(doc),
    }

    # fetch ALL versions — non-default versions may have different permissions
    versions = _try(lambda: iam.list_policy_versions(PolicyArn=policy_arn).get("Versions", [])) or []
    alt_versions = []
    for ver in versions:
        if ver.get("IsDefaultVersion"):
            continue
        vid = ver.get("VersionId", "")
        vdoc = _fetch_policy_version_doc(iam, policy_arn, vid)
        if vdoc:
            alt_versions.append({
                "VersionId": vid,
                "CreateDate": ver.get("CreateDate"),
                "Statements": _extract_statements(vdoc),
            })
    if alt_versions:
        entry["AlternateVersions"] = alt_versions

    return entry


def _enum_self_user(iam, username, result):
    """Enumerate all policies for the current user identity."""
    # inline policies
    inline_names = _try(lambda: iam.list_user_policies(UserName=username).get("PolicyNames", [])) or []
    for pname in inline_names:
        doc = _try(lambda: iam.get_user_policy(UserName=username, PolicyName=pname).get("PolicyDocument"))
        result["Policies"].append({
            "Name": pname, "Type": "inline", "AttachedTo": f"user/{username}",
            "Statements": _extract_statements(doc),
        })

    # attached managed policies (with alternate version enumeration)
    attached = _try(lambda: iam.list_attached_user_policies(UserName=username).get("AttachedPolicies", [])) or []
    for pol in attached:
        pa = pol.get("PolicyArn", "")
        entry = _build_managed_policy_entry(iam, pol.get("PolicyName", ""), pa, f"user/{username}")
        result["Policies"].append(entry)

    # group memberships and their policies
    groups = _try(lambda: iam.list_groups_for_user(UserName=username).get("Groups", [])) or []
    for group in groups:
        gname = group.get("GroupName", "")
        result["Groups"].append(gname)

        g_inline = _try(lambda: iam.list_group_policies(GroupName=gname).get("PolicyNames", [])) or []
        for gpname in g_inline:
            doc = _try(lambda: iam.get_group_policy(GroupName=gname, PolicyName=gpname).get("PolicyDocument"))
            result["Policies"].append({
                "Name": gpname, "Type": "inline", "AttachedTo": f"group/{gname}",
                "Statements": _extract_statements(doc),
            })

        g_attached = _try(lambda: iam.list_attached_group_policies(GroupName=gname).get("AttachedPolicies", [])) or []
        for pol in g_attached:
            pa = pol.get("PolicyArn", "")
            entry = _build_managed_policy_entry(iam, pol.get("PolicyName", ""), pa, f"group/{gname}")
            result["Policies"].append(entry)


def _enum_self_role(iam, role_name, result):
    """Enumerate all policies for the current role identity."""
    inline_names = _try(lambda: iam.list_role_policies(RoleName=role_name).get("PolicyNames", [])) or []
    for pname in inline_names:
        doc = _try(lambda: iam.get_role_policy(RoleName=role_name, PolicyName=pname).get("PolicyDocument"))
        result["Policies"].append({
            "Name": pname, "Type": "inline", "AttachedTo": f"role/{role_name}",
            "Statements": _extract_statements(doc),
        })

    attached = _try(lambda: iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", [])) or []
    for pol in attached:
        pa = pol.get("PolicyArn", "")
        entry = _build_managed_policy_entry(iam, pol.get("PolicyName", ""), pa, f"role/{role_name}")
        result["Policies"].append(entry)


def _discover_assumable_roles(iam, identity_arn, account, quick, result):
    """Find roles this identity can assume, then enumerate their policies."""
    assumable = {}  # arn -> reason

    # 1) scan our own policy statements for sts:AssumeRole
    for pol in result["Policies"]:
        for stmt in pol.get("Statements", []):
            if stmt["Effect"] != "Allow":
                continue
            if not any(a in ("sts:AssumeRole", "sts:*", "*") for a in stmt.get("Actions", [])):
                continue
            for res in stmt.get("Resources", []):
                if ":role/" in res and res != "*":
                    assumable[res] = f"policy '{pol['Name']}' grants sts:AssumeRole"

    # 2) check trust policies of roles discovered in the surface scan
    iam_svc = quick.get("iam")
    if iam_svc:
        roles_data = _get_call_data(iam_svc, "list_roles")
        for role in (roles_data or []):
            role_arn = role.get("Arn", "")
            trust = role.get("AssumeRolePolicyDocument", {})
            if _identity_matches_trust(identity_arn, account, trust):
                if role_arn not in assumable:
                    assumable[role_arn] = "trust policy allows this identity"

    # skip our own role if we're already in it
    own_role_arn = None
    if result["Type"] in ("role", "assumed-role"):
        own_role_arn = f"arn:aws:iam::{account}:role/{result['Principal']}"

    for role_arn, reason in assumable.items():
        if role_arn == own_role_arn:
            continue

        role_name = role_arn.rsplit("/", 1)[-1] if "/" in role_arn else role_arn
        role_info = _try(lambda: iam.get_role(RoleName=role_name))
        role_meta = (role_info or {}).get("Role", {})

        role_entry = {
            "RoleName": role_name,
            "Arn": role_arn,
            "Reason": reason,
            "Description": role_meta.get("Description", ""),
            "TrustPolicy": role_meta.get("AssumeRolePolicyDocument"),
            "Policies": [],
        }

        # role inline policies
        r_inline = _try(lambda: iam.list_role_policies(RoleName=role_name).get("PolicyNames", [])) or []
        for pname in r_inline:
            doc = _try(lambda: iam.get_role_policy(RoleName=role_name, PolicyName=pname).get("PolicyDocument"))
            role_entry["Policies"].append({
                "Name": pname, "Type": "inline",
                "Statements": _extract_statements(doc),
            })

        # role attached policies
        r_attached = _try(lambda: iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", [])) or []
        for pol in r_attached:
            pa = pol.get("PolicyArn", "")
            doc = _fetch_managed_policy_doc(iam, pa)
            role_entry["Policies"].append({
                "Name": pol.get("PolicyName", ""), "Arn": pa,
                "Type": "aws-managed" if "::aws:" in pa else "customer-managed",
                "Statements": _extract_statements(doc),
            })

        result["AssumableRoles"].append(role_entry)


# ---------------------------------------------------------------------------
# Registry and orchestrator
# ---------------------------------------------------------------------------

CHAINS = {
    "s3": chain_s3,
    "iam_users": chain_iam_users,
    "iam_roles": chain_iam_roles,
    "iam_self": chain_iam_self,
    "lambda": chain_lambda,
    "ec2_userdata": chain_ec2_userdata,
    "cloudtrail": chain_cloudtrail,
    "kms": chain_kms,
    "ecs": chain_ecs,
    "cloudformation": chain_cloudformation,
    "rds": chain_rds,
}


def run_deep(session, quick_results, workers=10, on_result=None):
    """
    Run all deep chains in parallel against the quick scan results.
    Returns a dict mapping chain names to their enriched data (or None).
    """
    deep_results = {}

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {}
        for name, func in CHAINS.items():
            f = pool.submit(func, session, quick_results)
            futures[f] = name

        for f in as_completed(futures):
            name = futures[f]
            try:
                data = f.result()
            except Exception:
                data = None

            deep_results[name] = data
            if on_result:
                count = len(data) if data else 0
                on_result(name, count)

    return deep_results
