"""
Security audit engine.

Runs detection rules against quick scan + deep enumeration results and produces
a list of findings sorted by severity. Each rule is a function that inspects
collected data and appends Finding objects when it spots something wrong.
"""

import json
import re
from datetime import datetime, timezone


SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW = "LOW"
SEVERITY_INFO = "INFO"


class Finding:
    __slots__ = ("severity", "service", "resource", "title", "detail", "recommendation")

    def __init__(self, severity, service, resource, title, detail="", recommendation=""):
        self.severity = severity
        self.service = service
        self.resource = resource
        self.title = title
        self.detail = detail
        self.recommendation = recommendation

    def to_dict(self):
        return {k: getattr(self, k) for k in self.__slots__}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_data(quick, svc, method):
    """Extract call data from a quick-scan ServiceResult."""
    sr = quick.get(svc)
    if not sr:
        return None
    for c in sr.calls:
        if c.method == method and c.status == "ok" and c.data:
            return c.data
    return None


_SECRET_PATTERNS = [
    re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*\S+"),
    re.compile(r"(?i)(secret|token|api[_-]?key)\s*[:=]\s*\S+"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"(?i)(db_password|database_password|mysql_pwd|pg_password)\s*[:=]\s*\S+"),
    re.compile(r"(?i)(aws_secret_access_key)\s*[:=]\s*\S+"),
    re.compile(r"(?i)(private[_-]?key|BEGIN RSA PRIVATE KEY|BEGIN OPENSSH PRIVATE KEY)"),
]

_SENSITIVE_PORTS = {
    22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL",
    1433: "MSSQL", 27017: "MongoDB", 6379: "Redis", 9200: "Elasticsearch",
    5900: "VNC", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
}


def _detect_secrets(text):
    """Return matched pattern descriptions if text contains credential-like content."""
    if not text or not isinstance(text, str):
        return []
    return [p.pattern for p in _SECRET_PATTERNS if p.search(text)]


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

def _rule_s3_public(quick, deep, findings):
    """Flag S3 buckets with public access, missing encryption, or website hosting."""
    buckets = deep.get("s3")
    if not buckets:
        return

    for b in buckets:
        name = b.get("Name", "?")
        res = f"s3://{name}"

        # public access block
        pab = b.get("PublicAccessBlock")
        if pab is None:
            findings.append(Finding(SEVERITY_HIGH, "s3", res,
                "No Public Access Block configured",
                "Bucket has no S3 Block Public Access settings",
                "Enable S3 Block Public Access at the bucket level"))
        else:
            cfg = pab.get("PublicAccessBlockConfiguration", {})
            if not all([cfg.get("BlockPublicAcls"), cfg.get("IgnorePublicAcls"),
                        cfg.get("BlockPublicPolicy"), cfg.get("RestrictPublicBuckets")]):
                findings.append(Finding(SEVERITY_HIGH, "s3", res,
                    "Public Access Block partially disabled",
                    f"Config: {json.dumps(cfg)}",
                    "Enable all four Public Access Block settings"))

        # ACL grants
        acl = b.get("Acl")
        if acl:
            for grant in acl.get("Grants", []):
                uri = grant.get("Grantee", {}).get("URI", "")
                if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                    findings.append(Finding(SEVERITY_CRITICAL, "s3", res,
                        f"Public ACL grant: {grant.get('Permission', '?')}",
                        f"Grantee: {uri}",
                        "Remove public ACL grants"))

        # bucket policy
        policy = b.get("Policy")
        if policy:
            ps = json.dumps(policy) if isinstance(policy, dict) else str(policy)
            if '"*"' in ps and '"Effect":"Allow"' in ps.replace(" ", "").replace("'", '"'):
                findings.append(Finding(SEVERITY_CRITICAL, "s3", res,
                    "Bucket policy allows public access",
                    "Policy contains Principal: * with Effect: Allow",
                    "Restrict the bucket policy to specific principals"))

        if b.get("Encryption") is None:
            findings.append(Finding(SEVERITY_MEDIUM, "s3", res,
                "No default encryption configured", "",
                "Enable SSE-S3 or SSE-KMS default encryption"))

        if b.get("Website"):
            findings.append(Finding(SEVERITY_MEDIUM, "s3", res,
                "Static website hosting enabled",
                "Bucket is configured to serve content publicly",
                "Verify this is intentional"))


def _rule_sg_open(quick, deep, findings):
    """Flag security groups that allow 0.0.0.0/0 or ::/0 on sensitive ports."""
    sgs = _get_data(quick, "ec2", "describe_security_groups")
    if not sgs:
        return

    for sg in sgs:
        sgid = sg.get("GroupId", "?")
        sgname = sg.get("GroupName", "?")
        vpc = sg.get("VpcId", "?")

        for rule in sg.get("IpPermissions", []):
            proto = rule.get("IpProtocol", "")
            from_port = rule.get("FromPort", 0)
            to_port = rule.get("ToPort", 65535)

            cidrs = [r.get("CidrIp", "") for r in rule.get("IpRanges", [])]
            cidrs += [r.get("CidrIpv6", "") for r in rule.get("Ipv6Ranges", [])]
            open_cidrs = [c for c in cidrs if c in ("0.0.0.0/0", "::/0")]
            if not open_cidrs:
                continue

            if proto == "-1":
                findings.append(Finding(SEVERITY_CRITICAL, "ec2", f"{sgid} ({sgname})",
                    "Security group allows ALL traffic from the internet",
                    f"VPC: {vpc}, CIDR: {', '.join(open_cidrs)}",
                    "Restrict to specific ports and source CIDRs"))
                continue

            for port, label in _SENSITIVE_PORTS.items():
                if from_port <= port <= to_port:
                    findings.append(Finding(SEVERITY_HIGH, "ec2", f"{sgid} ({sgname})",
                        f"{label} (port {port}) open to the internet",
                        f"VPC: {vpc}, CIDR: {', '.join(open_cidrs)}",
                        f"Restrict {label} access to specific IPs or use a VPN"))


def _rule_iam_no_mfa(quick, deep, findings):
    """Flag IAM users that have console access but no MFA device."""
    users = deep.get("iam_users")
    if not users:
        return
    for user in users:
        uname = user.get("UserName", "?")
        has_console = user.get("LoginProfile") is not None
        has_mfa = bool(user.get("MFADevices"))
        if has_console and not has_mfa:
            findings.append(Finding(SEVERITY_HIGH, "iam", uname,
                "Console access without MFA",
                f"User {uname} can log in but has no MFA device",
                "Enable MFA for all console users"))


def _rule_iam_old_keys(quick, deep, findings):
    """Flag active access keys older than 90 days."""
    users = deep.get("iam_users")
    if not users:
        return
    now = datetime.now(timezone.utc)
    for user in users:
        for key in (user.get("AccessKeys") or []):
            if key.get("Status") != "Active":
                continue
            created = key.get("CreateDate")
            if not created:
                continue
            if isinstance(created, str):
                try:
                    created = datetime.fromisoformat(created.replace("Z", "+00:00"))
                except Exception:
                    continue
            age = (now - created).days
            if age > 90:
                findings.append(Finding(SEVERITY_MEDIUM, "iam",
                    f"{user.get('UserName', '?')} / {key.get('AccessKeyId', '?')}",
                    f"Access key is {age} days old",
                    f"Created: {created.isoformat()}", "Rotate access keys every 90 days"))


def _is_admin_doc(doc):
    """Check if a policy document contains Action:* Resource:* Allow statements."""
    if not doc or not isinstance(doc, dict):
        return False
    for stmt in doc.get("Statement", []):
        if not isinstance(stmt, dict):
            continue
        if stmt.get("Effect") != "Allow":
            continue
        act = stmt.get("Action", [])
        res = stmt.get("Resource", [])
        if (act == "*" or act == ["*"]) and (res == "*" or res == ["*"]):
            return True
    return False


def _policy_name_from_arn(arn):
    """Extract the human-readable policy name from an ARN."""
    if "/" in arn:
        return arn.rsplit("/", 1)[-1]
    return arn


# known high-risk AWS managed policies
_DANGEROUS_MANAGED_POLICIES = {
    "AdministratorAccess", "PowerUserAccess", "IAMFullAccess",
    "AmazonS3FullAccess", "AmazonEC2FullAccess", "AWSLambda_FullAccess",
    "AmazonRDSFullAccess", "AmazonDynamoDBFullAccess",
    "AmazonVPCFullAccess", "AWSKeyManagementServicePowerUser",
}


def _rule_iam_admin(quick, deep, findings):
    """Flag roles with inline or attached policies granting full admin or known dangerous policies."""
    roles = deep.get("iam_roles")
    if not roles:
        return
    for role in roles:
        rname = role.get("RoleName", "?")

        # check inline policies
        for pname, doc in (role.get("InlinePolicyDocuments") or {}).items():
            if _is_admin_doc(doc):
                findings.append(Finding(SEVERITY_CRITICAL, "iam", f"role/{rname}",
                    f"Inline policy '{pname}' grants full admin",
                    "Action: *, Resource: *", "Apply least-privilege policies"))

        # check attached managed policies
        for arn, doc in (role.get("AttachedPolicyDocuments") or {}).items():
            pname = _policy_name_from_arn(arn)
            if _is_admin_doc(doc):
                findings.append(Finding(SEVERITY_CRITICAL, "iam", f"role/{rname}",
                    f"Attached policy '{pname}' grants full admin",
                    f"Policy: {arn}", "Replace with least-privilege managed policies"))

        # flag known dangerous managed policy names
        for pol in (role.get("AttachedPolicies") or []):
            pname = pol.get("PolicyName", "")
            if pname in _DANGEROUS_MANAGED_POLICIES:
                findings.append(Finding(SEVERITY_HIGH, "iam", f"role/{rname}",
                    f"High-risk managed policy attached: {pname}",
                    f"ARN: {pol.get('PolicyArn', '?')}",
                    "Review whether this broad policy is necessary"))


def _rule_iam_user_policies(quick, deep, findings):
    """Flag IAM users with inline or attached policies granting full admin or known dangerous policies."""
    users = deep.get("iam_users")
    if not users:
        return
    for user in users:
        uname = user.get("UserName", "?")

        # check inline policies
        for pname, doc in (user.get("InlinePolicyDocuments") or {}).items():
            if _is_admin_doc(doc):
                findings.append(Finding(SEVERITY_CRITICAL, "iam", f"user/{uname}",
                    f"Inline policy '{pname}' grants full admin",
                    "Action: *, Resource: *", "Apply least-privilege policies"))

        # check attached managed policies
        for arn, doc in (user.get("AttachedPolicyDocuments") or {}).items():
            pname = _policy_name_from_arn(arn)
            if _is_admin_doc(doc):
                findings.append(Finding(SEVERITY_CRITICAL, "iam", f"user/{uname}",
                    f"Attached policy '{pname}' grants full admin",
                    f"Policy: {arn}", "Replace with least-privilege managed policies"))

        # flag known dangerous managed policy names
        for pol in (user.get("AttachedPolicies") or []):
            pname = pol.get("PolicyName", "")
            if pname in _DANGEROUS_MANAGED_POLICIES:
                findings.append(Finding(SEVERITY_HIGH, "iam", f"user/{uname}",
                    f"High-risk managed policy attached: {pname}",
                    f"ARN: {pol.get('PolicyArn', '?')}",
                    "Attach policies to groups instead of directly to users"))

        # flag direct policy attachment (best practice: use groups)
        attached = user.get("AttachedPolicies") or []
        inline = user.get("InlinePolicies") or []
        if attached or inline:
            count = len(attached) + len(inline)
            policy_names = [p.get("PolicyName", "?") for p in attached] + list(inline)
            findings.append(Finding(SEVERITY_LOW, "iam", f"user/{uname}",
                f"{count} policies attached directly to user",
                f"Policies: {', '.join(policy_names[:5])}" + (f" (+{count - 5} more)" if count > 5 else ""),
                "Attach policies to groups instead of directly to users"))


def _rule_iam_trust(quick, deep, findings):
    """Flag roles with wildcard or cross-account trust policies."""
    roles = deep.get("iam_roles")
    if not roles:
        return

    # determine our own account id for cross-account detection
    acct = None
    sts = quick.get("sts")
    if sts:
        for c in sts.calls:
            if c.method == "get_caller_identity" and c.status == "ok" and c.data:
                acct = c.data.get("Account")

    for role in roles:
        rname = role.get("RoleName", "?")
        trust = role.get("TrustPolicy")
        if not trust:
            continue
        for stmt in (trust.get("Statement", []) if isinstance(trust, dict) else []):
            if stmt.get("Effect") != "Allow":
                continue
            principal = stmt.get("Principal", {})
            if principal == "*":
                findings.append(Finding(SEVERITY_CRITICAL, "iam", f"role/{rname}",
                    "Trust policy allows any AWS principal", "Principal: *",
                    "Restrict trust to specific accounts or services"))
                continue
            aws_p = principal.get("AWS", []) if isinstance(principal, dict) else []
            if isinstance(aws_p, str):
                aws_p = [aws_p]
            for p in aws_p:
                if p == "*":
                    findings.append(Finding(SEVERITY_CRITICAL, "iam", f"role/{rname}",
                        "Trust policy allows any AWS principal", "Principal.AWS: *",
                        "Restrict to specific accounts"))
                elif acct and acct not in p and ":root" in p:
                    findings.append(Finding(SEVERITY_MEDIUM, "iam", f"role/{rname}",
                        "Cross-account trust detected", f"Trusted: {p}",
                        "Verify this cross-account trust is authorized"))


def _rule_rds_public(quick, deep, findings):
    """Flag publicly accessible or unencrypted RDS instances."""
    instances = deep.get("rds")
    if not instances:
        return
    for inst in instances:
        dbid = inst.get("DBInstanceIdentifier", "?")
        if inst.get("PubliclyAccessible"):
            findings.append(Finding(SEVERITY_HIGH, "rds", dbid,
                "RDS instance is publicly accessible",
                f"Engine: {inst.get('Engine')}, Endpoint: {inst.get('Endpoint', {}).get('Address', '?')}",
                "Disable public accessibility"))
        if not inst.get("StorageEncrypted"):
            findings.append(Finding(SEVERITY_MEDIUM, "rds", dbid,
                "RDS storage is not encrypted", f"Engine: {inst.get('Engine')}",
                "Enable encryption at rest"))
        if not inst.get("DeletionProtection"):
            findings.append(Finding(SEVERITY_LOW, "rds", dbid,
                "No deletion protection", "", "Enable deletion protection for production databases"))


def _rule_cloudtrail(quick, deep, findings):
    """Flag missing, disabled, or incomplete CloudTrail configuration."""
    trail_data = _get_data(quick, "cloudtrail", "describe_trails")
    if not trail_data:
        findings.append(Finding(SEVERITY_CRITICAL, "cloudtrail", "account",
            "No CloudTrail trails configured", "",
            "Enable CloudTrail with multi-region logging"))
        return

    trails = deep.get("cloudtrail")
    if not trails:
        return
    for trail in trails:
        name = trail.get("Name", "?")
        status = trail.get("Status", {})
        if status and not status.get("IsLogging"):
            findings.append(Finding(SEVERITY_CRITICAL, "cloudtrail", name,
                "CloudTrail logging is disabled", "",
                "Start logging immediately"))
        if not trail.get("IsMultiRegionTrail"):
            findings.append(Finding(SEVERITY_MEDIUM, "cloudtrail", name,
                "Trail is single-region only", "",
                "Enable multi-region logging"))
        if not trail.get("LogFileValidationEnabled"):
            findings.append(Finding(SEVERITY_LOW, "cloudtrail", name,
                "Log file validation disabled", "",
                "Enable log file validation to detect tampering"))


def _rule_lambda_secrets(quick, deep, findings):
    """Detect secrets in Lambda environment variable names and values."""
    functions = deep.get("lambda")
    if not functions:
        return
    _kw = ("PASSWORD", "SECRET", "TOKEN", "API_KEY", "PRIVATE_KEY", "DB_PASS", "APIKEY")
    for fn in functions:
        fname = fn.get("FunctionName", "?")
        cfg = fn.get("FullConfig") or fn
        env = (cfg.get("Environment") or {}).get("Variables", {})
        for vname, vval in env.items():
            if any(k in vname.upper() for k in _kw):
                findings.append(Finding(SEVERITY_HIGH, "lambda", fname,
                    f"Suspicious env var name: {vname}",
                    f"Value length: {len(str(vval))} chars",
                    "Use Secrets Manager or SSM Parameter Store"))
            hits = _detect_secrets(str(vval))
            if hits:
                findings.append(Finding(SEVERITY_HIGH, "lambda", fname,
                    f"Secret pattern in env var: {vname}",
                    f"Matched: {', '.join(hits[:3])}",
                    "Move secrets out of environment variables"))


def _rule_ec2_userdata_secrets(quick, deep, findings):
    """Detect secrets embedded in EC2 user data scripts."""
    instances = deep.get("ec2_userdata")
    if not instances:
        return
    for inst in instances:
        ud = inst.get("UserData")
        if not ud:
            continue
        hits = _detect_secrets(ud)
        if hits:
            findings.append(Finding(SEVERITY_HIGH, "ec2", inst.get("InstanceId", "?"),
                "Secrets detected in user data",
                f"Matched: {', '.join(hits[:3])}",
                "Use Secrets Manager or instance roles instead"))


def _rule_ebs_unencrypted(quick, deep, findings):
    """Flag unencrypted EBS volumes."""
    volumes = _get_data(quick, "ec2", "describe_volumes")
    if not volumes:
        return
    for vol in volumes:
        if not vol.get("Encrypted"):
            att = vol.get("Attachments", [])
            inst = att[0].get("InstanceId", "unattached") if att else "unattached"
            findings.append(Finding(SEVERITY_MEDIUM, "ec2", vol.get("VolumeId", "?"),
                "EBS volume is not encrypted",
                f"Attached to: {inst}, Size: {vol.get('Size', '?')} GB",
                "Enable default EBS encryption in account settings"))


def _rule_kms_rotation(quick, deep, findings):
    """Flag customer-managed KMS keys without automatic rotation."""
    keys = deep.get("kms")
    if not keys:
        return
    for key in keys:
        meta = key.get("Description", {})
        if not meta:
            continue
        if meta.get("KeyManager") == "CUSTOMER" and key.get("RotationEnabled") is False:
            findings.append(Finding(SEVERITY_LOW, "kms", key.get("KeyId", "?"),
                "Key rotation is disabled",
                f"Key: {meta.get('Description', key.get('KeyId', '?'))}",
                "Enable automatic rotation for customer-managed keys"))


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

_ALL_RULES = [
    _rule_s3_public, _rule_sg_open, _rule_iam_no_mfa, _rule_iam_old_keys,
    _rule_iam_admin, _rule_iam_user_policies, _rule_iam_trust,
    _rule_rds_public, _rule_cloudtrail,
    _rule_lambda_secrets, _rule_ec2_userdata_secrets, _rule_ebs_unencrypted,
    _rule_kms_rotation,
]

_SEV_ORDER = {SEVERITY_CRITICAL: 0, SEVERITY_HIGH: 1, SEVERITY_MEDIUM: 2,
              SEVERITY_LOW: 3, SEVERITY_INFO: 4}


def run_audit(quick_results, deep_results):
    """
    Run every security rule and return findings sorted by severity.
    Rules that throw exceptions are silently skipped.
    """
    findings = []
    for rule in _ALL_RULES:
        try:
            rule(quick_results, deep_results, findings)
        except Exception:
            pass
    findings.sort(key=lambda f: _SEV_ORDER.get(f.severity, 99))
    return findings
