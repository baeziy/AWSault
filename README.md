# AWSault

Post-compromise AWS enumeration and analysis tool for penetration testers.

You have valid AWS credentials. AWSault tells you what those credentials can access, what is misconfigured, and where the secrets are.

Works on **Linux**, **macOS**, and **Windows**.

## Install

### From GitHub (recommended)

```bash
pip install git+https://github.com/baeziy/AWSault.git
```

That's it. The `awsault` command is now available globally.

### Using pipx (isolated environment)

```bash
pipx install git+https://github.com/baeziy/AWSault.git
```

### From source

```bash
git clone https://github.com/baeziy/AWSault.git
cd AWSault
pip install .
```

### Without installing

If you just want to run it without putting anything in your PATH:

```bash
git clone https://github.com/baeziy/AWSault.git
cd AWSault
pip install -r requirements.txt
python -m awsault
```

### Adding to PATH

After installing with `pip install .`, the `awsault` command should be available. If your terminal says `command not found`, pip installed the script to a directory that isn't in your PATH. Fix it for your platform:

**Linux**

```bash
# pip installs scripts to ~/.local/bin
export PATH="$HOME/.local/bin:$PATH"

# make it permanent (add to your shell config)
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
# if using zsh:
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

**macOS**

```bash
# same as Linux for most setups
export PATH="$HOME/.local/bin:$PATH"

# make it permanent
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc

# if using Homebrew Python, scripts may be in:
#   /opt/homebrew/bin (Apple Silicon)
#   /usr/local/bin (Intel)
# these are usually already in PATH
```

**Windows**

```powershell
# find where pip installed the script
python -m site --user-site
# the Scripts folder is next to the site-packages folder
# e.g. C:\Users\YourName\AppData\Roaming\Python\Python312\Scripts

# add to PATH permanently (PowerShell, run as Administrator)
$scriptPath = (python -m site --user-site) -replace 'site-packages','Scripts'
[Environment]::SetEnvironmentVariable("Path", "$env:Path;$scriptPath", "User")

# or add manually:
# Settings > System > About > Advanced system settings > Environment Variables
# edit the "Path" variable under User variables and add the Scripts folder
```

After updating PATH, restart your terminal and verify:

```bash
awsault --list-services
```

### Requirements

Python 3.8+ and valid AWS credentials configured on the machine (environment variables, `~/.aws/credentials`, or an instance role).

## Quick start

```bash
# surface scan with whatever credentials are available
awsault

# surface scan using a specific profile
awsault --profile staging

# full assault
awsault --godeep

# full assault, all regions, export to HTML
# global services (IAM, STS, Route53, etc.) scan once, regional services scan per-region
awsault --godeep --all-regions --output report.html

# only scan specific services
awsault --services iam,s3,ec2,lambda,rds

# list allowed permissions from the last scan
awsault --show iam
awsault --show iam,s3,lambda

# view the actual result data for a specific permission
awsault --show iam --detail list_users

# export last scan without running it again
awsault --output results.json
```

## How it works

By default, AWSault runs a **surface scan**: it fires read-only API calls (List, Get, Describe) across 120+ AWS services and reports which ones succeed. Think of it as a bulk permission check across every service.

Pass `--godeep` and it goes further.

## Credentials

If you pass `--profile`, AWSault loads that profile from `~/.aws/credentials`.

If you don't, it follows the standard boto3 credential chain: environment variables first, then the default profile from `~/.aws/`, then EC2/ECS instance metadata. If nothing works, it tells you what it tried and why it failed.

## Browsing results

After any scan, results get saved to `~/.awsault/last_scan.json`. Use `--show` to see which permissions you have without rescanning:

```bash
awsault --show iam              # list allowed permissions for IAM
awsault --show s3,lambda,ec2    # list allowed permissions across services
awsault --show all              # list all services and their permissions
```

The output shows allowed, denied, and errored API calls per service. To drill into the actual data returned by a specific call, use `--detail`:

```bash
awsault --show iam --detail list_users     # view the IAM users data
awsault --show s3 --detail list_buckets    # view the S3 buckets data
awsault --show ec2 --detail describe_instances
```

`--detail` requires a single service in `--show` and shows the full JSON response for that API call.

### Browsing deep scan data

After a `--godeep` scan, you can revisit the identity recon, security findings, and loot without rescanning:

```bash
awsault --recon                 # view identity, policies, roles, and privesc paths
awsault --findings              # view security audit findings
awsault --loot                  # view extracted secrets and credentials
awsault --recon --findings      # combine multiple views
awsault --recon --findings --loot   # view everything at once
```

`--recon` shows the full identity permission map: who you are, what policies are attached, what roles you can assume, and any privilege escalation paths detected. `--findings` shows all security audit findings sorted by severity. `--loot` shows extracted secrets with their actual values.

### Reading policy and role documents

Use `--policy` to fetch the full JSON document of any policy or role directly from AWS:

```bash
awsault --policy S3Access                             # read an inline or managed policy by name
awsault --policy S3Access,DbRead                      # read multiple policies at once
awsault --policy AmazonEC2ReadOnlyAccess              # works with AWS managed policies too
awsault --policy AmazonEC2ReadOnlyAccess --version v2  # read a specific version of a managed policy
awsault --policy arn:aws:iam::123456:policy/CrossAcct  # read a managed policy by ARN (cross-account)
awsault --policy S3Access --user admin                 # read a policy on a different user
awsault --policy S3Access --role BackendRole           # read an inline policy on a role
awsault --all-policies                                 # dump all policies on current identity
awsault --all-policies --user admin                    # dump all policies on another user
awsault --all-policies --role BackendRole              # trust policy + all attached policies on a role
```

`--policy` reads specific policy documents only (never auto-detects roles). It checks saved scan data first, then falls back to live API calls. Use `--user` or `--role` to target a different principal. Use `--version` to read a non-default managed policy version. ARNs are also accepted for cross-account policies.

`--all-policies` dumps everything on a user or role. When targeting a role, it shows the trust policy first, then all inline and managed permission policies. If a specific permission is denied, it tells you exactly which IAM action you're missing.

## What `--godeep` does

Five phases run back to back:

**Phase 1: Surface scan.**
Same as running without the flag. Fires parameterless API calls across every service and reports what succeeded vs what got denied.

**Phase 2: Deep enumeration.**
Takes the resources found in Phase 1 and pulls their detailed configurations:
- **S3**: ACL, policy, public access block, encryption, versioning, website config
- **IAM users**: access keys, MFA, inline policy documents, attached managed policy documents, group memberships, login profile
- **IAM roles**: trust policy, inline policy documents, attached managed policy documents
- **IAM self (identity recon)**: full policy chain for the current identity — enumerates every inline, attached, and group policy with their actual JSON documents, discovers assumable roles by scanning policy statements for `sts:AssumeRole` and checking trust policies, then enumerates those roles' policies too
- **Lambda**: full config with env vars and resource policies
- **EC2**: instance user data
- **KMS**: key policy and rotation status
- **CloudTrail**: trail status and event selectors
- **ECS**: full task definitions
- **CloudFormation**: stack details with outputs and parameters
- **RDS**: public accessibility and encryption status

**Phase 3: Security audit.**
Runs detection rules against the collected data and produces findings sorted by severity.

What it checks:
- S3 buckets with public ACLs, open policies, or missing encryption
- Security groups allowing 0.0.0.0/0 on SSH, RDP, database, and admin ports
- IAM users with console access but no MFA
- Active access keys older than 90 days
- Inline policies granting Action:\* Resource:\* on both roles and users
- Attached managed policies granting Action:\* Resource:\* on both roles and users
- Known high-risk AWS managed policies (AdministratorAccess, PowerUserAccess, IAMFullAccess, etc.)
- Policies attached directly to users instead of groups
- Roles with wildcard or cross-account trust policies
- Publicly accessible RDS instances and unencrypted storage
- CloudTrail not enabled, single region, or missing log validation
- Secrets in Lambda environment variables (pattern matching)
- Credentials embedded in EC2 user data scripts
- Unencrypted EBS volumes
- KMS keys without automatic rotation

**Phase 4: Loot extraction.**
Attempts to read secret values from: Secrets Manager, SSM Parameter Store (including decrypted SecureStrings), Lambda environment variables, EC2 instance user data, ECS task definition secrets, CodeBuild project environment variables, and CloudFormation stack outputs and parameters.

**Phase 5: Identity permission map.**
Displays a complete breakdown of the current identity's effective permissions:
- Every policy (inline, customer-managed, AWS-managed) with the actual Allow/Deny statements
- **Alternate policy versions** — for each managed policy, enumerates all non-default versions and their statements. If `iam:SetDefaultPolicyVersion` is available, these are potential escalation targets
- Group memberships and their inherited policies
- Assumable roles — discovered by scanning your policies for `sts:AssumeRole` grants AND checking trust policies of enumerated roles
- For each assumable role: its full policy set with statements
- **Privilege escalation path detection** — scans all discovered policies (direct and via assumable roles) for 14 known IAM escalation techniques:
  - `SetDefaultPolicyVersion` — switch a managed policy to an older, more permissive version
  - `CreatePolicyVersion` — inject a new policy version with arbitrary permissions
  - `AttachUserPolicy` / `AttachRolePolicy` / `AttachGroupPolicy` — attach AdministratorAccess
  - `PutUserPolicy` / `PutRolePolicy` / `PutGroupPolicy` — write inline admin policies
  - `AddUserToGroup` — join an admin group
  - `CreateLoginProfile` / `UpdateLoginProfile` — set console passwords for other users
  - `CreateAccessKey` — generate access keys for other users
  - `UpdateAssumeRolePolicy` — modify trust policies to allow self-assumption
  - `PassRole` — pass high-privilege roles to services
- **Suggested next steps** — concrete `aws` CLI commands based on discovered access, including privilege escalation commands (set-default-policy-version, attach-user-policy, etc.), role assumption, S3 access, secrets, SSM parameters, DynamoDB, and Lambda invocations

This is designed for the real pentesting workflow: discover who you are → map what you can do → find where to escalate → get the commands to do it.

## Output formats

Pass `--output` with a filename. Format is picked from the extension:

```bash
awsault --godeep --output report.json     # full JSON dump
awsault --godeep --output report.csv      # flat CSV
awsault --godeep --output report.html     # interactive HTML report
```

The HTML report has tabs for services, findings, loot, and recon. The recon tab includes the full identity permission map: effective policies with their Allow/Deny statements and resources, assumable roles with their policies, and everything you need to plan the next move. Each section is collapsible. The services tab has a search bar and status filters.

The CSV export includes the same recon data as flat rows: identity info, each policy statement (name, type, effect, actions, resources), and assumable roles with their policies.

The JSON export includes a top-level `recon` key with the full structured permission map.

To export a previous scan without rerunning it:

```bash
awsault --output report.html
```

Note: `--show` and `--output` cannot be used together.

## All flags

```
--profile NAME          AWS profile from ~/.aws/
--region REGION         override region
--services iam,s3,...   scope to specific services (default: all)
--threads N             concurrent threads (default: 10)
--godeep                full assault: deep recon + audit + loot
--all-regions           sweep all enabled regions (global once, regional per-region)
--output FILE           export results (.json, .csv, .html)
--show SERVICES         list allowed permissions from last scan
--detail METHOD         view result data for a specific permission (use with --show)
--recon                 view identity recon: policies, roles, and privesc paths
--findings              view security audit findings from last scan
--loot                  view extracted secrets and credentials from last scan
--policy NAME           read policy/role documents live from AWS (comma-separated)
--version VERSION       read a specific version of a managed policy (use with --policy)
--all-policies          list and read all policies on the current identity
--user USERNAME         target a different IAM user (use with --policy or --all-policies)
--role ROLENAME         target a different IAM role (use with --policy or --all-policies)
--verbose               print API data during scan
--list-services         show all supported services
```

## Project structure

```
src/awsault/
├── cli.py                  entry point, argument handling, terminal output
├── services.py             service registry (120+ AWS services)
├── core/
│   ├── creds.py            credential loading and validation
│   ├── scanner.py          surface scan engine with pagination and concurrency
│   └── store.py            local result persistence (~/.awsault/)
├── recon/
│   ├── deep.py             second pass resource chaining (11 chains) + privesc detection (14 techniques)
│   ├── audit.py            security finding detection (16 rules)
│   └── loot.py             secret and credential extraction (7 sources)
└── output/
    └── formatters.py       JSON, CSV, and HTML export
```

## Extending

**New service.** Add an entry to the relevant category dict in `src/awsault/services.py`.

**New deep chain.** Write a function in `src/awsault/recon/deep.py` that takes `(session, quick_results)` and returns enriched data, then register it in the `CHAINS` dict.

**New audit rule.** Write a function in `src/awsault/recon/audit.py` that takes `(quick, deep, findings)` and appends `Finding` objects, then add it to `_ALL_RULES`.

**New loot source.** Write a function in `src/awsault/recon/loot.py` that takes `(session)` and returns a list of items, then add it to `LOOT_SOURCES`.

## Cross-platform notes

AWSault runs on Linux, macOS, and Windows without any platform-specific dependencies. Scan results are stored in your home directory under `.awsault/` which resolves correctly on all operating systems. The only requirement is a working Python 3.8+ installation and valid AWS credentials.

On Windows, if you are using PowerShell or CMD and colors don't render properly, make sure you are running Windows Terminal or a terminal emulator that supports ANSI escape codes. The default Windows Terminal (available from the Microsoft Store) works fine.

## Disclaimer

For authorized use only. All API calls are read-only except `get_secret_value` (Secrets Manager) and `get_parameter` (SSM) in `--godeep` mode, which read actual secret values. Only run this against accounts you have explicit written permission to test.

## License

GPL-3.0
