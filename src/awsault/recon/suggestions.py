"""
Suggested next-step commands based on surface scan results.

For every service where the surface scan found at least one OK API call,
this module generates context-aware AWS CLI commands that guide the user
toward deeper investigation.

The commands are read-only by default. Anything destructive or write-based
is clearly labelled with a [WRITE] prefix so the user knows what they're
running.
"""

# ---------------------------------------------------------------------------
# Per-service command templates
# ---------------------------------------------------------------------------
# Keys   = service name (matches services.py)
# Values = list of (method_that_must_be_ok, description, command_template)
#
# Templates support these placeholders:
#   {profile}  - --profile <name> or empty string
#   {region}   - --region <name> or empty string
#   {p}        - shorthand for "{profile} {region}" (trimmed)
#
# If method_that_must_be_ok is None, the suggestion fires whenever the
# service has ANY ok call.
# ---------------------------------------------------------------------------

_SUGGESTIONS = {
    # -----------------------------------------------------------------------
    # Identity & Access
    # -----------------------------------------------------------------------
    "iam": [
        ("list_users", "List all IAM users with details",
         "aws iam list-users {profile}"),
        ("list_roles", "List all IAM roles",
         "aws iam list-roles {profile}"),
        ("list_policies", "List customer-managed policies",
         "aws iam list-policies --scope Local {profile}"),
        ("get_account_authorization_details", "Full IAM dump (users, roles, policies, groups)",
         "aws iam get-account-authorization-details {profile}"),
        ("get_credential_report", "Download credential report (password ages, MFA, keys)",
         "aws iam generate-credential-report {profile} && aws iam get-credential-report {profile}"),
        ("get_account_summary", "View account-level IAM summary (user/role/policy counts)",
         "aws iam get-account-summary {profile}"),
        ("list_groups", "List IAM groups and their members",
         "aws iam list-groups {profile}"),
        ("list_instance_profiles", "List instance profiles (roles attached to EC2)",
         "aws iam list-instance-profiles {profile}"),
        ("list_mfa_devices", "Check MFA device status",
         "aws iam list-mfa-devices {profile}"),
    ],
    "sts": [
        ("get_caller_identity", "Confirm current identity",
         "aws sts get-caller-identity {profile}"),
    ],
    "organizations": [
        ("describe_organization", "View organization details",
         "aws organizations describe-organization {profile}"),
        ("list_accounts", "List all accounts in the organization",
         "aws organizations list-accounts {profile}"),
        ("list_roots", "List organization roots",
         "aws organizations list-roots {profile}"),
        ("list_policies", "List service control policies",
         "aws organizations list-policies --filter SERVICE_CONTROL_POLICY {profile}"),
    ],
    "accessanalyzer": [
        ("list_analyzers", "List IAM Access Analyzers and their findings",
         "aws accessanalyzer list-analyzers {p}"),
    ],
    "sso-admin": [
        ("list_instances", "List SSO instances",
         "aws sso-admin list-instances {p}"),
    ],

    # -----------------------------------------------------------------------
    # Compute
    # -----------------------------------------------------------------------
    "ec2": [
        ("describe_instances", "List running instances (IPs, roles, key pairs)",
         "aws ec2 describe-instances --query 'Reservations[].Instances[].{{Id:InstanceId,Type:InstanceType,State:State.Name,IP:PublicIpAddress,Key:KeyName,Role:IamInstanceProfile.Arn}}' --output table {p}"),
        ("describe_instances", "Check instance user data for credentials",
         "aws ec2 describe-instance-attribute --instance-id <instance-id> --attribute userData {p}"),
        ("describe_security_groups", "Find security groups open to the internet",
         "aws ec2 describe-security-groups --filters Name=ip-permission.cidr,Values=0.0.0.0/0 {p}"),
        ("describe_snapshots", "List your own EC2 snapshots",
         "aws ec2 describe-snapshots --owner-ids self {p}"),
        ("describe_snapshots", "List public snapshots from this account",
         "aws ec2 describe-snapshots --owner-ids {account_id} --include-deprecated {p}"),
        ("describe_snapshots", "Try describing snapshots across other regions",
         "aws ec2 describe-snapshots --owner-ids self --region us-west-2 {profile}"),
        ("describe_volumes", "List EBS volumes (check for unencrypted)",
         "aws ec2 describe-volumes --query 'Volumes[].{{Id:VolumeId,Size:Size,Encrypted:Encrypted,State:State,AZ:AvailabilityZone}}' --output table {p}"),
        ("describe_images", "List AMIs owned by this account",
         "aws ec2 describe-images --owners self {p}"),
        ("describe_key_pairs", "List SSH key pairs",
         "aws ec2 describe-key-pairs {p}"),
        ("describe_vpcs", "List VPCs and their CIDR blocks",
         "aws ec2 describe-vpcs --query 'Vpcs[].{{Id:VpcId,CIDR:CidrBlock,Default:IsDefault}}' --output table {p}"),
        ("describe_network_interfaces", "Find ENIs with public IPs",
         "aws ec2 describe-network-interfaces --filters Name=association.public-ip,Values=* {p}"),
        ("describe_addresses", "List Elastic IPs",
         "aws ec2 describe-addresses {p}"),
        ("describe_vpc_endpoints", "List VPC endpoints (potential data exfil paths)",
         "aws ec2 describe-vpc-endpoints {p}"),
        ("describe_flow_logs", "Check VPC flow log configuration",
         "aws ec2 describe-flow-logs {p}"),
        ("describe_launch_templates", "List launch templates (may contain user data secrets)",
         "aws ec2 describe-launch-templates {p}"),
    ],
    "lambda": [
        ("list_functions", "List Lambda functions (check env vars for secrets)",
         "aws lambda list-functions --query 'Functions[].{{Name:FunctionName,Runtime:Runtime,Role:Role}}' --output table {p}"),
        ("list_functions", "Get function config including environment variables",
         "aws lambda get-function-configuration --function-name <function-name> {p}"),
        ("list_functions", "Download function code",
         "aws lambda get-function --function-name <function-name> {p}"),
        ("list_layers", "List Lambda layers (shared code, potential secrets)",
         "aws lambda list-layers {p}"),
        ("list_event_source_mappings", "List event source mappings",
         "aws lambda list-event-source-mappings {p}"),
    ],
    "ecs": [
        ("list_clusters", "List ECS clusters",
         "aws ecs list-clusters {p}"),
        ("list_clusters", "Describe cluster details",
         "aws ecs describe-clusters --clusters <cluster-arn> {p}"),
        ("list_task_definitions", "List task definitions (check for secrets in env vars)",
         "aws ecs list-task-definitions {p}"),
        ("list_task_definitions", "Describe a task definition",
         "aws ecs describe-task-definition --task-definition <task-def-arn> {p}"),
    ],
    "eks": [
        ("list_clusters", "List EKS clusters",
         "aws eks list-clusters {p}"),
        ("list_clusters", "Describe an EKS cluster (API endpoint, OIDC, logging)",
         "aws eks describe-cluster --name <cluster-name> {p}"),
    ],
    "lightsail": [
        ("get_instances", "List Lightsail instances",
         "aws lightsail get-instances {p}"),
        ("get_domains", "List Lightsail domains",
         "aws lightsail get-domains {p}"),
        ("get_key_pairs", "List Lightsail SSH key pairs",
         "aws lightsail get-key-pairs {p}"),
    ],
    "batch": [
        ("describe_compute_environments", "List Batch compute environments",
         "aws batch describe-compute-environments {p}"),
        ("describe_job_definitions", "List Batch job definitions (check for secrets)",
         "aws batch describe-job-definitions --status ACTIVE {p}"),
    ],
    "autoscaling": [
        ("describe_auto_scaling_groups", "List Auto Scaling groups",
         "aws autoscaling describe-auto-scaling-groups {p}"),
        ("describe_launch_configurations", "List launch configs (may contain user data)",
         "aws autoscaling describe-launch-configurations {p}"),
    ],
    "elasticbeanstalk": [
        ("describe_applications", "List Elastic Beanstalk applications",
         "aws elasticbeanstalk describe-applications {p}"),
        ("describe_environments", "List environments with health and endpoints",
         "aws elasticbeanstalk describe-environments {p}"),
        ("describe_environments", "Get environment config (may contain secrets)",
         "aws elasticbeanstalk describe-configuration-settings --application-name <app> --environment-name <env> {p}"),
    ],
    "emr": [
        ("list_clusters", "List EMR clusters",
         "aws emr list-clusters --active {p}"),
    ],
    "apprunner": [
        ("list_services", "List App Runner services",
         "aws apprunner list-services {p}"),
    ],

    # -----------------------------------------------------------------------
    # Storage
    # -----------------------------------------------------------------------
    "s3": [
        ("list_buckets", "List all S3 buckets",
         "aws s3 ls {profile}"),
        ("list_buckets", "List contents of a specific bucket",
         "aws s3 ls s3://<bucket-name> --recursive {profile}"),
        ("list_buckets", "Check bucket policy",
         "aws s3api get-bucket-policy --bucket <bucket-name> {profile}"),
        ("list_buckets", "Check bucket ACL",
         "aws s3api get-bucket-acl --bucket <bucket-name> {profile}"),
        ("list_buckets", "Check public access block",
         "aws s3api get-public-access-block --bucket <bucket-name> {profile}"),
        ("list_buckets", "Download a file from a bucket",
         "aws s3 cp s3://<bucket-name>/<key> . {profile}"),
    ],
    "dynamodb": [
        ("list_tables", "List DynamoDB tables",
         "aws dynamodb list-tables {p}"),
        ("list_tables", "Describe a table (keys, indexes, encryption)",
         "aws dynamodb describe-table --table-name <table-name> {p}"),
        ("list_tables", "Sample data from a table",
         "aws dynamodb scan --table-name <table-name> --max-items 10 {p}"),
        ("list_backups", "List DynamoDB backups",
         "aws dynamodb list-backups {p}"),
    ],
    "ecr": [
        ("describe_repositories", "List ECR repositories",
         "aws ecr describe-repositories {p}"),
        ("describe_repositories", "List images in a repository",
         "aws ecr list-images --repository-name <repo-name> {p}"),
        ("get_authorization_token", "Get ECR login token (docker pull access)",
         "aws ecr get-login-password {p} | docker login --username AWS --password-stdin <account>.dkr.ecr.<region>.amazonaws.com"),
    ],
    "efs": [
        ("describe_file_systems", "List EFS file systems",
         "aws efs describe-file-systems {p}"),
        ("describe_file_systems", "List mount targets for an EFS",
         "aws efs describe-mount-targets --file-system-id <fs-id> {p}"),
    ],
    "fsx": [
        ("describe_file_systems", "List FSx file systems",
         "aws fsx describe-file-systems {p}"),
    ],
    "storagegateway": [
        ("list_gateways", "List Storage Gateways",
         "aws storagegateway list-gateways {p}"),
    ],
    "backup": [
        ("list_backup_vaults", "List backup vaults",
         "aws backup list-backup-vaults {p}"),
        ("list_backup_plans", "List backup plans",
         "aws backup list-backup-plans {p}"),
        ("list_protected_resources", "List protected resources",
         "aws backup list-protected-resources {p}"),
    ],
    "glacier": [
        ("list_vaults", "List Glacier vaults",
         "aws glacier list-vaults --account-id - {p}"),
    ],

    # -----------------------------------------------------------------------
    # Databases
    # -----------------------------------------------------------------------
    "rds": [
        ("describe_db_instances", "List RDS instances (check public access, encryption)",
         "aws rds describe-db-instances --query 'DBInstances[].{{Id:DBInstanceIdentifier,Engine:Engine,Public:PubliclyAccessible,Encrypted:StorageEncrypted,Endpoint:Endpoint.Address}}' --output table {p}"),
        ("describe_db_clusters", "List RDS clusters",
         "aws rds describe-db-clusters {p}"),
        ("describe_db_snapshots", "List RDS snapshots (check for public ones)",
         "aws rds describe-db-snapshots --query 'DBSnapshots[].{{Id:DBSnapshotIdentifier,DB:DBInstanceIdentifier,Engine:Engine,Status:Status}}' --output table {p}"),
        ("describe_db_cluster_snapshots", "List cluster snapshots",
         "aws rds describe-db-cluster-snapshots {p}"),
        ("describe_db_snapshots", "Check if snapshots are shared publicly",
         "aws rds describe-db-snapshot-attributes --db-snapshot-identifier <snapshot-id> {p}"),
    ],
    "redshift": [
        ("describe_clusters", "List Redshift clusters",
         "aws redshift describe-clusters --query 'Clusters[].{{Id:ClusterIdentifier,Public:PubliclyAccessible,Encrypted:Encrypted,Endpoint:Endpoint.Address}}' --output table {p}"),
        ("describe_cluster_snapshots", "List Redshift snapshots",
         "aws redshift describe-cluster-snapshots {p}"),
    ],
    "elasticache": [
        ("describe_cache_clusters", "List ElastiCache clusters",
         "aws elasticache describe-cache-clusters --show-cache-node-info {p}"),
        ("describe_replication_groups", "List ElastiCache replication groups",
         "aws elasticache describe-replication-groups {p}"),
    ],
    "dax": [
        ("describe_clusters", "List DAX clusters",
         "aws dax describe-clusters {p}"),
    ],
    "neptune": [
        ("describe_db_clusters", "List Neptune clusters",
         "aws neptune describe-db-clusters {p}"),
    ],
    "docdb": [
        ("describe_db_clusters", "List DocumentDB clusters",
         "aws docdb describe-db-clusters {p}"),
    ],
    "memorydb": [
        ("describe_clusters", "List MemoryDB clusters",
         "aws memorydb describe-clusters {p}"),
    ],
    "timestream-write": [
        ("list_databases", "List Timestream databases",
         "aws timestream-write list-databases {p}"),
    ],

    # -----------------------------------------------------------------------
    # Networking & CDN
    # -----------------------------------------------------------------------
    "route53": [
        ("list_hosted_zones", "List Route53 hosted zones",
         "aws route53 list-hosted-zones {profile}"),
        ("list_hosted_zones", "List records in a hosted zone (DNS takeover check)",
         "aws route53 list-resource-record-sets --hosted-zone-id <zone-id> {profile}"),
    ],
    "route53domains": [
        ("list_domains", "List registered domains",
         "aws route53domains list-domains {profile}"),
    ],
    "cloudfront": [
        ("list_distributions", "List CloudFront distributions (origins, SSL)",
         "aws cloudfront list-distributions --query 'DistributionList.Items[].{{Id:Id,Domain:DomainName,Origins:Origins.Items[].DomainName}}' --output table {profile}"),
    ],
    "apigateway": [
        ("get_rest_apis", "List API Gateway REST APIs",
         "aws apigateway get-rest-apis {p}"),
        ("get_rest_apis", "List resources and methods for an API",
         "aws apigateway get-resources --rest-api-id <api-id> {p}"),
        ("get_api_keys", "List API keys (check for exposed keys)",
         "aws apigateway get-api-keys --include-values {p}"),
    ],
    "apigatewayv2": [
        ("get_apis", "List API Gateway v2 (HTTP/WebSocket) APIs",
         "aws apigatewayv2 get-apis {p}"),
    ],
    "elbv2": [
        ("describe_load_balancers", "List ALB/NLB load balancers",
         "aws elbv2 describe-load-balancers {p}"),
        ("describe_target_groups", "List target groups",
         "aws elbv2 describe-target-groups {p}"),
        ("describe_load_balancers", "List listeners (ports, protocols, SSL certs)",
         "aws elbv2 describe-listeners --load-balancer-arn <lb-arn> {p}"),
    ],
    "elb": [
        ("describe_load_balancers", "List Classic load balancers",
         "aws elb describe-load-balancers {p}"),
    ],
    "directconnect": [
        ("describe_connections", "List Direct Connect connections",
         "aws directconnect describe-connections {p}"),
    ],
    "globalaccelerator": [
        ("list_accelerators", "List Global Accelerators",
         "aws globalaccelerator list-accelerators {profile}"),
    ],
    "networkfirewall": [
        ("list_firewalls", "List Network Firewalls",
         "aws network-firewall list-firewalls {p}"),
        ("list_firewall_policies", "List firewall policies",
         "aws network-firewall list-firewall-policies {p}"),
    ],

    # -----------------------------------------------------------------------
    # Security & Compliance
    # -----------------------------------------------------------------------
    "cloudtrail": [
        ("describe_trails", "List CloudTrail trails",
         "aws cloudtrail describe-trails {p}"),
        ("describe_trails", "Check trail status (is logging enabled?)",
         "aws cloudtrail get-trail-status --name <trail-name> {p}"),
        ("list_trails", "Look up recent events (see who did what)",
         "aws cloudtrail lookup-events --max-results 20 {p}"),
    ],
    "guardduty": [
        ("list_detectors", "List GuardDuty detectors",
         "aws guardduty list-detectors {p}"),
        ("list_detectors", "List GuardDuty findings (active threats)",
         "aws guardduty list-findings --detector-id <detector-id> {p}"),
    ],
    "securityhub": [
        ("describe_hub", "Describe Security Hub configuration",
         "aws securityhub describe-hub {p}"),
        ("get_enabled_standards", "List enabled security standards",
         "aws securityhub get-enabled-standards {p}"),
    ],
    "kms": [
        ("list_keys", "List KMS keys",
         "aws kms list-keys {p}"),
        ("list_keys", "Describe a key (check key policy for misconfigs)",
         "aws kms describe-key --key-id <key-id> {p}"),
        ("list_keys", "Get key policy (who can use/manage this key)",
         "aws kms get-key-policy --key-id <key-id> --policy-name default {p}"),
        ("list_aliases", "List KMS key aliases",
         "aws kms list-aliases {p}"),
    ],
    "secretsmanager": [
        ("list_secrets", "List Secrets Manager secrets",
         "aws secretsmanager list-secrets {p}"),
        ("list_secrets", "Read a secret value",
         "aws secretsmanager get-secret-value --secret-id <secret-name> {p}"),
    ],
    "acm": [
        ("list_certificates", "List ACM certificates",
         "aws acm list-certificates {p}"),
        ("list_certificates", "Describe a certificate (domain, expiry, validation)",
         "aws acm describe-certificate --certificate-arn <cert-arn> {p}"),
    ],
    "wafv2": [
        ("list_web_acls", "List WAF web ACLs",
         "aws wafv2 list-web-acls --scope REGIONAL {p}"),
        ("list_ip_sets", "List WAF IP sets",
         "aws wafv2 list-ip-sets --scope REGIONAL {p}"),
    ],
    "inspector2": [
        ("list_coverage", "List Inspector coverage",
         "aws inspector2 list-coverage {p}"),
    ],
    "shield": [
        ("list_protections", "List Shield protections",
         "aws shield list-protections {profile}"),
    ],
    "macie2": [
        ("describe_buckets", "List buckets analyzed by Macie",
         "aws macie2 describe-buckets {p}"),
        ("get_macie_session", "Get Macie session details",
         "aws macie2 get-macie-session {p}"),
    ],
    "detective": [
        ("list_graphs", "List Detective graphs",
         "aws detective list-graphs {p}"),
    ],

    # -----------------------------------------------------------------------
    # Management & Monitoring
    # -----------------------------------------------------------------------
    "cloudformation": [
        ("list_stacks", "List CloudFormation stacks",
         "aws cloudformation list-stacks --stack-status-filter CREATE_COMPLETE UPDATE_COMPLETE {p}"),
        ("list_stacks", "Describe a stack (outputs, parameters may contain secrets)",
         "aws cloudformation describe-stacks --stack-name <stack-name> {p}"),
        ("list_stacks", "Get stack template (infrastructure as code)",
         "aws cloudformation get-template --stack-name <stack-name> {p}"),
        ("list_exports", "List CloudFormation exports (cross-stack references)",
         "aws cloudformation list-exports {p}"),
    ],
    "cloudwatch": [
        ("describe_alarms", "List CloudWatch alarms",
         "aws cloudwatch describe-alarms {p}"),
        ("list_dashboards", "List CloudWatch dashboards",
         "aws cloudwatch list-dashboards {p}"),
    ],
    "logs": [
        ("describe_log_groups", "List CloudWatch log groups",
         "aws logs describe-log-groups {p}"),
        ("describe_log_groups", "Tail a log group (look for secrets, errors)",
         "aws logs filter-log-events --log-group-name <group-name> --limit 50 {p}"),
    ],
    "ssm": [
        ("describe_parameters", "List SSM parameters (may contain secrets)",
         "aws ssm describe-parameters {p}"),
        ("describe_parameters", "Read a parameter value (with decryption)",
         "aws ssm get-parameter --name <param-name> --with-decryption {p}"),
        ("describe_instance_information", "List SSM-managed instances",
         "aws ssm describe-instance-information {p}"),
        ("describe_instance_information", "Run a command on an instance via SSM",
         "aws ssm send-command --instance-ids <instance-id> --document-name AWS-RunShellScript --parameters commands='whoami' {p}"),
        ("list_documents", "List SSM documents",
         "aws ssm list-documents --filters Key=Owner,Values=Self {p}"),
    ],
    "config": [
        ("describe_config_rules", "List AWS Config rules",
         "aws configservice describe-config-rules {p}"),
        ("describe_configuration_recorders", "List Config recorders",
         "aws configservice describe-configuration-recorders {p}"),
    ],
    "servicecatalog": [
        ("list_portfolios", "List Service Catalog portfolios",
         "aws servicecatalog list-portfolios {p}"),
    ],
    "resource-groups": [
        ("list_groups", "List resource groups",
         "aws resource-groups list-groups {p}"),
    ],
    "health": [
        ("describe_events", "List AWS Health events",
         "aws health describe-events {profile}"),
    ],
    "support": [
        ("describe_trusted_advisor_checks", "List Trusted Advisor checks",
         "aws support describe-trusted-advisor-checks --language en {profile}"),
    ],
    "pricing": [
        ("describe_services", "List pricing services",
         "aws pricing describe-services {p}"),
    ],

    # -----------------------------------------------------------------------
    # Messaging & Events
    # -----------------------------------------------------------------------
    "sns": [
        ("list_topics", "List SNS topics",
         "aws sns list-topics {p}"),
        ("list_topics", "Get topic attributes (policy, subscriptions)",
         "aws sns get-topic-attributes --topic-arn <topic-arn> {p}"),
        ("list_subscriptions", "List SNS subscriptions",
         "aws sns list-subscriptions {p}"),
    ],
    "sqs": [
        ("list_queues", "List SQS queues",
         "aws sqs list-queues {p}"),
        ("list_queues", "Get queue attributes (policy, DLQ config)",
         "aws sqs get-queue-attributes --queue-url <queue-url> --attribute-names All {p}"),
        ("list_queues", "Receive messages from a queue",
         "aws sqs receive-message --queue-url <queue-url> --max-number-of-messages 5 {p}"),
    ],
    "ses": [
        ("list_identities", "List SES identities (email/domain)",
         "aws ses list-identities {p}"),
        ("get_send_quota", "Check SES sending quota",
         "aws ses get-send-quota {p}"),
    ],
    "sesv2": [
        ("list_email_identities", "List SESv2 email identities",
         "aws sesv2 list-email-identities {p}"),
        ("get_account", "Get SESv2 account details",
         "aws sesv2 get-account {p}"),
    ],
    "events": [
        ("list_rules", "List EventBridge rules",
         "aws events list-rules {p}"),
        ("list_event_buses", "List event buses",
         "aws events list-event-buses {p}"),
    ],
    "pinpoint": [
        ("get_apps", "List Pinpoint applications",
         "aws pinpoint get-apps {p}"),
    ],

    # -----------------------------------------------------------------------
    # CI/CD & Developer Tools
    # -----------------------------------------------------------------------
    "codebuild": [
        ("list_projects", "List CodeBuild projects",
         "aws codebuild list-projects {p}"),
        ("list_projects", "Get project details (env vars may contain secrets)",
         "aws codebuild batch-get-projects --names <project-name> {p}"),
    ],
    "codecommit": [
        ("list_repositories", "List CodeCommit repositories",
         "aws codecommit list-repositories {p}"),
        ("list_repositories", "Get repo details (clone URL)",
         "aws codecommit get-repository --repository-name <repo-name> {p}"),
    ],
    "codepipeline": [
        ("list_pipelines", "List CodePipeline pipelines",
         "aws codepipeline list-pipelines {p}"),
        ("list_pipelines", "Get pipeline details",
         "aws codepipeline get-pipeline --name <pipeline-name> {p}"),
    ],
    "codedeploy": [
        ("list_applications", "List CodeDeploy applications",
         "aws deploy list-applications {p}"),
    ],
    "codeartifact": [
        ("list_domains", "List CodeArtifact domains",
         "aws codeartifact list-domains {p}"),
        ("list_repositories", "List CodeArtifact repositories",
         "aws codeartifact list-repositories {p}"),
    ],
    "amplify": [
        ("list_apps", "List Amplify apps",
         "aws amplify list-apps {p}"),
    ],
    "cloud9": [
        ("list_environments", "List Cloud9 environments",
         "aws cloud9 list-environments {p}"),
    ],
    "proton": [
        ("list_environments", "List Proton environments",
         "aws proton list-environments {p}"),
        ("list_services", "List Proton services",
         "aws proton list-services {p}"),
    ],

    # -----------------------------------------------------------------------
    # Analytics
    # -----------------------------------------------------------------------
    "glue": [
        ("get_databases", "List Glue databases",
         "aws glue get-databases {p}"),
        ("get_crawlers", "List Glue crawlers",
         "aws glue get-crawlers {p}"),
        ("get_jobs", "List Glue jobs",
         "aws glue get-jobs {p}"),
        ("get_connections", "List Glue connections (may contain JDBC credentials)",
         "aws glue get-connections {p}"),
        ("list_dev_endpoints", "List Glue dev endpoints (SSH access possible)",
         "aws glue get-dev-endpoints {p}"),
    ],
    "athena": [
        ("list_work_groups", "List Athena workgroups",
         "aws athena list-work-groups {p}"),
        ("list_named_queries", "List saved Athena queries",
         "aws athena list-named-queries {p}"),
    ],
    "kinesis": [
        ("list_streams", "List Kinesis streams",
         "aws kinesis list-streams {p}"),
        ("list_streams", "Describe a stream",
         "aws kinesis describe-stream --stream-name <stream-name> {p}"),
    ],
    "firehose": [
        ("list_delivery_streams", "List Firehose delivery streams",
         "aws firehose list-delivery-streams {p}"),
    ],
    "kafka": [
        ("list_clusters", "List MSK clusters",
         "aws kafka list-clusters {p}"),
    ],
    "opensearch": [
        ("list_domain_names", "List OpenSearch domains",
         "aws opensearch list-domain-names {p}"),
        ("list_domain_names", "Describe a domain (endpoints, access policies)",
         "aws opensearch describe-domain --domain-name <domain-name> {p}"),
    ],
    "lakeformation": [
        ("list_resources", "List Lake Formation resources",
         "aws lakeformation list-resources {p}"),
        ("get_data_lake_settings", "Get data lake settings",
         "aws lakeformation get-data-lake-settings {p}"),
    ],
    "databrew": [
        ("list_projects", "List DataBrew projects",
         "aws databrew list-projects {p}"),
        ("list_datasets", "List DataBrew datasets",
         "aws databrew list-datasets {p}"),
    ],

    # -----------------------------------------------------------------------
    # AI/ML
    # -----------------------------------------------------------------------
    "sagemaker": [
        ("list_notebook_instances", "List SageMaker notebook instances",
         "aws sagemaker list-notebook-instances {p}"),
        ("list_endpoints", "List SageMaker endpoints",
         "aws sagemaker list-endpoints {p}"),
        ("list_models", "List SageMaker models",
         "aws sagemaker list-models {p}"),
        ("list_training_jobs", "List training jobs",
         "aws sagemaker list-training-jobs {p}"),
    ],
    "comprehend": [
        ("list_document_classifiers", "List Comprehend classifiers",
         "aws comprehend list-document-classifiers {p}"),
    ],
    "rekognition": [
        ("list_collections", "List Rekognition collections",
         "aws rekognition list-collections {p}"),
    ],
    "translate": [
        ("list_terminologies", "List Translate terminologies",
         "aws translate list-terminologies {p}"),
    ],
    "transcribe": [
        ("list_transcription_jobs", "List transcription jobs",
         "aws transcribe list-transcription-jobs {p}"),
    ],
    "polly": [
        ("describe_voices", "List Polly voices",
         "aws polly describe-voices {p}"),
    ],

    # -----------------------------------------------------------------------
    # Application & Integration
    # -----------------------------------------------------------------------
    "cognito-idp": [
        ("list_user_pools", "List Cognito user pools",
         "aws cognito-idp list-user-pools --max-results 20 {p}"),
        ("list_user_pools", "List users in a pool",
         "aws cognito-idp list-users --user-pool-id <pool-id> {p}"),
    ],
    "cognito-identity": [
        ("list_identity_pools", "List Cognito identity pools",
         "aws cognito-identity list-identity-pools --max-results 20 {p}"),
    ],
    "stepfunctions": [
        ("list_state_machines", "List Step Functions state machines",
         "aws stepfunctions list-state-machines {p}"),
        ("list_state_machines", "Describe a state machine (workflow definition)",
         "aws stepfunctions describe-state-machine --state-machine-arn <arn> {p}"),
    ],
    "appsync": [
        ("list_graphql_apis", "List AppSync GraphQL APIs",
         "aws appsync list-graphql-apis {p}"),
    ],
    "mq": [
        ("list_brokers", "List MQ brokers",
         "aws mq list-brokers {p}"),
    ],
    "appconfig": [
        ("list_applications", "List AppConfig applications",
         "aws appconfig list-applications {p}"),
    ],

    # -----------------------------------------------------------------------
    # Migration & Transfer
    # -----------------------------------------------------------------------
    "datasync": [
        ("list_tasks", "List DataSync tasks",
         "aws datasync list-tasks {p}"),
        ("list_agents", "List DataSync agents",
         "aws datasync list-agents {p}"),
    ],
    "transfer": [
        ("list_servers", "List Transfer Family servers (SFTP/FTPS)",
         "aws transfer list-servers {p}"),
    ],
    "dms": [
        ("describe_replication_instances", "List DMS replication instances",
         "aws dms describe-replication-instances {p}"),
        ("describe_endpoints", "List DMS endpoints (connection strings)",
         "aws dms describe-endpoints {p}"),
    ],
    "snowball": [
        ("list_jobs", "List Snowball jobs",
         "aws snowball list-jobs {p}"),
    ],

    # -----------------------------------------------------------------------
    # IoT
    # -----------------------------------------------------------------------
    "iot": [
        ("list_things", "List IoT things",
         "aws iot list-things {p}"),
        ("list_policies", "List IoT policies",
         "aws iot list-policies {p}"),
        ("list_certificates", "List IoT certificates",
         "aws iot list-certificates {p}"),
    ],
    "iot-analytics": [
        ("list_channels", "List IoT Analytics channels",
         "aws iotanalytics list-channels {p}"),
        ("list_datasets", "List IoT Analytics datasets",
         "aws iotanalytics list-datasets {p}"),
    ],
    "greengrass": [
        ("list_groups", "List Greengrass groups",
         "aws greengrass list-groups {p}"),
    ],

    # -----------------------------------------------------------------------
    # Media
    # -----------------------------------------------------------------------
    "mediaconvert": [
        ("describe_endpoints", "List MediaConvert endpoints",
         "aws mediaconvert describe-endpoints {p}"),
    ],
    "medialive": [
        ("list_inputs", "List MediaLive inputs",
         "aws medialive list-inputs {p}"),
        ("list_channels", "List MediaLive channels",
         "aws medialive list-channels {p}"),
    ],
    "mediapackage": [
        ("list_channels", "List MediaPackage channels",
         "aws mediapackage list-channels {p}"),
    ],
    "mediastore": [
        ("list_containers", "List MediaStore containers",
         "aws mediastore list-containers {p}"),
    ],
    "mediatailor": [
        ("list_playback_configurations", "List MediaTailor playback configs",
         "aws mediatailor list-playback-configurations {p}"),
    ],

    # -----------------------------------------------------------------------
    # Other
    # -----------------------------------------------------------------------
    "xray": [
        ("get_sampling_rules", "List X-Ray sampling rules",
         "aws xray get-sampling-rules {p}"),
        ("get_groups", "List X-Ray groups",
         "aws xray get-groups {p}"),
    ],
    "ram": [
        ("get_resource_shares", "List RAM resource shares",
         "aws ram get-resource-shares --resource-owner SELF {p}"),
    ],
    "workspaces": [
        ("describe_workspaces", "List WorkSpaces",
         "aws workspaces describe-workspaces {p}"),
        ("describe_workspace_directories", "List WorkSpaces directories",
         "aws workspaces describe-workspace-directories {p}"),
    ],
    "workmail": [
        ("list_organizations", "List WorkMail organizations",
         "aws workmail list-organizations {p}"),
    ],
    "opsworks": [
        ("describe_stacks", "List OpsWorks stacks",
         "aws opsworks describe-stacks {p}"),
    ],
    "cloudhsmv2": [
        ("describe_clusters", "List CloudHSM clusters",
         "aws cloudhsmv2 describe-clusters {p}"),
    ],
    "cloudsearch": [
        ("describe_domains", "List CloudSearch domains",
         "aws cloudsearch describe-domains {p}"),
    ],
    "datapipeline": [
        ("list_pipelines", "List Data Pipeline pipelines",
         "aws datapipeline list-pipelines {p}"),
    ],
    "devicefarm": [
        ("list_projects", "List Device Farm projects",
         "aws devicefarm list-projects {p}"),
    ],
    "dlm": [
        ("get_lifecycle_policies", "List DLM lifecycle policies",
         "aws dlm get-lifecycle-policies {p}"),
    ],
    "signer": [
        ("list_signing_jobs", "List Signer jobs",
         "aws signer list-signing-jobs {p}"),
    ],
    "robomaker": [
        ("list_simulation_jobs", "List RoboMaker simulation jobs",
         "aws robomaker list-simulation-jobs {p}"),
    ],
    "grafana": [
        ("list_workspaces", "List Grafana workspaces",
         "aws grafana list-workspaces {p}"),
    ],
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_scan_suggestions(quick_results, profile=None, region=None, account_id=None):
    """
    Generate suggested next-step commands from surface scan results.

    Args:
        quick_results: dict of service_name -> ServiceResult
        profile:       AWS profile name (or None for default chain)
        region:        AWS region used for the scan
        account_id:    AWS account ID

    Returns:
        list of (service_name, ok_count, total_count, suggestions)
        where suggestions is a list of (description, command) tuples.
        Only services with at least one OK call are included.
    """
    profile_flag = f"--profile {profile}" if profile else ""
    region_flag = f"--region {region}" if region else ""
    p_combined = f"{profile_flag} {region_flag}".strip()

    results = []

    for svc_name in sorted(quick_results.keys()):
        # skip region-suffixed keys from multi-region scans
        if " (" in svc_name:
            base_name = svc_name.split(" (")[0]
        else:
            base_name = svc_name

        sr = quick_results[svc_name]
        if sr.ok == 0:
            continue

        # which methods succeeded?
        ok_methods = {c.method for c in sr.calls if c.status == "ok"}

        templates = _SUGGESTIONS.get(base_name, [])
        if not templates:
            continue

        svc_suggestions = []
        seen_cmds = set()

        for req_method, desc, cmd_tpl in templates:
            if req_method is not None and req_method not in ok_methods:
                continue

            cmd = cmd_tpl.format(
                profile=profile_flag,
                region=region_flag,
                p=p_combined,
                account_id=account_id or "<account-id>",
            ).strip()

            # collapse double spaces from empty placeholders
            while "  " in cmd:
                cmd = cmd.replace("  ", " ")

            if cmd not in seen_cmds:
                svc_suggestions.append((desc, cmd))
                seen_cmds.add(cmd)

        if svc_suggestions:
            results.append((base_name, sr.ok, sr.total, svc_suggestions))

    return results
