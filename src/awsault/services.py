"""
Service definitions for AWSault.

Each service maps to a boto3 client name and a list of read-only API calls.
Calls are parameterless unless 'params' is specified, and use boto3 paginators
where available.

To add a new service, drop an entry into the relevant category dict below.
The scanner picks it up automatically on the next run.

Fields:
    client    - boto3 client name
    global    - (optional) True if the service is region-independent (IAM, S3, etc.)
    calls     - list of API call definitions:
        method   - boto3 method name (snake_case)
        key      - response key that holds the data, or None for the full response
        paginate - (optional) True if a boto3 paginator exists for this call
        params   - (optional) dict of fixed parameters to pass to the call
"""

# ---------------------------------------------------------------------------
# Identity & Access
# ---------------------------------------------------------------------------

_IDENTITY = {
    "iam": {
        "client": "iam",
        "global": True,
        "calls": [
            {"method": "list_users", "key": "Users", "paginate": True},
            {"method": "list_roles", "key": "Roles", "paginate": True},
            {"method": "list_groups", "key": "Groups", "paginate": True},
            {"method": "list_policies", "key": "Policies", "paginate": True, "params": {"Scope": "Local"}},
            {"method": "list_instance_profiles", "key": "InstanceProfiles", "paginate": True},
            {"method": "list_saml_providers", "key": "SAMLProviderList"},
            {"method": "list_open_id_connect_providers", "key": "OpenIDConnectProviderList"},
            {"method": "list_mfa_devices", "key": "MFADevices", "paginate": True},
            {"method": "list_account_aliases", "key": "AccountAliases", "paginate": True},
            {"method": "list_server_certificates", "key": "ServerCertificateMetadataList", "paginate": True},
            {"method": "list_ssh_public_keys", "key": "SSHPublicKeys", "paginate": True},
            {"method": "get_account_summary", "key": "SummaryMap"},
            {"method": "get_account_authorization_details", "key": None, "paginate": True},
            {"method": "get_credential_report", "key": "Content"},
            {"method": "generate_credential_report", "key": "State"},
        ],
    },
    "sts": {
        "client": "sts",
        "global": True,
        "calls": [
            {"method": "get_caller_identity", "key": None},
        ],
    },
    "organizations": {
        "client": "organizations",
        "global": True,
        "calls": [
            {"method": "describe_organization", "key": "Organization"},
            {"method": "list_accounts", "key": "Accounts", "paginate": True},
            {"method": "list_roots", "key": "Roots", "paginate": True},
            {"method": "list_policies", "key": "Policies", "paginate": True, "params": {"Filter": "SERVICE_CONTROL_POLICY"}},
            {"method": "list_handshakes_for_organization", "key": "Handshakes", "paginate": True},
        ],
    },
    "accessanalyzer": {
        "client": "accessanalyzer",
        "calls": [
            {"method": "list_analyzers", "key": "analyzers"},
        ],
    },
    "sso-admin": {
        "client": "sso-admin",
        "calls": [
            {"method": "list_instances", "key": "Instances"},
        ],
    },
}

# ---------------------------------------------------------------------------
# Compute
# ---------------------------------------------------------------------------

_COMPUTE = {
    "ec2": {
        "client": "ec2",
        "calls": [
            {"method": "describe_instances", "key": "Reservations", "paginate": True},
            {"method": "describe_security_groups", "key": "SecurityGroups", "paginate": True},
            {"method": "describe_vpcs", "key": "Vpcs", "paginate": True},
            {"method": "describe_subnets", "key": "Subnets", "paginate": True},
            {"method": "describe_internet_gateways", "key": "InternetGateways", "paginate": True},
            {"method": "describe_nat_gateways", "key": "NatGateways", "paginate": True},
            {"method": "describe_route_tables", "key": "RouteTables", "paginate": True},
            {"method": "describe_network_acls", "key": "NetworkAcls", "paginate": True},
            {"method": "describe_network_interfaces", "key": "NetworkInterfaces", "paginate": True},
            {"method": "describe_addresses", "key": "Addresses"},
            {"method": "describe_key_pairs", "key": "KeyPairs"},
            {"method": "describe_images", "key": "Images", "params": {"Owners": ["self"]}},
            {"method": "describe_snapshots", "key": "Snapshots", "paginate": True, "params": {"OwnerIds": ["self"]}},
            {"method": "describe_volumes", "key": "Volumes", "paginate": True},
            {"method": "describe_vpn_connections", "key": "VpnConnections"},
            {"method": "describe_vpn_gateways", "key": "VpnGateways"},
            {"method": "describe_vpc_peering_connections", "key": "VpcPeeringConnections", "paginate": True},
            {"method": "describe_vpc_endpoints", "key": "VpcEndpoints", "paginate": True},
            {"method": "describe_flow_logs", "key": "FlowLogs", "paginate": True},
            {"method": "describe_launch_templates", "key": "LaunchTemplates", "paginate": True},
            {"method": "describe_transit_gateways", "key": "TransitGateways", "paginate": True},
            {"method": "describe_managed_prefix_lists", "key": "PrefixLists", "paginate": True},
            {"method": "describe_placement_groups", "key": "PlacementGroups"},
            {"method": "describe_reserved_instances", "key": "ReservedInstances"},
            {"method": "describe_spot_instance_requests", "key": "SpotInstanceRequests", "paginate": True},
            {"method": "describe_dhcp_options", "key": "DhcpOptions", "paginate": True},
            {"method": "describe_customer_gateways", "key": "CustomerGateways"},
        ],
    },
    "lambda": {
        "client": "lambda",
        "calls": [
            {"method": "list_functions", "key": "Functions", "paginate": True},
            {"method": "list_layers", "key": "Layers", "paginate": True},
            {"method": "list_event_source_mappings", "key": "EventSourceMappings", "paginate": True},
            {"method": "get_account_settings", "key": "AccountLimit"},
        ],
    },
    "ecs": {
        "client": "ecs",
        "calls": [
            {"method": "list_clusters", "key": "clusterArns", "paginate": True},
            {"method": "list_task_definitions", "key": "taskDefinitionArns", "paginate": True},
        ],
    },
    "eks": {
        "client": "eks",
        "calls": [
            {"method": "list_clusters", "key": "clusters", "paginate": True},
        ],
    },
    "lightsail": {
        "client": "lightsail",
        "calls": [
            {"method": "get_instances", "key": "instances"},
            {"method": "get_domains", "key": "domains"},
            {"method": "get_load_balancers", "key": "loadBalancers"},
            {"method": "get_static_ips", "key": "staticIps"},
            {"method": "get_key_pairs", "key": "keyPairs"},
            {"method": "get_disks", "key": "disks"},
            {"method": "get_blueprints", "key": "blueprints"},
        ],
    },
    "batch": {
        "client": "batch",
        "calls": [
            {"method": "describe_compute_environments", "key": "computeEnvironments", "paginate": True},
            {"method": "describe_job_definitions", "key": "jobDefinitions", "paginate": True},
            {"method": "describe_job_queues", "key": "jobQueues", "paginate": True},
        ],
    },
    "autoscaling": {
        "client": "autoscaling",
        "calls": [
            {"method": "describe_auto_scaling_groups", "key": "AutoScalingGroups", "paginate": True},
            {"method": "describe_launch_configurations", "key": "LaunchConfigurations", "paginate": True},
            {"method": "describe_policies", "key": "ScalingPolicies", "paginate": True},
            {"method": "describe_auto_scaling_instances", "key": "AutoScalingInstances", "paginate": True},
            {"method": "describe_scheduled_actions", "key": "ScheduledUpdateGroupActions", "paginate": True},
            {"method": "describe_notification_configurations", "key": "NotificationConfigurations", "paginate": True},
            {"method": "describe_tags", "key": "Tags", "paginate": True},
        ],
    },
    "elasticbeanstalk": {
        "client": "elasticbeanstalk",
        "calls": [
            {"method": "describe_applications", "key": "Applications"},
            {"method": "describe_environments", "key": "Environments"},
        ],
    },
    "emr": {
        "client": "emr",
        "calls": [
            {"method": "list_clusters", "key": "Clusters", "paginate": True},
        ],
    },
    "apprunner": {
        "client": "apprunner",
        "calls": [
            {"method": "list_services", "key": "ServiceSummaryList", "paginate": True},
            {"method": "list_auto_scaling_configurations", "key": "AutoScalingConfigurationSummaryList", "paginate": True},
        ],
    },
}

# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------

_STORAGE = {
    "s3": {
        "client": "s3",
        "global": True,
        "calls": [
            {"method": "list_buckets", "key": "Buckets"},
        ],
    },
    "dynamodb": {
        "client": "dynamodb",
        "calls": [
            {"method": "list_tables", "key": "TableNames", "paginate": True},
            {"method": "list_backups", "key": "BackupSummaries"},
            {"method": "list_global_tables", "key": "GlobalTables"},
            {"method": "describe_limits", "key": None},
            {"method": "describe_endpoints", "key": "Endpoints"},
        ],
    },
    "ecr": {
        "client": "ecr",
        "calls": [
            {"method": "describe_repositories", "key": "repositories", "paginate": True},
            {"method": "describe_registry", "key": None},
            {"method": "get_authorization_token", "key": "authorizationData"},
        ],
    },
    "efs": {
        "client": "efs",
        "calls": [
            {"method": "describe_file_systems", "key": "FileSystems", "paginate": True},
        ],
    },
    "fsx": {
        "client": "fsx",
        "calls": [
            {"method": "describe_file_systems", "key": "FileSystems", "paginate": True},
            {"method": "describe_backups", "key": "Backups", "paginate": True},
        ],
    },
    "storagegateway": {
        "client": "storagegateway",
        "calls": [
            {"method": "list_gateways", "key": "Gateways", "paginate": True},
        ],
    },
    "backup": {
        "client": "backup",
        "calls": [
            {"method": "list_backup_vaults", "key": "BackupVaultList", "paginate": True},
            {"method": "list_backup_plans", "key": "BackupPlansList", "paginate": True},
            {"method": "list_protected_resources", "key": "Results", "paginate": True},
            {"method": "list_backup_jobs", "key": "BackupJobs", "paginate": True},
            {"method": "get_supported_resource_types", "key": "ResourceTypes"},
        ],
    },
    "glacier": {
        "client": "glacier",
        "calls": [
            {"method": "list_vaults", "key": "VaultList", "params": {"accountId": "-"}},
        ],
    },
}

# ---------------------------------------------------------------------------
# Databases
# ---------------------------------------------------------------------------

_DATABASES = {
    "rds": {
        "client": "rds",
        "calls": [
            {"method": "describe_db_instances", "key": "DBInstances", "paginate": True},
            {"method": "describe_db_clusters", "key": "DBClusters", "paginate": True},
            {"method": "describe_db_snapshots", "key": "DBSnapshots", "paginate": True},
            {"method": "describe_db_cluster_snapshots", "key": "DBClusterSnapshots", "paginate": True},
            {"method": "describe_db_subnet_groups", "key": "DBSubnetGroups", "paginate": True},
            {"method": "describe_db_parameter_groups", "key": "DBParameterGroups", "paginate": True},
            {"method": "describe_event_subscriptions", "key": "EventSubscriptionsList", "paginate": True},
            {"method": "describe_reserved_db_instances", "key": "ReservedDBInstances", "paginate": True},
            {"method": "describe_global_clusters", "key": "GlobalClusters", "paginate": True},
        ],
    },
    "redshift": {
        "client": "redshift",
        "calls": [
            {"method": "describe_clusters", "key": "Clusters", "paginate": True},
            {"method": "describe_cluster_subnet_groups", "key": "ClusterSubnetGroups", "paginate": True},
            {"method": "describe_cluster_snapshots", "key": "Snapshots", "paginate": True},
            {"method": "describe_cluster_parameter_groups", "key": "ParameterGroups", "paginate": True},
        ],
    },
    "elasticache": {
        "client": "elasticache",
        "calls": [
            {"method": "describe_cache_clusters", "key": "CacheClusters", "paginate": True},
            {"method": "describe_replication_groups", "key": "ReplicationGroups", "paginate": True},
            {"method": "describe_cache_subnet_groups", "key": "CacheSubnetGroups", "paginate": True},
            {"method": "describe_cache_parameter_groups", "key": "CacheParameterGroups", "paginate": True},
            {"method": "describe_snapshots", "key": "Snapshots", "paginate": True},
        ],
    },
    "dax": {
        "client": "dax",
        "calls": [
            {"method": "describe_clusters", "key": "Clusters"},
            {"method": "describe_parameter_groups", "key": "ParameterGroups"},
            {"method": "describe_subnet_groups", "key": "SubnetGroups"},
        ],
    },
    "neptune": {
        "client": "neptune",
        "calls": [
            {"method": "describe_db_clusters", "key": "DBClusters", "paginate": True},
            {"method": "describe_db_instances", "key": "DBInstances", "paginate": True},
        ],
    },
    "docdb": {
        "client": "docdb",
        "calls": [
            {"method": "describe_db_clusters", "key": "DBClusters", "paginate": True},
            {"method": "describe_db_instances", "key": "DBInstances", "paginate": True},
        ],
    },
    "memorydb": {
        "client": "memorydb",
        "calls": [
            {"method": "describe_clusters", "key": "Clusters"},
        ],
    },
    "timestream-write": {
        "client": "timestream-write",
        "calls": [
            {"method": "list_databases", "key": "Databases", "paginate": True},
        ],
    },
}

# ---------------------------------------------------------------------------
# Networking & CDN
# ---------------------------------------------------------------------------

_NETWORKING = {
    "route53": {
        "client": "route53",
        "global": True,
        "calls": [
            {"method": "list_hosted_zones", "key": "HostedZones", "paginate": True},
            {"method": "list_health_checks", "key": "HealthChecks", "paginate": True},
            {"method": "get_checker_ip_ranges", "key": "CheckerIpRanges"},
        ],
    },
    "route53domains": {
        "client": "route53domains",
        "global": True,
        "calls": [
            {"method": "list_domains", "key": "Domains", "paginate": True},
        ],
    },
    "cloudfront": {
        "client": "cloudfront",
        "global": True,
        "calls": [
            {"method": "list_distributions", "key": "DistributionList", "paginate": True},
            {"method": "list_cloud_front_origin_access_identities", "key": "CloudFrontOriginAccessIdentityList", "paginate": True},
        ],
    },
    "apigateway": {
        "client": "apigateway",
        "calls": [
            {"method": "get_rest_apis", "key": "items", "paginate": True},
            {"method": "get_api_keys", "key": "items", "paginate": True},
            {"method": "get_domain_names", "key": "items", "paginate": True},
            {"method": "get_client_certificates", "key": "items", "paginate": True},
            {"method": "get_vpc_links", "key": "items", "paginate": True},
            {"method": "get_usage_plans", "key": "items", "paginate": True},
        ],
    },
    "apigatewayv2": {
        "client": "apigatewayv2",
        "calls": [
            {"method": "get_apis", "key": "Items"},
            {"method": "get_domain_names", "key": "Items"},
            {"method": "get_vpc_links", "key": "Items"},
        ],
    },
    "elbv2": {
        "client": "elbv2",
        "calls": [
            {"method": "describe_load_balancers", "key": "LoadBalancers", "paginate": True},
            {"method": "describe_target_groups", "key": "TargetGroups", "paginate": True},
            {"method": "describe_ssl_policies", "key": "SslPolicies"},
        ],
    },
    "elb": {
        "client": "elb",
        "calls": [
            {"method": "describe_load_balancers", "key": "LoadBalancerDescriptions", "paginate": True},
        ],
    },
    "directconnect": {
        "client": "directconnect",
        "calls": [
            {"method": "describe_connections", "key": "connections"},
            {"method": "describe_virtual_gateways", "key": "virtualGateways"},
            {"method": "describe_direct_connect_gateways", "key": "directConnectGateways"},
        ],
    },
    "globalaccelerator": {
        "client": "globalaccelerator",
        "global": True,
        "calls": [
            {"method": "list_accelerators", "key": "Accelerators", "paginate": True},
        ],
    },
    "networkfirewall": {
        "client": "network-firewall",
        "calls": [
            {"method": "list_firewalls", "key": "Firewalls", "paginate": True},
            {"method": "list_firewall_policies", "key": "FirewallPolicies", "paginate": True},
        ],
    },
}

# ---------------------------------------------------------------------------
# Security & Compliance
# ---------------------------------------------------------------------------

_SECURITY = {
    "cloudtrail": {
        "client": "cloudtrail",
        "calls": [
            {"method": "describe_trails", "key": "trailList"},
            {"method": "list_trails", "key": "Trails", "paginate": True},
        ],
    },
    "guardduty": {
        "client": "guardduty",
        "calls": [
            {"method": "list_detectors", "key": "DetectorIds", "paginate": True},
        ],
    },
    "securityhub": {
        "client": "securityhub",
        "calls": [
            {"method": "describe_hub", "key": None},
            {"method": "get_enabled_standards", "key": "StandardsSubscriptions", "paginate": True},
            {"method": "list_enabled_products_for_import", "key": "ProductSubscriptions", "paginate": True},
        ],
    },
    "kms": {
        "client": "kms",
        "calls": [
            {"method": "list_keys", "key": "Keys", "paginate": True},
            {"method": "list_aliases", "key": "Aliases", "paginate": True},
        ],
    },
    "secretsmanager": {
        "client": "secretsmanager",
        "calls": [
            {"method": "list_secrets", "key": "SecretList", "paginate": True},
        ],
    },
    "acm": {
        "client": "acm",
        "calls": [
            {"method": "list_certificates", "key": "CertificateSummaryList", "paginate": True},
        ],
    },
    "wafv2": {
        "client": "wafv2",
        "calls": [
            {"method": "list_web_acls", "key": "WebACLs", "params": {"Scope": "REGIONAL"}},
            {"method": "list_ip_sets", "key": "IPSets", "params": {"Scope": "REGIONAL"}},
            {"method": "list_rule_groups", "key": "RuleGroups", "params": {"Scope": "REGIONAL"}},
            {"method": "list_regex_pattern_sets", "key": "RegexPatternSets", "params": {"Scope": "REGIONAL"}},
        ],
    },
    "inspector2": {
        "client": "inspector2",
        "calls": [
            {"method": "list_coverage", "key": "coveredResources", "paginate": True},
        ],
    },
    "shield": {
        "client": "shield",
        "global": True,
        "calls": [
            {"method": "list_protections", "key": "Protections", "paginate": True},
            {"method": "describe_subscription", "key": "Subscription"},
        ],
    },
    "macie2": {
        "client": "macie2",
        "calls": [
            {"method": "get_macie_session", "key": None},
            {"method": "describe_buckets", "key": "buckets", "paginate": True},
        ],
    },
    "detective": {
        "client": "detective",
        "calls": [
            {"method": "list_graphs", "key": "GraphList"},
        ],
    },
}

# ---------------------------------------------------------------------------
# Management & Monitoring
# ---------------------------------------------------------------------------

_MANAGEMENT = {
    "cloudformation": {
        "client": "cloudformation",
        "calls": [
            {"method": "list_stacks", "key": "StackSummaries", "paginate": True},
            {"method": "list_exports", "key": "Exports", "paginate": True},
            {"method": "describe_account_limits", "key": "AccountLimits"},
        ],
    },
    "cloudwatch": {
        "client": "cloudwatch",
        "calls": [
            {"method": "describe_alarms", "key": "MetricAlarms", "paginate": True},
            {"method": "list_dashboards", "key": "DashboardEntries", "paginate": True},
        ],
    },
    "logs": {
        "client": "logs",
        "calls": [
            {"method": "describe_log_groups", "key": "logGroups", "paginate": True},
            {"method": "describe_metric_filters", "key": "metricFilters", "paginate": True},
            {"method": "describe_destinations", "key": "destinations", "paginate": True},
        ],
    },
    "ssm": {
        "client": "ssm",
        "calls": [
            {"method": "describe_instance_information", "key": "InstanceInformationList", "paginate": True},
            {"method": "list_documents", "key": "DocumentIdentifiers", "paginate": True},
            {"method": "describe_parameters", "key": "Parameters", "paginate": True},
            {"method": "list_associations", "key": "Associations", "paginate": True},
            {"method": "describe_maintenance_windows", "key": "WindowIdentities", "paginate": True},
        ],
    },
    "config": {
        "client": "config",
        "calls": [
            {"method": "describe_config_rules", "key": "ConfigRules", "paginate": True},
            {"method": "describe_configuration_recorders", "key": "ConfigurationRecorders"},
            {"method": "describe_delivery_channels", "key": "DeliveryChannels"},
            {"method": "describe_compliance_by_config_rule", "key": "ComplianceByConfigRules", "paginate": True},
        ],
    },
    "servicecatalog": {
        "client": "servicecatalog",
        "calls": [
            {"method": "list_portfolios", "key": "PortfolioDetails", "paginate": True},
            {"method": "list_accepted_portfolio_shares", "key": "PortfolioDetails", "paginate": True},
        ],
    },
    "resource-groups": {
        "client": "resource-groups",
        "calls": [
            {"method": "list_groups", "key": "GroupIdentifiers", "paginate": True},
        ],
    },
    "health": {
        "client": "health",
        "global": True,
        "calls": [
            {"method": "describe_events", "key": "events", "paginate": True},
        ],
    },
    "support": {
        "client": "support",
        "global": True,
        "calls": [
            {"method": "describe_trusted_advisor_checks", "key": "checks", "params": {"language": "en"}},
        ],
    },
    "pricing": {
        "client": "pricing",
        "calls": [
            {"method": "describe_services", "key": "Services", "paginate": True},
        ],
    },
}

# ---------------------------------------------------------------------------
# Messaging & Events
# ---------------------------------------------------------------------------

_MESSAGING = {
    "sns": {
        "client": "sns",
        "calls": [
            {"method": "list_topics", "key": "Topics", "paginate": True},
            {"method": "list_subscriptions", "key": "Subscriptions", "paginate": True},
            {"method": "list_platform_applications", "key": "PlatformApplications", "paginate": True},
        ],
    },
    "sqs": {
        "client": "sqs",
        "calls": [
            {"method": "list_queues", "key": "QueueUrls", "paginate": True},
        ],
    },
    "ses": {
        "client": "ses",
        "calls": [
            {"method": "list_identities", "key": "Identities", "paginate": True},
            {"method": "get_send_quota", "key": None},
        ],
    },
    "sesv2": {
        "client": "sesv2",
        "calls": [
            {"method": "list_email_identities", "key": "EmailIdentities"},
            {"method": "get_account", "key": None},
            {"method": "list_configuration_sets", "key": "ConfigurationSets"},
            {"method": "list_dedicated_ip_pools", "key": "DedicatedIpPools"},
        ],
    },
    "events": {
        "client": "events",
        "calls": [
            {"method": "list_rules", "key": "Rules", "paginate": True},
            {"method": "list_event_buses", "key": "EventBuses"},
        ],
    },
    "pinpoint": {
        "client": "pinpoint",
        "calls": [
            {"method": "get_apps", "key": "ApplicationsResponse"},
        ],
    },
}

# ---------------------------------------------------------------------------
# CI/CD & Developer Tools
# ---------------------------------------------------------------------------

_DEVTOOLS = {
    "codebuild": {
        "client": "codebuild",
        "calls": [
            {"method": "list_projects", "key": "projects"},
            {"method": "list_report_groups", "key": "reportGroups"},
        ],
    },
    "codecommit": {
        "client": "codecommit",
        "calls": [
            {"method": "list_repositories", "key": "repositories", "paginate": True},
        ],
    },
    "codepipeline": {
        "client": "codepipeline",
        "calls": [
            {"method": "list_pipelines", "key": "pipelines", "paginate": True},
            {"method": "list_webhooks", "key": "webhooks", "paginate": True},
        ],
    },
    "codedeploy": {
        "client": "codedeploy",
        "calls": [
            {"method": "list_applications", "key": "applications", "paginate": True},
        ],
    },
    "codeartifact": {
        "client": "codeartifact",
        "calls": [
            {"method": "list_domains", "key": "domains", "paginate": True},
            {"method": "list_repositories", "key": "repositories", "paginate": True},
        ],
    },
    "amplify": {
        "client": "amplify",
        "calls": [
            {"method": "list_apps", "key": "apps"},
        ],
    },
    "cloud9": {
        "client": "cloud9",
        "calls": [
            {"method": "list_environments", "key": "environmentIds", "paginate": True},
        ],
    },
    "proton": {
        "client": "proton",
        "calls": [
            {"method": "list_environments", "key": "environments", "paginate": True},
            {"method": "list_services", "key": "services", "paginate": True},
        ],
    },
}

# ---------------------------------------------------------------------------
# Analytics
# ---------------------------------------------------------------------------

_ANALYTICS = {
    "glue": {
        "client": "glue",
        "calls": [
            {"method": "get_databases", "key": "DatabaseList", "paginate": True},
            {"method": "get_crawlers", "key": "Crawlers", "paginate": True},
            {"method": "get_jobs", "key": "Jobs", "paginate": True},
            {"method": "get_connections", "key": "ConnectionList", "paginate": True},
            {"method": "get_security_configurations", "key": "SecurityConfigurations", "paginate": True},
            {"method": "list_dev_endpoints", "key": "DevEndpointNames", "paginate": True},
        ],
    },
    "athena": {
        "client": "athena",
        "calls": [
            {"method": "list_query_executions", "key": "QueryExecutionIds", "paginate": True},
            {"method": "list_named_queries", "key": "NamedQueryIds", "paginate": True},
            {"method": "list_work_groups", "key": "WorkGroups", "paginate": True},
        ],
    },
    "kinesis": {
        "client": "kinesis",
        "calls": [
            {"method": "list_streams", "key": "StreamNames", "paginate": True},
        ],
    },
    "firehose": {
        "client": "firehose",
        "calls": [
            {"method": "list_delivery_streams", "key": "DeliveryStreamNames"},
        ],
    },
    "kafka": {
        "client": "kafka",
        "calls": [
            {"method": "list_clusters", "key": "ClusterInfoList", "paginate": True},
            {"method": "list_clusters_v2", "key": "ClusterInfoList", "paginate": True},
        ],
    },
    "opensearch": {
        "client": "opensearch",
        "calls": [
            {"method": "list_domain_names", "key": "DomainNames"},
        ],
    },
    "lakeformation": {
        "client": "lakeformation",
        "calls": [
            {"method": "list_resources", "key": "ResourceInfoList", "paginate": True},
            {"method": "get_data_lake_settings", "key": "DataLakeSettings"},
        ],
    },
    "databrew": {
        "client": "databrew",
        "calls": [
            {"method": "list_projects", "key": "Projects", "paginate": True},
            {"method": "list_datasets", "key": "Datasets", "paginate": True},
        ],
    },
}

# ---------------------------------------------------------------------------
# AI/ML
# ---------------------------------------------------------------------------

_ML = {
    "sagemaker": {
        "client": "sagemaker",
        "calls": [
            {"method": "list_notebook_instances", "key": "NotebookInstances", "paginate": True},
            {"method": "list_endpoints", "key": "Endpoints", "paginate": True},
            {"method": "list_models", "key": "Models", "paginate": True},
            {"method": "list_training_jobs", "key": "TrainingJobSummaries", "paginate": True},
        ],
    },
    "comprehend": {
        "client": "comprehend",
        "calls": [
            {"method": "list_document_classifiers", "key": "DocumentClassifierPropertiesList", "paginate": True},
        ],
    },
    "rekognition": {
        "client": "rekognition",
        "calls": [
            {"method": "list_collections", "key": "CollectionIds", "paginate": True},
        ],
    },
    "translate": {
        "client": "translate",
        "calls": [
            {"method": "list_terminologies", "key": "TerminologyPropertiesList", "paginate": True},
        ],
    },
    "transcribe": {
        "client": "transcribe",
        "calls": [
            {"method": "list_transcription_jobs", "key": "TranscriptionJobSummaries", "paginate": True},
            {"method": "list_vocabularies", "key": "Vocabularies", "paginate": True},
        ],
    },
    "polly": {
        "client": "polly",
        "calls": [
            {"method": "describe_voices", "key": "Voices"},
        ],
    },
}

# ---------------------------------------------------------------------------
# Application & Integration
# ---------------------------------------------------------------------------

_APPLICATION = {
    "cognito-idp": {
        "client": "cognito-idp",
        "calls": [
            {"method": "list_user_pools", "key": "UserPools", "params": {"MaxResults": 60}},
        ],
    },
    "cognito-identity": {
        "client": "cognito-identity",
        "calls": [
            {"method": "list_identity_pools", "key": "IdentityPools", "params": {"MaxResults": 60}},
        ],
    },
    "stepfunctions": {
        "client": "stepfunctions",
        "calls": [
            {"method": "list_state_machines", "key": "stateMachines", "paginate": True},
            {"method": "list_activities", "key": "activities", "paginate": True},
        ],
    },
    "appsync": {
        "client": "appsync",
        "calls": [
            {"method": "list_graphql_apis", "key": "graphqlApis"},
        ],
    },
    "mq": {
        "client": "mq",
        "calls": [
            {"method": "list_brokers", "key": "BrokerSummaries", "paginate": True},
        ],
    },
    "appconfig": {
        "client": "appconfig",
        "calls": [
            {"method": "list_applications", "key": "Items", "paginate": True},
        ],
    },
}

# ---------------------------------------------------------------------------
# Migration & Transfer
# ---------------------------------------------------------------------------

_MIGRATION = {
    "datasync": {
        "client": "datasync",
        "calls": [
            {"method": "list_tasks", "key": "Tasks", "paginate": True},
            {"method": "list_agents", "key": "Agents", "paginate": True},
            {"method": "list_locations", "key": "Locations", "paginate": True},
        ],
    },
    "transfer": {
        "client": "transfer",
        "calls": [
            {"method": "list_servers", "key": "Servers", "paginate": True},
        ],
    },
    "dms": {
        "client": "dms",
        "calls": [
            {"method": "describe_replication_instances", "key": "ReplicationInstances", "paginate": True},
            {"method": "describe_replication_tasks", "key": "ReplicationTasks", "paginate": True},
            {"method": "describe_endpoints", "key": "Endpoints", "paginate": True},
        ],
    },
    "snowball": {
        "client": "snowball",
        "calls": [
            {"method": "list_jobs", "key": "JobListEntries"},
            {"method": "list_clusters", "key": "ClusterListEntries"},
        ],
    },
}

# ---------------------------------------------------------------------------
# IoT
# ---------------------------------------------------------------------------

_IOT = {
    "iot": {
        "client": "iot",
        "calls": [
            {"method": "list_things", "key": "things", "paginate": True},
            {"method": "list_policies", "key": "policies", "paginate": True},
            {"method": "list_certificates", "key": "certificates", "paginate": True},
        ],
    },
    "iot-analytics": {
        "client": "iotanalytics",
        "calls": [
            {"method": "list_channels", "key": "channelSummaries", "paginate": True},
            {"method": "list_datasets", "key": "datasetSummaries", "paginate": True},
            {"method": "list_datastores", "key": "datastoreSummaries", "paginate": True},
        ],
    },
    "greengrass": {
        "client": "greengrass",
        "calls": [
            {"method": "list_groups", "key": "Groups"},
        ],
    },
}

# ---------------------------------------------------------------------------
# Media
# ---------------------------------------------------------------------------

_MEDIA = {
    "mediaconvert": {
        "client": "mediaconvert",
        "calls": [
            {"method": "describe_endpoints", "key": "Endpoints"},
        ],
    },
    "medialive": {
        "client": "medialive",
        "calls": [
            {"method": "list_inputs", "key": "Inputs", "paginate": True},
            {"method": "list_channels", "key": "Channels", "paginate": True},
        ],
    },
    "mediapackage": {
        "client": "mediapackage",
        "calls": [
            {"method": "list_channels", "key": "Channels", "paginate": True},
            {"method": "list_origin_endpoints", "key": "OriginEndpoints", "paginate": True},
        ],
    },
    "mediastore": {
        "client": "mediastore",
        "calls": [
            {"method": "list_containers", "key": "Containers", "paginate": True},
        ],
    },
    "mediatailor": {
        "client": "mediatailor",
        "calls": [
            {"method": "list_playback_configurations", "key": "Items", "paginate": True},
        ],
    },
}

# ---------------------------------------------------------------------------
# Other
# ---------------------------------------------------------------------------

_OTHER = {
    "xray": {
        "client": "xray",
        "calls": [
            {"method": "get_sampling_rules", "key": "SamplingRuleRecords", "paginate": True},
            {"method": "get_groups", "key": "Groups", "paginate": True},
            {"method": "get_encryption_config", "key": "EncryptionConfig"},
        ],
    },
    "ram": {
        "client": "ram",
        "calls": [
            {"method": "get_resource_shares", "key": "resourceShares", "paginate": True, "params": {"resourceOwner": "SELF"}},
        ],
    },
    "workspaces": {
        "client": "workspaces",
        "calls": [
            {"method": "describe_workspaces", "key": "Workspaces", "paginate": True},
            {"method": "describe_workspace_directories", "key": "Directories"},
            {"method": "describe_workspace_bundles", "key": "Bundles", "paginate": True},
        ],
    },
    "workmail": {
        "client": "workmail",
        "calls": [
            {"method": "list_organizations", "key": "OrganizationSummaries", "paginate": True},
        ],
    },
    "opsworks": {
        "client": "opsworks",
        "calls": [
            {"method": "describe_stacks", "key": "Stacks"},
        ],
    },
    "cloudhsmv2": {
        "client": "cloudhsmv2",
        "calls": [
            {"method": "describe_clusters", "key": "Clusters", "paginate": True},
        ],
    },
    "cloudsearch": {
        "client": "cloudsearch",
        "calls": [
            {"method": "describe_domains", "key": "DomainStatusList"},
        ],
    },
    "datapipeline": {
        "client": "datapipeline",
        "calls": [
            {"method": "list_pipelines", "key": "pipelineIdList", "paginate": True},
        ],
    },
    "devicefarm": {
        "client": "devicefarm",
        "calls": [
            {"method": "list_projects", "key": "projects", "paginate": True},
        ],
    },
    "dlm": {
        "client": "dlm",
        "calls": [
            {"method": "get_lifecycle_policies", "key": "Policies"},
        ],
    },
    "signer": {
        "client": "signer",
        "calls": [
            {"method": "list_signing_jobs", "key": "jobs", "paginate": True},
        ],
    },
    "robomaker": {
        "client": "robomaker",
        "calls": [
            {"method": "list_simulation_jobs", "key": "simulationJobSummaries", "paginate": True},
        ],
    },
    "grafana": {
        "client": "grafana",
        "calls": [
            {"method": "list_workspaces", "key": "workspaces", "paginate": True},
        ],
    },
}


# ---------------------------------------------------------------------------
# Merged registry
# ---------------------------------------------------------------------------

SERVICES = {}
for _group in [_IDENTITY, _COMPUTE, _STORAGE, _DATABASES, _NETWORKING,
               _SECURITY, _MANAGEMENT, _MESSAGING, _DEVTOOLS, _ANALYTICS,
               _ML, _APPLICATION, _MIGRATION, _IOT, _MEDIA, _OTHER]:
    SERVICES.update(_group)


def get_service_names():
    """Returns a sorted list of all registered service names."""
    return sorted(SERVICES.keys())


def get_service(name):
    """Returns the service definition dict for a given name, or None."""
    return SERVICES.get(name)


def get_all_services():
    """Returns the complete services dict."""
    return SERVICES
