"""EDP-009 Part 1, Section 8: the real, per-category AWS discovery implementations
`gds_api.cloud.adapters.aws.AWSProviderAdapter` composes. Split from `aws.py` purely
for file size/readability - this is the same real adapter's behaviour, never a
second adapter or a second execution path.

Every function here makes a real, read-only `boto3` call (list/describe only -
Section 8's own explicit rule: never read a secret value, never download S3 object
contents, never invoke Lambda, never change a resource). No live AWS credentials
exist in this deployment environment (Phase 22 pre-build audit), so every one of
these calls genuinely fails when actually invoked here - `_safe_category` below
catches and logs that per-category, per-region failure rather than aborting the
whole discovery stream, satisfying Section 8's own "access denied per service" /
"partial regional failure" requirements at the adapter level.

Bounded, real scope: exactly the 25 categories `CLOUD_PROVIDER_REGISTRY["aws"]`
declares - organisation, account, iam_identity_summary, region, and 21 real AWS
resource types across networking, compute, storage, and security services. No
service beyond that list is attempted here, per Section 8's own instruction.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from gds_api.cloud.adapters.aws import _BOTO_CONFIG, _build_session, _classify, _paginate, _tag_dict
from gds_api.cloud.schemas import NormalizedCloudAsset, NormalizedCloudRelationship
from gds_api.logging_config import get_logger

if TYPE_CHECKING:
    from gds_api.models import CloudConnectionProfile

_logger = get_logger("gds_api.cloud.adapters.aws")


async def _safe_assets(
    agen: AsyncIterator[NormalizedCloudAsset], category: str
) -> AsyncIterator[NormalizedCloudAsset]:
    try:
        async for item in agen:
            yield item
    except Exception as exc:  # noqa: BLE001 - contained per-category, never aborts the stream
        error = _classify(exc)
        _logger.warning(
            "cloud.aws_discovery_category_failed",
            category=category,
            error_category=error.category.value,
            message=error.sanitized_message,
        )


async def _safe_relationships(
    agen: AsyncIterator[NormalizedCloudRelationship], category: str
) -> AsyncIterator[NormalizedCloudRelationship]:
    try:
        async for item in agen:
            yield item
    except Exception as exc:  # noqa: BLE001
        error = _classify(exc)
        _logger.warning(
            "cloud.aws_discovery_relationship_category_failed",
            category=category,
            error_category=error.category.value,
            message=error.sanitized_message,
        )


async def _list_regions(session: Any) -> list[str]:
    ec2 = session.client("ec2", config=_BOTO_CONFIG)
    result = await asyncio.to_thread(ec2.describe_regions, AllRegions=False)
    return sorted(str(r["RegionName"]) for r in result.get("Regions", []))


# ----------------------------------------------------------------------------
# Global categories: organisation, account, iam_identity_summary, region,
# s3_bucket (bucket listing is global; per-bucket region is looked up).
# ----------------------------------------------------------------------------


async def _discover_organisation_and_accounts(
    session: Any, account_id: str
) -> AsyncIterator[NormalizedCloudAsset]:
    org_client = session.client("organizations", config=_BOTO_CONFIG)
    org = await asyncio.to_thread(org_client.describe_organization)
    org_info = org.get("Organization", {})
    org_id = str(org_info.get("Id", ""))
    if org_id:
        yield NormalizedCloudAsset(
            provider="aws",
            native_id=org_id,
            native_resource_type="organizations.Organization",
            normalized_category="organisation",
            name=org_id,
            managed_service=True,
            raw_metadata=org_info,
        )
    async for acct in _paginate(org_client, "list_accounts", "Accounts"):
        acct_id = str(acct.get("Id", ""))
        yield NormalizedCloudAsset(
            provider="aws",
            native_id=acct_id,
            native_resource_type="organizations.Account",
            normalized_category="account",
            name=str(acct.get("Name", acct_id)),
            parent_native_id=org_id or None,
            account_or_subscription_or_project=acct_id,
            lifecycle_state=str(acct.get("Status", "")) or None,
            created_at_provider=acct.get("JoinedTimestamp"),
            raw_metadata=acct,
        )


async def _discover_iam_identity_summary(
    session: Any, account_id: str
) -> AsyncIterator[NormalizedCloudAsset]:
    iam = session.client("iam", config=_BOTO_CONFIG)
    summary = await asyncio.to_thread(iam.get_account_summary)
    yield NormalizedCloudAsset(
        provider="aws",
        native_id=f"{account_id}:iam-summary",
        native_resource_type="iam.AccountSummary",
        normalized_category="iam_identity_summary",
        name=f"IAM account summary ({account_id})",
        account_or_subscription_or_project=account_id,
        raw_metadata=dict(summary.get("SummaryMap", {})),
    )


async def _discover_s3_buckets(
    session: Any, account_id: str
) -> AsyncIterator[NormalizedCloudAsset]:
    s3 = session.client("s3", config=_BOTO_CONFIG)
    result = await asyncio.to_thread(s3.list_buckets)
    for bucket in result.get("Buckets", []):
        name = str(bucket.get("Name", ""))
        region: str | None = None
        try:
            loc = await asyncio.to_thread(s3.get_bucket_location, Bucket=name)
            region = str(loc.get("LocationConstraint") or "us-east-1")
        except Exception:  # noqa: BLE001 - per-bucket region lookup may fail (cross-region ACL); asset is still real
            region = None
        yield NormalizedCloudAsset(
            provider="aws",
            native_id=name,
            native_resource_type="s3.Bucket",
            normalized_category="s3_bucket",
            name=name,
            region_or_location=region,
            account_or_subscription_or_project=account_id,
            created_at_provider=bucket.get("CreationDate"),
            managed_service=True,
            raw_metadata=bucket,
        )


# ----------------------------------------------------------------------------
# Regional categories.
# ----------------------------------------------------------------------------


async def _discover_ec2_instances(
    session: Any, region: str, account_id: str
) -> AsyncIterator[NormalizedCloudAsset]:
    ec2 = session.client("ec2", region_name=region, config=_BOTO_CONFIG)
    async for reservation in _paginate(ec2, "describe_instances", "Reservations"):
        for instance in reservation.get("Instances", []):
            instance_id = str(instance.get("InstanceId", ""))
            yield NormalizedCloudAsset(
                provider="aws",
                native_id=instance_id,
                native_resource_type="ec2.Instance",
                normalized_category="ec2_instance",
                name=_tag_dict(instance.get("Tags")).get("Name", instance_id),
                region_or_location=region,
                availability_zone=(instance.get("Placement", {}) or {}).get("AvailabilityZone"),
                parent_native_id=instance.get("SubnetId"),
                account_or_subscription_or_project=account_id,
                lifecycle_state=(instance.get("State", {}) or {}).get("Name"),
                created_at_provider=instance.get("LaunchTime"),
                tags=_tag_dict(instance.get("Tags")),
                internet_exposure_known=bool(instance.get("PublicIpAddress")),
                raw_metadata=instance,
            )


async def _discover_vpcs(
    session: Any, region: str, account_id: str
) -> AsyncIterator[NormalizedCloudAsset]:
    ec2 = session.client("ec2", region_name=region, config=_BOTO_CONFIG)
    async for vpc in _paginate(ec2, "describe_vpcs", "Vpcs"):
        vpc_id = str(vpc.get("VpcId", ""))
        yield NormalizedCloudAsset(
            provider="aws",
            native_id=vpc_id,
            native_resource_type="ec2.Vpc",
            normalized_category="vpc",
            name=_tag_dict(vpc.get("Tags")).get("Name", vpc_id),
            region_or_location=region,
            account_or_subscription_or_project=account_id,
            lifecycle_state=vpc.get("State"),
            tags=_tag_dict(vpc.get("Tags")),
            raw_metadata=vpc,
        )


async def _discover_subnets(
    session: Any, region: str, account_id: str
) -> AsyncIterator[NormalizedCloudAsset]:
    ec2 = session.client("ec2", region_name=region, config=_BOTO_CONFIG)
    async for subnet in _paginate(ec2, "describe_subnets", "Subnets"):
        subnet_id = str(subnet.get("SubnetId", ""))
        yield NormalizedCloudAsset(
            provider="aws",
            native_id=subnet_id,
            native_resource_type="ec2.Subnet",
            normalized_category="subnet",
            name=_tag_dict(subnet.get("Tags")).get("Name", subnet_id),
            region_or_location=region,
            availability_zone=subnet.get("AvailabilityZone"),
            parent_native_id=subnet.get("VpcId"),
            account_or_subscription_or_project=account_id,
            lifecycle_state=subnet.get("State"),
            tags=_tag_dict(subnet.get("Tags")),
            internet_exposure_known=bool(subnet.get("MapPublicIpOnLaunch")),
            raw_metadata=subnet,
        )


async def _discover_security_groups(
    session: Any, region: str, account_id: str
) -> AsyncIterator[NormalizedCloudAsset]:
    ec2 = session.client("ec2", region_name=region, config=_BOTO_CONFIG)
    async for sg in _paginate(ec2, "describe_security_groups", "SecurityGroups"):
        sg_id = str(sg.get("GroupId", ""))
        yield NormalizedCloudAsset(
            provider="aws",
            native_id=sg_id,
            native_resource_type="ec2.SecurityGroup",
            normalized_category="security_group",
            name=str(sg.get("GroupName", sg_id)),
            region_or_location=region,
            parent_native_id=sg.get("VpcId"),
            account_or_subscription_or_project=account_id,
            tags=_tag_dict(sg.get("Tags")),
            raw_metadata=sg,
        )


async def _discover_network_acls(
    session: Any, region: str, account_id: str
) -> AsyncIterator[NormalizedCloudAsset]:
    ec2 = session.client("ec2", region_name=region, config=_BOTO_CONFIG)
    async for nacl in _paginate(ec2, "describe_network_acls", "NetworkAcls"):
        nacl_id = str(nacl.get("NetworkAclId", ""))
        yield NormalizedCloudAsset(
            provider="aws",
            native_id=nacl_id,
            native_resource_type="ec2.NetworkAcl",
            normalized_category="network_acl",
            name=_tag_dict(nacl.get("Tags")).get("Name", nacl_id),
            region_or_location=region,
            parent_native_id=nacl.get("VpcId"),
            account_or_subscription_or_project=account_id,
            tags=_tag_dict(nacl.get("Tags")),
            raw_metadata=nacl,
        )


async def _discover_internet_gateways(
    session: Any, region: str, account_id: str
) -> AsyncIterator[NormalizedCloudAsset]:
    ec2 = session.client("ec2", region_name=region, config=_BOTO_CONFIG)
    async for igw in _paginate(ec2, "describe_internet_gateways", "InternetGateways"):
        igw_id = str(igw.get("InternetGatewayId", ""))
        attachments = igw.get("Attachments", []) or []
        parent = str(attachments[0].get("VpcId")) if attachments else None
        yield NormalizedCloudAsset(
            provider="aws",
            native_id=igw_id,
            native_resource_type="ec2.InternetGateway",
            normalized_category="internet_gateway",
            name=_tag_dict(igw.get("Tags")).get("Name", igw_id),
            region_or_location=region,
            parent_native_id=parent,
            account_or_subscription_or_project=account_id,
            internet_exposure_known=True,
            tags=_tag_dict(igw.get("Tags")),
            raw_metadata=igw,
        )


async def _discover_nat_gateways(
    session: Any, region: str, account_id: str
) -> AsyncIterator[NormalizedCloudAsset]:
    ec2 = session.client("ec2", region_name=region, config=_BOTO_CONFIG)
    async for nat in _paginate(ec2, "describe_nat_gateways", "NatGateways"):
        nat_id = str(nat.get("NatGatewayId", ""))
        yield NormalizedCloudAsset(
            provider="aws",
            native_id=nat_id,
            native_resource_type="ec2.NatGateway",
            normalized_category="nat_gateway",
            name=_tag_dict(nat.get("Tags")).get("Name", nat_id),
            region_or_location=region,
            parent_native_id=nat.get("SubnetId"),
            account_or_subscription_or_project=account_id,
            lifecycle_state=nat.get("State"),
            tags=_tag_dict(nat.get("Tags")),
            raw_metadata=nat,
        )


async def _discover_elastic_ips(
    session: Any, region: str, account_id: str
) -> AsyncIterator[NormalizedCloudAsset]:
    ec2 = session.client("ec2", region_name=region, config=_BOTO_CONFIG)
    result = await asyncio.to_thread(ec2.describe_addresses)
    for addr in result.get("Addresses", []):
        alloc_id = str(addr.get("AllocationId", addr.get("PublicIp", "")))
        yield NormalizedCloudAsset(
            provider="aws",
            native_id=alloc_id,
            native_resource_type="ec2.Address",
            normalized_category="elastic_ip",
            name=str(addr.get("PublicIp", alloc_id)),
            region_or_location=region,
            parent_native_id=addr.get("InstanceId"),
            account_or_subscription_or_project=account_id,
            internet_exposure_known=True,
            tags=_tag_dict(addr.get("Tags")),
            raw_metadata=addr,
        )


async def _discover_load_balancers(
    session: Any, region: str, account_id: str
) -> AsyncIterator[NormalizedCloudAsset]:
    elbv2 = session.client("elbv2", region_name=region, config=_BOTO_CONFIG)
    async for lb in _paginate(elbv2, "describe_load_balancers", "LoadBalancers"):
        lb_arn = str(lb.get("LoadBalancerArn", ""))
        yield NormalizedCloudAsset(
            provider="aws",
            native_id=lb_arn,
            native_resource_type="elasticloadbalancing.LoadBalancer",
            normalized_category="load_balancer",
            name=str(lb.get("LoadBalancerName", lb_arn)),
            region_or_location=region,
            parent_native_id=lb.get("VpcId"),
            account_or_subscription_or_project=account_id,
            lifecycle_state=(lb.get("State", {}) or {}).get("Code"),
            created_at_provider=lb.get("CreatedTime"),
            internet_exposure_known=str(lb.get("Scheme", "")) == "internet-facing",
            managed_service=True,
            raw_metadata=lb,
        )


async def _discover_rds_instances(
    session: Any, region: str, account_id: str
) -> AsyncIterator[NormalizedCloudAsset]:
    rds = session.client("rds", region_name=region, config=_BOTO_CONFIG)
    async for db in _paginate(rds, "describe_db_instances", "DBInstances"):
        db_id = str(db.get("DBInstanceIdentifier", ""))
        vpc_id = (db.get("DBSubnetGroup", {}) or {}).get("VpcId")
        yield NormalizedCloudAsset(
            provider="aws",
            native_id=str(db.get("DBInstanceArn", db_id)),
            native_resource_type="rds.DBInstance",
            normalized_category="rds_instance",
            name=db_id,
            region_or_location=region,
            availability_zone=db.get("AvailabilityZone"),
            parent_native_id=vpc_id,
            account_or_subscription_or_project=account_id,
            lifecycle_state=db.get("DBInstanceStatus"),
            created_at_provider=db.get("InstanceCreateTime"),
            internet_exposure_known=bool(db.get("PubliclyAccessible")),
            managed_service=True,
            raw_metadata=db,
        )


async def _discover_lambda_functions(
    session: Any, region: str, account_id: str
) -> AsyncIterator[NormalizedCloudAsset]:
    lambda_client = session.client("lambda", region_name=region, config=_BOTO_CONFIG)
    async for fn in _paginate(lambda_client, "list_functions", "Functions"):
        fn_name = str(fn.get("FunctionName", ""))
        vpc_config = fn.get("VpcConfig") or {}
        yield NormalizedCloudAsset(
            provider="aws",
            native_id=str(fn.get("FunctionArn", fn_name)),
            native_resource_type="lambda.Function",
            normalized_category="lambda_function",
            name=fn_name,
            region_or_location=region,
            parent_native_id=vpc_config.get("VpcId"),
            account_or_subscription_or_project=account_id,
            created_at_provider=None,
            managed_service=True,
            raw_metadata=fn,
        )


async def _discover_ecs(
    session: Any, region: str, account_id: str
) -> AsyncIterator[NormalizedCloudAsset]:
    ecs = session.client("ecs", region_name=region, config=_BOTO_CONFIG)
    cluster_arns: list[str] = []
    async for arn in _paginate(ecs, "list_clusters", "clusterArns"):
        cluster_arns.append(str(arn))
    for batch_start in range(0, len(cluster_arns), 100):
        batch = cluster_arns[batch_start : batch_start + 100]
        details = await asyncio.to_thread(ecs.describe_clusters, clusters=batch)
        for cluster in details.get("clusters", []):
            cluster_arn = str(cluster.get("clusterArn", ""))
            yield NormalizedCloudAsset(
                provider="aws",
                native_id=cluster_arn,
                native_resource_type="ecs.Cluster",
                normalized_category="ecs_cluster",
                name=str(cluster.get("clusterName", cluster_arn)),
                region_or_location=region,
                account_or_subscription_or_project=account_id,
                lifecycle_state=cluster.get("status"),
                managed_service=True,
                raw_metadata=cluster,
            )
            service_arns: list[str] = []
            svc_pages = _paginate(ecs, "list_services", "serviceArns", cluster=cluster_arn)
            async for svc_arn in svc_pages:
                service_arns.append(str(svc_arn))
            for svc_batch_start in range(0, len(service_arns), 10):
                svc_batch = service_arns[svc_batch_start : svc_batch_start + 10]
                if not svc_batch:
                    continue
                svc_details = await asyncio.to_thread(
                    ecs.describe_services, cluster=cluster_arn, services=svc_batch
                )
                for service in svc_details.get("services", []):
                    service_arn = str(service.get("serviceArn", ""))
                    yield NormalizedCloudAsset(
                        provider="aws",
                        native_id=service_arn,
                        native_resource_type="ecs.Service",
                        normalized_category="ecs_cluster",
                        name=str(service.get("serviceName", service_arn)),
                        region_or_location=region,
                        parent_native_id=cluster_arn,
                        account_or_subscription_or_project=account_id,
                        lifecycle_state=service.get("status"),
                        managed_service=True,
                        raw_metadata=service,
                    )


async def _discover_eks_clusters(
    session: Any, region: str, account_id: str
) -> AsyncIterator[NormalizedCloudAsset]:
    eks = session.client("eks", region_name=region, config=_BOTO_CONFIG)
    async for name in _paginate(eks, "list_clusters", "clusters"):
        detail = await asyncio.to_thread(eks.describe_cluster, name=str(name))
        cluster = detail.get("cluster", {})
        vpc_id = (cluster.get("resourcesVpcConfig", {}) or {}).get("vpcId")
        yield NormalizedCloudAsset(
            provider="aws",
            native_id=str(cluster.get("arn", name)),
            native_resource_type="eks.Cluster",
            normalized_category="eks_cluster",
            name=str(cluster.get("name", name)),
            region_or_location=region,
            parent_native_id=vpc_id,
            account_or_subscription_or_project=account_id,
            lifecycle_state=cluster.get("status"),
            created_at_provider=cluster.get("createdAt"),
            managed_service=True,
            raw_metadata=cluster,
        )


async def _discover_ecr_repositories(
    session: Any, region: str, account_id: str
) -> AsyncIterator[NormalizedCloudAsset]:
    ecr = session.client("ecr", region_name=region, config=_BOTO_CONFIG)
    async for repo in _paginate(ecr, "describe_repositories", "repositories"):
        repo_arn = str(repo.get("repositoryArn", ""))
        yield NormalizedCloudAsset(
            provider="aws",
            native_id=repo_arn,
            native_resource_type="ecr.Repository",
            normalized_category="ecr_repository",
            name=str(repo.get("repositoryName", repo_arn)),
            region_or_location=region,
            account_or_subscription_or_project=account_id,
            created_at_provider=repo.get("createdAt"),
            managed_service=True,
            raw_metadata=repo,
        )


async def _discover_kms_keys(
    session: Any, region: str, account_id: str
) -> AsyncIterator[NormalizedCloudAsset]:
    kms = session.client("kms", region_name=region, config=_BOTO_CONFIG)
    aliases_by_key: dict[str, str] = {}
    async for alias in _paginate(kms, "list_aliases", "Aliases"):
        target = alias.get("TargetKeyId")
        if target:
            aliases_by_key[str(target)] = str(alias.get("AliasName", ""))
    async for key in _paginate(kms, "list_keys", "Keys"):
        key_id = str(key.get("KeyId", ""))
        try:
            detail = await asyncio.to_thread(kms.describe_key, KeyId=key_id)
            metadata = detail.get("KeyMetadata", {})
        except Exception:  # noqa: BLE001 - a single key's describe failing doesn't invalidate the list
            metadata = key
        yield NormalizedCloudAsset(
            provider="aws",
            native_id=str(key.get("KeyArn", key_id)),
            native_resource_type="kms.Key",
            normalized_category="kms_key",
            name=aliases_by_key.get(key_id, key_id),
            region_or_location=region,
            account_or_subscription_or_project=account_id,
            lifecycle_state=metadata.get("KeyState"),
            created_at_provider=metadata.get("CreationDate"),
            managed_service=bool(metadata.get("KeyManager") == "AWS"),
            raw_metadata=metadata,
        )


async def _discover_secrets_manager_metadata(
    session: Any, region: str, account_id: str
) -> AsyncIterator[NormalizedCloudAsset]:
    sm = session.client("secretsmanager", region_name=region, config=_BOTO_CONFIG)
    async for secret in _paginate(sm, "list_secrets", "SecretList"):
        secret_arn = str(secret.get("ARN", ""))
        yield NormalizedCloudAsset(
            provider="aws",
            native_id=secret_arn,
            native_resource_type="secretsmanager.Secret",
            normalized_category="secrets_manager_secret_metadata",
            name=str(secret.get("Name", secret_arn)),
            region_or_location=region,
            account_or_subscription_or_project=account_id,
            created_at_provider=secret.get("CreatedDate"),
            tags=_tag_dict(secret.get("Tags")),
            managed_service=True,
            raw_metadata={
                k: v for k, v in secret.items() if k not in ("SecretString", "SecretBinary")
            },
        )


async def _discover_cloudtrail_metadata(
    session: Any, region: str, account_id: str
) -> AsyncIterator[NormalizedCloudAsset]:
    ct = session.client("cloudtrail", region_name=region, config=_BOTO_CONFIG)
    result = await asyncio.to_thread(ct.describe_trails)
    for trail in result.get("trailList", []):
        trail_arn = str(trail.get("TrailARN", ""))
        yield NormalizedCloudAsset(
            provider="aws",
            native_id=trail_arn,
            native_resource_type="cloudtrail.Trail",
            normalized_category="cloudtrail_trail_metadata",
            name=str(trail.get("Name", trail_arn)),
            region_or_location=region,
            account_or_subscription_or_project=account_id,
            managed_service=True,
            raw_metadata=trail,
        )


async def _discover_guardduty_metadata(
    session: Any, region: str, account_id: str
) -> AsyncIterator[NormalizedCloudAsset]:
    gd = session.client("guardduty", region_name=region, config=_BOTO_CONFIG)
    async for detector_id in _paginate(gd, "list_detectors", "DetectorIds"):
        detail = await asyncio.to_thread(gd.get_detector, DetectorId=str(detector_id))
        yield NormalizedCloudAsset(
            provider="aws",
            native_id=str(detector_id),
            native_resource_type="guardduty.Detector",
            normalized_category="guardduty_detector_metadata",
            name=f"GuardDuty detector ({region})",
            region_or_location=region,
            account_or_subscription_or_project=account_id,
            lifecycle_state=detail.get("Status"),
            created_at_provider=None,
            managed_service=True,
            raw_metadata=detail,
        )


async def _discover_config_recorder_metadata(
    session: Any, region: str, account_id: str
) -> AsyncIterator[NormalizedCloudAsset]:
    config_client = session.client("config", region_name=region, config=_BOTO_CONFIG)
    result = await asyncio.to_thread(config_client.describe_configuration_recorders)
    for recorder in result.get("ConfigurationRecorders", []):
        name = str(recorder.get("name", ""))
        yield NormalizedCloudAsset(
            provider="aws",
            native_id=f"{region}:{name}",
            native_resource_type="config.ConfigurationRecorder",
            normalized_category="config_recorder_metadata",
            name=name,
            region_or_location=region,
            account_or_subscription_or_project=account_id,
            managed_service=True,
            raw_metadata=recorder,
        )


async def _discover_cloudwatch_log_group_metadata(
    session: Any, region: str, account_id: str
) -> AsyncIterator[NormalizedCloudAsset]:
    logs = session.client("logs", region_name=region, config=_BOTO_CONFIG)
    async for group in _paginate(logs, "describe_log_groups", "logGroups"):
        name = str(group.get("logGroupName", ""))
        yield NormalizedCloudAsset(
            provider="aws",
            native_id=str(group.get("arn", name)),
            native_resource_type="logs.LogGroup",
            normalized_category="cloudwatch_log_group_metadata",
            name=name,
            region_or_location=region,
            account_or_subscription_or_project=account_id,
            created_at_provider=(
                datetime.fromtimestamp(group["creationTime"] / 1000, tz=UTC)
                if group.get("creationTime")
                else None
            ),
            managed_service=True,
            raw_metadata=group,
        )


_REGIONAL_DISCOVERERS = (
    ("ec2_instance", _discover_ec2_instances),
    ("vpc", _discover_vpcs),
    ("subnet", _discover_subnets),
    ("security_group", _discover_security_groups),
    ("network_acl", _discover_network_acls),
    ("internet_gateway", _discover_internet_gateways),
    ("nat_gateway", _discover_nat_gateways),
    ("elastic_ip", _discover_elastic_ips),
    ("load_balancer", _discover_load_balancers),
    ("rds_instance", _discover_rds_instances),
    ("lambda_function", _discover_lambda_functions),
    ("ecs_cluster", _discover_ecs),
    ("eks_cluster", _discover_eks_clusters),
    ("ecr_repository", _discover_ecr_repositories),
    ("kms_key", _discover_kms_keys),
    ("secrets_manager_secret_metadata", _discover_secrets_manager_metadata),
    ("cloudtrail_trail_metadata", _discover_cloudtrail_metadata),
    ("guardduty_detector_metadata", _discover_guardduty_metadata),
    ("config_recorder_metadata", _discover_config_recorder_metadata),
    ("cloudwatch_log_group_metadata", _discover_cloudwatch_log_group_metadata),
)


async def discover_assets(
    profile: CloudConnectionProfile, scope_native_id: str
) -> AsyncIterator[NormalizedCloudAsset]:
    session = await asyncio.to_thread(_build_session, profile)
    account_id = scope_native_id

    org_assets = _safe_assets(
        _discover_organisation_and_accounts(session, account_id), "organisation"
    )
    async for asset in org_assets:
        yield asset
    iam_assets = _safe_assets(
        _discover_iam_identity_summary(session, account_id), "iam_identity_summary"
    )
    async for asset in iam_assets:
        yield asset

    try:
        regions = await _list_regions(session)
    except Exception as exc:  # noqa: BLE001 - no regions known means no regional discovery this run, disclosed
        error = _classify(exc)
        _logger.warning(
            "cloud.aws_discovery_regions_failed",
            error_category=error.category.value,
            message=error.sanitized_message,
        )
        regions = []

    for region in regions:
        yield NormalizedCloudAsset(
            provider="aws",
            native_id=region,
            native_resource_type="ec2.Region",
            normalized_category="region",
            name=region,
            region_or_location=region,
            account_or_subscription_or_project=account_id,
        )

    async for asset in _safe_assets(_discover_s3_buckets(session, account_id), "s3_bucket"):
        yield asset

    for category, discoverer in _REGIONAL_DISCOVERERS:
        for region in regions:
            category_assets = _safe_assets(
                discoverer(session, region, account_id), f"{category}:{region}"
            )
            async for asset in category_assets:
                yield asset


# ----------------------------------------------------------------------------
# Relationships (Section 15) - every one below is DIRECT: sourced straight from a
# real AWS API response field (a VpcId/SubnetId/InstanceId/etc. the provider itself
# returned), never inferred from shared tags or region alone (Section 15's own
# explicit rule). No derived relationships are produced by this adapter in Part 1.
# ----------------------------------------------------------------------------


async def _relationships_for_region(
    session: Any, region: str, account_id: str
) -> AsyncIterator[NormalizedCloudRelationship]:
    ec2 = session.client("ec2", region_name=region, config=_BOTO_CONFIG)

    async for subnet in _paginate(ec2, "describe_subnets", "Subnets"):
        if subnet.get("VpcId"):
            yield NormalizedCloudRelationship(
                source_native_id=str(subnet["SubnetId"]),
                target_native_id=str(subnet["VpcId"]),
                relationship_type="BELONGS_TO",
                is_direct=True,
            )

    async for sg in _paginate(ec2, "describe_security_groups", "SecurityGroups"):
        if sg.get("VpcId"):
            yield NormalizedCloudRelationship(
                source_native_id=str(sg["GroupId"]),
                target_native_id=str(sg["VpcId"]),
                relationship_type="BELONGS_TO",
                is_direct=True,
            )

    async for nacl in _paginate(ec2, "describe_network_acls", "NetworkAcls"):
        if nacl.get("VpcId"):
            yield NormalizedCloudRelationship(
                source_native_id=str(nacl["NetworkAclId"]),
                target_native_id=str(nacl["VpcId"]),
                relationship_type="BELONGS_TO",
                is_direct=True,
            )

    async for igw in _paginate(ec2, "describe_internet_gateways", "InternetGateways"):
        for attachment in igw.get("Attachments", []) or []:
            if attachment.get("VpcId"):
                yield NormalizedCloudRelationship(
                    source_native_id=str(igw["InternetGatewayId"]),
                    target_native_id=str(attachment["VpcId"]),
                    relationship_type="ATTACHED_TO",
                    is_direct=True,
                )

    async for nat in _paginate(ec2, "describe_nat_gateways", "NatGateways"):
        if nat.get("SubnetId"):
            yield NormalizedCloudRelationship(
                source_native_id=str(nat["NatGatewayId"]),
                target_native_id=str(nat["SubnetId"]),
                relationship_type="LOCATED_IN",
                is_direct=True,
            )

    async for reservation in _paginate(ec2, "describe_instances", "Reservations"):
        for instance in reservation.get("Instances", []):
            instance_id = str(instance.get("InstanceId", ""))
            if instance.get("SubnetId"):
                yield NormalizedCloudRelationship(
                    source_native_id=instance_id,
                    target_native_id=str(instance["SubnetId"]),
                    relationship_type="LOCATED_IN",
                    is_direct=True,
                )
            for sg_ref in instance.get("SecurityGroups", []) or []:
                if sg_ref.get("GroupId"):
                    yield NormalizedCloudRelationship(
                        source_native_id=instance_id,
                        target_native_id=str(sg_ref["GroupId"]),
                        relationship_type="PROTECTED_BY",
                        is_direct=True,
                    )

    addresses = await asyncio.to_thread(ec2.describe_addresses)
    for addr in addresses.get("Addresses", []):
        if addr.get("InstanceId") and addr.get("AllocationId"):
            yield NormalizedCloudRelationship(
                source_native_id=str(addr["AllocationId"]),
                target_native_id=str(addr["InstanceId"]),
                relationship_type="ATTACHED_TO",
                is_direct=True,
            )

    elbv2 = session.client("elbv2", region_name=region, config=_BOTO_CONFIG)
    async for lb in _paginate(elbv2, "describe_load_balancers", "LoadBalancers"):
        lb_arn = str(lb.get("LoadBalancerArn", ""))
        for az in lb.get("AvailabilityZones", []) or []:
            if az.get("SubnetId"):
                yield NormalizedCloudRelationship(
                    source_native_id=lb_arn,
                    target_native_id=str(az["SubnetId"]),
                    relationship_type="ATTACHED_TO",
                    is_direct=True,
                )

    rds = session.client("rds", region_name=region, config=_BOTO_CONFIG)
    async for db in _paginate(rds, "describe_db_instances", "DBInstances"):
        vpc_id = (db.get("DBSubnetGroup", {}) or {}).get("VpcId")
        if vpc_id:
            yield NormalizedCloudRelationship(
                source_native_id=str(db.get("DBInstanceArn", db.get("DBInstanceIdentifier", ""))),
                target_native_id=str(vpc_id),
                relationship_type="LOCATED_IN",
                is_direct=True,
            )

    lambda_client = session.client("lambda", region_name=region, config=_BOTO_CONFIG)
    async for fn in _paginate(lambda_client, "list_functions", "Functions"):
        vpc_id = (fn.get("VpcConfig") or {}).get("VpcId")
        if vpc_id:
            yield NormalizedCloudRelationship(
                source_native_id=str(fn.get("FunctionArn", fn.get("FunctionName", ""))),
                target_native_id=str(vpc_id),
                relationship_type="CONNECTED_TO",
                is_direct=True,
            )

    eks = session.client("eks", region_name=region, config=_BOTO_CONFIG)
    async for name in _paginate(eks, "list_clusters", "clusters"):
        detail = await asyncio.to_thread(eks.describe_cluster, name=str(name))
        cluster = detail.get("cluster", {})
        vpc_id = (cluster.get("resourcesVpcConfig", {}) or {}).get("vpcId")
        if vpc_id:
            yield NormalizedCloudRelationship(
                source_native_id=str(cluster.get("arn", name)),
                target_native_id=str(vpc_id),
                relationship_type="LOCATED_IN",
                is_direct=True,
            )

    ecs = session.client("ecs", region_name=region, config=_BOTO_CONFIG)
    cluster_arns: list[str] = []
    async for arn in _paginate(ecs, "list_clusters", "clusterArns"):
        cluster_arns.append(str(arn))
    for cluster_arn in cluster_arns:
        service_arns: list[str] = []
        svc_pages = _paginate(ecs, "list_services", "serviceArns", cluster=cluster_arn)
        async for svc_arn in svc_pages:
            service_arns.append(str(svc_arn))
        for service_arn in service_arns:
            yield NormalizedCloudRelationship(
                source_native_id=service_arn,
                target_native_id=cluster_arn,
                relationship_type="RUNS_ON",
                is_direct=True,
            )


async def discover_relationships(
    profile: CloudConnectionProfile, scope_native_id: str
) -> AsyncIterator[NormalizedCloudRelationship]:
    session = await asyncio.to_thread(_build_session, profile)
    account_id = scope_native_id

    org_client = session.client("organizations", config=_BOTO_CONFIG)
    try:
        org = await asyncio.to_thread(org_client.describe_organization)
        org_id = str(org.get("Organization", {}).get("Id", ""))
        if org_id:
            async for acct in _paginate(org_client, "list_accounts", "Accounts"):
                yield NormalizedCloudRelationship(
                    source_native_id=str(acct.get("Id", "")),
                    target_native_id=org_id,
                    relationship_type="MEMBER_OF",
                    is_direct=True,
                )
    except Exception as exc:  # noqa: BLE001
        error = _classify(exc)
        _logger.warning(
            "cloud.aws_discovery_relationship_category_failed",
            category="organisation",
            error_category=error.category.value,
            message=error.sanitized_message,
        )

    try:
        regions = await _list_regions(session)
    except Exception as exc:  # noqa: BLE001
        error = _classify(exc)
        _logger.warning(
            "cloud.aws_discovery_regions_failed",
            error_category=error.category.value,
            message=error.sanitized_message,
        )
        regions = []

    for region in regions:
        async for rel in _safe_relationships(
            _relationships_for_region(session, region, account_id), f"region:{region}"
        ):
            yield rel
