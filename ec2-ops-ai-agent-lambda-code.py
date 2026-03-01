import boto3
import json
import os
import time
import base64
import re
from botocore.exceptions import ClientError

# ------------------------------------------------------------
# DEFAULT REGION
# ------------------------------------------------------------
DEFAULT_REGION = os.environ.get("AWS_REGION", "us-east-1").strip()

# ------------------------------------------------------------
# DEFAULTS (demo / free-tier friendly)
# ------------------------------------------------------------
DEFAULT_AMI_ID = os.environ.get("DEFAULT_AMI_ID", "").strip()
DEFAULT_AMI_SSM_PARAM = os.environ.get(
    "DEFAULT_AMI_SSM_PARAM",
    "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
).strip()

DEFAULT_INSTANCE_TYPE = os.environ.get("DEFAULT_INSTANCE_TYPE", "t3.micro").strip()
ALLOWED_INSTANCE_TYPES = {"t3.micro", "t3.small", "t3.medium"}

DEFAULT_KEY_NAME = os.environ.get("DEFAULT_KEY_NAME", "").strip()
DEFAULT_IAM_INSTANCE_PROFILE_NAME = os.environ.get("DEFAULT_IAM_INSTANCE_PROFILE_NAME", "").strip()

DEFAULT_SECURITY_GROUP_IDS = [s.strip() for s in os.environ.get("DEFAULT_SECURITY_GROUP_IDS", "").split(",") if s.strip()]
DEFAULT_VPC_ID = os.environ.get("DEFAULT_VPC_ID", "").strip()
DEFAULT_SUBNET_IDS = [s.strip() for s in os.environ.get("DEFAULT_SUBNET_IDS", "").split(",") if s.strip()]

DEFAULT_USE_DEFAULT_NETWORK = os.environ.get("USE_DEFAULT_NETWORK_BY_DEFAULT", "true").strip().lower() in (
    "1", "true", "yes", "y"
)

DEFAULT_VOLUME_TYPE = os.environ.get("DEFAULT_VOLUME_TYPE", "gp3").strip()
DEFAULT_VOLUME_SIZE_GB = int(os.environ.get("DEFAULT_VOLUME_SIZE_GB", "8"))

# ------------------------------------------------------------
# ACTION MAP
# ------------------------------------------------------------
ACTION_MAP = {
    # Debug
    "whoami": "whoami",
    "get_region": "get_region",

    # Tagging
    "tag_resources": "tag_resources",

    
# Auto Scaling Groups (ASG)
"describe_asg": "describe_asg",
"create_asg": "create_asg",
"update_asg": "update_asg",
"delete_asg": "delete_asg",
"suspend_processes": "suspend_processes",
"resume_processes": "resume_processes",
"set_instance_protection": "set_instance_protection",

# EC2 instance lifecycle
    "describe_instances": "describe_instances",
    "create_instance": "create_instance",
    "run_instances": "create_instance",  # alias for agents that call EC2 API name

    "start_instance": "start_instance",
    "stop_instance": "stop_instance",
    "terminate_instance": "terminate_instance",
    "set_termination_protection": "set_termination_protection",

    # AMI + snapshots
    "create_ami": "create_ami",
    "deregister_ami": "deregister_ami",
    "create_snapshot": "create_snapshot",
    "delete_snapshot": "delete_snapshot",
    "copy_snapshot": "copy_snapshot",

    # EBS volumes
    "create_volume": "create_volume",
    "attach_volume": "attach_volume",
    "detach_volume": "detach_volume",
    "delete_volume": "delete_volume",

    # Security group
    "create_security_group": "create_security_group",
    "add_sg_rule": "add_sg_rule",
    "remove_sg_rule": "remove_sg_rule",

    # Key pair
    "create_key_pair": "create_key_pair",
    "import_key_pair": "import_key_pair",
    "delete_key_pair": "delete_key_pair",

    # Elastic IP
    "allocate_eip": "allocate_eip",
    "associate_eip": "associate_eip",
    "disassociate_eip": "disassociate_eip",
    "release_eip": "release_eip",

    # ENI
    "create_eni": "create_eni",
    "attach_eni": "attach_eni",
    "detach_eni": "detach_eni",
    "delete_eni": "delete_eni",

    # Placement groups
    "create_placement_group": "create_placement_group",
    "delete_placement_group": "delete_placement_group",

    # Launch templates
    "create_launch_template": "create_launch_template",
    "delete_launch_template": "delete_launch_template",

    # Load balancer (ALB)
    "create_load_balancer": "create_load_balancer",
    "delete_load_balancer": "delete_load_balancer",
    "register_targets": "register_targets",
    "deregister_targets": "deregister_targets",
    "delete_listener": "delete_listener",
    "delete_target_group": "delete_target_group",

    # CloudWatch alarms
    "create_alarm": "create_alarm",
    "delete_alarm": "delete_alarm",

    # VPC networking
    "create_vpc_basic": "create_vpc_basic",
    "create_nat_gateway": "create_nat_gateway",

    # SSM
    "ssm_send_command": "ssm_send_command",
}


def _is_default_token(val) -> bool:
    if val is None:
        return False
    s = str(val).strip().lower()
    return s in ("default", "use default", "use_default", "defaults", "use defaults")

def _default_to_empty(val):
    return "" if _is_default_token(val) else (val if val is not None else "")

# ------------------------------------------------------------
# RESPONSE HELPERS
# ------------------------------------------------------------
def _ok(event, body_obj):
    return {
        "messageVersion": "1.0",
        "response": {
            "actionGroup": event.get("actionGroup"),
            "apiPath": event.get("apiPath"),
            "httpMethod": event.get("httpMethod"),
            "httpStatusCode": 200,
            "responseBody": {"application/json": {"body": json.dumps(body_obj, default=str)}},
        },
    }

def _err(event, status_code: int, message: str, extra=None):
    payload = {"error": message}
    if extra is not None:
        payload["details"] = extra
    return {
        "messageVersion": "1.0",
        "response": {
            "actionGroup": event.get("actionGroup"),
            "apiPath": event.get("apiPath"),
            "httpMethod": event.get("httpMethod"),
            "httpStatusCode": status_code,
            "responseBody": {"application/json": {"body": json.dumps(payload, default=str)}},
        },
    }

def _extract_params(event: dict) -> dict:
    params_obj = event.get("parameters")
    if not params_obj:
        params_obj = (
            event.get("requestBody", {})
                 .get("content", {})
                 .get("application/json")
        )
    if params_obj is None:
        return {}
    if isinstance(params_obj, dict):
        if "properties" in params_obj and isinstance(params_obj["properties"], list):
            return {
                i.get("name"): i.get("value")
                for i in params_obj["properties"]
                if isinstance(i, dict) and i.get("name") is not None
            }
        return params_obj
    if isinstance(params_obj, list):
        out = {}
        for item in params_obj:
            if not isinstance(item, dict):
                continue
            k = item.get("name")
            v = item.get("value")
            if v is None:
                v = item.get("Value")
            if k:
                out[k] = v
        return out
    return {}

def _normalize_action(action_raw: str) -> str:
    a = (action_raw or "").strip().lower().replace(" ", "_")
    return ACTION_MAP.get(a, a)

def _to_int(val, field_name: str):
    if val is None or val == "":
        return None
    try:
        return int(val)
    except Exception:
        raise ValueError(f"{field_name} must be an integer (got: {val})")

def _to_bool(val, default=False):
    if val is None or val == "":
        return default
    if isinstance(val, bool):
        return val
    if isinstance(val, (int, float)):
        return bool(val)
    if isinstance(val, str):
        return val.strip().lower() in ("1", "true", "yes", "y")
    return default

def _parse_csv_list(val):
    if val is None:
        return []
    if isinstance(val, list):
        return [str(x).strip() for x in val if str(x).strip()]
    s = str(val).strip()
    if not s:
        return []
    return [x.strip() for x in s.split(",") if x.strip()]

def _parse_tags(val):
    """
    Accept:
      - {"Name":"demo","Env":"uat"} dict
      - [{"Key":"Name","Value":"demo"}] list
      - "Name=demo,Env=uat" string
    Return list of {"Key","Value"}.
    """
    if not val:
        return []
    if isinstance(val, list):
        out = []
        for t in val:
            if isinstance(t, dict) and "Key" in t and "Value" in t:
                out.append({"Key": str(t["Key"]), "Value": str(t["Value"])})
        return out
    if isinstance(val, dict):
        return [{"Key": str(k), "Value": str(v)} for k, v in val.items()]
    s = str(val).strip()
    if not s:
        return []
    out = []
    for pair in s.split(","):
        pair = pair.strip()
        if "=" in pair:
            k, v = pair.split("=", 1)
            out.append({"Key": k.strip(), "Value": v.strip()})
    return out

def _b64_try_decode(s: str) -> bytes:
    """
    Accept either:
      - raw SSH public key text (ssh-rsa/ssh-ed25519/etc)
      - base64 of the public key text
    Returns bytes for PublicKeyMaterial.
    """
    s = (s or "").strip()
    if not s:
        return b""
    if s.startswith("ssh-") or s.startswith("ecdsa-") or s.startswith("sk-"):
        return s.encode("utf-8")
    try:
        return base64.b64decode(s)
    except Exception:
        return s.encode("utf-8")

def _education(action: str) -> str:
    edu = {
        "create_instance": "Launches a VM (server). Charges apply if you exceed free-tier or keep it running.",
        "create_ami": "Creates a reusable image of your instance so you can launch the same setup again.",
        "create_snapshot": "Backups an EBS volume at a point in time (used for restore/copy).",
        "create_volume": "Creates an extra disk (EBS) you can attach to an instance.",
        "create_security_group": "A security group is a firewall that controls inbound/outbound traffic.",
        "create_load_balancer": "An ALB distributes traffic across instances and needs 2 subnets in different AZs.",
        "ssm_send_command": "Runs commands on the instance without SSH, using the SSM agent.",
        "allocate_eip": "Allocates a static public IP. Charges may apply if not attached/used.",
        "create_nat_gateway": "NAT Gateway enables private subnets to reach internet; it is NOT free-tier.",
    }
    return edu.get(action, "Done.")

# ------------------------------------------------------------
# CLIENTS (region-aware)
# ------------------------------------------------------------
def _clients(region: str):
    r = (region or DEFAULT_REGION).strip()
    return {
        "ec2": boto3.client("ec2", region_name=r),
        "ssm": boto3.client("ssm", region_name=r),
        "sts": boto3.client("sts", region_name=r),
        "elbv2": boto3.client("elbv2", region_name=r),
        "cw": boto3.client("cloudwatch", region_name=r),
        "asg": boto3.client("autoscaling", region_name=r),
        "r": r,
    }


# ------------------------------------------------------------
# INSTANCE TYPE HELPERS
# ------------------------------------------------------------
def _is_free_tier_eligible_instance_type(ec2, instance_type: str) -> bool:
    """
    Returns True if the instance type is free-tier eligible in this region/account.
    Uses DescribeInstanceTypes which includes FreeTierEligible.
    """
    it = (instance_type or "").strip()
    if not it:
        return False
    try:
        resp = ec2.describe_instance_types(InstanceTypes=[it])
        info = (resp.get("InstanceTypes") or [{}])[0]
        return bool(info.get("FreeTierEligible", False))
    except ClientError:
        return False

def _pick_free_tier_instance_type(ec2, preferred: str = "t3.micro") -> str:
    """
    Pick a free-tier eligible instance type. Prefer `preferred` if eligible.
    Otherwise, ask AWS for the list and pick the first.
    """
    if preferred and _is_free_tier_eligible_instance_type(ec2, preferred):
        return preferred
    try:
        resp = ec2.describe_instance_types(Filters=[{"Name": "free-tier-eligible", "Values": ["true"]}], MaxResults=20)
        lst = [x.get("InstanceType") for x in resp.get("InstanceTypes", []) if x.get("InstanceType")]
        return lst[0] if lst else (preferred or "t3.micro")
    except ClientError:
        return preferred or "t3.micro"

# ------------------------------------------------------------
# NETWORK HELPERS
# ------------------------------------------------------------

def _sanitize_ami_id(val: str) -> str:
    """
    Return a valid AMI id (ami-...), else empty string.
    This prevents agent placeholders like "use free tier AMI id" from breaking RunInstances.
    """
    s = (val or "").strip()
    return s if s.startswith("ami-") else ""

def _resolve_default_ami_id(ssm):
    if DEFAULT_AMI_ID:
        return DEFAULT_AMI_ID
    resp = ssm.get_parameter(Name=DEFAULT_AMI_SSM_PARAM)
    ami_id = resp.get("Parameter", {}).get("Value", "").strip()
    if not ami_id.startswith("ami-"):
        raise ValueError(f"SSM parameter did not return a valid AMI id: {ami_id}")
    return ami_id

def _get_default_vpc_and_subnets(ec2):
    if DEFAULT_VPC_ID and DEFAULT_SUBNET_IDS:
        return DEFAULT_VPC_ID, DEFAULT_SUBNET_IDS

    vpcs = ec2.describe_vpcs(Filters=[{"Name": "isDefault", "Values": ["true"]}]).get("Vpcs", [])
    if not vpcs:
        raise ValueError("No default VPC found in this region. Create a default VPC or use create_vpc_basic.")
    vpc_id = vpcs[0]["VpcId"]

    subs = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]).get("Subnets", [])
    subnet_ids = [s["SubnetId"] for s in subs if s.get("SubnetId")]
    if not subnet_ids:
        raise ValueError(f"No subnets found in default VPC {vpc_id}.")
    return vpc_id, subnet_ids

def _pick_two_subnets_different_az(ec2, subnet_ids):
    subnet_ids = [s for s in subnet_ids if s]
    if len(subnet_ids) <= 2:
        return subnet_ids

    subs = ec2.describe_subnets(SubnetIds=subnet_ids).get("Subnets", [])
    az_map = {}
    for s in subs:
        az = s.get("AvailabilityZone")
        sid = s.get("SubnetId")
        if az and sid and az not in az_map:
            az_map[az] = sid
    picked = list(az_map.values())[:2]
    if len(picked) == 2:
        return picked
    return subnet_ids[:2]

def _get_vpc_from_subnet(ec2, subnet_id: str) -> str:
    resp = ec2.describe_subnets(SubnetIds=[subnet_id]).get("Subnets", [])
    if not resp:
        raise ValueError(f"Subnet not found: {subnet_id}")
    return resp[0]["VpcId"]

def _ensure_sg(ec2, vpc_id: str, name: str, open_http=False, open_ssh=False) -> str:
    try:
        resp = ec2.describe_security_groups(
            Filters=[{"Name":"vpc-id","Values":[vpc_id]}, {"Name":"group-name","Values":[name]}]
        )
        sgs = resp.get("SecurityGroups", [])
        if sgs:
            return sgs[0]["GroupId"]
    except ClientError:
        pass

    sg = ec2.create_security_group(GroupName=name, Description=f"Created by EC2 agent: {name}", VpcId=vpc_id)
    sg_id = sg["GroupId"]

    # allow all egress
    try:
        ec2.authorize_security_group_egress(
            GroupId=sg_id,
            IpPermissions=[{"IpProtocol":"-1","IpRanges":[{"CidrIp":"0.0.0.0/0"}]}]
        )
    except ClientError:
        pass

    ingress = []
    if open_http:
        ingress.append({"IpProtocol":"tcp","FromPort":80,"ToPort":80,"IpRanges":[{"CidrIp":"0.0.0.0/0"}]})
    if open_ssh:
        ingress.append({"IpProtocol":"tcp","FromPort":22,"ToPort":22,"IpRanges":[{"CidrIp":"0.0.0.0/0"}]})

    if ingress:
        try:
            ec2.authorize_security_group_ingress(GroupId=sg_id, IpPermissions=ingress)
        except ClientError:
            pass

    return sg_id


# ------------------------------------------------------------
# KEY PAIR HELPERS
# ------------------------------------------------------------
def _key_pair_exists(ec2, key_name: str) -> bool:
    try:
        ec2.describe_key_pairs(KeyNames=[key_name])
        return True
    except ClientError as e:
        # When the key does not exist, AWS raises InvalidKeyPair.NotFound
        if "InvalidKeyPair.NotFound" in str(e):
            return False
        raise

def _make_safe_key_name(base: str) -> str:
    """
    EC2 key pair name can include letters, numbers, and certain special chars.
    Keep it simple & safe: [A-Za-z0-9-_].
    """
    base = (base or "").strip()
    if not base:
        base = "ec2-agent-key"
    # Replace invalid chars with '-'
    base = re.sub(r"[^A-Za-z0-9\-_]", "-", base)
    base = re.sub(r"-{2,}", "-", base).strip("-")
    return base[:250] if base else "ec2-agent-key"

def _ensure_key_pair(ec2, desired_name: str = "", tags=None):
    """
    Ensures a key pair exists.
    - If desired_name is empty: create a new key with a generated name.
    - If desired_name is provided:
        - if it exists -> use it
        - if not -> create it
    Returns (key_name_used, key_material_or_none, created_bool)
    """
    desired_name = _make_safe_key_name(desired_name)
    key_material = None
    created = False

    if desired_name and _key_pair_exists(ec2, desired_name):
        return desired_name, None, False

    if not desired_name:
        # Generate a unique-ish name
        desired_name = _make_safe_key_name(f"ec2-agent-key-{int(time.time())}")

    # Create key pair
    resp = ec2.create_key_pair(KeyName=desired_name)
    key_material = resp.get("KeyMaterial")
    created = True

    # Optional tagging (create_key_pair doesn't support tags directly in older APIs)
    if tags:
        try:
            ec2.create_tags(Resources=[desired_name], Tags=tags)  # This may fail; ignore safely
        except ClientError:
            pass

    return desired_name, key_material, created

# ------------------------------------------------------------
# SG RULE BUILDER
# ------------------------------------------------------------
def _build_ip_permissions(params: dict):
    if isinstance(params.get("rules"), list) and params["rules"]:
        perms = []
        for r in params["rules"]:
            if not isinstance(r, dict):
                continue
            perms.extend(_build_ip_permissions(r))
        return perms

    proto = (params.get("protocol") or "tcp").strip()
    from_port = params.get("from_port")
    to_port = params.get("to_port")

    cidr_ipv4 = (params.get("cidr_ipv4") or "").strip()
    cidr_ipv6 = (params.get("cidr_ipv6") or "").strip()
    source_sg_id = (params.get("source_sg_id") or "").strip()

    perm = {"IpProtocol": proto}

    if proto not in ("-1", "icmp", "icmpv6"):
        fp = int(from_port) if from_port is not None else 0
        tp = int(to_port) if to_port is not None else fp
        perm["FromPort"] = fp
        perm["ToPort"] = tp

    if cidr_ipv4:
        perm["IpRanges"] = [{"CidrIp": cidr_ipv4}]
    if cidr_ipv6:
        perm["Ipv6Ranges"] = [{"CidrIpv6": cidr_ipv6}]
    if source_sg_id:
        perm["UserIdGroupPairs"] = [{"GroupId": source_sg_id}]

    if not cidr_ipv4 and not cidr_ipv6 and not source_sg_id:
        raise ValueError("Provide one of cidr_ipv4 / cidr_ipv6 / source_sg_id for SG rule")

    return [perm]

# ------------------------------------------------------------
# MAIN HANDLER
# ------------------------------------------------------------
def lambda_handler(event, context):
    print("Received event:", json.dumps(event))

    try:
        params = _extract_params(event)
        print("Parsed params:", params)

        req_region = (params.get("region") or "").strip()
        C = _clients(req_region)
        ec2, ssm, sts, elbv2, cw, asg, REGION = C["ec2"], C["ssm"], C["sts"], C["elbv2"], C["cw"], C["asg"], C["r"]

        action_raw = params.get("action")
        if not action_raw:
            return _err(event, 400, "Missing required parameter: action")

        action = _normalize_action(action_raw)
        print("Normalized action:", action, "Region:", REGION)

        # -------------------------
        # DEBUG
        # -------------------------
        if action == "get_region":
            return _ok(event, {"region_used": REGION, "education": "This is the AWS region your Lambda executed in."})

        if action == "whoami":
            ident = sts.get_caller_identity()
            return _ok(event, {
                "region_used": REGION,
                "account": ident.get("Account"),
                "arn": ident.get("Arn"),
                "user_id": ident.get("UserId"),
                "education": "This shows which AWS account/role is calling the backend."
            })

        # -------------------------
        # TAG RESOURCES
        # -------------------------
        if action == "tag_resources":
            resources = _parse_csv_list(params.get("resources"))
            tags = _parse_tags(params.get("tags"))
            if not resources:
                return _err(event, 400, "resources required for tag_resources")
            if not tags:
                return _err(event, 400, "tags required for tag_resources")
            resp = ec2.create_tags(Resources=resources, Tags=tags)
            return _ok(event, {
                "region_used": REGION,
                "message": "Tags applied.",
                "resources": resources,
                "tags": tags,
                "result": resp,
                "education": "Tags are labels used for billing and searching."
            })

        # -------------------------
        # EC2: describe / lifecycle
        # -------------------------
        if action == "describe_instances":
            instance_id = (params.get("instance_id") or "").strip()
            if instance_id:
                return _ok(event, {"region_used": REGION, "result": ec2.describe_instances(InstanceIds=[instance_id])})
            return _ok(event, {"region_used": REGION, "result": ec2.describe_instances()})

        if action == "start_instance":
            iid = (params.get("instance_id") or "").strip()
            if not iid:
                return _err(event, 400, "instance_id required for start_instance")
            return _ok(event, {
                "region_used": REGION,
                "result": ec2.start_instances(InstanceIds=[iid]),
                "education": "Start means the server begins running (may incur charges)."
            })

        if action == "stop_instance":
            iid = (params.get("instance_id") or "").strip()
            if not iid:
                return _err(event, 400, "instance_id required for stop_instance")
            return _ok(event, {
                "region_used": REGION,
                "result": ec2.stop_instances(InstanceIds=[iid]),
                "education": "Stop shuts down compute; EBS storage may still cost."
            })

        if action == "terminate_instance":
            iid = (params.get("instance_id") or "").strip()
            if not iid:
                return _err(event, 400, "instance_id required for terminate_instance")
            return _ok(event, {
                "region_used": REGION,
                "result": ec2.terminate_instances(InstanceIds=[iid]),
                "education": "Terminate deletes the instance; EBS volumes may still exist if set to keep."
            })

        if action == "set_termination_protection":
            instance_id = (params.get("instance_id") or "").strip()
            enabled = _to_bool(params.get("enabled"), default=True)
            if not instance_id:
                return _err(event, 400, "instance_id required for set_termination_protection")
            resp = ec2.modify_instance_attribute(
                InstanceId=instance_id,
                DisableApiTermination={"Value": bool(enabled)}
            )
            return _ok(event, {
                "region_used": REGION,
                "message": "Termination protection updated.",
                "instance_id": instance_id,
                "enabled": enabled,
                "result": resp,
                "education": "Prevents accidental delete via API/console."
            })

        

        # -------------------------
        # ASG: Auto Scaling Groups
        # -------------------------
        if action == "describe_asg":
            asg_name = (params.get("asg_name") or "").strip()
            if asg_name:
                resp = asg.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])
            else:
                resp = asg.describe_auto_scaling_groups()
            groups = resp.get("AutoScalingGroups", [])
            return _ok(event, {
                "region_used": REGION,
                "count": len(groups),
                "auto_scaling_groups": groups,
                "education": "Describe ASGs (optionally filtered by asg_name)."
            })

        if action == "create_asg":
            asg_name = (params.get("asg_name") or "").strip()
            if not asg_name:
                return _err(event, 400, "asg_name is required for create_asg")

            min_size = _to_int(params.get("min_size"), "min_size")
            max_size = _to_int(params.get("max_size"), "max_size")
            desired = _to_int(params.get("desired_capacity"), "desired_capacity")

            # sensible defaults
            if desired is None and min_size is not None:
                desired = min_size
            if min_size is None and desired is not None:
                min_size = desired
            if max_size is None and desired is not None:
                max_size = desired
            if min_size is None:
                min_size = 1
            if max_size is None:
                max_size = max(min_size, 1)
            if desired is None:
                desired = min_size

            # Networking
            use_default_network = _to_bool(params.get("use_default_network"), default=DEFAULT_USE_DEFAULT_NETWORK)
            subnets = _parse_csv_list(params.get("subnets"))
            if not subnets:
                if not use_default_network:
                    return _err(event, 400, "subnets required OR set use_default_network=true for create_asg")
                _vpc_id, subnet_ids = _get_default_vpc_and_subnets(ec2)
                subnets = subnet_ids[:2] if len(subnet_ids) >= 2 else subnet_ids

            # Launch Template (required for this implementation)
            lt_id = (params.get("launch_template_id") or "").strip()
            lt_ver = (params.get("launch_template_version") or "").strip() or "$Latest"
            if not lt_id:
                return _err(event, 400, "launch_template_id is required for create_asg")

            lt = {"LaunchTemplateId": lt_id, "Version": lt_ver}

            tags_in = _parse_tags(params.get("tags"))
            asg_tags = []
            if tags_in:
                for t in tags_in:
                    asg_tags.append({
                        "ResourceId": asg_name,
                        "ResourceType": "auto-scaling-group",
                        "Key": t["Key"],
                        "Value": t["Value"],
                        "PropagateAtLaunch": True
                    })

            payload = {
                "AutoScalingGroupName": asg_name,
                "MinSize": min_size,
                "MaxSize": max_size,
                "DesiredCapacity": desired,
                "VPCZoneIdentifier": ",".join(subnets),
                "LaunchTemplate": lt,
            }
            if asg_tags:
                payload["Tags"] = asg_tags

            resp = asg.create_auto_scaling_group(**payload)
            return _ok(event, {
                "region_used": REGION,
                "asg_name": asg_name,
                "payload_sent": payload,
                "result": resp,
                "education": "Created an Auto Scaling Group using a Launch Template and subnets."
            })

        if action == "update_asg":
            asg_name = (params.get("asg_name") or "").strip()
            if not asg_name:
                return _err(event, 400, "asg_name is required for update_asg")

            payload = {"AutoScalingGroupName": asg_name}

            min_size = _to_int(params.get("min_size"), "min_size")
            max_size = _to_int(params.get("max_size"), "max_size")
            desired = _to_int(params.get("desired_capacity"), "desired_capacity")
            if min_size is not None:
                payload["MinSize"] = min_size
            if max_size is not None:
                payload["MaxSize"] = max_size
            if desired is not None:
                payload["DesiredCapacity"] = desired

            subnets = _parse_csv_list(params.get("subnets"))
            use_default_network = _to_bool(params.get("use_default_network"), default=None)
            if subnets:
                payload["VPCZoneIdentifier"] = ",".join(subnets)
            elif use_default_network:
                _vpc_id, subnet_ids = _get_default_vpc_and_subnets(ec2)
                use_subnets = subnet_ids[:2] if len(subnet_ids) >= 2 else subnet_ids
                payload["VPCZoneIdentifier"] = ",".join(use_subnets)

            lt_id = (params.get("launch_template_id") or "").strip()
            lt_ver = (params.get("launch_template_version") or "").strip()
            if lt_id:
                payload["LaunchTemplate"] = {"LaunchTemplateId": lt_id, "Version": lt_ver or "$Latest"}

            resp = asg.update_auto_scaling_group(**payload)

            # optional tags update
            tags_in = _parse_tags(params.get("tags"))
            tags_result = None
            if tags_in:
                asg_tags = []
                for t in tags_in:
                    asg_tags.append({
                        "ResourceId": asg_name,
                        "ResourceType": "auto-scaling-group",
                        "Key": t["Key"],
                        "Value": t["Value"],
                        "PropagateAtLaunch": True
                    })
                tags_result = asg.create_or_update_tags(Tags=asg_tags)

            return _ok(event, {
                "region_used": REGION,
                "asg_name": asg_name,
                "payload_sent": payload,
                "result": resp,
                "tags_result": tags_result,
                "education": "Updated an Auto Scaling Group. Only provided parameters are updated."
            })

        if action == "delete_asg":
            asg_name = (params.get("asg_name") or "").strip()
            if not asg_name:
                return _err(event, 400, "asg_name is required for delete_asg")
            force_delete = _to_bool(params.get("force_delete"), default=False)
            resp = asg.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=force_delete)
            return _ok(event, {
                "region_used": REGION,
                "asg_name": asg_name,
                "force_delete": force_delete,
                "result": resp,
                "education": "Deleted an Auto Scaling Group. ForceDelete removes instances managed by the ASG."
            })

        if action == "suspend_processes":
            asg_name = (params.get("asg_name") or "").strip()
            if not asg_name:
                return _err(event, 400, "asg_name is required for suspend_processes")
            procs = _parse_csv_list(params.get("suspended_processes"))
            payload = {"AutoScalingGroupName": asg_name}
            if procs:
                payload["ScalingProcesses"] = procs
            resp = asg.suspend_processes(**payload)
            return _ok(event, {
                "region_used": REGION,
                "asg_name": asg_name,
                "processes": procs,
                "payload_sent": payload,
                "result": resp,
                "education": "Suspended ASG processes (e.g., ReplaceUnhealthy) to prevent automatic replacement."
            })

        if action == "resume_processes":
            asg_name = (params.get("asg_name") or "").strip()
            if not asg_name:
                return _err(event, 400, "asg_name is required for resume_processes")
            procs = _parse_csv_list(params.get("suspended_processes"))
            payload = {"AutoScalingGroupName": asg_name}
            if procs:
                payload["ScalingProcesses"] = procs
            resp = asg.resume_processes(**payload)
            return _ok(event, {
                "region_used": REGION,
                "asg_name": asg_name,
                "processes": procs,
                "payload_sent": payload,
                "result": resp,
                "education": "Resumed ASG processes."
            })

        if action == "set_instance_protection":
            asg_name = (params.get("asg_name") or "").strip()
            instance_ids = _parse_csv_list(params.get("instance_ids"))
            protected = _to_bool(params.get("protected_from_scale_in"), default=True)
            if not asg_name:
                return _err(event, 400, "asg_name is required for set_instance_protection")
            if not instance_ids:
                return _err(event, 400, "instance_ids is required for set_instance_protection")
            resp = asg.set_instance_protection(
                AutoScalingGroupName=asg_name,
                InstanceIds=instance_ids,
                ProtectedFromScaleIn=protected
            )
            return _ok(event, {
                "region_used": REGION,
                "asg_name": asg_name,
                "instance_ids": instance_ids,
                "protected_from_scale_in": protected,
                "result": resp,
                "education": "Set scale-in protection for instances in an ASG."
            })


# -------------------------
        # EC2: create instance (NO ASG)
        # -------------------------
        if action == "create_instance":
            use_default_network = _to_bool(params.get("use_default_network"), default=DEFAULT_USE_DEFAULT_NETWORK)
            subnet_id = str(_default_to_empty(params.get("subnet_id") or "")).strip()
            vpc_id = (params.get("vpc_id") or "").strip()

            if not subnet_id:
                if not use_default_network:
                    return _err(event, 400, "subnet_id required OR set use_default_network=true")
                vpc_id_resolved, subnet_ids = _get_default_vpc_and_subnets(ec2)
                subnet_ids = _pick_two_subnets_different_az(ec2, subnet_ids)
                subnet_id = subnet_ids[0]
                if not vpc_id:
                    vpc_id = vpc_id_resolved
            else:
                if not vpc_id:
                    vpc_id = _get_vpc_from_subnet(ec2, subnet_id)

            requested_ami = _default_to_empty(params.get("ami_id") or params.get("image_id") or "")
            ami_id = _sanitize_ami_id(requested_ami)
            ami_warning = None
            if requested_ami and not ami_id:
                ami_warning = f'Invalid ami_id "{str(requested_ami).strip()}". Using default AMI from SSM/env.'
            ami_id = ami_id or _resolve_default_ami_id(ssm)

            instance_type = (params.get("instance_type") or DEFAULT_INSTANCE_TYPE).strip()

            # If the user requests a non-free-tier eligible instance type, automatically fall back to a free-tier eligible type.
            # This avoids InvalidParameterCombination: "instance type is not eligible for Free Tier".
            it_warning = None
            if instance_type and not _is_free_tier_eligible_instance_type(ec2, instance_type):
                fallback_it = _pick_free_tier_instance_type(ec2, preferred=DEFAULT_INSTANCE_TYPE or "t3.micro")
                it_warning = (
                    f'Instance type "{instance_type}" is not Free Tier eligible. '
                    f'Using "{fallback_it}" instead.'
                )
                instance_type = fallback_it

            sg_ids = _parse_csv_list(_default_to_empty(params.get("security_group_ids") or ""))
            # if user/agent passes ["default"], treat as empty
            if len(sg_ids) == 1 and _is_default_token(sg_ids[0]):
                sg_ids = []

            if not sg_ids:
                if DEFAULT_SECURITY_GROUP_IDS:
                    sg_ids = DEFAULT_SECURITY_GROUP_IDS
                else:
                    sg_id = _ensure_sg(ec2, vpc_id, name="ec2-agent-instance-sg", open_http=False, open_ssh=False)
                    sg_ids = [sg_id]

            name_tag = (params.get("name") or "").strip()
            tags = _parse_tags(params.get("tags"))
            if name_tag:
                tags = tags + [{"Key": "Name", "Value": name_tag}] if tags else [{"Key": "Name", "Value": name_tag}]

            run_args = {
                "ImageId": ami_id,
                "InstanceType": instance_type,
                "MinCount": 1,
                "MaxCount": 1,
                "SubnetId": subnet_id,
                "SecurityGroupIds": sg_ids,
            }
            # Key pair handling:
            # - If user provides key_name -> use it; if missing -> auto-create
            # - If DEFAULT_KEY_NAME is set but doesn't exist -> auto-create it
            desired_key_name = str(_default_to_empty(params.get("key_name") or DEFAULT_KEY_NAME or "")).strip()

            # If key_name is empty, auto-create a new key pair and use it
            # If key_name provided but not found, create it and use it
            key_name_used, key_material, key_created = _ensure_key_pair(ec2, desired_key_name)

            run_args["KeyName"] = key_name_used

            iam_profile_name = str(_default_to_empty(params.get("iam_instance_profile_name") or DEFAULT_IAM_INSTANCE_PROFILE_NAME or "")).strip()
            if iam_profile_name:
                run_args["IamInstanceProfile"] = {"Name": iam_profile_name}

            resp = ec2.run_instances(**run_args)
            instance_id = resp["Instances"][0]["InstanceId"]

            if tags:
                try:
                    ec2.create_tags(Resources=[instance_id], Tags=tags)
                except ClientError:
                    pass

            return _ok(event, {
                "region_used": REGION,
                "message": "Instance launch started.",
                "instance_id": instance_id,
                "ami_id": ami_id,
                "instance_type": instance_type,
                "vpc_id": vpc_id,
                "subnet_id": subnet_id,
                "security_group_ids": sg_ids,
                "key_name_used": key_name_used or None,
                "key_created": bool(key_created),
                "key_material": key_material,
                "tags_applied": tags,
                "result": resp,
                "warnings": [w for w in [ami_warning, it_warning] if w],
                "education": _education("create_instance")
            })

        # -------------------------
        # AMI: create / deregister
        # -------------------------
        if action == "create_ami":
            instance_id = (params.get("instance_id") or "").strip()
            if not instance_id:
                return _err(event, 400, "instance_id required for create_ami")

            ami_name = (params.get("ami_name") or f"ec2-agent-ami-{instance_id}-{int(time.time())}").strip()
            no_reboot = _to_bool(params.get("no_reboot"), default=True)

            resp = ec2.create_image(InstanceId=instance_id, Name=ami_name, NoReboot=bool(no_reboot))
            return _ok(event, {
                "region_used": REGION,
                "message": "AMI creation started.",
                "image_id": resp.get("ImageId"),
                "ami_name": ami_name,
                "result": resp,
                "education": _education("create_ami")
            })

        if action == "deregister_ami":
            image_id = (params.get("image_id") or "").strip()
            if not image_id:
                return _err(event, 400, "image_id required for deregister_ami")
            resp = ec2.deregister_image(ImageId=image_id)
            return _ok(event, {
                "region_used": REGION,
                "message": "AMI deregistered.",
                "image_id": image_id,
                "result": resp,
                "education": "Removes the AMI so it can’t be used to launch instances."
            })

        # -------------------------
        # Snapshot: create / delete / copy
        # -------------------------
        if action == "create_snapshot":
            volume_id = (params.get("volume_id") or "").strip()
            if not volume_id:
                return _err(event, 400, "volume_id required for create_snapshot")
            desc = (params.get("description") or f"Snapshot by EC2 agent for {volume_id}").strip()
            resp = ec2.create_snapshot(VolumeId=volume_id, Description=desc)
            snap_id = resp.get("SnapshotId")

            tags = _parse_tags(params.get("tags"))
            if tags and snap_id:
                try:
                    ec2.create_tags(Resources=[snap_id], Tags=tags)
                except ClientError:
                    pass

            return _ok(event, {
                "region_used": REGION,
                "message": "Snapshot creation started.",
                "snapshot_id": snap_id,
                "volume_id": volume_id,
                "tags_applied": tags,
                "result": resp,
                "education": _education("create_snapshot")
            })

        if action == "delete_snapshot":
            snapshot_id = (params.get("snapshot_id") or "").strip()
            if not snapshot_id:
                return _err(event, 400, "snapshot_id required for delete_snapshot")
            resp = ec2.delete_snapshot(SnapshotId=snapshot_id)
            return _ok(event, {
                "region_used": REGION,
                "message": "Snapshot deleted.",
                "snapshot_id": snapshot_id,
                "result": resp,
                "education": "Deletes the backup snapshot permanently."
            })

        if action == "copy_snapshot":
            source_region = (params.get("source_region") or REGION).strip()
            source_snapshot_id = (params.get("source_snapshot_id") or "").strip()
            description = (params.get("description") or f"Copy of {source_snapshot_id}").strip()
            encrypted = _to_bool(params.get("encrypted"), default=False)
            kms_key_id = (params.get("kms_key_id") or "").strip()

            if not source_snapshot_id:
                return _err(event, 400, "source_snapshot_id required for copy_snapshot")

            kwargs = {
                "SourceRegion": source_region,
                "SourceSnapshotId": source_snapshot_id,
                "Description": description,
            }
            if encrypted:
                kwargs["Encrypted"] = True
                if kms_key_id:
                    kwargs["KmsKeyId"] = kms_key_id

            resp = ec2.copy_snapshot(**kwargs)
            new_snap_id = resp.get("SnapshotId")

            tags = _parse_tags(params.get("tags"))
            if tags and new_snap_id:
                try:
                    ec2.create_tags(Resources=[new_snap_id], Tags=tags)
                except ClientError:
                    pass

            return _ok(event, {
                "region_used": REGION,
                "message": "Snapshot copy started.",
                "source_region": source_region,
                "source_snapshot_id": source_snapshot_id,
                "new_snapshot_id": new_snap_id,
                "encrypted": encrypted,
                "kms_key_id": kms_key_id or None,
                "tags_applied": tags,
                "result": resp,
                "education": "Copies a snapshot to same/other region for migration or backup."
            })

        # -------------------------
        # EBS: create / attach / detach / delete
        # -------------------------
        if action == "create_volume":
            subnet_id = str(_default_to_empty(params.get("subnet_id") or "")).strip()
            if not subnet_id:
                _, subnet_ids = _get_default_vpc_and_subnets(ec2)
                subnet_id = _pick_two_subnets_different_az(ec2, subnet_ids)[0]
            sn = ec2.describe_subnets(SubnetIds=[subnet_id])["Subnets"][0]
            az = sn["AvailabilityZone"]

            size_gb = _to_int(params.get("size_gb"), "size_gb") or DEFAULT_VOLUME_SIZE_GB
            vol_type = (params.get("volume_type") or DEFAULT_VOLUME_TYPE).strip()

            encrypted = _to_bool(params.get("encrypted"), default=False)
            kms_key_id = (params.get("kms_key_id") or "").strip()

            kwargs = {"AvailabilityZone": az, "Size": size_gb, "VolumeType": vol_type}
            if encrypted:
                kwargs["Encrypted"] = True
                if kms_key_id:
                    kwargs["KmsKeyId"] = kms_key_id

            resp = ec2.create_volume(**kwargs)
            vol_id = resp.get("VolumeId")

            tags = _parse_tags(params.get("tags"))
            if tags and vol_id:
                try:
                    ec2.create_tags(Resources=[vol_id], Tags=tags)
                except ClientError:
                    pass

            return _ok(event, {
                "region_used": REGION,
                "message": "EBS volume creation started.",
                "volume_id": vol_id,
                "availability_zone": az,
                "size_gb": size_gb,
                "volume_type": vol_type,
                "encrypted": encrypted,
                "kms_key_id": kms_key_id or None,
                "tags_applied": tags,
                "result": resp,
                "education": _education("create_volume")
            })

        if action == "attach_volume":
            volume_id = (params.get("volume_id") or "").strip()
            instance_id = (params.get("instance_id") or "").strip()
            device = (params.get("device") or "/dev/sdf").strip()
            if not volume_id or not instance_id:
                return _err(event, 400, "volume_id and instance_id required for attach_volume")
            resp = ec2.attach_volume(VolumeId=volume_id, InstanceId=instance_id, Device=device)
            return _ok(event, {
                "region_used": REGION,
                "message": "Attach volume requested.",
                "volume_id": volume_id,
                "instance_id": instance_id,
                "device": device,
                "result": resp,
                "education": "Attaches the disk to the server; you must mount it inside OS."
            })

        if action == "detach_volume":
            volume_id = (params.get("volume_id") or "").strip()
            if not volume_id:
                return _err(event, 400, "volume_id required for detach_volume")
            force = _to_bool(params.get("force"), default=False)
            resp = ec2.detach_volume(VolumeId=volume_id, Force=bool(force))
            return _ok(event, {
                "region_used": REGION,
                "message": "Detach volume requested.",
                "volume_id": volume_id,
                "force": force,
                "result": resp,
                "education": "Detach removes the disk from instance; safe after unmount."
            })

        if action == "delete_volume":
            volume_id = (params.get("volume_id") or "").strip()
            if not volume_id:
                return _err(event, 400, "volume_id required for delete_volume")
            resp = ec2.delete_volume(VolumeId=volume_id)
            return _ok(event, {
                "region_used": REGION,
                "message": "Volume delete requested.",
                "volume_id": volume_id,
                "result": resp,
                "education": "Deletes the EBS disk permanently."
            })

        # -------------------------
        # SG: create + rule add/remove
        # -------------------------
        if action == "create_security_group":
            use_default_network = _to_bool(params.get("use_default_network"), default=True)
            vpc_id = (params.get("vpc_id") or "").strip()
            if not vpc_id:
                if not use_default_network:
                    return _err(event, 400, "vpc_id required OR set use_default_network=true")
                vpc_id, _ = _get_default_vpc_and_subnets(ec2)

            sg_name = (params.get("sg_name") or f"ec2-agent-sg-{int(time.time())}").strip()
            open_http = _to_bool(params.get("open_http"), default=False)
            open_ssh = _to_bool(params.get("open_ssh"), default=False)

            sg_id = _ensure_sg(ec2, vpc_id, name=sg_name, open_http=open_http, open_ssh=open_ssh)
            tags = _parse_tags(params.get("tags"))
            if tags:
                try:
                    ec2.create_tags(Resources=[sg_id], Tags=tags)
                except ClientError:
                    pass

            return _ok(event, {
                "region_used": REGION,
                "message": "Security group ready.",
                "vpc_id": vpc_id,
                "sg_name": sg_name,
                "security_group_id": sg_id,
                "open_http": open_http,
                "open_ssh": open_ssh,
                "tags_applied": tags,
                "education": _education("create_security_group")
            })

        if action == "add_sg_rule":
            sg_id = (params.get("security_group_id") or "").strip()
            direction = (params.get("direction") or "ingress").strip().lower()
            if not sg_id:
                return _err(event, 400, "security_group_id required for add_sg_rule")

            ip_permissions = _build_ip_permissions(params)

            if direction == "ingress":
                resp = ec2.authorize_security_group_ingress(GroupId=sg_id, IpPermissions=ip_permissions)
            elif direction == "egress":
                resp = ec2.authorize_security_group_egress(GroupId=sg_id, IpPermissions=ip_permissions)
            else:
                return _err(event, 400, "direction must be ingress or egress")

            return _ok(event, {
                "region_used": REGION,
                "message": "Security group rule added.",
                "security_group_id": sg_id,
                "direction": direction,
                "ip_permissions": ip_permissions,
                "result": resp,
                "education": "Adds a firewall rule to allow/deny traffic."
            })

        if action == "remove_sg_rule":
            sg_id = (params.get("security_group_id") or "").strip()
            direction = (params.get("direction") or "ingress").strip().lower()
            if not sg_id:
                return _err(event, 400, "security_group_id required for remove_sg_rule")

            ip_permissions = _build_ip_permissions(params)

            if direction == "ingress":
                resp = ec2.revoke_security_group_ingress(GroupId=sg_id, IpPermissions=ip_permissions)
            elif direction == "egress":
                resp = ec2.revoke_security_group_egress(GroupId=sg_id, IpPermissions=ip_permissions)
            else:
                return _err(event, 400, "direction must be ingress or egress")

            return _ok(event, {
                "region_used": REGION,
                "message": "Security group rule removed.",
                "security_group_id": sg_id,
                "direction": direction,
                "ip_permissions": ip_permissions,
                "result": resp,
                "education": "Removes the firewall rule."
            })

        # -------------------------
        # KEY PAIRS
        # -------------------------
        if action == "create_key_pair":
            key_name = (params.get("key_name") or DEFAULT_KEY_NAME or "").strip()
            if not key_name:
                return _err(event, 400, "key_name required for create_key_pair (or set DEFAULT_KEY_NAME env var)")

            resp = ec2.create_key_pair(KeyName=key_name)
            return _ok(event, {
                "region_used": REGION,
                "message": "Key pair created.",
                "key_name": key_name,
                "key_fingerprint": resp.get("KeyFingerprint"),
                "key_material": resp.get("KeyMaterial"),
                "education": "Key pair is used for SSH login. Save the private key safely (you can’t download it again)."
            })

        if action == "import_key_pair":
            key_name = (params.get("key_name") or DEFAULT_KEY_NAME or "").strip()
            public_key_material = (params.get("public_key_material") or "").strip()

            if not key_name:
                return _err(event, 400, "key_name required for import_key_pair (or set DEFAULT_KEY_NAME env var)")
            if not public_key_material:
                return _err(event, 400, "public_key_material required for import_key_pair (SSH public key text or base64)")

            pk_bytes = _b64_try_decode(public_key_material)
            if not pk_bytes:
                return _err(event, 400, "public_key_material is empty/invalid")

            resp = ec2.import_key_pair(KeyName=key_name, PublicKeyMaterial=pk_bytes)
            return _ok(event, {
                "region_used": REGION,
                "message": "Key pair imported.",
                "key_name": key_name,
                "result": resp,
                "education": "Imports your existing SSH public key into AWS (no private key stored in AWS)."
            })

        if action == "delete_key_pair":
            key_name = (params.get("key_name") or DEFAULT_KEY_NAME or "").strip()
            if not key_name:
                return _err(event, 400, "key_name required for delete_key_pair (or set DEFAULT_KEY_NAME env var)")
            resp = ec2.delete_key_pair(KeyName=key_name)
            return _ok(event, {
                "region_used": REGION,
                "message": "Key pair deleted.",
                "key_name": key_name,
                "result": resp,
                "education": "Deletes key pair record from AWS (instances already using it won’t be changed)."
            })

        # -------------------------
        # ELASTIC IP
        # -------------------------
        if action == "allocate_eip":
            resp = ec2.allocate_address(Domain="vpc")
            return _ok(event, {
                "region_used": REGION,
                "message": "Elastic IP allocated.",
                "allocation_id": resp.get("AllocationId"),
                "public_ip": resp.get("PublicIp"),
                "result": resp,
                "education": _education("allocate_eip")
            })

        if action == "associate_eip":
            allocation_id = (params.get("allocation_id") or "").strip()
            public_ip = (params.get("public_ip") or "").strip()
            instance_id = (params.get("instance_id") or "").strip()
            network_interface_id = (params.get("network_interface_id") or "").strip()
            private_ip_address = (params.get("private_ip_address") or "").strip()

            if allocation_id and public_ip:
                return _err(event, 400, "Provide only one: allocation_id OR public_ip (not both)")
            if not allocation_id and not public_ip:
                return _err(event, 400, "Provide allocation_id OR public_ip for associate_eip")
            if not instance_id and not network_interface_id:
                return _err(event, 400, "Provide instance_id OR network_interface_id for associate_eip")

            kwargs = {}
            if allocation_id:
                kwargs["AllocationId"] = allocation_id
            else:
                kwargs["PublicIp"] = public_ip

            # Prefer ENI if provided
            if network_interface_id:
                kwargs["NetworkInterfaceId"] = network_interface_id
                if private_ip_address:
                    kwargs["PrivateIpAddress"] = private_ip_address
            else:
                kwargs["InstanceId"] = instance_id

            resp = ec2.associate_address(**kwargs)
            return _ok(event, {
                "region_used": REGION,
                "message": "Elastic IP associated.",
                "association_id": resp.get("AssociationId"),
                "result": resp,
                "education": "Links the static IP to your instance/ENI."
            })

        if action == "disassociate_eip":
            association_id = (params.get("association_id") or "").strip()
            if not association_id:
                return _err(event, 400, "association_id required for disassociate_eip")
            resp = ec2.disassociate_address(AssociationId=association_id)
            return _ok(event, {
                "region_used": REGION,
                "message": "Elastic IP disassociated.",
                "association_id": association_id,
                "result": resp,
                "education": "Removes the Elastic IP from the instance/ENI."
            })

        if action == "release_eip":
            allocation_id = (params.get("allocation_id") or "").strip()
            if not allocation_id:
                return _err(event, 400, "allocation_id required for release_eip")
            resp = ec2.release_address(AllocationId=allocation_id)
            return _ok(event, {
                "region_used": REGION,
                "message": "Elastic IP released.",
                "allocation_id": allocation_id,
                "result": resp,
                "education": "Releases the Elastic IP back to AWS."
            })

        # -------------------------
        # ENI (Network Interface)
        # -------------------------
        if action == "create_eni":
            subnet_id = str(_default_to_empty(params.get("subnet_id") or "")).strip()
            use_default_network = _to_bool(params.get("use_default_network"), default=DEFAULT_USE_DEFAULT_NETWORK)

            if not subnet_id:
                if not use_default_network:
                    return _err(event, 400, "subnet_id required OR set use_default_network=true")
                _, subnet_ids = _get_default_vpc_and_subnets(ec2)
                subnet_id = _pick_two_subnets_different_az(ec2, subnet_ids)[0]

            sg_ids = _parse_csv_list(_default_to_empty(params.get("security_group_ids") or ""))
            # if user/agent passes ["default"], treat as empty
            if len(sg_ids) == 1 and _is_default_token(sg_ids[0]):
                sg_ids = []

            if not sg_ids:
                vpc_id = _get_vpc_from_subnet(ec2, subnet_id)
                sg_ids = [_ensure_sg(ec2, vpc_id, name="ec2-agent-eni-sg", open_http=False, open_ssh=False)]

            private_ip_address = (params.get("private_ip_address") or "").strip()
            kwargs = {"SubnetId": subnet_id, "Groups": sg_ids}
            if private_ip_address:
                kwargs["PrivateIpAddress"] = private_ip_address

            resp = ec2.create_network_interface(**kwargs)
            eni_id = resp.get("NetworkInterface", {}).get("NetworkInterfaceId")

            tags = _parse_tags(params.get("tags"))
            if tags and eni_id:
                try:
                    ec2.create_tags(Resources=[eni_id], Tags=tags)
                except ClientError:
                    pass

            return _ok(event, {
                "region_used": REGION,
                "message": "ENI created.",
                "network_interface_id": eni_id,
                "subnet_id": subnet_id,
                "security_group_ids": sg_ids,
                "private_ip_address": private_ip_address or None,
                "tags_applied": tags,
                "result": resp,
                "education": "ENI is a virtual network card you can attach to instances."
            })

        if action == "attach_eni":
            eni_id = (params.get("network_interface_id") or "").strip()
            instance_id = (params.get("instance_id") or "").strip()
            device_index = _to_int(params.get("device_index"), "device_index")
            delete_on_termination = _to_bool(params.get("delete_on_termination"), default=False)

            if not eni_id or not instance_id:
                return _err(event, 400, "network_interface_id and instance_id required for attach_eni")

            if device_index is None:
                device_index = 1  # typical secondary ENI slot

            resp = ec2.attach_network_interface(
                NetworkInterfaceId=eni_id,
                InstanceId=instance_id,
                DeviceIndex=device_index
            )
            attachment_id = resp.get("AttachmentId")

            # Optional console-like checkbox
            if attachment_id:
                try:
                    ec2.modify_network_interface_attribute(
                        NetworkInterfaceId=eni_id,
                        Attachment={"AttachmentId": attachment_id, "DeleteOnTermination": bool(delete_on_termination)}
                    )
                except ClientError:
                    pass

            return _ok(event, {
                "region_used": REGION,
                "message": "ENI attach requested.",
                "network_interface_id": eni_id,
                "instance_id": instance_id,
                "device_index": device_index,
                "attachment_id": attachment_id,
                "delete_on_termination": delete_on_termination,
                "result": resp,
                "education": "Attaches the ENI to the instance as another network card."
            })

        if action == "detach_eni":
            attachment_id = (params.get("attachment_id") or "").strip()
            force = _to_bool(params.get("force"), default=False)
            if not attachment_id:
                return _err(event, 400, "attachment_id required for detach_eni")
            resp = ec2.detach_network_interface(AttachmentId=attachment_id, Force=bool(force))
            return _ok(event, {
                "region_used": REGION,
                "message": "ENI detach requested.",
                "attachment_id": attachment_id,
                "force": force,
                "result": resp,
                "education": "Detaches the ENI from the instance."
            })

        if action == "delete_eni":
            eni_id = (params.get("network_interface_id") or "").strip()
            if not eni_id:
                return _err(event, 400, "network_interface_id required for delete_eni")
            resp = ec2.delete_network_interface(NetworkInterfaceId=eni_id)
            return _ok(event, {
                "region_used": REGION,
                "message": "ENI deleted.",
                "network_interface_id": eni_id,
                "result": resp,
                "education": "Deletes the ENI resource."
            })

        # -------------------------
        # PLACEMENT GROUP
        # -------------------------
        if action == "create_placement_group":
            name = (params.get("placement_group_name") or "").strip()
            strategy = (params.get("strategy") or "spread").strip()
            if not name:
                return _err(event, 400, "placement_group_name required for create_placement_group")
            resp = ec2.create_placement_group(GroupName=name, Strategy=strategy)
            return _ok(event, {
                "region_used": REGION,
                "message": "Placement group created.",
                "placement_group_name": name,
                "strategy": strategy,
                "result": resp,
                "education": "Placement groups control how instances are placed on AWS hardware."
            })

        if action == "delete_placement_group":
            name = (params.get("placement_group_name") or "").strip()
            if not name:
                return _err(event, 400, "placement_group_name required for delete_placement_group")
            resp = ec2.delete_placement_group(GroupName=name)
            return _ok(event, {
                "region_used": REGION,
                "message": "Placement group deleted.",
                "placement_group_name": name,
                "result": resp,
                "education": "Deletes the placement group container."
            })

        # -------------------------
        # LAUNCH TEMPLATE
        # -------------------------
        if action == "create_launch_template":
            lt_name = (params.get("launch_template_name") or f"ec2-agent-lt-{int(time.time())}").strip()
            instance_type = (params.get("instance_type") or DEFAULT_INSTANCE_TYPE).strip()

            # If the user requests a non-free-tier eligible instance type, automatically fall back to a free-tier eligible type.
            # This avoids InvalidParameterCombination: "instance type is not eligible for Free Tier".
            it_warning = None
            if instance_type and not _is_free_tier_eligible_instance_type(ec2, instance_type):
                fallback_it = _pick_free_tier_instance_type(ec2, preferred=DEFAULT_INSTANCE_TYPE or "t3.micro")
                it_warning = (
                    f'Instance type "{instance_type}" is not Free Tier eligible. '
                    f'Using "{fallback_it}" instead.'
                )
                instance_type = fallback_it

            use_default_network = _to_bool(params.get("use_default_network"), default=True)
            subnet_id = str(_default_to_empty(params.get("subnet_id") or "")).strip()
            vpc_id = (params.get("vpc_id") or "").strip()

            if not subnet_id:
                if not use_default_network:
                    return _err(event, 400, "subnet_id required OR set use_default_network=true")
                vpc_id_resolved, subnet_ids = _get_default_vpc_and_subnets(ec2)
                subnet_id = _pick_two_subnets_different_az(ec2, subnet_ids)[0]
                if not vpc_id:
                    vpc_id = vpc_id_resolved
            else:
                if not vpc_id:
                    vpc_id = _get_vpc_from_subnet(ec2, subnet_id)

            requested_ami = _default_to_empty(params.get("ami_id") or params.get("image_id") or "")
            ami_id = _sanitize_ami_id(requested_ami)
            ami_warning = None
            if requested_ami and not ami_id:
                ami_warning = f'Invalid ami_id "{str(requested_ami).strip()}". Using default AMI from SSM/env.'
            ami_id = ami_id or _resolve_default_ami_id(ssm)

            sg_ids = _parse_csv_list(_default_to_empty(params.get("security_group_ids") or ""))
            # if user/agent passes ["default"], treat as empty
            if len(sg_ids) == 1 and _is_default_token(sg_ids[0]):
                sg_ids = []

            if not sg_ids:
                if DEFAULT_SECURITY_GROUP_IDS:
                    sg_ids = DEFAULT_SECURITY_GROUP_IDS
                else:
                    sg_ids = [_ensure_sg(ec2, vpc_id, name="ec2-agent-lt-sg", open_http=False, open_ssh=False)]

            lt_data = {
                "ImageId": ami_id,
                "InstanceType": instance_type,
                "SecurityGroupIds": sg_ids,
            }

            # Key pair handling for Launch Template:
            desired_key_name = str(_default_to_empty(params.get("key_name") or DEFAULT_KEY_NAME or "")).strip()
            key_name_used, key_material, key_created = _ensure_key_pair(ec2, desired_key_name)
            lt_data["KeyName"] = key_name_used

            iam_profile_name = str(_default_to_empty(params.get("iam_instance_profile_name") or DEFAULT_IAM_INSTANCE_PROFILE_NAME or "")).strip()
            if iam_profile_name:
                lt_data["IamInstanceProfile"] = {"Name": iam_profile_name}

            resp = ec2.create_launch_template(LaunchTemplateName=lt_name, LaunchTemplateData=lt_data)
            lt_id = resp.get("LaunchTemplate", {}).get("LaunchTemplateId")

            tags = _parse_tags(params.get("tags"))
            if tags and lt_id:
                try:
                    ec2.create_tags(Resources=[lt_id], Tags=tags)
                except ClientError:
                    pass

            return _ok(event, {
                "region_used": REGION,
                "message": "Launch template created.",
                "launch_template_name": lt_name,
                "launch_template_id": lt_id,
                "ami_id": ami_id,
                "instance_type": instance_type,
                "security_group_ids": sg_ids,
                "key_name_used": key_name_used or None,
                "key_created": bool(key_created),
                "key_material": key_material,
                "tags_applied": tags,
                "result": resp,
                "warnings": [w for w in [ami_warning, it_warning] if w],
                "education": "Launch template stores instance settings so you can reuse them quickly."
            })

        if action == "delete_launch_template":
            lt_id = (params.get("launch_template_id") or "").strip()
            lt_name = (params.get("launch_template_name") or "").strip()
            if not lt_id and not lt_name:
                return _err(event, 400, "Provide launch_template_id OR launch_template_name for delete_launch_template")
            kwargs = {"LaunchTemplateId": lt_id} if lt_id else {"LaunchTemplateName": lt_name}
            resp = ec2.delete_launch_template(**kwargs)
            return _ok(event, {
                "region_used": REGION,
                "message": "Launch template deleted.",
                "launch_template_id": lt_id or None,
                "launch_template_name": lt_name or None,
                "result": resp,
                "education": "Deletes the reusable template settings."
            })

        # -------------------------
        # ALB (creates LB + target group + HTTP listener)
        # -------------------------
        if action == "create_load_balancer":
            name = (params.get("name") or f"ec2-agent-alb-{int(time.time())}").strip()

            use_default_network = _to_bool(params.get("use_default_network"), default=True)
            vpc_id = (params.get("vpc_id") or "").strip()
            subnet_list = _parse_csv_list(params.get("subnets"))

            if not subnet_list:
                if not use_default_network:
                    return _err(event, 400, "subnets required OR set use_default_network=true")
                vpc_id_resolved, subnet_ids = _get_default_vpc_and_subnets(ec2)
                subnet_list = _pick_two_subnets_different_az(ec2, subnet_ids)
                if not vpc_id:
                    vpc_id = vpc_id_resolved
            else:
                if not vpc_id:
                    vpc_id = _get_vpc_from_subnet(ec2, subnet_list[0])
                subnet_list = _pick_two_subnets_different_az(ec2, subnet_list)

            sg_ids = _parse_csv_list(_default_to_empty(params.get("security_group_ids") or ""))
            # if user/agent passes ["default"], treat as empty
            if len(sg_ids) == 1 and _is_default_token(sg_ids[0]):
                sg_ids = []

            if not sg_ids:
                sg_ids = [_ensure_sg(ec2, vpc_id, name="ec2-agent-alb-sg", open_http=True, open_ssh=False)]

            lb = elbv2.create_load_balancer(
                Name=name,
                Subnets=subnet_list,
                SecurityGroups=sg_ids,
                Scheme="internet-facing",
                Type="application",
                IpAddressType="ipv4",
            )
            lb_arn = lb["LoadBalancers"][0]["LoadBalancerArn"]
            dns = lb["LoadBalancers"][0]["DNSName"]

            tg_name = (params.get("target_group_name") or f"{name}-tg").strip()
            port = _to_int(params.get("port"), "port") or 80
            protocol = (params.get("protocol") or "HTTP").strip().upper()

            tg = elbv2.create_target_group(
                Name=tg_name[:32],
                Protocol=protocol,
                Port=port,
                VpcId=vpc_id,
                TargetType="instance",
                HealthCheckProtocol=protocol,
                HealthCheckPort=str(port),
                HealthCheckEnabled=True,
                HealthCheckPath="/",
            )
            tg_arn = tg["TargetGroups"][0]["TargetGroupArn"]

            listener = elbv2.create_listener(
                LoadBalancerArn=lb_arn,
                Protocol=protocol,
                Port=port,
                DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
            )
            listener_arn = listener["Listeners"][0]["ListenerArn"]

            return _ok(event, {
                "region_used": REGION,
                "message": "ALB created (with target group + listener).",
                "load_balancer_name": name,
                "load_balancer_arn": lb_arn,
                "dns_name": dns,
                "target_group_name": tg_name,
                "target_group_arn": tg_arn,
                "listener_arn": listener_arn,
                "subnets": subnet_list,
                "security_group_ids": sg_ids,
                "education": _education("create_load_balancer")
            })

        if action == "delete_load_balancer":
            lb_arn = (params.get("load_balancer_arn") or "").strip()
            if not lb_arn:
                return _err(event, 400, "load_balancer_arn required for delete_load_balancer")
            resp = elbv2.delete_load_balancer(LoadBalancerArn=lb_arn)
            return _ok(event, {
                "region_used": REGION,
                "message": "Load balancer delete requested.",
                "load_balancer_arn": lb_arn,
                "result": resp,
                "education": "Deletes the ALB (target group/listener can be deleted separately)."
            })

        if action == "register_targets":
            tg_arn = (params.get("target_group_arn") or "").strip()
            targets = _parse_csv_list(params.get("targets"))
            port = _to_int(params.get("port"), "port") or 80
            if not tg_arn or not targets:
                return _err(event, 400, "target_group_arn and targets required for register_targets")
            resp = elbv2.register_targets(
                TargetGroupArn=tg_arn,
                Targets=[{"Id": t, "Port": port} for t in targets]
            )
            return _ok(event, {
                "region_used": REGION,
                "message": "Targets registered.",
                "target_group_arn": tg_arn,
                "targets": targets,
                "port": port,
                "result": resp,
                "education": "Adds instances behind the load balancer."
            })

        if action == "deregister_targets":
            tg_arn = (params.get("target_group_arn") or "").strip()
            targets = _parse_csv_list(params.get("targets"))
            port = _to_int(params.get("port"), "port") or 80
            if not tg_arn or not targets:
                return _err(event, 400, "target_group_arn and targets required for deregister_targets")
            resp = elbv2.deregister_targets(
                TargetGroupArn=tg_arn,
                Targets=[{"Id": t, "Port": port} for t in targets]
            )
            return _ok(event, {
                "region_used": REGION,
                "message": "Targets deregistered.",
                "target_group_arn": tg_arn,
                "targets": targets,
                "port": port,
                "result": resp,
                "education": "Removes instances from the load balancer target group."
            })

        if action == "delete_listener":
            listener_arn = (params.get("listener_arn") or "").strip()
            if not listener_arn:
                return _err(event, 400, "listener_arn required for delete_listener")
            resp = elbv2.delete_listener(ListenerArn=listener_arn)
            return _ok(event, {
                "region_used": REGION,
                "message": "Listener deleted.",
                "listener_arn": listener_arn,
                "result": resp,
                "education": "Deletes the ALB listener (port rule)."
            })

        if action == "delete_target_group":
            tg_arn = (params.get("target_group_arn") or "").strip()
            if not tg_arn:
                return _err(event, 400, "target_group_arn required for delete_target_group")
            resp = elbv2.delete_target_group(TargetGroupArn=tg_arn)
            return _ok(event, {
                "region_used": REGION,
                "message": "Target group deleted.",
                "target_group_arn": tg_arn,
                "result": resp,
                "education": "Deletes the group that holds registered targets."
            })

        # -------------------------
        # CLOUDWATCH ALARMS (optional auto-recovery)
        # -------------------------
        if action == "create_alarm":
            alarm_name = (params.get("alarm_name") or "").strip()
            instance_id = (params.get("instance_id") or "").strip()
            if not alarm_name or not instance_id:
                return _err(event, 400, "alarm_name and instance_id required for create_alarm")

            auto_recover = _to_bool(params.get("auto_recover"), default=False)

            metric_name = (params.get("metric_name") or ("StatusCheckFailed_System" if auto_recover else "CPUUtilization")).strip()
            namespace = (params.get("namespace") or "AWS/EC2").strip()
            threshold = float(params.get("threshold") or (1 if auto_recover else 80))
            comparison_operator = (params.get("comparison_operator") or "GreaterThanThreshold").strip()
            period = _to_int(params.get("period"), "period") or 300
            evaluation_periods = _to_int(params.get("evaluation_periods"), "evaluation_periods") or 1

            alarm_actions = []
            if auto_recover:
                alarm_actions = [f"arn:aws:automate:{REGION}:ec2:recover"]

            resp = cw.put_metric_alarm(
                AlarmName=alarm_name,
                Namespace=namespace,
                MetricName=metric_name,
                Dimensions=[{"Name": "InstanceId", "Value": instance_id}],
                Statistic="Average",
                Period=period,
                EvaluationPeriods=evaluation_periods,
                Threshold=threshold,
                ComparisonOperator=comparison_operator,
                ActionsEnabled=True,
                AlarmActions=alarm_actions,
            )

            return _ok(event, {
                "region_used": REGION,
                "message": "Alarm created/updated.",
                "alarm_name": alarm_name,
                "instance_id": instance_id,
                "metric_name": metric_name,
                "namespace": namespace,
                "threshold": threshold,
                "auto_recover": auto_recover,
                "result": resp,
                "education": "Alarm watches a metric and can notify or auto-recover (if enabled)."
            })

        if action == "delete_alarm":
            alarm_name = (params.get("alarm_name") or "").strip()
            if not alarm_name:
                return _err(event, 400, "alarm_name required for delete_alarm")
            resp = cw.delete_alarms(AlarmNames=[alarm_name])
            return _ok(event, {
                "region_used": REGION,
                "message": "Alarm deleted.",
                "alarm_name": alarm_name,
                "result": resp,
                "education": "Stops monitoring and removes the alarm."
            })

        # -------------------------
        # VPC BASIC (2 public subnets + IGW + route)
        # -------------------------
        if action == "create_vpc_basic":
            vpc_cidr = (params.get("vpc_cidr") or "10.0.0.0/16").strip()

            vpc = ec2.create_vpc(CidrBlock=vpc_cidr)["Vpc"]
            vpc_id = vpc["VpcId"]

            ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
            ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

            azs = ec2.describe_availability_zones()["AvailabilityZones"]
            az1 = azs[0]["ZoneName"]
            az2 = azs[1]["ZoneName"] if len(azs) > 1 else azs[0]["ZoneName"]

            subnet1 = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.0.1.0/24", AvailabilityZone=az1)["Subnet"]["SubnetId"]
            subnet2 = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.0.2.0/24", AvailabilityZone=az2)["Subnet"]["SubnetId"]

            ec2.modify_subnet_attribute(SubnetId=subnet1, MapPublicIpOnLaunch={"Value": True})
            ec2.modify_subnet_attribute(SubnetId=subnet2, MapPublicIpOnLaunch={"Value": True})

            igw_id = ec2.create_internet_gateway()["InternetGateway"]["InternetGatewayId"]
            ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)

            rt_id = ec2.create_route_table(VpcId=vpc_id)["RouteTable"]["RouteTableId"]
            ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)

            ec2.associate_route_table(RouteTableId=rt_id, SubnetId=subnet1)
            ec2.associate_route_table(RouteTableId=rt_id, SubnetId=subnet2)

            return _ok(event, {
                "region_used": REGION,
                "message": "Basic VPC created (2 public subnets + IGW + route).",
                "vpc_id": vpc_id,
                "subnets": [subnet1, subnet2],
                "internet_gateway_id": igw_id,
                "route_table_id": rt_id,
                "education": "Creates a simple network so instances can have internet access."
            })

        # -------------------------
        # NAT GATEWAY (NOT free-tier)
        # -------------------------
        if action == "create_nat_gateway":
            subnet_id = str(_default_to_empty(params.get("subnet_id") or "")).strip()
            if not subnet_id:
                _, subnet_ids = _get_default_vpc_and_subnets(ec2)
                subnet_id = _pick_two_subnets_different_az(ec2, subnet_ids)[0]

            allocation_id = (params.get("allocation_id") or "").strip()
            if not allocation_id:
                eip = ec2.allocate_address(Domain="vpc")
                allocation_id = eip.get("AllocationId")

            resp = ec2.create_nat_gateway(SubnetId=subnet_id, AllocationId=allocation_id)
            nat_id = resp.get("NatGateway", {}).get("NatGatewayId")

            return _ok(event, {
                "region_used": REGION,
                "message": "NAT Gateway creation started.",
                "nat_gateway_id": nat_id,
                "subnet_id": subnet_id,
                "allocation_id": allocation_id,
                "result": resp,
                "education": _education("create_nat_gateway")
            })

        # -------------------------
        # SSM: send-command (no SSH)
        # -------------------------
        if action == "ssm_send_command":
            instance_ids = _parse_csv_list(params.get("instance_ids"))
            if not instance_ids:
                iid = (params.get("instance_id") or "").strip()
                if iid:
                    instance_ids = [iid]

            if not instance_ids:
                return _err(event, 400, "instance_id or instance_ids required for ssm_send_command")

            document_name = (params.get("document_name") or "AWS-RunShellScript").strip()
            commands = params.get("commands")

            if isinstance(commands, str):
                commands = [commands]
            if not isinstance(commands, list) or not commands:
                return _err(event, 400, "commands required for ssm_send_command (string or list of strings)")

            timeout_seconds = _to_int(params.get("timeout_seconds"), "timeout_seconds") or 600
            comment = (params.get("comment") or "Command sent by EC2 agent").strip()

            resp = ssm.send_command(
                InstanceIds=instance_ids,
                DocumentName=document_name,
                Comment=comment,
                TimeoutSeconds=timeout_seconds,
                Parameters={"commands": [str(c) for c in commands]},
            )

            cmd_id = resp.get("Command", {}).get("CommandId")
            return _ok(event, {
                "region_used": REGION,
                "message": "SSM command sent.",
                "document_name": document_name,
                "instance_ids": instance_ids,
                "command_id": cmd_id,
                "result": resp,
                "education": _education("ssm_send_command")
            })

        print("Unknown action requested:", action_raw, "=>", action)
        return _err(event, 400, f"Unknown action: {action}")

    except ClientError as ce:
        print("ClientError:", str(ce))
        msg = str(ce)
        hint = "Check IAM permissions and confirm region/account are correct."
        return _err(event, 500, f"AWS ClientError: {msg}", extra=hint)

    except Exception as e:
        print("Error:", str(e))
        return _err(event, 500, str(e))