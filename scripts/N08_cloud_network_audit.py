#!/usr/bin/env python3
"""N-08: Audit AWS VPC security-group inbound sources against an explicit approval policy.

Read-only: uses DescribeSecurityGroups and DescribeSecurityGroupRules exclusively.
CSV output is saved for report evidence. PASS/FAIL/REVIEW are policy-comparison results,
not proof of reachability.

Run: python3 check_n08.py --vpc-id vpc-xxxxxxxxxxxxxxxxx
"""
import argparse
import csv
from datetime import datetime, timezone
from pathlib import Path
from collections import Counter

# Edit the following examples to match the team's officially approved ingress rules.
# Keys are Security Group names in the selected VPC. Source SG names are resolved
# to IDs in that same VPC so no fixed SG IDs are required.
# Any SG omitted here receives REVIEW when it has inbound rules.
# Rule: (protocol, start_port, end_port, source_kind, source_value)
# - protocol: tcp / udp / icmp / -1 (all)
# - source_kind: cidr4 / cidr6 / sg / prefix-list
# - for "sg", source_value is the *source security group name* in this VPC
APPROVED_INGRESS = {
    "404-alb-sg": [
        ("tcp", 80, 80, "cidr4", "0.0.0.0/0"),
        ("tcp", 443, 443, "cidr4", "0.0.0.0/0"),
    ],
    "kt-web": [
        ("tcp", 5000, 5000, "sg", "404-alb-sg"),
    ],
    # After team approval, add NAT / IPS / DB SGs here with exact source rules.
}


def protocol(value):
    return {"6": "tcp", "17": "udp", "1": "icmp", "58": "icmpv6", "all": "-1"}.get(str(value).lower(), str(value).lower())


def approval_key(rule, id_to_name):
    """Normalize a DescribeSecurityGroupRules entry into a comparable 5-tuple."""
    proto = protocol(rule.get("IpProtocol", ""))
    start, end = rule.get("FromPort"), rule.get("ToPort")
    if proto == "-1":
        start = end = None
    if "CidrIpv4" in rule:
        return (proto, start, end, "cidr4", rule["CidrIpv4"])
    if "CidrIpv6" in rule:
        return (proto, start, end, "cidr6", rule["CidrIpv6"])
    if "PrefixListId" in rule:
        return (proto, start, end, "prefix-list", rule["PrefixListId"])
    src = rule.get("ReferencedGroupInfo")
    if src and src.get("GroupId"):
        group_id = src["GroupId"]
        # An unknown/cross-account group is not silently approved by name.
        return (proto, start, end, "sg", id_to_name.get(group_id, group_id))
    return (proto, start, end, "unknown", "not resolved")


def get_aws_data(region, vpc_id):
    import boto3
    ec2 = boto3.client("ec2", region_name=region)
    groups = []
    for page in ec2.get_paginator("describe_security_groups").paginate(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
    ):
        groups.extend(page.get("SecurityGroups", []))
    rules = {g["GroupId"]: [] for g in groups}
    # One VPC-level paginated request for all SG rules, including IPv6 and SG references.
    for page in ec2.get_paginator("describe_security_group_rules").paginate():
        for rule in page.get("SecurityGroupRules", []):
            group_id = rule.get("GroupId")
            if group_id in rules and not rule.get("IsEgress", False):
                rules[group_id].append(rule)
    return groups, rules


def check_group(group, rules, id_to_name):
    name, gid = group["GroupName"], group["GroupId"]
    actual = [(approval_key(r, id_to_name), r.get("SecurityGroupRuleId", "?")) for r in rules]
    if name not in APPROVED_INGRESS:
        if actual:
            return "REVIEW", ["No approval policy defined. Current ingress rules:"] + [f"  {rid}: {key}" for key, rid in actual]
        return "PASS", ["No ingress rules (approval policy not defined)"]

    approved = set(APPROVED_INGRESS[name])
    found = {key for key, _ in actual}
    extras = [(key, rid) for key, rid in actual if key not in approved]
    missing = sorted(approved - found, key=str)
    if extras or missing:
        details = []
        details += [f"Unapproved rule {rid}: {key}" for key, rid in extras]
        details += [f"Missing required approved rule: {key}" for key in missing]
        return "FAIL", details
    return "PASS", [f"Matched approved ingress rules: {len(actual)} rule(s)"]


def main():
    parser = argparse.ArgumentParser(description="N-08 Approved ingress sources audit (read-only)")
    parser.add_argument("--vpc-id", required=True, help="Target VPC ID")
    parser.add_argument("--region", default="ap-northeast-2", help="AWS region")
    parser.add_argument("--output-dir", default="reports", help="CSV evidence directory")
    args = parser.parse_args()
    try:
        groups, rules_by_group = get_aws_data(args.region, args.vpc_id)
    except Exception as exc:
        print(f"[ERROR] AWS query failed: {type(exc).__name__}: {exc}")
        return 3
    if not groups:
        print("[REVIEW] No security groups found. Verify region and VPC ID.")
        return 2

    id_to_name = {g["GroupId"]: g["GroupName"] for g in groups}
    name_counts = Counter(g["GroupName"] for g in groups)
    counts = Counter()
    rows = []
    print(f"N-08 Unauthorized Ingress Audit | {args.region} | {args.vpc_id}")
    print("NOTE: Compare AWS inbound rules against team-approved source policies (read-only).")
    print("=" * 88)
    for group in sorted(groups, key=lambda g: (g["GroupName"], g["GroupId"])):
        name = group["GroupName"]
        gid = group["GroupId"]
        if name_counts[name] > 1:
            status, details = "REVIEW", ["Duplicate security group name in VPC; resolve policy identity"]
        else:
            status, details = check_group(group, rules_by_group.get(gid, []), id_to_name)
        counts[status] += 1
        print(f"[{status:<6}] N-08 {name} ({gid})")
        for detail in details:
            print(f"        {detail}")
        rows.append({"check_id": "N-08", "status": status, "sg_name": name,
                     "sg_id": gid, "vpc_id": args.vpc_id, "details": "; ".join(details)})

    print("=" * 88)
    print(f"SUMMARY: PASS={counts['PASS']} FAIL={counts['FAIL']} REVIEW={counts['REVIEW']} ({len(groups)} security groups)")
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    filename = output_dir / f"N08_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S_UTC')}.csv"
    with filename.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["check_id", "status", "sg_name", "sg_id", "vpc_id", "details"])
        writer.writeheader()
        writer.writerows(rows)
    print(f"CSV saved: {filename}")
    print("NOTE: SG policy comparison only; actual network reachability is not verified.")
    print("NOTE: No AWS settings were modified.")
    return 1 if counts["FAIL"] else (2 if counts["REVIEW"] else 0)


if __name__ == "__main__":
    raise SystemExit(main())
