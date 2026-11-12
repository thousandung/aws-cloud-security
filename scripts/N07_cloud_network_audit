#!/usr/bin/env python3
"""N-07: Six read-only ALB and Web EC2 access-control configuration checks.

Examples:
    python3 check_n07.py --vpc-id vpc-xxxxxxxxxxxxxxxxx
    python3 check_n07.py --vpc-id vpc-xxxxxxxxxxxxxxxxx --alb-name 404-web-alb

Only AWS Describe APIs are called. Results print to the terminal and are saved as CSV.
This is a configuration audit, not a network reachability or TLS certificate test.
"""

import argparse
import csv
from datetime import datetime, timezone
from pathlib import Path
from collections import Counter

import boto3
from botocore.exceptions import BotoCoreError, ClientError

EXPECTED_LISTENERS = {("HTTP", 80), ("HTTPS", 443)}


ROWS = []


def emit(item, status, detail, alb_name=""):
    check_id = f"N07-{item:02d}"
    print(f"[{status:<6}] {check_id} {detail}")
    ROWS.append({"check_id": check_id, "status": status,
                 "resource": alb_name, "details": detail})
    return status


def inbound_rules(ec2, sg_id, cache):
    if sg_id not in cache:
        cache[sg_id] = []
        for page in ec2.get_paginator("describe_security_group_rules").paginate(
            Filters=[{"Name": "group-id", "Values": [sg_id]}]
        ):
            cache[sg_id].extend(
                rule for rule in page.get("SecurityGroupRules", [])
                if not rule.get("IsEgress", False)
            )
    return cache[sg_id]


def covers_tcp(rule, port):
    proto = str(rule.get("IpProtocol", "")).lower()
    if proto == "-1":
        return True
    low, high = rule.get("FromPort"), rule.get("ToPort")
    return proto in ("tcp", "6") and low is not None and high is not None and low <= port <= high


def exact_tcp(rule, port):
    return (str(rule.get("IpProtocol", "")).lower() in ("tcp", "6")
            and rule.get("FromPort") == port and rule.get("ToPort") == port)


def source(rule):
    ref = rule.get("ReferencedGroupInfo") or {}
    return (rule.get("CidrIpv4") or rule.get("CidrIpv6") or
            ref.get("GroupId") or rule.get("PrefixListId") or "unknown")


def main():
    parser = argparse.ArgumentParser(description="N-07: six read-only ALB/Web EC2 checks")
    parser.add_argument("--vpc-id", required=True, help="VPC ID to audit")
    parser.add_argument("--region", default="ap-northeast-2")
    parser.add_argument("--alb-name", help="Optional: limit scan to one ALB")
    parser.add_argument("--output-dir", default="reports", help="CSV evidence directory")
    parser.add_argument("--web-port", type=int, default=5000,
                        help="Expected backend web service port (default: 5000)")
    args = parser.parse_args()

    ec2 = boto3.client("ec2", region_name=args.region)
    elb = boto3.client("elbv2", region_name=args.region)
    cache = {}
    statuses = []

    print(f"N-07 ALB Access Control | region={args.region} | VPC={args.vpc_id}")
    print("NOTE: Read-only AWS checks; the CSV evidence is saved locally.\n")

    lbs = []
    for page in elb.get_paginator("describe_load_balancers").paginate():
        lbs.extend(lb for lb in page.get("LoadBalancers", [])
                   if lb.get("Type") == "application" and lb.get("VpcId") == args.vpc_id
                   and (not args.alb_name or lb.get("LoadBalancerName") == args.alb_name))
    if not lbs:
        print("[REVIEW] No matching application load balancers. Verify the VPC, region and name.")
        return 2

    for alb in lbs:
        name = alb["LoadBalancerName"]
        print(f"=== ALB: {name} ===")
        # 01. ALB type and VPC membership
        ok = alb.get("VpcId") == args.vpc_id and alb.get("Type") == "application"
        statuses.append(emit(1, "PASS" if ok else "FAIL",
                             f"ALB VPC/type: VPC={alb.get('VpcId')} type={alb.get('Type')}"))

        alb_sgs = set(alb.get("SecurityGroups", []))
        # 02. ALB security groups attached and belong to the VPC
        sg_details = []
        if alb_sgs:
            for sg_id in sorted(alb_sgs):
                sg_details.extend(ec2.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"])
        valid_alb_sgs = bool(sg_details) and all(sg.get("VpcId") == args.vpc_id for sg in sg_details)
        statuses.append(emit(2, "PASS" if valid_alb_sgs else "FAIL",
                             f"ALB SG attachment: SGs={sorted(alb_sgs)} VPC-match={valid_alb_sgs}"))

        # 03. Expected ALB listener ports and protocols, no extra listeners
        listeners = []
        for page in elb.get_paginator("describe_listeners").paginate(
            LoadBalancerArn=alb["LoadBalancerArn"]
        ):
            listeners.extend(page.get("Listeners", []))
        actual_listeners = {(x["Protocol"], x["Port"]) for x in listeners}
        listener_ok = actual_listeners == EXPECTED_LISTENERS
        statuses.append(emit(3, "PASS" if listener_ok else "FAIL",
                             f"ALB listeners: actual={sorted(actual_listeners)} expected={sorted(EXPECTED_LISTENERS)}"))

        tgs = []
        for page in elb.get_paginator("describe_target_groups").paginate(
            LoadBalancerArn=alb["LoadBalancerArn"]
        ):
            tgs.extend(page.get("TargetGroups", []))
        web_tgs = [tg for tg in tgs if tg.get("TargetType") == "instance" and tg.get("Port") == args.web_port]
        targets = []
        for tg in web_tgs:
            for target in elb.describe_target_health(
                TargetGroupArn=tg["TargetGroupArn"]
            ).get("TargetHealthDescriptions", []):
                targets.append((tg, target))

        instance_ids = sorted({target["Target"]["Id"] for _, target in targets})
        instances = {}
        if instance_ids:
            for page in ec2.get_paginator("describe_instances").paginate(InstanceIds=instance_ids):
                for reservation in page.get("Reservations", []):
                    for inst in reservation.get("Instances", []):
                        instances[inst["InstanceId"]] = inst

        # 04. Web service ingress: every matching TCP port rule must reference an ALB SG
        # exactly, not a public CIDR / other SG / wider port range.
        ingress_findings = []
        authorized = 0
        for tg, target in targets:
            iid = target["Target"]["Id"]
            target_port = target["Target"].get("Port", tg["Port"])
            if target_port != args.web_port or iid not in instances:
                ingress_findings.append(f"{iid}: unexpected target port or missing instance")
                continue
            for sg in instances[iid].get("SecurityGroups", []):
                for rule in inbound_rules(ec2, sg["GroupId"], cache):
                    if not covers_tcp(rule, target_port):
                        continue
                    ref = (rule.get("ReferencedGroupInfo") or {}).get("GroupId")
                    if exact_tcp(rule, target_port) and ref in alb_sgs:
                        authorized += 1
                    else:
                        ingress_findings.append(
                            f"{iid}/{sg['GroupId']}: protocol={rule.get('IpProtocol')} "
                            f"ports={rule.get('FromPort')}-{rule.get('ToPort')} source={source(rule)}"
                        )
        if not targets:
            st04 = "REVIEW"
        else:
            st04 = "PASS" if authorized >= len(targets) and not ingress_findings else "FAIL"
        statuses.append(emit(4, st04,
                             f"Web TCP/{args.web_port} restricted to ALB SG: "
                             f"approved-rules={authorized} unexpected={ingress_findings}"))

        # 05. The actual registered web EC2 instances have SGs attached in the VPC
        # and at least one attached SG contains the expected ALB SG reference rule.
        missing_or_invalid = []
        for tg, target in targets:
            iid = target["Target"]["Id"]
            ins = instances.get(iid)
            if not ins or ins.get("VpcId") != args.vpc_id or not ins.get("SecurityGroups"):
                missing_or_invalid.append(iid)
                continue
            matching = any(
                exact_tcp(rule, args.web_port) and
                (rule.get("ReferencedGroupInfo") or {}).get("GroupId") in alb_sgs
                for sg in ins["SecurityGroups"]
                for rule in inbound_rules(ec2, sg["GroupId"], cache)
            )
            if not matching:
                missing_or_invalid.append(iid)
        if not targets:
            st05 = "REVIEW"
        else:
            st05 = "PASS" if not missing_or_invalid else "FAIL"
        statuses.append(emit(5, st05,
                             f"Web EC2 SG attachment and ALB reference: "
                             f"instances={instance_ids} invalid={missing_or_invalid}"))

        # 06. Web target group target(s) are healthy on the expected backend port
        healthy = [(tg["TargetGroupName"], target["Target"].get("Port", tg["Port"]),
                    target["TargetHealth"].get("State")) for tg, target in targets]
        if not targets:
            st06 = "REVIEW"
        else:
            st06 = "PASS" if all(p == args.web_port and state == "healthy"
                                  for _, p, state in healthy) else "FAIL"
        statuses.append(emit(6, st06, f"ALB target health: {healthy}"))
        for row in ROWS[-6:]:
            row["resource"] = name
        print()

    counts = Counter(statuses)
    print(f"SUMMARY: PASS={counts['PASS']} FAIL={counts['FAIL']} REVIEW={counts['REVIEW']}")
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    filename = output_dir / f"N07_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S_UTC')}.csv"
    with filename.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["check_id", "status", "resource", "details"])
        writer.writeheader()
        writer.writerows(ROWS)
    print(f"CSV saved: {filename}")
    print("NOTE: Configuration only. Actual reachability, ALB egress, routing and TLS validity need separate tests.")
    return 1 if counts["FAIL"] else (2 if counts["REVIEW"] else 0)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ClientError, BotoCoreError) as exc:
        print(f"AWS query error: {exc}")
        raise SystemExit(3)
