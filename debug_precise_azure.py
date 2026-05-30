#!/usr/bin/env python3
"""
Precise Azure VM detection to match Asset Explorer's 109 without + 15 with sensor = 124 total
"""

import os
import sys
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def debug_precise_azure_detection():
    """Debug Azure VM detection to match Asset Explorer exactly"""

    # Initialize the API clients
    client_id = os.environ.get("FALCON_CLIENT_ID")
    client_secret = os.environ.get("FALCON_CLIENT_SECRET")

    if not client_id or not client_secret:
        print("Error: FALCON_CLIENT_ID and FALCON_CLIENT_SECRET must be set")
        return

    from falconpy import OAuth2, Hosts

    auth = OAuth2(
        client_id=client_id,
        client_secret=client_secret,
        base_url=os.environ.get("FALCON_BASE_URL", "https://api.crowdstrike.com"),
    )

    hosts_sdk = Hosts(auth_object=auth)

    print("🔍 Debugging Precise Azure VM Detection")
    print("=" * 60)
    print("Target: 109 without sensor + 15 with sensor = 124 total Azure VMs")
    print("=" * 60)

    # Get ALL hosts first and analyze what we have
    all_hosts = []
    offset = 0
    batch_size = 1000

    print("📊 Step 1: Collecting ALL host data for analysis...")
    while True:
        try:
            r = hosts_sdk.query_devices_by_filter(limit=batch_size, offset=offset)
            if r["status_code"] != 200:
                break

            batch_ids = r["body"].get("resources") or []
            if not batch_ids:
                break

            # Get detailed host information
            host_details_r = hosts_sdk.get_device_details(ids=batch_ids)
            if host_details_r["status_code"] == 200:
                hosts_data = host_details_r["body"].get("resources") or []
                all_hosts.extend(hosts_data)

            offset += len(batch_ids)
            meta = r["body"].get("meta", {})
            total = meta.get("total", 0)
            if offset >= total:
                break

        except Exception as e:
            print(f"Error: {e}")
            break

    print(f"   Total hosts collected: {len(all_hosts)}")

    # Analyze host characteristics to identify Azure VMs precisely
    print(f"\n📋 Step 2: Analyzing host characteristics...")

    # Group hosts by different characteristics
    platforms = {}
    device_types = {}
    cloud_indicators = {}
    sensor_versions = {}

    potential_azure_vms = []

    for host in all_hosts:
        hostname = host.get("hostname", "N/A")
        platform = host.get("platform_name", "N/A")
        device_type = host.get("device_type", "N/A")
        external_ip = host.get("external_ip", "")
        machine_domain = host.get("machine_domain", "")
        agent_version = host.get("agent_version", "No Sensor")

        # Count platforms
        platforms[platform] = platforms.get(platform, 0) + 1
        device_types[device_type] = device_types.get(device_type, 0) + 1

        # Look for Azure-specific indicators
        azure_indicators = []

        # Check for Azure-specific fields that might exist
        for field in host.keys():
            if 'azure' in field.lower():
                azure_indicators.append(f"{field}:{host[field]}")

        # Check hostname patterns
        hostname_lower = hostname.lower()
        if any(pattern in hostname_lower for pattern in ['azure', 'vm-', 'server-']):
            azure_indicators.append(f"hostname_pattern:{hostname}")

        # Check external IP ranges (Azure public IP ranges)
        if external_ip and any(external_ip.startswith(prefix) for prefix in [
            '20.', '40.', '52.', '13.', '104.', '168.'
        ]):
            azure_indicators.append(f"azure_ip_range:{external_ip}")

        # More precise filtering - likely Azure VMs
        is_likely_azure_vm = (
            platform == 'Windows' and
            device_type != 'Mobile' and
            len(hostname) > 3 and
            not hostname_lower.startswith('android') and
            not any(mobile_indicator in hostname_lower for mobile_indicator in ['phone', 'mobile', 'tablet']) and
            # Exclude container/k8s systems
            '/subscriptions/' not in hostname and
            not hostname.startswith('/') and
            # More specific Azure VM characteristics
            (
                any(pattern in hostname_lower for pattern in ['vm', 'server', 'win', 'ws']) or
                external_ip and any(external_ip.startswith(prefix) for prefix in ['20.', '40.', '52.', '13.', '104.']) or
                machine_domain == '' or 'azure' in machine_domain.lower()
            )
        )

        if is_likely_azure_vm or azure_indicators:
            potential_azure_vms.append({
                'hostname': hostname,
                'platform': platform,
                'device_type': device_type,
                'external_ip': external_ip,
                'machine_domain': machine_domain,
                'agent_version': agent_version,
                'azure_indicators': azure_indicators
            })

    # Display analysis
    print(f"\n🔍 Platform Distribution (top 10):")
    for platform, count in sorted(platforms.items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"   {platform}: {count}")

    print(f"\n🔍 Device Type Distribution:")
    for device_type, count in sorted(device_types.items(), key=lambda x: x[1], reverse=True):
        print(f"   {device_type}: {count}")

    # Analyze potential Azure VMs
    print(f"\n🎯 Potential Azure VMs Found: {len(potential_azure_vms)}")

    # Separate by sensor status
    with_sensor = [vm for vm in potential_azure_vms if vm['agent_version'] != 'No Sensor']
    without_sensor = [vm for vm in potential_azure_vms if vm['agent_version'] == 'No Sensor']

    print(f"   With Sensor: {len(with_sensor)} (target: 15)")
    print(f"   Without Sensor: {len(without_sensor)} (target: 109)")

    # Show samples
    if with_sensor:
        print(f"\n📋 Sample VMs WITH sensor:")
        for i, vm in enumerate(with_sensor[:5]):
            print(f"   {i+1}. {vm['hostname']} | {vm['agent_version']} | {vm['platform']} | {vm['external_ip']}")

    if without_sensor:
        print(f"\n📋 Sample VMs WITHOUT sensor:")
        for i, vm in enumerate(without_sensor[:10]):
            print(f"   {i+1}. {vm['hostname']} | {vm['platform']} | {vm['external_ip']} | indicators:{vm['azure_indicators']}")

    print(f"\n" + "=" * 60)
    print("💡 Analysis Summary:")
    print(f"   Current detection: {len(potential_azure_vms)} total Azure VMs")
    print(f"   Target: 124 total Azure VMs")
    print(f"   Gap: {abs(len(potential_azure_vms) - 124)} VMs")

    if len(potential_azure_vms) > 124:
        print("   🔧 Detection too broad - need to refine criteria")
        print("   📝 Consider: platform type, device type, hostname patterns")
    elif len(potential_azure_vms) < 124:
        print("   🔧 Detection too narrow - need to expand criteria")
        print("   📝 Consider: additional IP ranges, hostname patterns")
    else:
        print("   ✅ Detection matches target!")

if __name__ == "__main__":
    debug_precise_azure_detection()