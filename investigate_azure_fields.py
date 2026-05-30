#!/usr/bin/env python3
"""
Investigate Asset Explorer approach - check if there are Azure-specific fields
"""

import os
import sys
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def investigate_azure_fields():
    """Investigate what fields might indicate Azure VMs specifically"""

    from falconpy import OAuth2, Hosts

    auth = OAuth2(
        client_id=os.environ.get("FALCON_CLIENT_ID"),
        client_secret=os.environ.get("FALCON_CLIENT_SECRET"),
        base_url=os.environ.get("FALCON_BASE_URL", "https://api.crowdstrike.com"),
    )

    hosts_sdk = Hosts(auth_object=auth)

    print("🔍 Investigating Azure-specific fields in Hosts API")
    print("=" * 60)

    # Get a sample of hosts to examine all available fields
    r = hosts_sdk.query_devices_by_filter(limit=10)
    if r["status_code"] != 200:
        print(f"Error: {r}")
        return

    host_ids = r["body"].get("resources", [])
    if not host_ids:
        print("No hosts found")
        return

    # Get detailed information
    r2 = hosts_sdk.get_device_details(ids=host_ids)
    if r2["status_code"] != 200:
        print(f"Error: {r2}")
        return

    hosts_data = r2["body"].get("resources", [])

    print(f"📋 Examining {len(hosts_data)} sample hosts for Azure-specific fields...")

    # Collect all unique fields across all hosts
    all_fields = set()
    azure_related_fields = []

    for host in hosts_data:
        all_fields.update(host.keys())
        # Look for Azure-related field names
        for field, value in host.items():
            if 'azure' in field.lower() or (isinstance(value, str) and 'azure' in str(value).lower()):
                azure_related_fields.append((field, value))

    print(f"\n🔍 All available fields in Hosts API ({len(all_fields)} total):")
    for field in sorted(all_fields):
        print(f"   {field}")

    if azure_related_fields:
        print(f"\n🎯 Azure-related fields found:")
        for field, value in azure_related_fields:
            print(f"   {field}: {value}")
    else:
        print(f"\n⚠️  No obvious Azure-related fields found in sample")

    print(f"\n📊 Sample host data structure:")
    if hosts_data:
        sample_host = hosts_data[0]
        print(f"   Hostname: {sample_host.get('hostname')}")
        print(f"   Platform: {sample_host.get('platform_name')}")
        print(f"   Agent Version: {sample_host.get('agent_version')}")
        print(f"   External IP: {sample_host.get('external_ip')}")
        print(f"   Machine Domain: {sample_host.get('machine_domain')}")
        print(f"   Device ID: {sample_host.get('device_id')}")

        # Check for other potentially relevant fields
        potential_fields = ['cloud_provider', 'instance_id', 'vpc_id', 'subnet_id', 'resource_group',
                          'subscription_id', 'tenant_id', 'cloud_account', 'cloud_region']

        print(f"\n   Checking for cloud-related fields:")
        for field in potential_fields:
            if field in sample_host:
                print(f"     {field}: {sample_host[field]}")
            else:
                print(f"     {field}: Not present")

    print(f"\n" + "=" * 60)
    print("💡 Next Steps:")
    print("1. Asset Explorer might use CloudSecurityAssets API with different params")
    print("2. Or there might be a specific 'cloud_provider' field we're missing")
    print("3. May need to cross-reference with CloudSecurityAssets for Azure VM identification")
    print("4. Consider that 'sensor status' might be determined differently than agent_version")

if __name__ == "__main__":
    investigate_azure_fields()