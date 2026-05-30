#!/usr/bin/env python3
"""
Enhanced Azure VM investigation - check different asset types and approaches
"""

import os
import sys
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def investigate_azure_assets():
    """Investigate Azure assets more thoroughly"""

    # Initialize the API client
    client_id = os.environ.get("FALCON_CLIENT_ID")
    client_secret = os.environ.get("FALCON_CLIENT_SECRET")

    if not client_id or not client_secret:
        print("Error: FALCON_CLIENT_ID and FALCON_CLIENT_SECRET must be set")
        return

    from falconpy import OAuth2, CloudSecurityAssets
    auth = OAuth2(
        client_id=client_id,
        client_secret=client_secret,
        base_url=os.environ.get("FALCON_BASE_URL", "https://api.crowdstrike.com"),
    )
    csa = CloudSecurityAssets(auth_object=auth)

    print("🔍 Enhanced Azure asset investigation...")
    print("=" * 60)

    # Test 1: Get a larger sample of Azure assets
    print(f"\n📊 Test 1: Get more Azure assets (limit 100)")
    try:
        r = csa.query_assets(filter="cloud_provider:'azure'", limit=100)
        if r["status_code"] == 200:
            ids = r.get("body", {}).get("resources", [])
            print(f"   ✅ Found: {len(ids)} total Azure asset IDs")

            if ids:
                # Get details for first 20 assets
                sample_size = min(20, len(ids))
                r2 = csa.get_assets(ids=ids[:sample_size])
                if r2["status_code"] == 200:
                    assets = r2.get("body", {}).get("resources", [])
                    print(f"   📋 Retrieved details for {len(assets)} assets:")

                    # Analyze the asset types and characteristics
                    asset_types = {}
                    managed_by_values = {}
                    instance_states = {}

                    for asset in assets:
                        # Asset type
                        asset_type = asset.get("asset_type") or asset.get("resource_type") or "unknown"
                        asset_types[asset_type] = asset_types.get(asset_type, 0) + 1

                        # Managed by
                        managed_by = asset.get("managed_by", "unknown")
                        managed_by_values[managed_by] = managed_by_values.get(managed_by, 0) + 1

                        # Instance state
                        instance_state = asset.get("instance_state", "unknown")
                        instance_states[instance_state] = instance_states.get(instance_state, 0) + 1

                        # Show first few assets in detail
                        if len(asset_types) <= 5:
                            asset_name = asset.get("asset_name") or asset.get("resource_name", "N/A")
                            resource_id = asset.get("resource_id", "N/A")
                            print(f"      Sample: {asset_name} | type:{asset_type} | managed_by:{managed_by} | state:{instance_state}")
                            print(f"              resource_id: {resource_id}")

                    print(f"\n   📈 Asset Type Distribution:")
                    for asset_type, count in sorted(asset_types.items()):
                        print(f"      {asset_type}: {count}")

                    print(f"\n   🏷️ Managed By Distribution:")
                    for managed_by, count in sorted(managed_by_values.items()):
                        print(f"      {managed_by}: {count}")

                    print(f"\n   ⚡ Instance State Distribution:")
                    for state, count in sorted(instance_states.items()):
                        print(f"      {state}: {count}")

        else:
            print(f"   ❌ Error {r['status_code']}: {r.get('body', {}).get('errors', 'Unknown error')}")
    except Exception as e:
        print(f"   ❌ Exception: {e}")

    # Test 2: Look for VM-specific resources
    print(f"\n📊 Test 2: Look for Azure VM-specific resource types")
    vm_filters = [
        ("Virtual Machines", "cloud_provider:'azure'+resource_type:'Microsoft.Compute/virtualMachines'"),
        ("All Compute", "cloud_provider:'azure'+service:'Compute'"),
        ("Running resources", "cloud_provider:'azure'+instance_state:'running'"),
        ("Stopped resources", "cloud_provider:'azure'+instance_state:'stopped'"),
        ("All instance states", "cloud_provider:'azure'+instance_state:*"),
    ]

    for description, filter_str in vm_filters:
        try:
            r = csa.query_assets(filter=filter_str, limit=20)
            if r["status_code"] == 200:
                ids = r.get("body", {}).get("resources", [])
                print(f"   {description}: {len(ids)} assets")
            else:
                print(f"   {description}: Error {r['status_code']}")
        except Exception as e:
            print(f"   {description}: Exception {e}")

    print(f"\n" + "=" * 60)
    print("🎯 Key Findings:")
    print("1. Asset Explorer 'VMs without sensor' may be from a different API endpoint")
    print("2. CloudSecurityAssets API might not include sensor installation status")
    print("3. The 109 VMs might be tracked in Endpoint Protection or Host Management APIs")
    print("4. Consider checking Host Management API for sensor status")

if __name__ == "__main__":
    investigate_azure_assets()