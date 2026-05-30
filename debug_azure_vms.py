#!/usr/bin/env python3
"""
Debug script to investigate Azure VM query parameters and find the 109 VMs without sensor
"""

import os
import sys
from dotenv import load_dotenv
from falconpy import CloudSecurityAssets

# Load environment variables
load_dotenv()

def test_azure_vm_queries():
    """Test different query parameters to find Azure VMs"""

    # Initialize the API client
    client_id = os.environ.get("FALCON_CLIENT_ID")
    client_secret = os.environ.get("FALCON_CLIENT_SECRET")

    if not client_id or not client_secret:
        print("Error: FALCON_CLIENT_ID and FALCON_CLIENT_SECRET must be set")
        return

    from falconpy import OAuth2
    auth = OAuth2(
        client_id=client_id,
        client_secret=client_secret,
        base_url=os.environ.get("FALCON_BASE_URL", "https://api.crowdstrike.com"),
    )
    csa = CloudSecurityAssets(auth_object=auth)

    print("🔍 Testing different Azure VM query parameters...")
    print("=" * 60)

    # Test different filter combinations
    test_filters = [
        ("Current tool filter", "managed_by:'Unmanaged'+cloud_provider:'azure'+instance_state:'running'"),
        ("Azure without managed_by", "cloud_provider:'azure'+instance_state:'running'"),
        ("Azure all states", "cloud_provider:'azure'"),
        ("Azure without sensor", "cloud_provider:'azure'+sensor_status:'Not Installed'"),
        ("Azure no sensor coverage", "cloud_provider:'azure'+sensor_coverage:'No'"),
        ("Azure sensor false", "cloud_provider:'azure'+sensor_installed:'false'"),
        ("Azure managed Crowdstrike", "cloud_provider:'azure'+managed_by:'CrowdStrike'"),
        ("Azure NOT CrowdStrike managed", "cloud_provider:'azure'+managed_by!:'CrowdStrike'"),
    ]

    for description, filter_str in test_filters:
        print(f"\n📊 {description}")
        print(f"   Filter: {filter_str}")

        try:
            # Step 1: Query for asset IDs
            r = csa.query_assets(filter=filter_str, limit=10)
            if r["status_code"] == 200:
                ids = r.get("body", {}).get("resources", [])
                print(f"   ✅ Found: {len(ids)} asset IDs")

                if ids:
                    # Step 2: Get asset details
                    r2 = csa.get_assets(ids=ids)
                    if r2["status_code"] == 200:
                        assets = r2.get("body", {}).get("resources", [])
                        print(f"   📋 Retrieved: {len(assets)} asset details")

                        # Show details of first few assets
                        for i, asset in enumerate(assets[:3]):
                            asset_name = asset.get("asset_name", "N/A")
                            managed_by = asset.get("managed_by", "N/A")
                            sensor_status = asset.get("sensor_status", "N/A")
                            instance_state = asset.get("instance_state", "N/A")
                            asset_type = asset.get("asset_type", "N/A")
                            print(f"      {i+1}. {asset_name} | type:{asset_type} | managed_by:{managed_by} | sensor:{sensor_status} | state:{instance_state}")
                    else:
                        print(f"   ❌ get_assets Error {r2['status_code']}: {r2.get('body', {}).get('errors', 'Unknown error')}")
                else:
                    print("   📋 No assets match this filter")
            else:
                print(f"   ❌ query_assets Error {r['status_code']}: {r.get('body', {}).get('errors', 'Unknown error')}")

        except Exception as e:
            print(f"   ❌ Exception: {e}")

    print(f"\n" + "=" * 60)
    print("🎯 Recommendations based on findings:")
    print("1. Check which filter returns 109 VMs (matching Asset Explorer)")
    print("2. Compare 'sensor_status' vs 'managed_by' fields")
    print("3. Consider VMs in different states (not just 'running')")
    print("4. Look for VMs managed by 'CrowdStrike' vs 'Unmanaged'")

if __name__ == "__main__":
    test_azure_vm_queries()