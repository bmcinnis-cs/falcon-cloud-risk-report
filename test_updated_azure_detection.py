#!/usr/bin/env python3
"""
Test the updated Azure VM detection using the new Hosts API approach
"""

import os
import sys
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def test_updated_azure_detection():
    """Test the new Azure VM detection approach"""

    # Initialize the API clients
    client_id = os.environ.get("FALCON_CLIENT_ID")
    client_secret = os.environ.get("FALCON_CLIENT_SECRET")

    if not client_id or not client_secret:
        print("Error: FALCON_CLIENT_ID and FALCON_CLIENT_SECRET must be set")
        return

    from falconpy import OAuth2, Hosts, CloudSecurityAssets

    auth = OAuth2(
        client_id=client_id,
        client_secret=client_secret,
        base_url=os.environ.get("FALCON_BASE_URL", "https://api.crowdstrike.com"),
    )

    hosts_sdk = Hosts(auth_object=auth)
    csa_sdk = CloudSecurityAssets(auth_object=auth)

    print("🧪 Testing Updated Azure VM Detection")
    print("=" * 60)

    # Import the new function from the updated script
    sys.path.insert(0, '.')
    try:
        from cloud_risks_report_pdf import fetch_cloud_vms_comprehensive

        print("📊 Testing comprehensive Azure VM detection...")
        azure_vms = fetch_cloud_vms_comprehensive(hosts_sdk, csa_sdk, 'azure')

        print(f"✅ Found {len(azure_vms)} Azure VMs")

        if azure_vms:
            print(f"\n📋 Sample Azure VMs without sensor:")
            for i, vm in enumerate(azure_vms[:5]):  # Show first 5
                hostname = vm.get('hostname', 'N/A')
                sensor = vm.get('sensor_version', 'N/A')
                platform = vm.get('platform_name', 'N/A')
                print(f"   {i+1}. {hostname} | sensor:{sensor} | platform:{platform}")

            if len(azure_vms) > 5:
                print(f"   ... and {len(azure_vms) - 5} more")
        else:
            print("   No Azure VMs found - investigating Hosts API query...")

            # Test basic Hosts API query
            try:
                print("\n🔍 Testing basic Hosts API query...")
                r = hosts_sdk.query_devices_by_filter(limit=10)
                if r["status_code"] == 200:
                    total_hosts = len(r.get("body", {}).get("resources", []))
                    print(f"   Total hosts in environment: {total_hosts}")

                    if total_hosts > 0:
                        # Get details for a few hosts
                        host_ids = r["body"]["resources"][:5]
                        r2 = hosts_sdk.get_device_details(ids=host_ids)
                        if r2["status_code"] == 200:
                            hosts_data = r2.get("body", {}).get("resources", [])
                            print(f"   Sample hosts:")
                            for host in hosts_data:
                                hostname = host.get('hostname', 'N/A')
                                platform = host.get('platform_name', 'N/A')
                                external_ip = host.get('external_ip', 'N/A')
                                print(f"      {hostname} | {platform} | {external_ip}")
                else:
                    print(f"   Error: {r['status_code']} - {r.get('body', {}).get('errors', 'Unknown error')}")
            except Exception as e:
                print(f"   Exception: {e}")

        print(f"\n" + "=" * 60)
        print("🎯 Results Summary:")
        print(f"   Azure VMs found: {len(azure_vms)}")

        if len(azure_vms) >= 109:
            print("   ✅ SUCCESS: Found >=109 VMs (matches Asset Explorer expectation)")
        elif len(azure_vms) > 0:
            print(f"   ⚠️  PARTIAL: Found {len(azure_vms)} VMs (less than expected 109)")
            print("   💡 May need to refine cloud detection logic")
        else:
            print("   ❌ ISSUE: Found 0 VMs (same as before)")
            print("   💡 Need to investigate Hosts API parameters further")

    except ImportError as e:
        print(f"❌ Error importing updated functions: {e}")
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_updated_azure_detection()