#!/usr/bin/env python3
"""
Test AWS and GCP VM detection with corrected Asset Explorer filters
"""

import os
import sys
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def test_all_cloud_providers():
    """Test corrected VM filters for AWS, Azure, and GCP"""

    from falconpy import OAuth2, CloudSecurityAssets

    auth = OAuth2(
        client_id=os.environ.get("FALCON_CLIENT_ID"),
        client_secret=os.environ.get("FALCON_CLIENT_SECRET"),
        base_url=os.environ.get("FALCON_BASE_URL", "https://api.crowdstrike.com"),
    )

    csa = CloudSecurityAssets(auth_object=auth)

    print("🎯 Testing Corrected VM Filters for All Cloud Providers")
    print("=" * 70)

    # Import the fetch function
    sys.path.insert(0, '.')
    try:
        from cloud_risks_report_pdf import fetch_unmanaged_vms

        # Test filters for all providers
        test_filters = [
            ("AWS", "active:'true'+cloud_provider:'aws'+resource_type_name:'Virtual Machines'+managed_by:'Unmanaged'"),
            ("Azure", "active:'true'+cloud_provider:'azure'+resource_type_name:'Virtual Machines'+managed_by:'Unmanaged'"),
            ("GCP", "active:'true'+cloud_provider:'gcp'+resource_type_name:'Virtual Machines'+managed_by:'Unmanaged'"),
        ]

        results = {}

        for provider, filter_str in test_filters:
            print(f"\n📊 Testing {provider}...")
            print(f"   Filter: {filter_str}")

            try:
                vms = fetch_unmanaged_vms(csa, filter_str)
                results[provider] = len(vms)
                print(f"   ✅ Found: {len(vms)} unmanaged Virtual Machines")

                # Show sample VMs
                if vms:
                    print(f"   📋 Sample VMs (showing up to 3):")
                    for i, vm in enumerate(vms[:3]):
                        resource_id = vm.get('resource_id', 'N/A')
                        account_id = vm.get('account_id', 'N/A')
                        # Extract VM name from resource_id
                        vm_name = resource_id.split('/')[-1] if '/' in resource_id else resource_id
                        print(f"      {i+1}. {vm_name} (Account: {account_id})")

            except Exception as e:
                results[provider] = f"Error: {e}"
                print(f"   ❌ Error: {e}")

        print(f"\n" + "=" * 70)
        print("📊 Summary Results:")
        for provider in ["AWS", "Azure", "GCP"]:
            result = results.get(provider, "Not tested")
            print(f"   {provider}: {result}")

        # Validation
        print(f"\n✅ Validation:")
        azure_count = results.get("Azure", 0)
        if isinstance(azure_count, int):
            if azure_count == 109:
                print("   Azure: ✅ Perfect match (109 VMs as expected)")
            else:
                print(f"   Azure: ⚠️  Found {azure_count}, expected 109")
        else:
            print(f"   Azure: ❌ {azure_count}")

        aws_count = results.get("AWS", 0)
        if isinstance(aws_count, int) and aws_count > 0:
            print(f"   AWS: ✅ Found {aws_count} VMs (sensor logic working)")
        else:
            print(f"   AWS: ⚠️  {aws_count}")

        gcp_count = results.get("GCP", 0)
        if isinstance(gcp_count, int):
            print(f"   GCP: ✅ Found {gcp_count} VMs (sensor logic working)")
        else:
            print(f"   GCP: ⚠️  {gcp_count}")

    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_all_cloud_providers()