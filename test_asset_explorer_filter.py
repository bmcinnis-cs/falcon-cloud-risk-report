#!/usr/bin/env python3
"""
Test the exact Asset Explorer filter for Azure VMs
"""

import os
import sys
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def test_asset_explorer_filter():
    """Test the exact Asset Explorer Azure VM filter"""

    from falconpy import OAuth2, CloudSecurityAssets

    auth = OAuth2(
        client_id=os.environ.get("FALCON_CLIENT_ID"),
        client_secret=os.environ.get("FALCON_CLIENT_SECRET"),
        base_url=os.environ.get("FALCON_BASE_URL", "https://api.crowdstrike.com"),
    )

    csa = CloudSecurityAssets(auth_object=auth)

    print("🎯 Testing Exact Asset Explorer Filter")
    print("=" * 60)
    print("Filter: active:'true'+cloud_provider:'azure'+resource_type_name:'Virtual Machines'+managed_by:'Unmanaged'")
    print("=" * 60)

    # Import the fetch function from the updated script
    sys.path.insert(0, '.')
    try:
        from cloud_risks_report_pdf import fetch_unmanaged_vms

        # Use exact Asset Explorer filter
        asset_explorer_filter = "active:'true'+cloud_provider:'azure'+resource_type_name:'Virtual Machines'+managed_by:'Unmanaged'"

        print("📊 Testing exact Asset Explorer filter...")
        azure_vms = fetch_unmanaged_vms(csa, asset_explorer_filter)

        print(f"\n✅ Results:")
        print(f"   Total Azure VMs found: {len(azure_vms)}")
        print(f"   Target from Asset Explorer: 109")
        print(f"   Difference: {abs(len(azure_vms) - 109)}")

        # Show samples
        if azure_vms:
            print(f"\n📋 Sample Azure Virtual Machines (showing up to 10):")
            for i, vm in enumerate(azure_vms[:10]):
                resource_id = vm.get('resource_id', 'N/A')
                account_id = vm.get('account_id', 'N/A')
                asset_name = vm.get('asset_name', 'N/A')
                print(f"   {i+1}. {asset_name}")
                print(f"       Resource ID: {resource_id}")
                print(f"       Account ID: {account_id}")
                print()

        # Accuracy check
        if len(azure_vms) == 109:
            print("🎉 PERFECT MATCH: Found exactly 109 Azure VMs!")
        elif abs(len(azure_vms) - 109) <= 5:
            print(f"✅ CLOSE MATCH: Within 5 VMs of target (difference: {abs(len(azure_vms) - 109)})")
        else:
            print(f"⚠️  NEEDS INVESTIGATION: Significant difference ({abs(len(azure_vms) - 109)} VMs)")

    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_asset_explorer_filter()