#!/usr/bin/env python3
"""
Test the corrected Azure VM detection using service_provider field
"""

import os
import sys
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def test_corrected_azure_detection():
    """Test the corrected Azure VM detection approach"""

    from falconpy import OAuth2, Hosts

    auth = OAuth2(
        client_id=os.environ.get("FALCON_CLIENT_ID"),
        client_secret=os.environ.get("FALCON_CLIENT_SECRET"),
        base_url=os.environ.get("FALCON_BASE_URL", "https://api.crowdstrike.com"),
    )

    hosts_sdk = Hosts(auth_object=auth)

    print("🧪 Testing Corrected Azure VM Detection")
    print("=" * 60)
    print("Target: 109 without sensor + 15 with sensor = 124 total")
    print("=" * 60)

    # Import the corrected function
    sys.path.insert(0, '.')
    try:
        from cloud_risks_report_pdf import fetch_vms_without_sensor

        print("📊 Testing corrected Azure VM detection...")
        azure_vms = fetch_vms_without_sensor(hosts_sdk, 'azure')

        # Separate by sensor status
        with_sensor = [vm for vm in azure_vms if vm.get('has_sensor', False)]
        without_sensor = [vm for vm in azure_vms if not vm.get('has_sensor', False)]

        print(f"\n✅ Results:")
        print(f"   Total Azure VMs: {len(azure_vms)}")
        print(f"   With Sensor: {len(with_sensor)} (target: 15)")
        print(f"   Without Sensor: {len(without_sensor)} (target: 109)")

        # Check accuracy
        total_target = 124
        with_target = 15
        without_target = 109

        print(f"\n📊 Accuracy Assessment:")
        print(f"   Total VMs: {len(azure_vms)} vs {total_target} target = {abs(len(azure_vms) - total_target)} difference")
        print(f"   With Sensor: {len(with_sensor)} vs {with_target} target = {abs(len(with_sensor) - with_target)} difference")
        print(f"   Without Sensor: {len(without_sensor)} vs {without_target} target = {abs(len(without_sensor) - without_target)} difference")

        # Show samples
        if with_sensor:
            print(f"\n📋 Sample Azure VMs WITH sensor (showing up to 5):")
            for i, vm in enumerate(with_sensor[:5]):
                print(f"   {i+1}. {vm['hostname']} | {vm['sensor_version']} | {vm['platform_name']}")

        if without_sensor:
            print(f"\n📋 Sample Azure VMs WITHOUT sensor (showing up to 10):")
            for i, vm in enumerate(without_sensor[:10]):
                print(f"   {i+1}. {vm['hostname']} | {vm['platform_name']} | {vm['external_ip']}")

        # Success criteria
        is_success = (
            abs(len(azure_vms) - total_target) <= 5 and  # Within 5 VMs of total
            abs(len(without_sensor) - without_target) <= 10  # Within 10 of without-sensor target
        )

        print(f"\n" + "=" * 60)
        if is_success:
            print("🎉 SUCCESS: VM detection is now accurate!")
            print("   ✅ Matches expected Asset Explorer numbers")
        else:
            print("⚠️  NEEDS REFINEMENT: Still not matching expected numbers")
            print("   💡 May need additional filtering criteria")

    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_corrected_azure_detection()