#!/usr/bin/env python3
"""
Investigate sensor status determination - what makes a VM "without sensor" in Asset Explorer
"""

import os
import sys
from dotenv import load_dotenv

def investigate_sensor_status():
    """Investigate how to determine sensor status correctly"""

    from falconpy import OAuth2, Hosts

    auth = OAuth2(
        client_id=os.environ.get("FALCON_CLIENT_ID"),
        client_secret=os.environ.get("FALCON_CLIENT_SECRET"),
        base_url=os.environ.get("FALCON_BASE_URL", "https://api.crowdstrike.com"),
    )

    hosts_sdk = Hosts(auth_object=auth)

    print("🔍 Investigating Sensor Status Logic")
    print("=" * 60)

    # Query Azure hosts
    r = hosts_sdk.query_devices_by_filter(filter="service_provider:'AZURE'", limit=20)
    if r["status_code"] != 200:
        print(f"Error: {r}")
        return

    host_ids = r["body"].get("resources", [])
    if not host_ids:
        print("No Azure hosts found")
        return

    # Get detailed information
    r2 = hosts_sdk.get_device_details(ids=host_ids)
    if r2["status_code"] != 200:
        print(f"Error: {r2}")
        return

    hosts_data = r2["body"].get("resources", [])

    print(f"📋 Analyzing {len(hosts_data)} Azure hosts for sensor status patterns...")

    # Analyze sensor-related fields
    sensor_fields = {}
    for host in hosts_data:
        hostname = host.get('hostname', 'N/A')
        agent_version = host.get('agent_version', 'N/A')

        # Look for all fields that might indicate sensor status
        relevant_fields = {}
        for field, value in host.items():
            if any(term in field.lower() for term in ['agent', 'sensor', 'status', 'provision']):
                relevant_fields[field] = value

        print(f"\n🔍 Host: {hostname}")
        print(f"   agent_version: {agent_version}")

        for field, value in relevant_fields.items():
            print(f"   {field}: {value}")

            # Track field value distributions
            if field not in sensor_fields:
                sensor_fields[field] = {}
            sensor_fields[field][str(value)] = sensor_fields[field].get(str(value), 0) + 1

    print(f"\n📊 Sensor-related field distributions:")
    for field, values in sensor_fields.items():
        print(f"\n{field}:")
        for value, count in sorted(values.items(), key=lambda x: x[1], reverse=True):
            print(f"   {value}: {count}")

    print(f"\n💡 Key insights for determining 'without sensor':")
    print("1. Check if 'provision_status' field indicates sensor deployment status")
    print("2. Look for 'status' field values that indicate sensor state")
    print("3. Consider if certain agent_version values indicate 'no sensor'")
    print("4. Asset Explorer might use a different definition of 'sensor status'")

if __name__ == "__main__":
    investigate_sensor_status()