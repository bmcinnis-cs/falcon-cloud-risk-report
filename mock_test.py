#!/usr/bin/env python3
"""
Mock test script that generates sample data to test the PDF report generation
for AWS, Azure, and GCP without requiring actual CrowdStrike API credentials.
"""

import sys
import os
sys.path.insert(0, '.')

# Mock the FalconPy modules before importing our script
import unittest.mock

def create_mock_data():
    """Create sample data structures for testing"""

    # Mock risks data (with correct API structure)
    risks = [
        {
            'rule_name': 'S3 Bucket Publicly Accessible',
            'rule_description': 'S3 bucket allows public read access which may expose sensitive data',
            'severity': 'High',
            'status': 'Open',
            'cloud_provider': 'aws',
            'asset_name': 'example-bucket',
            'asset_type': 's3',
            'asset_region': 'us-east-1',
            'account_name': 'Production Account',
            'account_id': '123456789012',
            'service_category': 'Storage',
            'first_seen': '2026-05-20T10:30:00Z',
            'last_seen': '2026-05-30T09:15:00Z',
            'risk_factors': [
                {'factor': 'Public Access', 'severity': 'High'},
                {'factor': 'Contains PII', 'severity': 'Medium'}
            ]
        },
        {
            'rule_name': 'Azure Storage Account HTTP Traffic',
            'rule_description': 'Storage account allows unencrypted HTTP traffic',
            'severity': 'High',
            'status': 'Open',
            'cloud_provider': 'azure',
            'asset_name': 'storageaccount123',
            'asset_type': 'storage_account',
            'asset_region': 'eastus',
            'account_name': 'Azure Subscription',
            'account_id': 'sub-abc-123',
            'service_category': 'Storage',
            'first_seen': '2026-05-18T14:20:00Z',
            'last_seen': '2026-05-30T08:45:00Z',
            'risk_factors': [
                {'factor': 'Unencrypted Traffic', 'severity': 'High'}
            ]
        },
        {
            'rule_name': 'GCP Cloud Storage Public Bucket',
            'rule_description': 'Cloud Storage bucket configured with public access',
            'severity': 'Critical',
            'status': 'Open',
            'cloud_provider': 'gcp',
            'asset_name': 'example-gcp-bucket',
            'asset_type': 'storage_bucket',
            'asset_region': 'us-central1',
            'account_name': 'GCP Project',
            'account_id': 'project-456',
            'service_category': 'Storage',
            'first_seen': '2026-05-15T16:00:00Z',
            'last_seen': '2026-05-30T10:00:00Z',
            'risk_factors': [
                {'factor': 'Public Access', 'severity': 'Critical'},
                {'factor': 'No Access Logs', 'severity': 'Medium'}
            ]
        }
    ]

    # Mock IOAs
    ioas = [
        {
            'id': 'ioa-001',
            'description': 'Suspicious API activity detected',
            'severity': 'Medium',
            'cloud_provider': 'aws'
        }
    ]

    # Mock VM data
    vm_data = {
        'AWS': [{'instance_id': 'i-1234567', 'state': 'running'}],
        'Azure': [{'vm_name': 'vm-test-001', 'state': 'running'}],
        'GCP': [{'instance_name': 'instance-001', 'state': 'running'}]
    }

    # Mock AI packages (with correct structure)
    ai_packages = [
        {
            'package_name_version': 'tensorflow==2.8.0',
            'type': 'python',
            'all_images': 5,
            'running_images': 3,
            'images': ['tensorflow/tensorflow:2.8.0', 'custom/ml-model:latest'],
            'critical_vulnerabilities': [
                {
                    'cve_id': 'CVE-2023-25659',
                    'severity': 'Critical',
                    'description': 'Buffer overflow in TensorFlow',
                    'score': 9.8
                }
            ]
        },
        {
            'package_name_version': 'pytorch==1.12.0',
            'type': 'python',
            'all_images': 3,
            'running_images': 2,
            'images': ['pytorch/pytorch:1.12.0'],
            'critical_vulnerabilities': [
                {
                    'cve_id': 'CVE-2023-12345',
                    'severity': 'Critical',
                    'description': 'Remote code execution in PyTorch',
                    'score': 9.5
                }
            ]
        }
    ]

    # Mock IOMs (with correct API structure)
    ioms = [
        {
            'resource_id': 'arn:aws:s3:::example-bucket',
            'rule_name': 'S3 Bucket Encryption Not Enabled',
            'severity': 'High',
            'service': 'S3',
            'resource_type': 'aws::s3::bucket',
            'provider': 'aws',
            'account_name': 'Production Account',
            'account_id': '123456789012',
            'region': 'us-east-1',
            'description': 'S3 bucket does not have server-side encryption enabled which may expose data at rest'
        },
        {
            'resource_id': 'projects/project-456/zones/us-central1-a/instances/instance-001',
            'rule_name': 'VM OS Login Configuration Missing',
            'severity': 'Medium',
            'service': 'Compute Engine',
            'resource_type': 'compute.googleapis.com/instance',
            'provider': 'gcp',
            'account_name': 'GCP Project',
            'account_id': 'project-456',
            'region': 'us-central1',
            'description': 'Virtual machine instance lacks OS Login configuration for centralized user management'
        },
        {
            'resource_id': '/subscriptions/sub-abc-123/resourceGroups/rg-prod/providers/Microsoft.Storage/storageAccounts/storageaccount123',
            'rule_name': 'Storage Account Network Access Not Restricted',
            'severity': 'High',
            'service': 'Storage',
            'resource_type': 'microsoft.storage/storageaccounts',
            'provider': 'azure',
            'account_name': 'Azure Subscription',
            'account_id': 'sub-abc-123',
            'region': 'eastus',
            'description': 'Storage account allows access from all networks instead of restricting to specific virtual networks'
        }
    ]

    return risks, ioas, vm_data, ai_packages, ioms

def test_mock_report():
    """Test PDF generation with mock data"""

    print("🧪 Running Mock Test for Multi-Cloud Security Report")
    print("=" * 60)

    try:
        # Import after mocking
        from cloud_risks_report_pdf import build_pdf, get_default_output_filename

        # Generate mock data
        risks, ioas, vm_data, ai_packages, ioms = create_mock_data()

        # Mock configuration
        config = {
            'include_risks': True,
            'include_ioas': True,
            'include_vms': True,
            'include_ai_packages': True,
            'output_file': f"test_{get_default_output_filename()}",
            'providers': ['aws', 'azure', 'gcp'],
            'severities': ['Critical', 'High'],
            'status': 'Open'
        }

        print(f"📊 Mock Data Summary:")
        print(f"   • Cloud Risks: {len(risks)} (AWS: 1, Azure: 1, GCP: 1)")
        print(f"   • IOA Detections: {len(ioas)}")
        print(f"   • Unmanaged VMs: {sum(len(vms) for vms in vm_data.values())}")
        print(f"   • AI Package Risks: {len(ai_packages)}")
        print(f"   • Cloud IOMs: {len(ioms)}")

        # Calculate VM totals
        vm_totals = {provider: len(vms) for provider, vms in vm_data.items()}

        print(f"\n📄 Generating PDF Report: {config['output_file']}")

        # Generate the PDF
        build_pdf(risks, ioas, vm_data, ai_packages, ioms, config)

        print("✅ Mock test completed successfully!")
        print(f"📁 Report saved as: {config['output_file']}")

        return True

    except Exception as e:
        print(f"❌ Mock test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_mock_report()
    sys.exit(0 if success else 1)