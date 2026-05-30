#!/usr/bin/env python3
"""
Test script to demonstrate CrowdStrike Falcon Cloud Security Report functionality
for AWS, Azure, and GCP providers.
"""

import sys
import os
from datetime import datetime

def print_header(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")

def print_section(section, items):
    print(f"\n📋 {section}:")
    for item in items:
        print(f"   ✓ {item}")

def main():
    print_header("FALCON CLOUD SECURITY REPORT - TEST CONFIGURATION")

    print("\n🕒 Test initiated at:", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    # Test 1: AWS Configuration
    print_header("TEST 1: AWS CLOUD PROVIDER")
    print("🔧 Configuration:")
    print("   • Provider: AWS")
    print("   • Include: Cloud Risks, IOA Detections, Unmanaged VMs, AI Packages, IOMs")
    print("   • Risk Severities: Critical, High")
    print("   • Status: Open")

    print_section("AWS Services to be Scanned", [
        "EC2 Instances (running unmanaged instances)",
        "S3 Buckets (storage misconfigurations)",
        "IAM Policies and Roles (identity risks)",
        "Security Groups (networking vulnerabilities)",
        "VPC Configuration (network security)",
        "Lambda Functions (serverless risks)",
        "RDS Databases (data security)",
        "EKS/ECS Containers (container security)",
        "SageMaker/Bedrock AI Services (AI package vulnerabilities)",
        "KMS/Secrets Manager (encryption & secrets)"
    ])

    print_section("AWS IOM Categories", [
        "compute: EC2 instances, volumes, images, snapshots",
        "networking: Security groups, VPCs, subnets, load balancers",
        "iam: IAM users, roles, policies, access keys",
        "storage: S3 buckets, encryption, access policies",
        "database: RDS instances, security configurations",
        "containers: ECR repositories, EKS clusters, ECS tasks",
        "serverless: Lambda functions, EventBridge rules",
        "ai: SageMaker models, Bedrock configurations",
        "secrets: KMS keys, Secrets Manager secrets",
        "account: CloudTrail logs, CloudFormation stacks"
    ])

    # Test 2: Azure Configuration
    print_header("TEST 2: AZURE CLOUD PROVIDER")
    print("🔧 Configuration:")
    print("   • Provider: Azure")
    print("   • Include: Cloud Risks, IOA Detections, Unmanaged VMs, AI Packages, IOMs")
    print("   • Risk Severities: Critical, High")
    print("   • Status: Open")

    print_section("Azure Services to be Scanned", [
        "Virtual Machines (running unmanaged instances)",
        "Storage Accounts (blob storage security)",
        "Azure AD/Entra ID (identity and access)",
        "Network Security Groups (firewall rules)",
        "Virtual Networks (network configurations)",
        "Azure Functions (serverless applications)",
        "SQL Databases (data protection)",
        "Container Instances/AKS (container security)",
        "Cognitive Services/ML (AI vulnerabilities)",
        "Key Vault (secrets and encryption)"
    ])

    print_section("Azure Resource Types", [
        "Microsoft.Compute/virtualMachines",
        "Microsoft.Storage/storageAccounts",
        "Microsoft.Network/networkSecurityGroups",
        "Microsoft.Network/virtualNetworks",
        "Microsoft.Sql/servers and databases",
        "Microsoft.ContainerService/clusters",
        "Microsoft.Web/sites (App Services)",
        "Microsoft.CognitiveServices accounts",
        "Microsoft.KeyVault/vaults",
        "Microsoft.ManagedIdentity resources"
    ])

    # Test 3: GCP Configuration
    print_header("TEST 3: GCP CLOUD PROVIDER")
    print("🔧 Configuration:")
    print("   • Provider: GCP")
    print("   • Include: Cloud Risks, IOA Detections, Unmanaged VMs, AI Packages, IOMs")
    print("   • Risk Severities: Critical, High")
    print("   • Status: Open")

    print_section("GCP Services to be Scanned", [
        "Compute Engine Instances (VM security)",
        "Cloud Storage Buckets (data access controls)",
        "Cloud IAM (identity and permissions)",
        "VPC Firewall Rules (network security)",
        "Cloud SQL Instances (database protection)",
        "Cloud Functions (serverless security)",
        "GKE Clusters (Kubernetes security)",
        "AI Platform Services (ML vulnerabilities)",
        "Cloud KMS (key management)",
        "Pub/Sub Topics (messaging security)"
    ])

    print_section("GCP Resource Types", [
        "compute.googleapis.com/instance",
        "storage.googleapis.com/bucket",
        "compute.googleapis.com/firewall",
        "compute.googleapis.com/network",
        "sqladmin.googleapis.com/instance",
        "container.googleapis.com/cluster",
        "cloudfunctions.googleapis.com/function",
        "aiplatform.googleapis.com resources",
        "secretmanager.googleapis.com/secret",
        "pubsub.googleapis.com/topic"
    ])

    # Multi-Cloud Test
    print_header("TEST 4: MULTI-CLOUD CONFIGURATION")
    print("🔧 Configuration:")
    print("   • Provider: ALL (AWS + Azure + GCP)")
    print("   • Include: All sections enabled")
    print("   • Risk Severities: Critical, High, Medium")
    print("   • Status: Open")

    print_section("Cross-Cloud Security Analysis", [
        "Unified security posture across all cloud providers",
        "Consistent policy enforcement",
        "Multi-cloud identity federation risks",
        "Cross-platform container security (EKS, AKS, GKE)",
        "Hybrid cloud networking vulnerabilities",
        "Cloud-to-cloud data transfer security",
        "Centralized secret management across clouds",
        "Multi-cloud AI/ML service vulnerabilities"
    ])

    # Expected Output
    print_header("EXPECTED PDF REPORT STRUCTURE")

    print_section("Report Sections", [
        "Cover Page - with generation timestamp",
        "Executive Summary - risk counts by provider",
        "AWS Cloud Risks - High/Critical findings",
        "Azure Cloud Risks - High/Critical findings",
        "GCP Cloud Risks - High/Critical findings",
        "Cross-Cloud IOA Detections",
        "Unmanaged VM Summary (by provider)",
        "AI Package Vulnerabilities (Critical CVEs)",
        "Cloud Service IOMs (Infrastructure Misconfigurations)",
        "Remediation Links - Deep links to Falcon console"
    ])

    # Test Commands
    print_header("TEST EXECUTION COMMANDS")

    test_commands = [
        "# Test 1: AWS Only",
        "python cloud_risks_report_pdf.py --interactive",
        "# Select: Y,Y,Y,Y -> High -> Open -> aws -> all -> Critical -> AWS -> ai,compute,storage",
        "",
        "# Test 2: Azure Only",
        "python cloud_risks_report_pdf.py --interactive",
        "# Select: Y,Y,Y,Y -> High -> Open -> azure -> all -> Critical -> Azure -> ai,compute,storage",
        "",
        "# Test 3: GCP Only",
        "python cloud_risks_report_pdf.py --interactive",
        "# Select: Y,Y,Y,Y -> High -> Open -> gcp -> all -> Critical -> GCP -> ai,compute,storage",
        "",
        "# Test 4: Multi-Cloud",
        "python cloud_risks_report_pdf.py --interactive",
        "# Select: Y,Y,Y,Y -> Critical,High,Medium -> Open -> all -> all -> Critical -> AWS,Azure,GCP -> all"
    ]

    for cmd in test_commands:
        if cmd.startswith("#"):
            print(f"\n💡 {cmd[2:]}")
        elif cmd:
            print(f"   $ {cmd}")

    print_header("AUTHENTICATION REQUIREMENTS")

    print_section("Required Environment Variables", [
        "FALCON_CLIENT_ID - CrowdStrike API client ID",
        "FALCON_CLIENT_SECRET - CrowdStrike API client secret",
        "FALCON_BASE_URL - CrowdStrike API base URL (optional)",
        "Or use .env file in project directory"
    ])

    print_section("Falcon API Scopes Needed", [
        "Cloud Security: Read",
        "Cloud Security Assets: Read",
        "Alerts: Read",
        "Container Security: Read",
        "Detection: Read"
    ])

    print("\n✅ Test configuration complete!")
    print("🔑 Set up CrowdStrike Falcon API credentials to run actual tests")
    print("📄 Each test will generate a timestamped PDF report")

    return True

if __name__ == "__main__":
    main()