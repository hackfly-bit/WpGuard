#!/usr/bin/env python3
"""
Test script for WPGuard Scheduler functionality
"""
import requests
import json
import time

BASE_URL = "http://127.0.0.1:5000/api/v1"

def test_scheduler_endpoints():
    """Test all scheduler-related endpoints"""
    
    print("🧪 Testing WPGuard Scheduler API Endpoints")
    print("=" * 50)
      # Test 1: Get all scheduled scans
    print("\n1️⃣ Testing: GET /scheduler/scans")
    try:
        response = requests.get(f"{BASE_URL}/scheduler/scans")
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            scans = response.json()
            print(f"   Active scans: {len(scans)}")
            print(f"   Response: {json.dumps(scans, indent=2)}")
        else:
            print(f"   Error: {response.text}")
    except Exception as e:
        print(f"   Exception: {e}")
    
    # Test 2: Create a scheduled FTP scan
    print("\n2️⃣ Testing: POST /scheduler/scans")
    test_scan_data = {
        "name": "test-ftp-scan",
        "scan_type": "ftp",
        "schedule_type": "interval",
        "schedule_config": {
            "hours": 1
        },
        "ftp_config": {
            "host": "test.example.com",
            "port": 21,
            "username": "testuser",
            "password": "testpass",
            "scan_path": "/public_html"
        },
        "notify_on_completion": True,
        "notify_on_threats": True,
        "notification_channels": ["email"],
        "include_malware_scan": True,
        "include_integrity_check": True,
        "enabled": True
    }
    
    try:
        response = requests.post(
            f"{BASE_URL}/scheduler/scans",
            json=test_scan_data,
            headers={"Content-Type": "application/json"}
        )
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            scan = response.json()
            print(f"   Created scan ID: {scan.get('id')}")
            print(f"   Response: {json.dumps(scan, indent=2)}")
        else:
            print(f"   Error: {response.text}")
    except Exception as e:
        print(f"   Exception: {e}")
    
    # Test 3: Get all scans again to see the new one
    print("\n3️⃣ Testing: GET /scheduler/scans (after creation)")
    try:
        response = requests.get(f"{BASE_URL}/scheduler/scans")
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            scans = response.json()
            print(f"   Active scans: {len(scans)}")
            for scan in scans:
                print(f"   - Scan: {scan.get('id')} | {scan.get('name')} | Next run: {scan.get('next_run')}")
        else:
            print(f"   Error: {response.text}")
    except Exception as e:
        print(f"   Exception: {e}")
    
    # Test 4: Test scheduler status
    print("\n4️⃣ Testing: GET /scheduler/status")
    try:
        response = requests.get(f"{BASE_URL}/scheduler/status")
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            status = response.json()
            print(f"   Scheduler running: {status.get('running')}")
            print(f"   Job count: {status.get('job_count')}")
            print(f"   Response: {json.dumps(status, indent=2)}")
        else:
            print(f"   Error: {response.text}")
    except Exception as e:
        print(f"   Exception: {e}")

def test_basic_api():
    """Test basic API endpoints to ensure server is working"""
    
    print("\n🔍 Testing Basic API Endpoints")
    print("=" * 30)
    
    # Test health check
    print("\n🏥 Testing: GET /health")
    try:
        response = requests.get(f"{BASE_URL}/health")
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            print(f"   Response: {response.json()}")
    except Exception as e:
        print(f"   Exception: {e}")
    
    # Test scan records
    print("\n📊 Testing: GET /scans")
    try:
        response = requests.get(f"{BASE_URL}/scans")
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            scans = response.json()
            print(f"   Scan records: {len(scans)}")
    except Exception as e:
        print(f"   Exception: {e}")

if __name__ == "__main__":
    print("🚀 WPGuard Scheduler Test Suite")
    print("Waiting 2 seconds for server to be ready...")
    time.sleep(2)
    
    test_basic_api()
    test_scheduler_endpoints()
    
    print("\n✅ Test completed!")
