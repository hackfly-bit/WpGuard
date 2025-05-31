#!/usr/bin/env python3
"""
Complete workflow test for WPGuard API
"""

import requests
import os
import time

def test_complete_workflow():
    base_url = 'http://localhost:6000/api/v1'
    
    print('=== Testing Complete Upload and Scan Workflow ===')
    print()
    
    # Test file upload
    print('1. Testing file upload:')
    zip_file_path = 'd:/WpGuard/test_wordpress_fixed.zip'
    if os.path.exists(zip_file_path):
        with open(zip_file_path, 'rb') as f:
            files = {'file': ('test_wordpress_fixed.zip', f, 'application/zip')}
            response = requests.post(f'{base_url}/upload', files=files)
        
        print('   Status:', response.status_code)
        if response.status_code == 200:
            upload_data = response.json()
            upload_id = upload_data['upload_id']
            print('   Upload ID:', upload_id)
            
            # Start scan
            print('\n2. Starting malware scan:')
            scan_response = requests.post(f'{base_url}/scan/{upload_id}')
            print('   Status:', scan_response.status_code)
            
            if scan_response.status_code == 200:
                scan_data = scan_response.json()
                scan_id = scan_data['scan_id']
                print('   Scan ID:', scan_id)
                print('   Initial status:', scan_data['status'])
                
                # Check status after a moment
                time.sleep(2)
                
                print('\n3. Checking scan status:')
                status_response = requests.get(f'{base_url}/scan/{scan_id}/status')
                print('   Status:', status_response.status_code)
                
                if status_response.status_code == 200:
                    status_data = status_response.json()
                    print('   Scan status:', status_data['status'])
                    print('   Suspicious files:', status_data['suspicious_files'])
                    
                    if status_data['status'] == 'completed':
                        print('\n4. Getting scan summary:')
                        summary_response = requests.get(f'{base_url}/summary/{scan_id}')
                        print('   Status:', summary_response.status_code)
                        
                        if summary_response.status_code == 200:
                            summary_data = summary_response.json()
                            print('   Overall risk:', summary_data['overall_risk'])
                            print('   Duration:', f"{summary_data['scan_duration']:.3f} seconds")
                            
                            print('\n5. Getting findings:')
                            findings_response = requests.get(f'{base_url}/findings/{scan_id}')
                            if findings_response.status_code == 200:
                                findings_data = findings_response.json()
                                print('   Total findings:', findings_data['total_findings'])
                                print('   High risk findings:')
                                for finding in findings_data['findings']:
                                    if finding['risk_level'] == 'high':
                                        print(f'     - {finding["finding_type"]}: {finding["description"]}')
            else:
                print('   Error:', scan_response.text)
        else:
            print('   Error:', response.text)
    else:
        print('   Error: Test file not found at', zip_file_path)
    
    print('\n=== Workflow test completed ===')

if __name__ == '__main__':
    test_complete_workflow()
