"""
Test script for WPGuard functionality
"""
import pytest
import asyncio
from pathlib import Path
from app.scanner.baseline import create_baseline_snapshot
from app.scanner.malware import scan_for_malware

@pytest.mark.asyncio
async def test_baseline_snapshot():
    """Test baseline snapshot creation"""
    # This is a basic test - in real scenarios you'd use test fixtures
    test_dir = Path("tests/fixtures/wordpress")
    if not test_dir.exists():
        pytest.skip("Test WordPress directory not found")
    
    scan_id = "test_scan_001"
    snapshot = await create_baseline_snapshot(scan_id, test_dir)
    
    assert snapshot["scan_id"] == scan_id
    assert "files" in snapshot
    assert "created_at" in snapshot

@pytest.mark.asyncio 
async def test_malware_scanner():
    """Test malware scanning functionality"""
    test_dir = Path("tests/fixtures/wordpress")
    if not test_dir.exists():
        pytest.skip("Test WordPress directory not found")
    
    findings, summary, wp_info = await scan_for_malware(test_dir)
    
    assert isinstance(findings, list)
    assert isinstance(summary, dict)
    assert isinstance(wp_info, dict)
    assert "total_suspicious_files" in summary

def test_api_endpoints():
    """Test API endpoint availability"""
    # This would typically use FastAPI TestClient
    # For now, just a placeholder
    assert True

if __name__ == "__main__":
    # Run basic tests
    print("Running WPGuard tests...")
    pytest.main([__file__, "-v"])
