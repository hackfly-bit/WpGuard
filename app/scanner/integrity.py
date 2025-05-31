"""
File integrity checker - compares current state with baseline
"""
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from app.scanner.baseline import BaselineSnapshot
from app.models.findings import Finding, FindingType, RiskLevel

class IntegrityChecker:
    """Handles file integrity checking against baseline snapshots"""
    
    def __init__(self, scan_id: str):
        self.scan_id = scan_id
        self.baseline = BaselineSnapshot(scan_id)
    
    async def compare_with_snapshot(self, current_dir: Path, baseline_snapshot: Optional[Dict] = None) -> List[Finding]:
        """
        Compare current directory state with baseline snapshot
        
        Args:
            current_dir: Current directory to scan
            baseline_snapshot: Optional baseline snapshot, will load if not provided
            
        Returns:
            List of findings
        """
        if baseline_snapshot is None:
            baseline_snapshot = await self.baseline.load_snapshot()
            if baseline_snapshot is None:
                raise ValueError(f"No baseline snapshot found for scan_id: {self.scan_id}")
        
        findings = []
        
        # Get current state
        current_snapshot = await self.baseline.generate_snapshot(current_dir)
        current_files = current_snapshot["files"]
        baseline_files = baseline_snapshot["files"]
        
        # Find new files
        new_files = set(current_files.keys()) - set(baseline_files.keys())
        for file_path in new_files:
            findings.append(Finding(
                file_path=file_path,
                finding_type=FindingType.NEW_FILE,
                risk_level=self._assess_new_file_risk(file_path),
                description=f"New file detected: {file_path}",
                new_hash=current_files[file_path]["hash"],
                new_modified=datetime.fromisoformat(current_files[file_path]["modified"])
            ))
        
        # Find deleted files
        deleted_files = set(baseline_files.keys()) - set(current_files.keys())
        for file_path in deleted_files:
            findings.append(Finding(
                file_path=file_path,
                finding_type=FindingType.DELETED_FILE,
                risk_level=self._assess_deleted_file_risk(file_path),
                description=f"File deleted: {file_path}",
                old_hash=baseline_files[file_path]["hash"],
                old_modified=datetime.fromisoformat(baseline_files[file_path]["modified"])
            ))
        
        # Find changed files
        common_files = set(current_files.keys()) & set(baseline_files.keys())
        for file_path in common_files:
            current_info = current_files[file_path]
            baseline_info = baseline_files[file_path]
            
            # Check if file has changed
            if current_info["hash"] != baseline_info["hash"]:
                findings.append(Finding(
                    file_path=file_path,
                    finding_type=FindingType.CHANGED_FILE,
                    risk_level=self._assess_changed_file_risk(file_path),
                    description=f"File modified: {file_path}",
                    old_hash=baseline_info["hash"],
                    new_hash=current_info["hash"],
                    old_modified=datetime.fromisoformat(baseline_info["modified"]),
                    new_modified=datetime.fromisoformat(current_info["modified"])
                ))
        
        return findings
    
    def _assess_new_file_risk(self, file_path: str) -> RiskLevel:
        """Assess risk level for new files"""
        file_path_lower = file_path.lower()
        
        # High risk file locations and patterns
        high_risk_patterns = [
            '.htaccess',
            'wp-config.php',
            '/wp-admin/',
            '/wp-includes/',
            '.php',
            'shell',
            'backdoor',
            'malware'
        ]
        
        # Critical locations
        if any(pattern in file_path_lower for pattern in ['.htaccess', 'wp-config.php']):
            return RiskLevel.CRITICAL
        
        # WordPress core directories
        if any(pattern in file_path_lower for pattern in ['/wp-admin/', '/wp-includes/']):
            return RiskLevel.HIGH
        
        # PHP files in uploads or unusual locations
        if file_path_lower.endswith('.php'):
            if any(pattern in file_path_lower for pattern in ['/uploads/', '/cache/', '/tmp/']):
                return RiskLevel.HIGH
            return RiskLevel.MEDIUM
        
        return RiskLevel.LOW
    
    def _assess_deleted_file_risk(self, file_path: str) -> RiskLevel:
        """Assess risk level for deleted files"""
        file_path_lower = file_path.lower()
        
        # Critical system files
        if any(pattern in file_path_lower for pattern in ['wp-config.php', '.htaccess']):
            return RiskLevel.CRITICAL
        
        # WordPress core files
        if any(pattern in file_path_lower for pattern in ['/wp-admin/', '/wp-includes/']):
            return RiskLevel.HIGH
        
        return RiskLevel.MEDIUM
    
    def _assess_changed_file_risk(self, file_path: str) -> RiskLevel:
        """Assess risk level for changed files"""
        file_path_lower = file_path.lower()
        
        # Critical configuration files
        if any(pattern in file_path_lower for pattern in ['wp-config.php', '.htaccess']):
            return RiskLevel.CRITICAL
        
        # WordPress core files
        if any(pattern in file_path_lower for pattern in ['/wp-admin/', '/wp-includes/']):
            return RiskLevel.HIGH
        
        # Theme and plugin files
        if any(pattern in file_path_lower for pattern in ['/themes/', '/plugins/']):
            return RiskLevel.MEDIUM
        
        return RiskLevel.LOW
    
    async def get_integrity_summary(self, findings: List[Finding]) -> Dict[str, Any]:
        """Generate summary of integrity check results"""
        summary = {
            "total_findings": len(findings),
            "new_files": 0,
            "changed_files": 0,
            "deleted_files": 0,
            "risk_breakdown": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0
            }
        }
        
        for finding in findings:
            # Count by type
            if finding.finding_type == FindingType.NEW_FILE:
                summary["new_files"] += 1
            elif finding.finding_type == FindingType.CHANGED_FILE:
                summary["changed_files"] += 1
            elif finding.finding_type == FindingType.DELETED_FILE:
                summary["deleted_files"] += 1
            
            # Count by risk level
            summary["risk_breakdown"][finding.risk_level.value] += 1
        
        return summary

# Utility functions
async def check_file_integrity(scan_id: str, current_dir: Path) -> Tuple[List[Finding], Dict[str, Any]]:
    """
    Convenience function to check file integrity
    
    Returns:
        Tuple of (findings, summary)
    """
    checker = IntegrityChecker(scan_id)
    findings = await checker.compare_with_snapshot(current_dir)
    summary = await checker.get_integrity_summary(findings)
    
    return findings, summary
