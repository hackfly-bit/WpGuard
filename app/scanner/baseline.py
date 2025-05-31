"""
Baseline snapshot system for file integrity monitoring
"""
import os
import json
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional
from app.core.config import settings

class BaselineSnapshot:
    """Handles creation and management of baseline file snapshots"""
    
    def __init__(self, scan_id: str):
        self.scan_id = scan_id
        self.snapshot_path = Path(settings.SNAPSHOTS_DIR) / f"{scan_id}.json"
    
    async def generate_snapshot(self, scan_dir: Path) -> Dict[str, Any]:
        """
        Generate baseline snapshot of all files in the scan directory
        
        Args:
            scan_dir: Path to the directory to scan
            
        Returns:
            Dictionary containing file fingerprints
        """
        snapshot = {
            "scan_id": self.scan_id,
            "created_at": datetime.utcnow().isoformat(),
            "scan_directory": str(scan_dir),
            "files": {}
        }
        
        # Recursively scan all files
        for file_path in self._get_scannable_files(scan_dir):
            try:
                file_info = await self._get_file_info(file_path)
                # Store relative path from scan directory
                rel_path = file_path.relative_to(scan_dir)
                snapshot["files"][str(rel_path)] = file_info
            except Exception as e:
                print(f"Error processing file {file_path}: {e}")
                continue
        
        # Save snapshot to disk
        await self._save_snapshot(snapshot)
        
        return snapshot
    
    def _get_scannable_files(self, scan_dir: Path):
        """Get all files that should be included in the scan"""
        for root, dirs, files in os.walk(scan_dir):
            # Skip certain directories
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['node_modules', '__pycache__']]
            
            for file in files:
                file_path = Path(root) / file
                
                # Check file extension
                if file_path.suffix.lower() in settings.SCAN_EXTENSIONS or file.startswith('.'):
                    yield file_path
    
    async def _get_file_info(self, file_path: Path) -> Dict[str, Any]:
        """Get file information including hash and metadata"""
        stat = file_path.stat()
        
        # Calculate SHA256 hash
        file_hash = await self._calculate_file_hash(file_path)
        
        return {
            "hash": file_hash,
            "size": stat.st_size,
            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "permissions": oct(stat.st_mode)[-3:],
        }
    
    async def _calculate_file_hash(self, file_path: Path) -> str:
        """Calculate SHA256 hash of a file"""
        sha256_hash = hashlib.sha256()
        
        try:
            with open(file_path, "rb") as f:
                # Read in chunks to handle large files
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)
        except Exception:
            # Return empty hash for files that can't be read
            return ""
        
        return sha256_hash.hexdigest()
    
    async def _save_snapshot(self, snapshot: Dict[str, Any]):
        """Save snapshot to JSON file"""
        os.makedirs(settings.SNAPSHOTS_DIR, exist_ok=True)
        
        with open(self.snapshot_path, 'w') as f:
            json.dump(snapshot, f, indent=2)
    
    async def load_snapshot(self) -> Optional[Dict[str, Any]]:
        """Load existing snapshot from disk"""
        if not self.snapshot_path.exists():
            return None
        
        try:
            with open(self.snapshot_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading snapshot: {e}")
            return None
    
    @staticmethod
    def get_snapshot_path(scan_id: str) -> Path:
        """Get path to snapshot file for given scan ID"""
        return Path(settings.SNAPSHOTS_DIR) / f"{scan_id}.json"
    
    @staticmethod
    def snapshot_exists(scan_id: str) -> bool:
        """Check if snapshot exists for given scan ID"""
        return BaselineSnapshot.get_snapshot_path(scan_id).exists()

# Utility functions
async def create_baseline_snapshot(scan_id: str, scan_dir: Path) -> Dict[str, Any]:
    """Create a new baseline snapshot"""
    snapshot = BaselineSnapshot(scan_id)
    return await snapshot.generate_snapshot(scan_dir)

async def load_baseline_snapshot(scan_id: str) -> Optional[Dict[str, Any]]:
    """Load an existing baseline snapshot"""
    snapshot = BaselineSnapshot(scan_id)
    return await snapshot.load_snapshot()
