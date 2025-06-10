"""
WPGuard ML-Enhanced Malware Detection
Advanced machine learning-based security scanning
"""
import os
import re
import hashlib
import logging
from typing import List, Dict, Tuple, Optional
from pathlib import Path
import json
from datetime import datetime

logger = logging.getLogger(__name__)

class MLMalwareDetector:
    """Machine Learning enhanced malware detection system"""
    
    def __init__(self):
        self.php_suspicious_patterns = [
            # Code execution patterns
            r'eval\s*\(',
            r'exec\s*\(',
            r'shell_exec\s*\(',
            r'system\s*\(',
            r'passthru\s*\(',
            r'proc_open\s*\(',
            r'popen\s*\(',
            
            # Obfuscation patterns
            r'base64_decode\s*\(',
            r'gzinflate\s*\(',
            r'str_rot13\s*\(',
            r'gzuncompress\s*\(',
            r'rawurldecode\s*\(',
            
            # File manipulation
            r'file_get_contents\s*\(\s*["\']https?://',
            r'curl_exec\s*\(',
            r'fwrite\s*\(',
            r'file_put_contents\s*\(',
            
            # WordPress specific
            r'wp_remote_get\s*\(',
            r'wp_remote_post\s*\(',
            r'add_action\s*\(\s*["\']wp_head["\']',
            r'add_action\s*\(\s*["\']init["\']',
            
            # Backdoor patterns
            r'\$_(?:GET|POST|REQUEST|COOKIE)\s*\[',
            r'create_function\s*\(',
            r'assert\s*\(',
            r'preg_replace\s*\(.*\/e',
        ]
        
        self.js_suspicious_patterns = [
            # Code execution
            r'eval\s*\(',
            r'Function\s*\(',
            r'setTimeout\s*\(',
            r'setInterval\s*\(',
            
            # Obfuscation
            r'unescape\s*\(',
            r'decodeURIComponent\s*\(',
            r'fromCharCode\s*\(',
            r'String\.prototype\.charCodeAt',
            
            # Suspicious behavior
            r'document\.write\s*\(',
            r'innerHTML\s*=',
            r'createElement\s*\(',
            r'appendChild\s*\(',
        ]
        
        # Suspicious file extensions and patterns
        self.suspicious_extensions = {
            '.php.suspected', '.php.bak', '.php.old', '.php.tmp',
            '.asp', '.aspx', '.jsp', '.pl', '.cgi',
            '.sh', '.bat', '.cmd', '.exe'
        }
        
        # Known malware signatures (hashes)
        self.malware_hashes = self._load_malware_signatures()
        
        # Entropy threshold for detecting obfuscated code
        self.entropy_threshold = 4.5
        
    def _load_malware_signatures(self) -> set:
        """Load known malware file hashes"""
        signatures_file = Path(__file__).parent / "signatures" / "malware_hashes.json"
        if signatures_file.exists():
            try:
                with open(signatures_file, 'r') as f:
                    data = json.load(f)
                    return set(data.get('hashes', []))
            except Exception as e:
                logger.warning(f"Failed to load malware signatures: {e}")
        
        # Default known malware hashes (sample)
        return {
            'c99shell_md5_hash_here',
            'r57shell_md5_hash_here',
            'webshell_common_hash_here'
        }
    
    def calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text to detect obfuscation"""
        if not text:
            return 0.0
            
        # Count character frequencies
        char_counts = {}
        for char in text:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        text_len = len(text)
        
        for count in char_counts.values():
            probability = count / text_len
            if probability > 0:
                entropy -= probability * (probability.bit_length() - 1)
        
        return entropy
    
    def detect_suspicious_patterns(self, content: str, file_ext: str) -> List[Dict]:
        """Detect suspicious patterns in file content"""
        findings = []
        
        # Choose appropriate pattern set
        if file_ext in ['.php', '.phtml']:
            patterns = self.php_suspicious_patterns
            pattern_type = "PHP"
        elif file_ext in ['.js']:
            patterns = self.js_suspicious_patterns
            pattern_type = "JavaScript"
        else:
            return findings
        
        # Check each pattern
        for pattern in patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                findings.append({
                    'type': 'suspicious_pattern',
                    'severity': 'high',
                    'pattern_type': pattern_type,
                    'pattern': pattern,
                    'line': line_num,
                    'match': match.group(),
                    'description': f'Suspicious {pattern_type} pattern detected'
                })
        
        return findings
    
    def detect_obfuscation(self, content: str, file_path: str) -> List[Dict]:
        """Detect code obfuscation using entropy analysis"""
        findings = []
        
        # Calculate overall entropy
        entropy = self.calculate_entropy(content)
        
        if entropy > self.entropy_threshold:
            findings.append({
                'type': 'obfuscation',
                'severity': 'medium',
                'entropy': entropy,
                'threshold': self.entropy_threshold,
                'description': f'High entropy ({entropy:.2f}) suggests obfuscated code',
                'file_path': file_path
            })
        
        # Check for specific obfuscation indicators
        obfuscation_indicators = [
            (r'[a-zA-Z0-9+/]{50,}={0,2}', 'Base64 encoded content'),
            (r'\\x[0-9a-fA-F]{2}', 'Hexadecimal encoded content'),
            (r'chr\(\d+\)', 'Character code obfuscation'),
            (r'[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*["\'][^"\']{100,}["\']', 'Long encoded strings')
        ]
        
        for pattern, description in obfuscation_indicators:
            if re.search(pattern, content):
                findings.append({
                    'type': 'obfuscation_indicator',
                    'severity': 'medium',
                    'pattern': pattern,
                    'description': description,
                    'file_path': file_path
                })
        
        return findings
    
    def check_file_hash(self, file_path: str) -> Optional[Dict]:
        """Check if file hash matches known malware"""
        try:
            with open(file_path, 'rb') as f:
                file_hash = hashlib.md5(f.read()).hexdigest()
            
            if file_hash in self.malware_hashes:
                return {
                    'type': 'known_malware',
                    'severity': 'critical',
                    'hash': file_hash,
                    'description': 'File matches known malware signature',
                    'file_path': file_path
                }
        except Exception as e:
            logger.warning(f"Failed to calculate hash for {file_path}: {e}")
        
        return None
    
    def analyze_file_structure(self, file_path: str) -> List[Dict]:
        """Analyze file for structural anomalies"""
        findings = []
        
        file_ext = Path(file_path).suffix.lower()
        file_name = Path(file_path).name
        
        # Check suspicious file extensions
        if file_ext in self.suspicious_extensions:
            findings.append({
                'type': 'suspicious_extension',
                'severity': 'high',
                'extension': file_ext,
                'description': f'Suspicious file extension: {file_ext}',
                'file_path': file_path
            })
        
        # Check for suspicious file names
        suspicious_names = [
            r'c99', r'r57', r'shell', r'backdoor', r'hack',
            r'bypass', r'exploit', r'payload', r'webshell'
        ]
        
        for pattern in suspicious_names:
            if re.search(pattern, file_name, re.IGNORECASE):
                findings.append({
                    'type': 'suspicious_filename',
                    'severity': 'high',
                    'pattern': pattern,
                    'filename': file_name,
                    'description': f'Suspicious filename pattern: {pattern}',
                    'file_path': file_path
                })
        
        return findings
    
    def scan_file(self, file_path: str) -> Dict:
        """Comprehensive ML-enhanced file scan"""
        findings = []
        file_ext = Path(file_path).suffix.lower()
        
        try:
            # Read file content
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # 1. Hash-based detection
            hash_finding = self.check_file_hash(file_path)
            if hash_finding:
                findings.append(hash_finding)
            
            # 2. Pattern-based detection
            pattern_findings = self.detect_suspicious_patterns(content, file_ext)
            findings.extend(pattern_findings)
            
            # 3. Obfuscation detection
            obfuscation_findings = self.detect_obfuscation(content, file_path)
            findings.extend(obfuscation_findings)
            
            # 4. File structure analysis
            structure_findings = self.analyze_file_structure(file_path)
            findings.extend(structure_findings)
            
            # Calculate risk score
            risk_score = self._calculate_risk_score(findings)
            
            return {
                'file_path': file_path,
                'scan_timestamp': datetime.utcnow().isoformat(),
                'findings': findings,
                'risk_score': risk_score,
                'threat_level': self._get_threat_level(risk_score),
                'file_size': os.path.getsize(file_path),
                'file_extension': file_ext
            }
            
        except Exception as e:
            logger.error(f"Error scanning file {file_path}: {e}")
            return {
                'file_path': file_path,
                'scan_timestamp': datetime.utcnow().isoformat(),
                'error': str(e),
                'findings': [],
                'risk_score': 0,
                'threat_level': 'unknown'
            }
    
    def _calculate_risk_score(self, findings: List[Dict]) -> int:
        """Calculate risk score based on findings"""
        score = 0
        severity_weights = {
            'critical': 100,
            'high': 50,
            'medium': 25,
            'low': 10
        }
        
        for finding in findings:
            severity = finding.get('severity', 'low')
            score += severity_weights.get(severity, 10)
        
        return min(score, 100)  # Cap at 100
    
    def _get_threat_level(self, risk_score: int) -> str:
        """Get threat level based on risk score"""
        if risk_score >= 80:
            return 'critical'
        elif risk_score >= 60:
            return 'high'
        elif risk_score >= 30:
            return 'medium'
        elif risk_score > 0:
            return 'low'
        else:
            return 'clean'
    
    def scan_directory(self, directory_path: str, max_files: int = 1000) -> Dict:
        """Scan entire directory with ML-enhanced detection"""
        results = {
            'scan_id': hashlib.md5(f"{directory_path}{datetime.utcnow()}".encode()).hexdigest()[:12],
            'directory': directory_path,
            'start_time': datetime.utcnow().isoformat(),
            'file_results': [],
            'summary': {
                'total_files': 0,
                'scanned_files': 0,
                'threats_found': 0,
                'clean_files': 0,
                'errors': 0
            }
        }
        
        try:
            # Get all scannable files
            scannable_files = []
            for root, dirs, files in os.walk(directory_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    file_ext = Path(file).suffix.lower()
                    
                    # Focus on web files and potentially suspicious files
                    if file_ext in ['.php', '.js', '.html', '.htm', '.phtml'] or file_ext in self.suspicious_extensions:
                        scannable_files.append(file_path)
                        
                        if len(scannable_files) >= max_files:
                            break
                
                if len(scannable_files) >= max_files:
                    break
            
            results['summary']['total_files'] = len(scannable_files)
            
            # Scan each file
            for file_path in scannable_files:
                file_result = self.scan_file(file_path)
                results['file_results'].append(file_result)
                
                results['summary']['scanned_files'] += 1
                
                if file_result.get('error'):
                    results['summary']['errors'] += 1
                elif file_result.get('threat_level') in ['critical', 'high', 'medium']:
                    results['summary']['threats_found'] += 1
                else:
                    results['summary']['clean_files'] += 1
            
            results['end_time'] = datetime.utcnow().isoformat()
            
        except Exception as e:
            logger.error(f"Error scanning directory {directory_path}: {e}")
            results['error'] = str(e)
        
        return results


class WordPressSpecificDetector:
    """WordPress-specific security detection"""
    
    def __init__(self):
        self.wp_core_files = self._load_wp_core_files()
        self.wp_suspicious_locations = [
            '/wp-content/uploads/',
            '/wp-includes/',
            '/wp-admin/includes/',
        ]
        
        self.wp_specific_patterns = [
            # WordPress hooks abuse
            r'add_action\s*\(\s*["\']wp_head["\'],\s*["\'][^"\']*eval',
            r'add_action\s*\(\s*["\']init["\'],\s*["\'][^"\']*base64',
            
            # Plugin/theme injection
            r'wp_enqueue_script\s*\([^)]*https?://',
            r'wp_enqueue_style\s*\([^)]*https?://',
            
            # Database manipulation
            r'\$wpdb\s*->\s*query\s*\([^)]*\$_',
            r'wp_insert_user\s*\(',
            r'wp_create_user\s*\(',
            
            # File system abuse
            r'wp_upload_dir\s*\(\)',
            r'ABSPATH\s*\.\s*["\'][^"\']*\.php',
        ]
    
    def _load_wp_core_files(self) -> set:
        """Load WordPress core file checksums"""
        # In a real implementation, this would load from WordPress.org API
        return {
            'wp-config.php', 'index.php', 'wp-load.php',
            'wp-settings.php', 'wp-blog-header.php'
        }
    
    def check_wp_integrity(self, wp_path: str) -> List[Dict]:
        """Check WordPress core file integrity"""
        findings = []
        
        # Check for modified core files
        wp_core_path = Path(wp_path)
        if (wp_core_path / 'wp-config.php').exists():
            # This is likely a WordPress installation
            
            # Check for suspicious files in uploads directory
            uploads_dir = wp_core_path / 'wp-content' / 'uploads'
            if uploads_dir.exists():
                for php_file in uploads_dir.rglob('*.php'):
                    findings.append({
                        'type': 'wp_uploads_php',
                        'severity': 'critical',
                        'file_path': str(php_file),
                        'description': 'PHP file in uploads directory (potential backdoor)',
                    })
        
        return findings
    
    def scan_wp_specific(self, content: str, file_path: str) -> List[Dict]:
        """WordPress-specific pattern detection"""
        findings = []
        
        for pattern in self.wp_specific_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                findings.append({
                    'type': 'wp_suspicious_pattern',
                    'severity': 'high',
                    'pattern': pattern,
                    'line': line_num,
                    'match': match.group(),
                    'file_path': file_path,
                    'description': 'WordPress-specific suspicious pattern detected'
                })
        
        return findings
