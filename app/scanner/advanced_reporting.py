"""
WPGuard Advanced Reporting and Analytics
Enhanced reporting with risk assessment and recommendations
"""
import json
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from pathlib import Path
import logging
from dataclasses import dataclass
from collections import defaultdict, Counter

logger = logging.getLogger(__name__)

@dataclass
class SecurityMetric:
    """Security metric data structure"""
    name: str
    value: float
    max_value: float
    unit: str
    description: str
    severity: str

@dataclass
class Recommendation:
    """Security recommendation data structure"""
    priority: str  # critical, high, medium, low
    category: str
    title: str
    description: str
    impact: str
    effort: str  # low, medium, high
    steps: List[str]

class AdvancedReportGenerator:
    """Generate comprehensive security reports with analytics"""
    
    def __init__(self):
        self.severity_weights = {
            'critical': 100,
            'high': 50,
            'medium': 25,
            'low': 10,
            'info': 5
        }
        
        self.threat_categories = {
            'malware': 'Malware & Backdoors',
            'vulnerability': 'Security Vulnerabilities',
            'configuration': 'Configuration Issues',
            'compliance': 'Compliance Violations',
            'performance': 'Performance Issues'
        }
    
    def generate_executive_summary(self, scan_results: Dict) -> Dict:
        """Generate executive summary for management"""
        summary = scan_results.get('summary', {})
        file_results = scan_results.get('file_results', [])
        
        # Calculate key metrics
        total_files = summary.get('scanned_files', 0)
        threats_found = summary.get('threats_found', 0)
        threat_percentage = (threats_found / total_files * 100) if total_files > 0 else 0
        
        # Risk assessment
        risk_scores = [result.get('risk_score', 0) for result in file_results]
        avg_risk_score = sum(risk_scores) / len(risk_scores) if risk_scores else 0
        
        # Threat distribution
        threat_levels = Counter(result.get('threat_level', 'clean') for result in file_results)
        
        # Security posture
        security_posture = self._calculate_security_posture(scan_results)
        
        return {
            'scan_overview': {
                'scan_id': scan_results.get('scan_id'),
                'scan_date': scan_results.get('start_time'),
                'total_files_scanned': total_files,
                'scan_duration': self._calculate_duration(scan_results),
                'scan_scope': scan_results.get('directory', 'Unknown')
            },
            'security_status': {
                'overall_risk_level': self._get_overall_risk_level(avg_risk_score),
                'security_score': max(0, 100 - avg_risk_score),
                'threats_detected': threats_found,
                'threat_percentage': round(threat_percentage, 2),
                'clean_files': summary.get('clean_files', 0)
            },
            'threat_breakdown': {
                'critical': threat_levels.get('critical', 0),
                'high': threat_levels.get('high', 0),
                'medium': threat_levels.get('medium', 0),
                'low': threat_levels.get('low', 0),
                'clean': threat_levels.get('clean', 0)
            },
            'security_posture': security_posture,
            'key_findings': self._extract_key_findings(file_results),
            'immediate_actions': self._generate_immediate_actions(file_results)
        }
    
    def generate_technical_report(self, scan_results: Dict) -> Dict:
        """Generate detailed technical report"""
        file_results = scan_results.get('file_results', [])
        
        # Analyze findings by type
        findings_analysis = self._analyze_findings_by_type(file_results)
        
        # File type analysis
        file_type_analysis = self._analyze_file_types(file_results)
        
        # Pattern analysis
        pattern_analysis = self._analyze_attack_patterns(file_results)
        
        # Timeline analysis
        timeline_analysis = self._analyze_detection_timeline(file_results)
        
        return {
            'detailed_findings': self._format_detailed_findings(file_results),
            'findings_by_type': findings_analysis,
            'file_type_analysis': file_type_analysis,
            'attack_patterns': pattern_analysis,
            'timeline_analysis': timeline_analysis,
            'affected_locations': self._analyze_affected_locations(file_results),
            'risk_metrics': self._calculate_risk_metrics(file_results),
            'comparison_data': self._generate_comparison_data(scan_results)
        }
    
    def generate_compliance_report(self, scan_results: Dict) -> Dict:
        """Generate compliance and best practices report"""
        file_results = scan_results.get('file_results', [])
        
        # WordPress security best practices
        wp_compliance = self._check_wp_compliance(file_results)
        
        # General web security compliance
        web_security_compliance = self._check_web_security_compliance(file_results)
        
        # File security compliance
        file_security_compliance = self._check_file_security_compliance(file_results)
        
        return {
            'wordpress_compliance': wp_compliance,
            'web_security_compliance': web_security_compliance,
            'file_security_compliance': file_security_compliance,
            'compliance_score': self._calculate_compliance_score([
                wp_compliance, web_security_compliance, file_security_compliance
            ]),
            'recommendations': self._generate_compliance_recommendations(file_results)
        }
    
    def generate_recommendations(self, scan_results: Dict) -> List[Recommendation]:
        """Generate prioritized security recommendations"""
        file_results = scan_results.get('file_results', [])
        recommendations = []
        
        # Critical findings first
        critical_files = [r for r in file_results if r.get('threat_level') == 'critical']
        if critical_files:
            recommendations.append(Recommendation(
                priority='critical',
                category='malware',
                title='Immediate Malware Removal Required',
                description=f'Found {len(critical_files)} files with critical threat level that require immediate attention.',
                impact='System compromise, data theft, service disruption',
                effort='high',
                steps=[
                    'Immediately isolate affected files',
                    'Backup clean files before remediation',
                    'Remove or quarantine malicious files',
                    'Change all passwords and access keys',
                    'Update WordPress core and plugins',
                    'Implement additional monitoring'
                ]
            ))
        
        # High-risk findings
        high_risk_files = [r for r in file_results if r.get('threat_level') == 'high']
        if high_risk_files:
            recommendations.append(Recommendation(
                priority='high',
                category='vulnerability',
                title='Address High-Risk Security Issues',
                description=f'Found {len(high_risk_files)} files with high-risk security issues.',
                impact='Potential security breaches, unauthorized access',
                effort='medium',
                steps=[
                    'Review and analyze flagged files',
                    'Remove unnecessary or suspicious files',
                    'Update file permissions',
                    'Implement file integrity monitoring',
                    'Regular security scanning'
                ]
            ))
        
        # Configuration recommendations
        config_issues = self._identify_configuration_issues(file_results)
        if config_issues:
            recommendations.append(Recommendation(
                priority='medium',
                category='configuration',
                title='Security Configuration Improvements',
                description='Several configuration improvements can enhance security posture.',
                impact='Reduced attack surface, better security controls',
                effort='low',
                steps=config_issues
            ))
        
        # General security hardening
        recommendations.append(Recommendation(
            priority='medium',
            category='compliance',
            title='Implement Security Best Practices',
            description='Follow WordPress and web security best practices.',
            impact='Overall security improvement, compliance alignment',
            effort='medium',
            steps=[
                'Enable WordPress automatic updates',
                'Install security plugins (Wordfence, Sucuri)',
                'Implement Web Application Firewall (WAF)',
                'Set up regular automated backups',
                'Enable two-factor authentication',
                'Use strong, unique passwords',
                'Limit login attempts',
                'Hide WordPress version information'
            ]
        ))
        
        return recommendations
    
    def _calculate_security_posture(self, scan_results: Dict) -> Dict:
        """Calculate overall security posture metrics"""
        file_results = scan_results.get('file_results', [])
        summary = scan_results.get('summary', {})
        
        # Calculate metrics
        total_files = summary.get('scanned_files', 0)
        threats = summary.get('threats_found', 0)
        
        # Security metrics
        metrics = []
        
        # Threat density
        threat_density = (threats / total_files * 100) if total_files > 0 else 0
        metrics.append(SecurityMetric(
            name='threat_density',
            value=threat_density,
            max_value=100,
            unit='%',
            description='Percentage of files with threats',
            severity='high' if threat_density > 10 else 'medium' if threat_density > 5 else 'low'
        ))
        
        # File integrity
        clean_files = summary.get('clean_files', 0)
        integrity_score = (clean_files / total_files * 100) if total_files > 0 else 0
        metrics.append(SecurityMetric(
            name='file_integrity',
            value=integrity_score,
            max_value=100,
            unit='%',
            description='Percentage of clean files',
            severity='low' if integrity_score > 90 else 'medium' if integrity_score > 70 else 'high'
        ))
        
        # Risk distribution
        risk_scores = [r.get('risk_score', 0) for r in file_results]
        avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0
        metrics.append(SecurityMetric(
            name='average_risk',
            value=avg_risk,
            max_value=100,
            unit='points',
            description='Average risk score across all files',
            severity='high' if avg_risk > 50 else 'medium' if avg_risk > 25 else 'low'
        ))
        
        return {
            'metrics': [metric.__dict__ for metric in metrics],
            'overall_score': max(0, 100 - avg_risk),
            'posture_level': self._get_posture_level(avg_risk)
        }
    
    def _analyze_findings_by_type(self, file_results: List[Dict]) -> Dict:
        """Analyze findings by type and severity"""
        findings_by_type = defaultdict(lambda: defaultdict(int))
        
        for result in file_results:
            findings = result.get('findings', [])
            for finding in findings:
                finding_type = finding.get('type', 'unknown')
                severity = finding.get('severity', 'low')
                findings_by_type[finding_type][severity] += 1
        
        return dict(findings_by_type)
    
    def _analyze_file_types(self, file_results: List[Dict]) -> Dict:
        """Analyze threats by file type"""
        file_type_stats = defaultdict(lambda: {
            'total': 0, 'threats': 0, 'clean': 0, 'avg_risk': 0
        })
        
        for result in file_results:
            file_ext = result.get('file_extension', 'unknown')
            threat_level = result.get('threat_level', 'clean')
            risk_score = result.get('risk_score', 0)
            
            stats = file_type_stats[file_ext]
            stats['total'] += 1
            stats['avg_risk'] = (stats['avg_risk'] * (stats['total'] - 1) + risk_score) / stats['total']
            
            if threat_level in ['critical', 'high', 'medium']:
                stats['threats'] += 1
            else:
                stats['clean'] += 1
        
        return dict(file_type_stats)
    
    def _extract_key_findings(self, file_results: List[Dict]) -> List[Dict]:
        """Extract the most important findings"""
        key_findings = []
        
        # Get top 5 highest risk files
        sorted_results = sorted(file_results, key=lambda x: x.get('risk_score', 0), reverse=True)[:5]
        
        for result in sorted_results:
            if result.get('risk_score', 0) > 0:
                key_findings.append({
                    'file_path': result.get('file_path'),
                    'threat_level': result.get('threat_level'),
                    'risk_score': result.get('risk_score'),
                    'finding_count': len(result.get('findings', [])),
                    'primary_threats': [f.get('type') for f in result.get('findings', [])[:3]]
                })
        
        return key_findings
    
    def _generate_immediate_actions(self, file_results: List[Dict]) -> List[str]:
        """Generate list of immediate actions needed"""
        actions = []
        
        critical_files = [r for r in file_results if r.get('threat_level') == 'critical']
        high_files = [r for r in file_results if r.get('threat_level') == 'high']
        
        if critical_files:
            actions.append(f"🚨 CRITICAL: Immediately quarantine {len(critical_files)} files with critical threats")
        
        if high_files:
            actions.append(f"⚠️ HIGH: Review and address {len(high_files)} high-risk files")
        
        # Check for specific threat types
        malware_files = []
        for result in file_results:
            findings = result.get('findings', [])
            if any(f.get('type') == 'known_malware' for f in findings):
                malware_files.append(result)
        
        if malware_files:
            actions.append(f"🦠 MALWARE: Remove {len(malware_files)} confirmed malware files")
        
        if not actions:
            actions.append("✅ No immediate critical actions required")
        
        return actions
    
    def generate_full_report(self, scan_results: Dict) -> Dict:
        """Generate comprehensive report with all sections"""
        return {
            'report_metadata': {
                'generated_at': datetime.utcnow().isoformat(),
                'report_version': '2.0',
                'scan_id': scan_results.get('scan_id'),
                'generator': 'WPGuard Advanced Analytics'
            },
            'executive_summary': self.generate_executive_summary(scan_results),
            'technical_report': self.generate_technical_report(scan_results),
            'compliance_report': self.generate_compliance_report(scan_results),
            'recommendations': [r.__dict__ for r in self.generate_recommendations(scan_results)],
            'raw_scan_data': scan_results
        }
    
    # Helper methods for various calculations and analysis
    def _calculate_duration(self, scan_results: Dict) -> str:
        """Calculate scan duration"""
        try:
            start = datetime.fromisoformat(scan_results.get('start_time', ''))
            end = datetime.fromisoformat(scan_results.get('end_time', ''))
            duration = end - start
            return str(duration)
        except:
            return 'Unknown'
    
    def _get_overall_risk_level(self, avg_risk: float) -> str:
        """Get overall risk level from average risk score"""
        if avg_risk >= 70:
            return 'Critical'
        elif avg_risk >= 50:
            return 'High'
        elif avg_risk >= 25:
            return 'Medium'
        elif avg_risk > 0:
            return 'Low'
        else:
            return 'Minimal'
    
    def _get_posture_level(self, avg_risk: float) -> str:
        """Get security posture level"""
        if avg_risk < 10:
            return 'Excellent'
        elif avg_risk < 25:
            return 'Good'
        elif avg_risk < 50:
            return 'Fair'
        elif avg_risk < 75:
            return 'Poor'
        else:
            return 'Critical'
    
    def _check_wp_compliance(self, file_results: List[Dict]) -> Dict:
        """Check WordPress-specific compliance"""
        issues = []
        
        # Check for PHP files in uploads
        upload_php_files = [
            r for r in file_results 
            if 'uploads' in r.get('file_path', '') and r.get('file_extension') == '.php'
        ]
        
        if upload_php_files:
            issues.append(f"Found {len(upload_php_files)} PHP files in uploads directory")
        
        return {
            'score': max(0, 100 - len(issues) * 20),
            'issues': issues,
            'compliant': len(issues) == 0
        }
    
    def _check_web_security_compliance(self, file_results: List[Dict]) -> Dict:
        """Check general web security compliance"""
        issues = []
        
        # Check for suspicious file extensions
        suspicious_files = [
            r for r in file_results 
            if r.get('file_extension') in ['.asp', '.aspx', '.jsp']
        ]
        
        if suspicious_files:
            issues.append(f"Found {len(suspicious_files)} files with suspicious extensions")
        
        return {
            'score': max(0, 100 - len(issues) * 15),
            'issues': issues,
            'compliant': len(issues) == 0
        }
    
    def _check_file_security_compliance(self, file_results: List[Dict]) -> Dict:
        """Check file security compliance"""
        issues = []
        
        # Check for high entropy files (possible obfuscation)
        obfuscated_files = []
        for result in file_results:
            findings = result.get('findings', [])
            if any(f.get('type') == 'obfuscation' for f in findings):
                obfuscated_files.append(result)
        
        if obfuscated_files:
            issues.append(f"Found {len(obfuscated_files)} potentially obfuscated files")
        
        return {
            'score': max(0, 100 - len(issues) * 25),
            'issues': issues,
            'compliant': len(issues) == 0
        }
    
    def _calculate_compliance_score(self, compliance_results: List[Dict]) -> int:
        """Calculate overall compliance score"""
        if not compliance_results:
            return 0
        
        scores = [result.get('score', 0) for result in compliance_results]
        return int(sum(scores) / len(scores))
    
    def _generate_compliance_recommendations(self, file_results: List[Dict]) -> List[str]:
        """Generate compliance-specific recommendations"""
        recommendations = []
        
        # WordPress-specific recommendations
        recommendations.extend([
            "Keep WordPress core, themes, and plugins updated",
            "Remove unused themes and plugins",
            "Use strong passwords and enable 2FA",
            "Implement file integrity monitoring",
            "Regular security scans and backups"
        ])
        
        return recommendations
    
    def _identify_configuration_issues(self, file_results: List[Dict]) -> List[str]:
        """Identify configuration issues from scan results"""
        issues = []
        
        # Check for common configuration problems
        php_files_in_uploads = any(
            'uploads' in r.get('file_path', '') and r.get('file_extension') == '.php'
            for r in file_results
        )
        
        if php_files_in_uploads:
            issues.append("Remove PHP execution capability from uploads directory")
        
        # Add more configuration checks
        issues.extend([
            "Disable file editing in WordPress admin",
            "Limit login attempts",
            "Hide WordPress version information",
            "Disable directory browsing"
        ])
        
        return issues
    
    def _analyze_attack_patterns(self, file_results: List[Dict]) -> Dict:
        """Analyze common attack patterns"""
        patterns = defaultdict(int)
        
        for result in file_results:
            findings = result.get('findings', [])
            for finding in findings:
                pattern_type = finding.get('type', 'unknown')
                patterns[pattern_type] += 1
        
        return dict(patterns)
    
    def _analyze_detection_timeline(self, file_results: List[Dict]) -> Dict:
        """Analyze when threats were detected"""
        # In a real implementation, this would analyze file modification times
        # and detection patterns over time
        return {
            'recent_threats': len([r for r in file_results if r.get('threat_level') != 'clean']),
            'trend': 'stable',  # Could be 'increasing', 'decreasing', 'stable'
            'analysis': 'Timeline analysis requires historical data'
        }
    
    def _analyze_affected_locations(self, file_results: List[Dict]) -> Dict:
        """Analyze which directories/locations are most affected"""
        location_stats = defaultdict(lambda: {'total': 0, 'threats': 0})
        
        for result in file_results:
            file_path = result.get('file_path', '')
            # Extract directory
            directory = str(Path(file_path).parent)
            
            location_stats[directory]['total'] += 1
            if result.get('threat_level') in ['critical', 'high', 'medium']:
                location_stats[directory]['threats'] += 1
        
        return dict(location_stats)
    
    def _calculate_risk_metrics(self, file_results: List[Dict]) -> Dict:
        """Calculate detailed risk metrics"""
        risk_scores = [r.get('risk_score', 0) for r in file_results]
        
        if not risk_scores:
            return {'error': 'No risk data available'}
        
        return {
            'min_risk': min(risk_scores),
            'max_risk': max(risk_scores),
            'avg_risk': sum(risk_scores) / len(risk_scores),
            'median_risk': sorted(risk_scores)[len(risk_scores) // 2],
            'risk_distribution': {
                'low': len([s for s in risk_scores if 0 < s <= 25]),
                'medium': len([s for s in risk_scores if 25 < s <= 50]),
                'high': len([s for s in risk_scores if 50 < s <= 75]),
                'critical': len([s for s in risk_scores if s > 75])
            }
        }
    
    def _generate_comparison_data(self, scan_results: Dict) -> Dict:
        """Generate data for comparison with previous scans"""
        # In a real implementation, this would compare with historical scan data
        return {
            'baseline_available': False,
            'improvement_needed': True,
            'note': 'Historical comparison requires multiple scans'
        }
    
    def _format_detailed_findings(self, file_results: List[Dict]) -> List[Dict]:
        """Format findings for detailed technical report"""
        detailed_findings = []
        
        for result in file_results:
            if result.get('findings'):
                detailed_findings.append({
                    'file_path': result.get('file_path'),
                    'file_size': result.get('file_size'),
                    'threat_level': result.get('threat_level'),
                    'risk_score': result.get('risk_score'),
                    'scan_timestamp': result.get('scan_timestamp'),
                    'findings': result.get('findings'),
                    'recommendation': self._get_file_recommendation(result)
                })
        
        return detailed_findings
    
    def _get_file_recommendation(self, file_result: Dict) -> str:
        """Get specific recommendation for a file"""
        threat_level = file_result.get('threat_level', 'clean')
        
        if threat_level == 'critical':
            return "IMMEDIATE ACTION: Quarantine or remove this file immediately"
        elif threat_level == 'high':
            return "HIGH PRIORITY: Review and likely remove this file"
        elif threat_level == 'medium':
            return "MEDIUM PRIORITY: Investigate and consider removing"
        elif threat_level == 'low':
            return "LOW PRIORITY: Monitor and review during next maintenance"
        else:
            return "File appears clean, no action needed"
