import re
import json
from pathlib import Path
import xml.etree.ElementTree as ET
from typing import Dict, List, Set

class SecurityAnalyzer:
    def __init__(self):
        self.vulnerabilities = []
        self.security_issues = []
        self.load_patterns()
    
    def load_patterns(self):
        """تحميل أنماط الثغرات الأمنية"""
        patterns_file = Path(__file__).parent.parent / 'config' / 'patterns.json'
        with open(patterns_file) as f:
            self.patterns = json.load(f)
    
    def full_analysis(self, project_dir):
        """تحليل أمني شامل"""
        project_dir = Path(project_dir)
        
        results = {
            'manifest_analysis': self.analyze_manifest(project_dir),
            'code_analysis': self.analyze_code(project_dir),
            'permission_analysis': self.analyze_permissions(project_dir),
            'resource_analysis': self.analyze_resources(project_dir),
            'vulnerabilities': [],
            'security_issues': [],
            'risk_score': 0
        }
        
        # جمع جميع الثغرات
        all_vulns = []
        all_vulns.extend(results['manifest_analysis']['vulnerabilities'])
        all_vulns.extend(results['code_analysis']['vulnerabilities'])
        all_vulns.extend(results['permission_analysis']['vulnerabilities'])
        
        results['vulnerabilities'] = all_vulns
        results['security_issues'] = self.security_issues
        
        # حساب درجة الخطورة
        results['risk_score'] = self.calculate_risk_score(all_vulns)
        
        return results
    
    def analyze_manifest(self, project_dir):
        """تحليل AndroidManifest.xml"""
        manifest_path = project_dir / 'manifest' / 'AndroidManifest.xml'
        
        if not manifest_path.exists():
            return {'error': 'Manifest not found'}
        
        vulnerabilities = []
        issues = []
        
        try:
            tree = ET.parse(manifest_path)
            root = tree.getroot()
            
            # تحليل الأذونات
            permissions = self.extract_permissions(root)
            
            # تحليل المكونات
            components = self.analyze_components(root)
            
            # كشف الثغرات في المكونات
            vulnerabilities.extend(self.check_component_vulnerabilities(components))
            
            # تحليل intents
            vulnerabilities.extend(self.analyze_intent_filters(root))
            
            # تحليل إعدادات الأمان
            vulnerabilities.extend(self.check_security_config(root))
            
        except Exception as e:
            issues.append(f"Error parsing manifest: {e}")
        
        return {
            'permissions': permissions,
            'components': components,
            'vulnerabilities': vulnerabilities,
            'issues': issues
        }
    
    def analyze_code(self, project_dir):
        """تحليل الكود بحثاً عن ثغرات"""
        java_dir = project_dir / 'java'
        smali_dir = project_dir / 'smali'
        
        vulnerabilities = []
        
        # تحليل كود Java
        if java_dir.exists():
            vulnerabilities.extend(self.analyze_java_code(java_dir))
        
        # تحليل كود Smali
        if smali_dir.exists():
            vulnerabilities.extend(self.analyze_smali_code(smali_dir))
        
        return {
            'vulnerabilities': vulnerabilities,
            'files_analyzed': self.count_files(java_dir) + self.count_files(smali_dir)
        }
    
    def analyze_java_code(self, java_dir):
        """تحليل كود Java"""
        vulnerabilities = []
        
        # البحث عن معلومات حساسة
        sensitive_patterns = [
            (r'(?i)password\s*=\s*["\'][^"\']+["\']', 'كلمة مرور نصية'),
            (r'(?i)api[_-]?key\s*=\s*["\'][^"\']+["\']', 'مفتاح API'),
            (r'(?i)token\s*=\s*["\'][^"\']+["\']', 'Token'),
            (r'http://', 'اتصال HTTP غير آمن'),
            (r'android:usesCleartextTraffic="true"', 'تصريح حركة نصية واضحة'),
        ]
        
        for file_path in java_dir.rglob('*.java'):
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    line_num = 0
                    for line in content.split('\n'):
                        line_num += 1
                        for pattern, issue in sensitive_patterns:
                            if re.search(pattern, line):
                                vulnerabilities.append({
                                    'file': str(file_path.relative_to(java_dir)),
                                    'line': line_num,
                                    'type': 'SENSITIVE_DATA',
                                    'severity': 'HIGH',
                                    'description': f'معلومات حساسة: {issue}',
                                    'code_snippet': line.strip()
                                })
                
                # تحليل WebView
                if 'WebView' in content:
                    vulnerabilities.extend(self.analyze_webview_security(content, file_path))
                
                # تحليل قاعدة البيانات
                vulnerabilities.extend(self.analyze_database_security(content, file_path))
                
            except:
                continue
        
        return vulnerabilities
    
    def analyze_webview_security(self, content, file_path):
        """تحليل إعدادات أمان WebView"""
        issues = []
        
        # WebView بدون JavaScript مقيد
        if 'setJavaScriptEnabled(true)' in content:
            if 'setAllowFileAccess(false)' not in content:
                issues.append({
                    'file': str(file_path),
                    'type': 'WEBVIEW_INSECURE',
                    'severity': 'HIGH',
                    'description': 'WebView مع تمكين JavaScript بدون قيود أمنية كافية',
                    'recommendation': 'تعطيل JavaScript أو تطبيق سياسات أمنية صارمة'
                })
        
        return issues
    
    def analyze_permissions(self, project_dir):
        """تحليل الأذونات"""
        manifest_path = project_dir / 'manifest' / 'AndroidManifest.xml'
        
        if not manifest_path.exists():
            return {'vulnerabilities': []}
        
        vulnerabilities = []
        
        try:
            tree = ET.parse(manifest_path)
            root = tree.getroot()
            
            permissions = self.extract_permissions(root)
            
            # كشف الأذونات الخطيرة
            dangerous_perms = [
                'android.permission.READ_SMS',
                'android.permission.SEND_SMS',
                'android.permission.RECORD_AUDIO',
                'android.permission.ACCESS_FINE_LOCATION',
                'android.permission.CAMERA',
                'android.permission.READ_CONTACTS',
                'android.permission.WRITE_CONTACTS'
            ]
            
            for perm in permissions:
                if perm in dangerous_perms:
                    vulnerabilities.append({
                        'type': 'DANGEROUS_PERMISSION',
                        'severity': 'MEDIUM',
                        'description': f'إذن خطير: {perm}',
                        'recommendation': 'التحقق من ضرورة هذا الإذن'
                    })
            
            # كشف أذونات غير ضرورية
            code_dir = project_dir / 'java'
            used_perms = self.detect_used_permissions(code_dir)
            
            for perm in permissions:
                if perm not in used_perms:
                    vulnerabilities.append({
                        'type': 'UNUSED_PERMISSION',
                        'severity': 'LOW',
                        'description': f'إذن غير مستخدم: {perm}',
                        'recommendation': 'إزالة الإذن غير الضروري'
                    })
                    
        except Exception as e:
            vulnerabilities.append({
                'type': 'ANALYSIS_ERROR',
                'severity': 'INFO',
                'description': f'خطأ في تحليل الأذونات: {e}'
            })
        
        return {
            'permissions': permissions,
            'vulnerabilities': vulnerabilities
        }
    
    def calculate_risk_score(self, vulnerabilities):
        """حساب درجة الخطورة"""
        severity_scores = {'CRITICAL': 10, 'HIGH': 7, 'MEDIUM': 4, 'LOW': 2, 'INFO': 1}
        score = 0
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'INFO')
            score += severity_scores.get(severity, 1)
        
        return min(score, 100)
    
    def get_summary(self):
        """الحصول على ملخص التحليل"""
        return {
            'total_vulnerabilities': len(self.vulnerabilities),
            'high_severity': len([v for v in self.vulnerabilities if v['severity'] == 'HIGH']),
            'medium_severity': len([v for v in self.vulnerabilities if v['severity'] == 'MEDIUM']),
            'low_severity': len([v for v in self.vulnerabilities if v['severity'] == 'LOW'])
        }