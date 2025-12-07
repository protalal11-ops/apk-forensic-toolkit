from pathlib import Path
import json
import markdown
from datetime import datetime
import pdfkit

class ReportGenerator:
    def __init__(self):
        self.templates_dir = Path(__file__).parent.parent / 'templates'
    
    def generate_report(self, analysis_results, format='md'):
        """إنشاء تقرير"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if format == 'md':
            return self.generate_markdown(analysis_results, timestamp)
        elif format == 'html':
            return self.generate_html(analysis_results, timestamp)
        elif format == 'pdf':
            return self.generate_pdf(analysis_results, timestamp)
    
    def generate_markdown(self, analysis_results, timestamp):
        """إنشاء تقرير Markdown"""
        report_content = self.create_report_content(analysis_results)
        
        report_dir = Path('reports')
        report_dir.mkdir(exist_ok=True)
        
        report_file = report_dir / f'report_{timestamp}.md'
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(report_content)
        
        return report_file
    
    def create_report_content(self, analysis_results):
        """إنشاء محتوى التقرير"""
        content = []
        
        # العنوان
        content.append("# تقرير التحليل الأمني لتطبيق Android")
        content.append(f"تاريخ الإنشاء: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        content.append("---\n")
        
        # ملخص التنفيذية
        content.append("## 1. الملخص التنفيذي")
        content.append(f"**درجة الخطورة:** {analysis_results['risk_score']}/100")
        
        vuln_counts = {
            'HIGH': len([v for v in analysis_results['vulnerabilities'] if v['severity'] == 'HIGH']),
            'MEDIUM': len([v for v in analysis_results['vulnerabilities'] if v['severity'] == 'MEDIUM']),
            'LOW': len([v for v in analysis_results['vulnerabilities'] if v['severity'] == 'LOW'])
        }
        
        content.append(f"**إجمالي الثغرات:** {len(analysis_results['vulnerabilities'])}")
        content.append(f"  - **عالية الخطورة:** {vuln_counts['HIGH']}")
        content.append(f"  - **متوسطة الخطورة:** {vuln_counts['MEDIUM']}")
        content.append(f"  - **منخفضة الخطورة:** {vuln_counts['LOW']}")
        content.append("\n")
        
        # معلومات التطبيق
        if 'apk_info' in analysis_results:
            content.append("## 2. معلومات التطبيق")
            info = analysis_results['apk_info']
            content.append(f"- **اسم الحزمة:** {info.get('package_name', 'غير معروف')}")
            content.append(f"- **النسخة:** {info.get('version_name', 'غير معروف')}")
            content.append(f"- **SHA256:** `{info.get('sha256', 'غير معروف')}`")
            content.append(f"- **حد أدنى لـ SDK:** {info.get('min_sdk', 'غير معروف')}")
            content.append(f"- **هدف SDK:** {info.get('target_sdk', 'غير معروف')}")
            content.append("\n")
        
        # الثغرات المكتشفة
        content.append("## 3. الثغرات الأمنية المكتشفة")
        
        for severity in ['HIGH', 'MEDIUM', 'LOW']:
            vulns = [v for v in analysis_results['vulnerabilities'] if v['severity'] == severity]
            if vulns:
                content.append(f"### {severity} - خطورة {self.get_severity_arabic(severity)}")
                
                for i, vuln in enumerate(vulns, 1):
                    content.append(f"#### {i}. {vuln.get('description', 'ثغرة')}")
                    content.append(f"**النوع:** {vuln.get('type', 'غير معروف')}")
                    
                    if 'file' in vuln:
                        content.append(f"**الملف:** `{vuln['file']}`")
                    
                    if 'line' in vuln:
                        content.append(f"**السطر:** {vuln['line']}")
                    
                    if 'code_snippet' in vuln:
                        content.append("**مقتطف الكود:**")
                        content.append(f"```java\n{vuln['code_snippet']}\n```")
                    
                    if 'recommendation' in vuln:
                        content.append(f"**التوصية:** {vuln['recommendation']}")
                    
                    content.append("---")
                content.append("\n")
        
        # تحليل الأذونات
        if 'permission_analysis' in analysis_results:
            content.append("## 4. تحليل الأذونات")
            perm_analysis = analysis_results['permission_analysis']
            
            content.append(f"**إجمالي الأذونات:** {len(perm_analysis.get('permissions', []))}")
            content.append("\n**الأذونات المستخدمة:**")
            
            for perm in perm_analysis.get('permissions', [])[:20]:  # أول 20 إذن فقط
                content.append(f"- `{perm}`")
            
            if len(perm_analysis.get('permissions', [])) > 20:
                content.append(f"- ... و{len(perm_analysis.get('permissions', [])) - 20} أذونات أخرى")
            content.append("\n")
        
        # التوصيات العامة
        content.append("## 5. التوصيات الأمنية")
        content.append(self.generate_recommendations(analysis_results))
        
        # الخاتمة
        content.append("## 6. الخاتمة")
        content.append("هذا التقرير تم إنشاؤه تلقائياً باستخدام APK Forensic Toolkit (AFT).")
        content.append("يوصى بمراجعة جميع النتائج مع مختص أمني.")
        
        return "\n".join(content)
    
    def get_severity_arabic(self, severity):
        """تحويل درجة الخطورة للعربية"""
        mapping = {
            'CRITICAL': 'حرجة',
            'HIGH': 'عالية',
            'MEDIUM': 'متوسطة',
            'LOW': 'منخفضة',
            'INFO': 'معلومات'
        }
        return mapping.get(severity, severity)
    
    def generate_recommendations(self, analysis_results):
        """إنشاء توصيات أمنية"""
        recommendations = [
            "### أفضل الممارسات الأمنية:",
            "1. **تشفير البيانات الحساسة:** تجنب تخزين البيانات الحساسة كنص واضح",
            "2. **استخدام HTTPS:** تجنب استخدام بروتوكول HTTP في الاتصالات الشبكية",
            "3. **التحقق من المدخلات:** تنفيذ التحقق من صحة جميع المدخلات من المستخدم",
            "4. **حد الأدنى من الأذونات:** منح الأذونات الضرورية فقط للتطبيق",
            "5. **تحديث المكتبات:** استخدام أحدث إصدارات المكتبات والتبعيات",
            "6. **تعطيل التصحيح:** تعطيل وضع التصحيح في إصدارات الإنتاج",
            "7. **تأمين WebView:** تطبيق قيود أمنية صارمة على WebView",
            "8. **مراجعة الكود:** إجراء مراجعات أمنية دورية للكود المصدري",
            "9. **اختبار الاختراق:** إجراء اختبارات اختراق منتظمة",
            "10. **التوثيق المناسب:** توثيق جميع الإجراءات الأمنية المطبقة"
        ]
        
        return "\n".join(recommendations)