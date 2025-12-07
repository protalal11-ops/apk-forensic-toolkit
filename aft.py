#!/usr/bin/env python3
"""
APK Forensic Toolkit (AFT)
أداة متقدمة للهندسة العكسية وتحليل تطبيقات Android
"""

import argparse
import sys
import os
import logging
from pathlib import Path

from core.disassembler import APKDisassembler
from core.analyzer import SecurityAnalyzer
from core.rebuilder import APKRebuilder
from core.reporter import ReportGenerator

class APKForensicToolkit:
    def __init__(self):
        self.setup_logging()
        self.disassembler = APKDisassembler()
        self.analyzer = SecurityAnalyzer()
        self.rebuilder = APKRebuilder()
        self.reporter = ReportGenerator()
    
    def setup_logging(self):
        """إعداد نظام التسجيل"""
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_dir / 'aft.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def extract(self, apk_path, output_dir):
        """تفكيك ملف APK"""
        self.logger.info(f"بدء تفكيك APK: {apk_path}")
        return self.disassembler.disassemble(apk_path, output_dir)
    
    def analyze(self, project_dir, report_format="md"):
        """تحليل أمني شامل"""
        self.logger.info(f"بدء التحليل الأمني: {project_dir}")
        analysis_results = self.analyzer.full_analysis(project_dir)
        report_path = self.reporter.generate_report(analysis_results, report_format)
        return report_path
    
    def rebuild(self, project_dir, output_apk=None):
        """إعادة بناء التطبيق"""
        self.logger.info(f"إعادة بناء التطبيق من: {project_dir}")
        return self.rebuilder.rebuild_apk(project_dir, output_apk)
    
    def sign(self, apk_path, keystore=None):
        """توقيع التطبيق"""
        self.logger.info(f"توقيع APK: {apk_path}")
        return self.rebuilder.sign_apk(apk_path, keystore)
    
    def patch(self, project_dir, patch_file):
        """تطبيق تصحيح على الكود"""
        self.logger.info(f"تطبيق التصحيح: {patch_file}")
        return self.rebuilder.apply_patch(project_dir, patch_file)
    
    def full_analysis(self, apk_path, output_dir=None, report_format="pdf"):
        """تنفيذ العملية الكاملة"""
        if not output_dir:
            apk_name = Path(apk_path).stem
            output_dir = Path("output") / apk_name
        
        # التفكيك
        project_dir = self.extract(apk_path, output_dir)
        
        # التحليل
        report_path = self.analyze(project_dir, report_format)
        
        # إرجاع النتائج
        return {
            'project_dir': project_dir,
            'report_path': report_path,
            'analysis': self.analyzer.get_summary()
        }

def main():
    parser = argparse.ArgumentParser(
        description='APK Forensic Toolkit - أداة متقدمة للهندسة العكسية وتحليل APK',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
أمثلة الاستخدام:
  aft extract --apk app.apk --out ./output
  aft analyze --dir ./output --report pdf
  aft rebuild --dir ./output
  aft all --apk app.apk --report html
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='الأوامر')
    
    # أمر extract
    extract_parser = subparsers.add_parser('extract', help='تفكيك ملف APK')
    extract_parser.add_argument('--apk', required=True, help='مسار ملف APK')
    extract_parser.add_argument('--out', default='./output', help='مجلد الإخراج')
    extract_parser.add_argument('--decompile', action='store_true', help='فك التجميع إلى Java')
    
    # أمر analyze
    analyze_parser = subparsers.add_parser('analyze', help='تحليل أمني')
    analyze_parser.add_argument('--dir', required=True, help='مجلد المشروع')
    analyze_parser.add_argument('--report', choices=['md', 'html', 'pdf'], default='md')
    analyze_parser.add_argument('--deep', action='store_true', help='تحليل عميق')
    
    # أمر rebuild
    rebuild_parser = subparsers.add_parser('rebuild', help='إعادة بناء التطبيق')
    rebuild_parser.add_argument('--dir', required=True, help='مجلد المشروع')
    rebuild_parser.add_argument('--output', help='اسم ملف الإخراج')
    rebuild_parser.add_argument('--sign', action='store_true', help='توقيع تلقائي')
    
    # أمر sign
    sign_parser = subparsers.add_parser('sign', help='توقيع APK')
    sign_parser.add_argument('--apk', required=True, help='مسار ملف APK')
    sign_parser.add_argument('--keystore', default='debug.keystore')
    
    # أمر patch
    patch_parser = subparsers.add_parser('patch', help='تطبيق تصحيح')
    patch_parser.add_argument('--dir', required=True, help='مجلد المشروع')
    patch_parser.add_argument('--patch', required=True, help='ملف التصحيح')
    
    # أمر all
    all_parser = subparsers.add_parser('all', help='التحليل الكامل')
    all_parser.add_argument('--apk', required=True, help='مسار ملف APK')
    all_parser.add_argument('--out', default='./output', help='مجلد الإخراج')
    all_parser.add_argument('--report', choices=['md', 'html', 'pdf'], default='pdf')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    toolkit = APKForensicToolkit()
    
    try:
        if args.command == 'extract':
            toolkit.extract(args.apk, args.out)
            
        elif args.command == 'analyze':
            toolkit.analyze(args.dir, args.report)
            
        elif args.command == 'rebuild':
            toolkit.rebuild(args.dir, args.output)
            if args.sign:
                toolkit.sign(args.output)
                
        elif args.command == 'sign':
            toolkit.sign(args.apk, args.keystore)
            
        elif args.command == 'patch':
            toolkit.patch(args.dir, args.patch)
            
        elif args.command == 'all':
            toolkit.full_analysis(args.apk, args.out, args.report)
            
    except Exception as e:
        print(f"خطأ: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()