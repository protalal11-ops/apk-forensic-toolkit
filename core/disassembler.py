import subprocess
import shutil
import zipfile
from pathlib import Path
import hashlib
import json
import xml.etree.ElementTree as ET
from androguard.core.apk import APK as AndroAPK

class APKDisassembler:
    def __init__(self):
        self.tools = {
            'apktool': 'apktool',
            'jadx': 'jadx'
        }
    
    def disassemble(self, apk_path, output_dir):
        """تفكيك APK باستخدام APKTool وJadx"""
        apk_path = Path(apk_path)
        output_dir = Path(output_dir)
        
        # إنشاء الهيكل التنظيمي
        dirs = ['manifest', 'java', 'smali', 'resources', 'assets', 'libs', 'original']
        for dir_name in dirs:
            (output_dir / dir_name).mkdir(parents=True, exist_ok=True)
        
        # حفظ APK الأصلي
        shutil.copy2(apk_path, output_dir / 'original' / apk_path.name)
        
        # استخراج معلومات APK
        apk_info = self.extract_apk_info(apk_path, output_dir)
        
        # استخدام APKTool
        self.run_apktool(apk_path, output_dir / 'smali')
        
        # استخدام Jadx
        self.run_jadx(apk_path, output_dir / 'java')
        
        # تنظيم الملفات
        self.organize_files(output_dir)
        
        # حفظ المعلومات
        with open(output_dir / 'apk_info.json', 'w') as f:
            json.dump(apk_info, f, indent=2)
        
        return output_dir
    
    def extract_apk_info(self, apk_path, output_dir):
        """استخراج معلومات APK باستخدام Androguard"""
        apk = AndroAPK(apk_path)
        
        info = {
            'package_name': apk.get_package(),
            'version': apk.get_androidversion_code(),
            'version_name': apk.get_androidversion_name(),
            'min_sdk': apk.get_min_sdk_version(),
            'target_sdk': apk.get_target_sdk_version(),
            'sha256': self.calculate_hash(apk_path),
            'permissions': apk.get_permissions(),
            'activities': apk.get_activities(),
            'services': apk.get_services(),
            'receivers': apk.get_receivers(),
            'providers': apk.get_providers(),
            'libraries': apk.get_libraries(),
            'files': list(apk.get_files())
        }
        
        # استخراج AndroidManifest.xml
        manifest_xml = apk.get_android_manifest_xml()
        manifest_str = ET.tostring(manifest_xml, encoding='unicode')
        
        with open(output_dir / 'manifest' / 'AndroidManifest.xml', 'w') as f:
            f.write(manifest_str)
        
        # استخراج الموارد
        self.extract_resources(apk, output_dir / 'resources')
        
        # استخراج الـ Assets
        self.extract_assets(apk, output_dir / 'assets')
        
        # استخراج المكتبات
        self.extract_libs(apk, output_dir / 'libs')
        
        return info
    
    def calculate_hash(self, file_path):
        """حساب البصمة الرقمية"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    
    def run_apktool(self, apk_path, output_dir):
        """تشغيل APKTool"""
        cmd = [self.tools['apktool'], 'd', str(apk_path), '-o', str(output_dir), '-f']
        subprocess.run(cmd, check=True)
    
    def run_jadx(self, apk_path, output_dir):
        """تشغيل Jadx"""
        cmd = [self.tools['jadx'], str(apk_path), '-d', str(output_dir), '--deobf']
        subprocess.run(cmd, check=True)
    
    def extract_resources(self, apk, output_dir):
        """استخراج الموارد"""
        resources = apk.get_files()
        for resource in resources:
            if resource.startswith('res/'):
                try:
                    data = apk.get_file(resource)
                    resource_path = output_dir / resource
                    resource_path.parent.mkdir(parents=True, exist_ok=True)
                    with open(resource_path, 'wb') as f:
                        f.write(data)
                except:
                    continue
    
    def extract_assets(self, apk, output_dir):
        """استخراج Assets"""
        assets = [f for f in apk.get_files() if f.startswith('assets/')]
        for asset in assets:
            try:
                data = apk.get_file(asset)
                asset_path = output_dir / asset
                asset_path.parent.mkdir(parents=True, exist_ok=True)
                with open(asset_path, 'wb') as f:
                    f.write(data)
            except:
                continue
    
    def extract_libs(self, apk, output_dir):
        """استخراج المكتبات"""
        libs = [f for f in apk.get_files() if f.startswith('lib/')]
        for lib in libs:
            try:
                data = apk.get_file(lib)
                lib_path = output_dir / lib
                lib_path.parent.mkdir(parents=True, exist_ok=True)
                with open(lib_path, 'wb') as f:
                    f.write(data)
            except:
                continue
    
    def organize_files(self, output_dir):
        """تنظيم الملفات في هيكل منظم"""
        # نقل ملفات APKTool
        smali_dir = output_dir / 'smali'
        if smali_dir.exists():
            # البحث عن ملفات smali
            for smali_file in smali_dir.rglob('*.smali'):
                relative = smali_file.relative_to(smali_dir)
                target = output_dir / 'smali' / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(smali_file), str(target))