#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
وحدة التكوين لأداة SaudiAttack
"""

import os
import yaml
import json
from pathlib import Path

# الإعدادات الافتراضية
DEFAULT_CONFIG = {
    # إعدادات عامة
    'general': {
        'threads': 5,
        'timeout': 30,
        'user_agent': 'SaudiAttack/1.0',
        'verbose': False,
        'output_dir': os.path.join(os.path.expanduser('~'), '.saudi_attack', 'reports'),
    },
    
    # إعدادات المسح
    'scanning': {
        'ports': {
            'default': [80, 443, 8080, 8443],
            'web': [80, 443, 8080, 8443],
            'wordpress': [80, 443],
            'joomla': [80, 443],
            'full': list(range(1, 1025)),
        },
        'nmap_scripts': [
            'default', 'banner', 'http-enum', 'http-headers', 'http-methods',
            'http-title', 'ssl-cert', 'ssl-enum-ciphers', 'vuln'
        ],
    },
    
    # إعدادات الويب
    'web': {
        'paths_to_check': [
            '/', '/robots.txt', '/sitemap.xml', '/admin', '/login', '/wp-admin',
            '/administrator', '/phpmyadmin', '/.git', '/.env', '/backup', '/config'
        ],
        'security_headers': [
            'Strict-Transport-Security', 'Content-Security-Policy',
            'X-Content-Type-Options', 'X-Frame-Options', 'X-XSS-Protection',
            'Referrer-Policy', 'Permissions-Policy'
        ],
    },
    
    # إعدادات ووردبريس
    'wordpress': {
        'paths_to_check': [
            '/wp-login.php', '/wp-admin/', '/wp-config.php', '/wp-content/',
            '/wp-includes/', '/xmlrpc.php', '/wp-json/'
        ],
        'version_detection_paths': [
            '/feed/', '/wp-includes/css/dist/block-library/style.min.css',
            '/readme.html', '/wp-includes/js/wp-emoji-release.min.js'
        ],
    },
    
    # إعدادات جوملا
    'joomla': {
        'paths_to_check': [
            '/administrator/', '/administrator/index.php', '/configuration.php',
            '/htaccess.txt', '/installation/', '/robots.txt.dist', '/web.config.txt',
            '/administrator/manifests/files/joomla.xml', '/language/en-GB/en-GB.xml',
            '/administrator/components/', '/components/'
        ],
        'version_detection_paths': [
            '/administrator/manifests/files/joomla.xml',
            '/language/en-GB/en-GB.xml',
            '/includes/version.php'
        ],
    },
    
    # إعدادات التقارير
    'reporting': {
        'formats': ['html', 'json', 'txt', 'md', 'yaml'],
        'default_format': 'html',
        'include_timestamp': True,
        'include_banner': True,
        'severity_levels': ['critical', 'high', 'medium', 'low', 'info'],
        'template_dir': os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'templates'),
    }
}


class Config:
    """
    فئة لإدارة تكوين SaudiAttack
    """
    
    def __init__(self, config_file=None):
        """
        تهيئة كائن التكوين
        
        المعلمات:
            config_file (str): مسار ملف التكوين الاختياري
        """
        self.config = DEFAULT_CONFIG.copy()
        
        # إنشاء دليل الإخراج الافتراضي إذا لم يكن موجودًا
        os.makedirs(self.config['general']['output_dir'], exist_ok=True)
        
        # تحميل ملف التكوين إذا تم تحديده
        if config_file and os.path.exists(config_file):
            self.load_config(config_file)
    
    def load_config(self, config_file):
        """
        تحميل التكوين من ملف
        
        المعلمات:
            config_file (str): مسار ملف التكوين
        """
        try:
            with open(config_file, 'r') as f:
                if config_file.endswith('.yaml') or config_file.endswith('.yml'):
                    user_config = yaml.safe_load(f)
                elif config_file.endswith('.json'):
                    user_config = json.load(f)
                else:
                    raise ValueError(f"نوع ملف التكوين غير مدعوم: {config_file}")
                
                # دمج التكوين المخصص مع الإعدادات الافتراضية
                self._merge_config(self.config, user_config)
        except Exception as e:
            print(f"خطأ في تحميل ملف التكوين: {str(e)}")
    
    def _merge_config(self, default_config, user_config):
        """
        دمج تكوين المستخدم مع التكوين الافتراضي
        
        المعلمات:
            default_config (dict): التكوين الافتراضي
            user_config (dict): تكوين المستخدم
        """
        for key, value in user_config.items():
            if key in default_config and isinstance(default_config[key], dict) and isinstance(value, dict):
                self._merge_config(default_config[key], value)
            else:
                default_config[key] = value
    
    def get(self, section, key=None):
        """
        الحصول على قيمة التكوين
        
        المعلمات:
            section (str): قسم التكوين
            key (str): مفتاح التكوين (اختياري)
        
        العوائد:
            قيمة التكوين أو قسم التكوين بأكمله
        """
        if section not in self.config:
            return None
        
        if key is None:
            return self.config[section]
        
        if key not in self.config[section]:
            return None
        
        return self.config[section][key]
    
    def set(self, section, key, value):
        """
        تعيين قيمة التكوين
        
        المعلمات:
            section (str): قسم التكوين
            key (str): مفتاح التكوين
            value: قيمة التكوين
        """
        if section not in self.config:
            self.config[section] = {}
        
        self.config[section][key] = value
    
    def save_config(self, config_file):
        """
        حفظ التكوين إلى ملف
        
        المعلمات:
            config_file (str): مسار ملف التكوين
        """
        try:
            # إنشاء الدليل إذا لم يكن موجودًا
            os.makedirs(os.path.dirname(os.path.abspath(config_file)), exist_ok=True)
            
            with open(config_file, 'w') as f:
                if config_file.endswith('.yaml') or config_file.endswith('.yml'):
                    yaml.dump(self.config, f, default_flow_style=False)
                elif config_file.endswith('.json'):
                    json.dump(self.config, f, indent=4)
                else:
                    raise ValueError(f"نوع ملف التكوين غير مدعوم: {config_file}")
        except Exception as e:
            print(f"خطأ في حفظ ملف التكوين: {str(e)}")
    
    def get_user_agent(self):
        """
        الحصول على وكيل المستخدم
        
        العوائد:
            str: وكيل المستخدم
        """
        return self.config['general']['user_agent']
    
    def get_threads(self):
        """
        الحصول على عدد المواضيع
        
        العوائد:
            int: عدد المواضيع
        """
        return self.config['general']['threads']
    
    def get_timeout(self):
        """
        الحصول على مهلة الاتصال
        
        العوائد:
            int: مهلة الاتصال بالثواني
        """
        return self.config['general']['timeout']
    
    def get_ports(self, scan_type='default'):
        """
        الحصول على المنافذ للمسح
        
        المعلمات:
            scan_type (str): نوع المسح
        
        العوائد:
            list: قائمة المنافذ
        """
        ports = self.config['scanning']['ports']
        return ports.get(scan_type, ports['default'])
    
    def get_output_dir(self):
        """
        الحصول على دليل الإخراج
        
        العوائد:
            str: مسار دليل الإخراج
        """
        return self.config['general']['output_dir']
    
    def get_template_dir(self):
        """
        الحصول على دليل القوالب
        
        العوائد:
            str: مسار دليل القوالب
        """
        return self.config['reporting']['template_dir']
    
    def get_nmap_scripts(self):
        """
        الحصول على نصوص Nmap
        
        العوائد:
            list: قائمة نصوص Nmap
        """
        return self.config['scanning']['nmap_scripts']
    
    def get_paths_to_check(self, scan_type):
        """
        الحصول على المسارات للتحقق
        
        المعلمات:
            scan_type (str): نوع المسح (web, wordpress, joomla)
        
        العوائد:
            list: قائمة المسارات
        """
        if scan_type in self.config and 'paths_to_check' in self.config[scan_type]:
            return self.config[scan_type]['paths_to_check']
        return []
    
    def get_security_headers(self):
        """
        الحصول على رؤوس الأمان
        
        العوائد:
            list: قائمة رؤوس الأمان
        """
        return self.config['web']['security_headers']
    
    def get_report_formats(self):
        """
        الحصول على تنسيقات التقارير
        
        العوائد:
            list: قائمة تنسيقات التقارير
        """
        return self.config['reporting']['formats']
    
    def get_default_report_format(self):
        """
        الحصول على تنسيق التقرير الافتراضي
        
        العوائد:
            str: تنسيق التقرير الافتراضي
        """
        return self.config['reporting']['default_format']
    
    def get_severity_levels(self):
        """
        الحصول على مستويات الخطورة
        
        العوائد:
            list: قائمة مستويات الخطورة
        """
        return self.config['reporting']['severity_levels']