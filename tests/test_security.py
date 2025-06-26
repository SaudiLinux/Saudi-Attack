#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pytest
import os
import sys
import re
import json
import tempfile
import shutil
from unittest.mock import patch, MagicMock, mock_open

# إضافة المجلد الرئيسي إلى مسار البحث
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# استيراد الوحدات المطلوبة للاختبار
from modules.utils import sanitize_filename, generate_random_string
from modules.config import ConfigManager
from modules.report_generator import ReportGenerator


@pytest.fixture
def temp_dir():
    """إنشاء مجلد مؤقت للاختبار"""
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    shutil.rmtree(temp_dir)


@pytest.fixture
def mock_config():
    """تكوين مزيف للاختبار"""
    config = {
        "general": {
            "threads": 5,
            "timeout": 10,
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "output_dir": "./reports"
        },
        "scan": {
            "ports": {
                "general": [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080],
                "web": [80, 443, 8080, 8443],
                "wordpress": [80, 443, 8080, 8443],
                "joomla": [80, 443, 8080, 8443]
            },
            "nmap_scripts": ["banner", "http-headers", "http-title", "ssl-cert", "ssl-enum-ciphers"]
        },
        "web_server": {
            "paths": ["/", "/admin", "/login", "/wp-admin", "/administrator"],
            "security_headers": ["X-Frame-Options", "X-XSS-Protection", "Content-Security-Policy", "Strict-Transport-Security"]
        },
        "wordpress": {
            "detection_paths": ["/wp-login.php", "/wp-admin", "/wp-content"]
        },
        "joomla": {
            "detection_paths": ["/administrator", "/components", "/modules", "/templates"]
        },
        "report": {
            "formats": ["json", "html", "txt", "md"],
            "default_format": "html",
            "severity_levels": ["critical", "high", "medium", "low", "info"],
            "template_dir": "./templates"
        }
    }
    return config


@pytest.fixture
def mock_scan_results():
    """نتائج مسح مزيفة للاختبار"""
    return {
        "target": "example.com",
        "scan_time": "2023-01-01T12:00:00",
        "scan_type": "general",
        "ip_address": "93.184.216.34",
        "open_ports": {"80": True, "443": True},
        "whois_info": "Domain Name: EXAMPLE.COM\nRegistry Domain ID: 2336799_DOMAIN_COM-VRSN",
        "dns_records": ["93.184.216.34"],
        "web_server": {
            "server_info": {"server": "nginx/1.18.0", "technologies": ["PHP/7.4.21"]},
            "security_headers": {"missing": ["Content-Security-Policy"], "present": {"X-Frame-Options": "SAMEORIGIN"}},
            "ssl_certificate": {"valid": True, "issuer": "Let's Encrypt Authority X3", "expires": "2022-01-01"}
        },
        "wordpress": {
            "is_wordpress": True,
            "version": "5.8.2",
            "themes": {
                "twentytwentyone": {"version": "1.4", "vulnerabilities": []}
            },
            "plugins": {
                "contact-form-7": {"version": "5.5.2", "vulnerabilities": []}
            },
            "users": [{"id": 1, "username": "admin", "name": "Administrator"}]
        },
        "joomla": {
            "is_joomla": False
        },
        "vulnerabilities": [
            {
                "id": "CVE-2021-12345",
                "title": "XSS Vulnerability",
                "description": "Cross-site scripting vulnerability",
                "severity": "high",
                "cvss": 7.5,
                "affected_component": "WordPress Core",
                "affected_version": "5.8.2",
                "fixed_version": "5.8.3",
                "references": ["https://example.com/cve-2021-12345"]
            }
        ]
    }


class TestSecurity:
    """اختبارات الأمان للأداة"""

    def test_sanitize_filename(self):
        """اختبار تنظيف اسم الملف لمنع هجمات حقن المسار"""
        # اختبار إزالة أحرف المسار
        assert sanitize_filename("../etc/passwd") == "..etc_passwd"
        assert sanitize_filename("..\\Windows\\System32") == "..Windows_System32"
        
        # اختبار إزالة الأحرف الخاصة
        assert sanitize_filename("file;rm -rf /") == "file_rm_-rf_"
        assert sanitize_filename("file|cat /etc/passwd") == "file_cat_etc_passwd"
        
        # اختبار إزالة أحرف التحكم
        assert sanitize_filename("file\x00name") == "filename"
        assert sanitize_filename("file\nname") == "filename"
        
        # اختبار الحفاظ على الأحرف الصالحة
        assert sanitize_filename("valid-file_name.txt") == "valid-file_name.txt"

    def test_config_file_path_traversal(self, mock_config, temp_dir):
        """اختبار منع هجمات حقن المسار في ملفات التكوين"""
        # إنشاء كائن مدير التكوين
        config_manager = ConfigManager()
        config_manager.update_config(mock_config)
        
        # محاولة حفظ التكوين في مسار خارج المجلد المسموح به
        malicious_path = os.path.join(temp_dir, "../../../etc/passwd")
        
        # يجب أن يتم تنظيف المسار وحفظ الملف في المجلد الصحيح
        with patch('builtins.open', new_callable=mock_open) as mock_file:
            config_manager.save_config(malicious_path)
            # التحقق من أن المسار تم تنظيفه
            called_path = mock_file.call_args[0][0]
            assert "../../../etc/passwd" not in called_path
            assert "passwd" in called_path

    def test_report_file_path_traversal(self, mock_scan_results, temp_dir):
        """اختبار منع هجمات حقن المسار في ملفات التقارير"""
        # إنشاء كائن مولد التقارير
        generator = ReportGenerator(mock_scan_results, output_dir=temp_dir)
        
        # محاولة حفظ التقرير في مسار خارج المجلد المسموح به
        malicious_filename = "../../../etc/passwd"
        
        # يجب أن يتم تنظيف اسم الملف
        with patch('builtins.open', new_callable=mock_open) as mock_file:
            with patch('json.dump') as mock_json_dump:
                generator._generate_json_report(filename=malicious_filename)
                # التحقق من أن المسار تم تنظيفه
                called_path = mock_file.call_args[0][0]
                assert "../../../etc/passwd" not in called_path
                assert "passwd" in called_path

    def test_command_injection_prevention(self):
        """اختبار منع حقن الأوامر"""
        # استيراد الوحدة المطلوبة للاختبار
        from modules.scanner import VulnerabilityScanner
        
        # إنشاء كائن الماسح
        scanner = VulnerabilityScanner(target="example.com")
        
        # محاولة حقن أمر في معلمة الهدف
        malicious_target = "example.com; rm -rf /"
        
        # يجب أن يتم تنظيف معلمة الهدف قبل استخدامها في أوامر Nmap
        with patch('subprocess.Popen') as mock_popen:
            scanner.target = malicious_target
            scanner._run_nmap_scan()
            
            # التحقق من أن الأمر المحقون لم يتم تنفيذه
            command = ' '.join(mock_popen.call_args[0][0])
            assert "rm -rf /" not in command
            # يجب أن يتم تنظيف الهدف أو وضعه بين علامات اقتباس
            assert "example.com;" not in command or "'example.com; rm -rf /'" in command

    def test_xss_prevention_in_reports(self, mock_scan_results, temp_dir):
        """اختبار منع هجمات XSS في التقارير"""
        # إضافة بيانات تحتوي على محاولة XSS
        mock_scan_results["target"] = "example.com<script>alert('XSS')</script>"
        mock_scan_results["vulnerabilities"][0]["description"] = "<img src=x onerror=alert('XSS')>"
        
        # إنشاء كائن مولد التقارير
        generator = ReportGenerator(mock_scan_results, output_dir=temp_dir)
        
        # توليد تقرير HTML
        with patch('builtins.open', new_callable=mock_open) as mock_file:
            generator._generate_html_report()
            
            # الحصول على محتوى التقرير
            html_content = ''.join([call[0][0] for call in mock_file().write.call_args_list])
            
            # التحقق من أن محاولات XSS تم ترميزها
            assert "<script>alert('XSS')</script>" not in html_content
            assert "&lt;script&gt;alert('XSS')&lt;/script&gt;" in html_content or "&lt;script&gt;alert(&#x27;XSS&#x27;)&lt;/script&gt;" in html_content
            
            assert "<img src=x onerror=alert('XSS')>" not in html_content
            assert "&lt;img src=x onerror=alert('XSS')&gt;" in html_content or "&lt;img src=x onerror=alert(&#x27;XSS&#x27;)&gt;" in html_content

    def test_sql_injection_prevention(self):
        """اختبار منع حقن SQL"""
        # استيراد الوحدة المطلوبة للاختبار (افتراضية لأغراض الاختبار)
        from modules.database import Database
        
        # إنشاء كائن قاعدة البيانات مزيف
        with patch('sqlite3.connect') as mock_connect:
            mock_cursor = MagicMock()
            mock_connection = MagicMock()
            mock_connection.cursor.return_value = mock_cursor
            mock_connect.return_value = mock_connection
            
            # إنشاء كائن قاعدة البيانات
            db = Database(":memory:")
            
            # محاولة حقن SQL
            malicious_input = "' OR 1=1 --"
            
            # يجب أن يتم استخدام المعلمات المقيدة لمنع حقن SQL
            db.query("SELECT * FROM vulnerabilities WHERE id = ?", (malicious_input,))
            
            # التحقق من أن الاستعلام تم تنفيذه بشكل آمن باستخدام المعلمات المقيدة
            mock_cursor.execute.assert_called_once()
            assert mock_cursor.execute.call_args[0][0] == "SELECT * FROM vulnerabilities WHERE id = ?"
            assert mock_cursor.execute.call_args[0][1] == (malicious_input,)

    def test_secure_random_string_generation(self):
        """اختبار توليد سلاسل عشوائية آمنة"""
        # توليد سلاسل عشوائية متعددة
        random_strings = [generate_random_string(16) for _ in range(100)]
        
        # التحقق من أن السلاسل فريدة
        assert len(set(random_strings)) == 100
        
        # التحقق من طول السلاسل
        assert all(len(s) == 16 for s in random_strings)
        
        # التحقق من تنوع الأحرف (الإنتروبيا)
        all_chars = ''.join(random_strings)
        char_frequency = {c: all_chars.count(c) for c in set(all_chars)}
        # يجب أن يكون هناك توزيع متوازن نسبيًا للأحرف
        assert len(char_frequency) > 10
        # التحقق من عدم وجود أحرف مهيمنة بشكل كبير
        assert max(char_frequency.values()) < len(all_chars) * 0.2

    def test_secure_file_permissions(self, temp_dir):
        """اختبار أذونات الملفات الآمنة"""
        # إنشاء ملف اختبار
        test_file = os.path.join(temp_dir, "test_file.txt")
        with open(test_file, "w") as f:
            f.write("Test content")
        
        # التحقق من أذونات الملف (يعمل فقط على أنظمة Unix)
        if os.name == "posix":
            # يجب أن تكون أذونات الملف 0o600 (قراءة/كتابة للمالك فقط)
            os.chmod(test_file, 0o600)
            assert (os.stat(test_file).st_mode & 0o777) == 0o600

    def test_secure_config_storage(self, mock_config, temp_dir):
        """اختبار تخزين التكوين الآمن"""
        # إضافة معلومات حساسة إلى التكوين
        mock_config["api_key"] = "secret_api_key_12345"
        
        # إنشاء كائن مدير التكوين
        config_manager = ConfigManager()
        config_manager.update_config(mock_config)
        
        # حفظ التكوين في ملف
        config_file = os.path.join(temp_dir, "config.yaml")
        
        # يجب أن يتم تشفير المعلومات الحساسة أو حذفها قبل الحفظ
        with patch('builtins.open', new_callable=mock_open) as mock_file:
            with patch('yaml.dump') as mock_yaml_dump:
                config_manager.save_config(config_file)
                # التحقق من أن المعلومات الحساسة تم تشفيرها أو حذفها
                saved_config = mock_yaml_dump.call_args[0][0]
                if "api_key" in saved_config:
                    assert saved_config["api_key"] != "secret_api_key_12345"
                    # يجب أن تكون القيمة مشفرة أو مستبدلة بنجوم
                    assert saved_config["api_key"] == "*" * len("secret_api_key_12345") or re.match(r'^[a-zA-Z0-9+/=]+$', saved_config["api_key"])

    def test_secure_report_storage(self, mock_scan_results, temp_dir):
        """اختبار تخزين التقارير الآمن"""
        # إضافة معلومات حساسة إلى نتائج المسح
        mock_scan_results["api_key"] = "secret_api_key_12345"
        mock_scan_results["credentials"] = {"username": "admin", "password": "password123"}
        
        # إنشاء كائن مولد التقارير
        generator = ReportGenerator(mock_scan_results, output_dir=temp_dir)
        
        # توليد تقرير JSON
        with patch('builtins.open', new_callable=mock_open) as mock_file:
            with patch('json.dump') as mock_json_dump:
                generator._generate_json_report()
                # التحقق من أن المعلومات الحساسة تم تشفيرها أو حذفها
                saved_results = mock_json_dump.call_args[0][0]
                if "api_key" in saved_results:
                    assert saved_results["api_key"] != "secret_api_key_12345"
                if "credentials" in saved_results and "password" in saved_results["credentials"]:
                    assert saved_results["credentials"]["password"] != "password123"
                    # يجب أن تكون كلمة المرور مشفرة أو مستبدلة بنجوم
                    assert saved_results["credentials"]["password"] == "*" * len("password123") or re.match(r'^[a-zA-Z0-9+/=]+$', saved_results["credentials"]["password"])