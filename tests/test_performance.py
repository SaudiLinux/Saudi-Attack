#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pytest
import os
import sys
import time
import tempfile
import shutil
from unittest.mock import patch, MagicMock

# إضافة المجلد الرئيسي إلى مسار البحث
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# استيراد الوحدات المطلوبة للاختبار
from modules.scanner import VulnerabilityScanner
from modules.web_scanner import WebServerScanner
from modules.wordpress_scanner import WordPressScanner
from modules.joomla_scanner import JoomlaScanner
from modules.config import ConfigManager
from modules.report_generator import ReportGenerator
from main import run_scan


@pytest.fixture
def temp_reports_dir():
    """إنشاء مجلد مؤقت للتقارير"""
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


class TestPerformance:
    """اختبارات الأداء للأداة"""

    @patch('modules.scanner.VulnerabilityScanner._run_nmap_scan')
    def test_scanner_performance(self, mock_run_nmap, mock_config, temp_reports_dir):
        """اختبار أداء وحدة المسح"""
        # تكوين السلوك المزيف
        mock_run_nmap.return_value = """
        Starting Nmap 7.91
        Nmap scan report for example.com (93.184.216.34)
        Host is up (0.15s latency).
        PORT    STATE SERVICE  VERSION
        80/tcp  open  http     nginx
        443/tcp open  https    nginx
        
        Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
        Nmap done: 1 IP address (1 host up) scanned in 15.20 seconds
        """
        
        # إنشاء كائن الماسح
        scanner = VulnerabilityScanner(target="example.com", config=mock_config)
        
        # قياس وقت التنفيذ
        start_time = time.time()
        results = scanner.scan()
        end_time = time.time()
        
        # التحقق من النتائج
        assert results is not None
        assert "target" in results
        assert results["target"] == "example.com"
        
        # التحقق من الأداء
        execution_time = end_time - start_time
        assert execution_time < 2.0  # يجب أن يكون وقت التنفيذ أقل من 2 ثانية

    @patch('modules.web_scanner.WebServerScanner._get_web_server_info')
    @patch('modules.web_scanner.WebServerScanner._check_security_headers')
    @patch('modules.web_scanner.WebServerScanner._check_ssl_certificate')
    def test_web_scanner_performance(self, mock_check_ssl, mock_check_headers, mock_get_info, mock_config):
        """اختبار أداء وحدة مسح خادم الويب"""
        # تكوين السلوك المزيف
        mock_get_info.return_value = {
            "server": "nginx/1.18.0",
            "technologies": ["PHP/7.4.21", "WordPress/5.8.2"],
            "status_code": 200
        }
        mock_check_headers.return_value = {
            "missing": ["Content-Security-Policy"],
            "present": {"X-Frame-Options": "SAMEORIGIN"}
        }
        mock_check_ssl.return_value = {
            "valid": True,
            "issuer": "Let's Encrypt Authority X3",
            "expires": "2022-01-01"
        }
        
        # إنشاء كائن الماسح
        scanner = WebServerScanner(target="example.com", config=mock_config)
        
        # قياس وقت التنفيذ
        start_time = time.time()
        results = scanner.scan()
        end_time = time.time()
        
        # التحقق من النتائج
        assert results is not None
        assert "server_info" in results
        assert "security_headers" in results
        assert "ssl_certificate" in results
        
        # التحقق من الأداء
        execution_time = end_time - start_time
        assert execution_time < 1.0  # يجب أن يكون وقت التنفيذ أقل من 1 ثانية

    @patch('modules.wordpress_scanner.WordPressScanner._is_wordpress')
    @patch('modules.wordpress_scanner.WordPressScanner._get_wordpress_version')
    @patch('modules.wordpress_scanner.WordPressScanner._get_themes')
    @patch('modules.wordpress_scanner.WordPressScanner._get_plugins')
    @patch('modules.wordpress_scanner.WordPressScanner._enumerate_users')
    def test_wordpress_scanner_performance(self, mock_users, mock_plugins, mock_themes, mock_version, mock_is_wp, mock_config):
        """اختبار أداء وحدة مسح ووردبريس"""
        # تكوين السلوك المزيف
        mock_is_wp.return_value = True
        mock_version.return_value = "5.8.2"
        mock_themes.return_value = {
            "twentytwentyone": {"version": "1.4", "vulnerabilities": []},
            "twentytwenty": {"version": "1.8", "vulnerabilities": []}
        }
        mock_plugins.return_value = {
            "contact-form-7": {"version": "5.5.2", "vulnerabilities": []},
            "woocommerce": {"version": "5.9.0", "vulnerabilities": []}
        }
        mock_users.return_value = [
            {"id": 1, "username": "admin", "name": "Administrator"}
        ]
        
        # إنشاء كائن الماسح
        scanner = WordPressScanner(target="example.com", config=mock_config)
        
        # قياس وقت التنفيذ
        start_time = time.time()
        results = scanner.scan()
        end_time = time.time()
        
        # التحقق من النتائج
        assert results is not None
        assert results["is_wordpress"] is True
        assert results["version"] == "5.8.2"
        assert len(results["themes"]) == 2
        assert len(results["plugins"]) == 2
        assert len(results["users"]) == 1
        
        # التحقق من الأداء
        execution_time = end_time - start_time
        assert execution_time < 1.0  # يجب أن يكون وقت التنفيذ أقل من 1 ثانية

    @patch('modules.joomla_scanner.JoomlaScanner._is_joomla')
    @patch('modules.joomla_scanner.JoomlaScanner._get_joomla_version')
    @patch('modules.joomla_scanner.JoomlaScanner._get_components')
    @patch('modules.joomla_scanner.JoomlaScanner._get_templates')
    def test_joomla_scanner_performance(self, mock_templates, mock_components, mock_version, mock_is_joomla, mock_config):
        """اختبار أداء وحدة مسح جوملا"""
        # تكوين السلوك المزيف
        mock_is_joomla.return_value = True
        mock_version.return_value = "3.9.26"
        mock_components.return_value = {
            "com_content": {"version": "3.9.26", "vulnerabilities": []},
            "com_contact": {"version": "3.9.26", "vulnerabilities": []}
        }
        mock_templates.return_value = {
            "protostar": {"version": "3.9.26", "vulnerabilities": []},
            "beez3": {"version": "3.9.26", "vulnerabilities": []}
        }
        
        # إنشاء كائن الماسح
        scanner = JoomlaScanner(target="example.com", config=mock_config)
        
        # قياس وقت التنفيذ
        start_time = time.time()
        results = scanner.scan()
        end_time = time.time()
        
        # التحقق من النتائج
        assert results is not None
        assert results["is_joomla"] is True
        assert results["version"] == "3.9.26"
        assert len(results["components"]) == 2
        assert len(results["templates"]) == 2
        
        # التحقق من الأداء
        execution_time = end_time - start_time
        assert execution_time < 1.0  # يجب أن يكون وقت التنفيذ أقل من 1 ثانية

    @patch('modules.report_generator.ReportGenerator._generate_json_report')
    @patch('modules.report_generator.ReportGenerator._generate_html_report')
    @patch('modules.report_generator.ReportGenerator._generate_txt_report')
    @patch('modules.report_generator.ReportGenerator._generate_md_report')
    def test_report_generator_performance(self, mock_md, mock_txt, mock_html, mock_json, mock_config, temp_reports_dir):
        """اختبار أداء وحدة توليد التقارير"""
        # تكوين السلوك المزيف
        mock_json.return_value = os.path.join(temp_reports_dir, "report.json")
        mock_html.return_value = os.path.join(temp_reports_dir, "report.html")
        mock_txt.return_value = os.path.join(temp_reports_dir, "report.txt")
        mock_md.return_value = os.path.join(temp_reports_dir, "report.md")
        
        # إنشاء بيانات التقرير
        scan_results = {
            "target": "example.com",
            "scan_time": "2023-01-01T12:00:00",
            "scan_type": "general",
            "open_ports": {"80": True, "443": True},
            "vulnerabilities": [
                {"id": "CVE-2021-12345", "severity": "high", "description": "Test vulnerability"}
            ]
        }
        
        # إنشاء كائن مولد التقارير
        generator = ReportGenerator(scan_results, output_dir=temp_reports_dir, config=mock_config)
        
        # قياس وقت التنفيذ
        start_time = time.time()
        generator.generate_report(formats=["json", "html", "txt", "md"])
        end_time = time.time()
        
        # التحقق من النتائج
        assert mock_json.call_count == 1
        assert mock_html.call_count == 1
        assert mock_txt.call_count == 1
        assert mock_md.call_count == 1
        
        # التحقق من الأداء
        execution_time = end_time - start_time
        assert execution_time < 1.0  # يجب أن يكون وقت التنفيذ أقل من 1 ثانية

    @patch('modules.config.ConfigManager.load_config')
    @patch('modules.scanner.VulnerabilityScanner.scan')
    @patch('modules.web_scanner.WebServerScanner.scan')
    @patch('modules.wordpress_scanner.WordPressScanner.scan')
    @patch('modules.joomla_scanner.JoomlaScanner.scan')
    @patch('modules.report_generator.ReportGenerator.generate_report')
    def test_full_scan_performance(self, mock_report, mock_joomla, mock_wp, mock_web, mock_vuln, mock_config_load, mock_config, temp_reports_dir):
        """اختبار أداء المسح الكامل"""
        # تكوين السلوك المزيف
        mock_config_load.return_value = mock_config
        mock_vuln.return_value = {"target": "example.com", "open_ports": {"80": True, "443": True}}
        mock_web.return_value = {"server_info": {"server": "nginx"}, "security_headers": {}}
        mock_wp.return_value = {"is_wordpress": False}
        mock_joomla.return_value = {"is_joomla": False}
        mock_report.return_value = [os.path.join(temp_reports_dir, "report.html")]
        
        # قياس وقت التنفيذ
        start_time = time.time()
        result = run_scan(target="example.com", scan_type="general", output_format="html", config_file=None, verbose=False)
        end_time = time.time()
        
        # التحقق من النتائج
        assert result is not None
        assert mock_vuln.call_count == 1
        assert mock_web.call_count == 1
        assert mock_wp.call_count == 1
        assert mock_joomla.call_count == 1
        assert mock_report.call_count == 1
        
        # التحقق من الأداء
        execution_time = end_time - start_time
        assert execution_time < 3.0  # يجب أن يكون وقت التنفيذ أقل من 3 ثوانٍ

    @patch('modules.config.ConfigManager.load_config')
    @patch('modules.scanner.VulnerabilityScanner.scan')
    @patch('modules.web_scanner.WebServerScanner.scan')
    @patch('modules.wordpress_scanner.WordPressScanner.scan')
    @patch('modules.joomla_scanner.JoomlaScanner.scan')
    @patch('modules.report_generator.ReportGenerator.generate_report')
    def test_web_scan_performance(self, mock_report, mock_joomla, mock_wp, mock_web, mock_vuln, mock_config_load, mock_config, temp_reports_dir):
        """اختبار أداء مسح الويب"""
        # تكوين السلوك المزيف
        mock_config_load.return_value = mock_config
        mock_vuln.return_value = {"target": "example.com", "open_ports": {"80": True, "443": True}}
        mock_web.return_value = {"server_info": {"server": "nginx"}, "security_headers": {}}
        mock_wp.return_value = {"is_wordpress": True, "version": "5.8.2"}
        mock_joomla.return_value = {"is_joomla": False}
        mock_report.return_value = [os.path.join(temp_reports_dir, "report.html")]
        
        # قياس وقت التنفيذ
        start_time = time.time()
        result = run_scan(target="example.com", scan_type="web", output_format="html", config_file=None, verbose=False)
        end_time = time.time()
        
        # التحقق من النتائج
        assert result is not None
        assert mock_vuln.call_count == 1
        assert mock_web.call_count == 1
        assert mock_wp.call_count == 1
        assert mock_joomla.call_count == 1
        assert mock_report.call_count == 1
        
        # التحقق من الأداء
        execution_time = end_time - start_time
        assert execution_time < 3.0  # يجب أن يكون وقت التنفيذ أقل من 3 ثوانٍ

    def test_config_manager_performance(self, mock_config):
        """اختبار أداء مدير التكوين"""
        # قياس وقت التنفيذ لإنشاء كائن مدير التكوين
        start_time = time.time()
        config_manager = ConfigManager()
        end_time = time.time()
        
        # التحقق من الأداء
        execution_time = end_time - start_time
        assert execution_time < 0.1  # يجب أن يكون وقت التنفيذ أقل من 0.1 ثانية
        
        # قياس وقت التنفيذ لتحديث التكوين
        start_time = time.time()
        config_manager.update_config(mock_config)
        end_time = time.time()
        
        # التحقق من الأداء
        execution_time = end_time - start_time
        assert execution_time < 0.1  # يجب أن يكون وقت التنفيذ أقل من 0.1 ثانية
        
        # قياس وقت التنفيذ للحصول على التكوين
        start_time = time.time()
        config = config_manager.get_config()
        end_time = time.time()
        
        # التحقق من النتائج
        assert config is not None
        
        # التحقق من الأداء
        execution_time = end_time - start_time
        assert execution_time < 0.1  # يجب أن يكون وقت التنفيذ أقل من 0.1 ثانية