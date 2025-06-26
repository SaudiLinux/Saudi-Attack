#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pytest
import os
import sys
import json
from unittest.mock import patch, MagicMock

# إضافة المجلد الرئيسي إلى مسار البحث
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# استيراد وحدة واجهة برمجة التطبيقات
from modules.api import SaudiAttackAPI


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


class TestAPI:
    """اختبارات لوحدة واجهة برمجة التطبيقات"""

    def test_api_initialization(self, mock_config):
        """اختبار تهيئة واجهة برمجة التطبيقات"""
        api = SaudiAttackAPI(config=mock_config)
        assert api.config == mock_config

    @patch('modules.scanner.VulnerabilityScanner.scan')
    @patch('modules.web_scanner.WebServerScanner.scan')
    @patch('modules.wordpress_scanner.WordPressScanner.scan')
    @patch('modules.joomla_scanner.JoomlaScanner.scan')
    def test_scan_target(self, mock_joomla, mock_wp, mock_web, mock_vuln, mock_config):
        """اختبار مسح الهدف"""
        # تكوين السلوك المزيف
        mock_vuln.return_value = {"target": "example.com", "open_ports": {"80": True, "443": True}}
        mock_web.return_value = {"server_info": {"server": "nginx"}, "security_headers": {}}
        mock_wp.return_value = {"is_wordpress": True, "version": "5.8.2"}
        mock_joomla.return_value = {"is_joomla": False}
        
        # إنشاء كائن واجهة برمجة التطبيقات
        api = SaudiAttackAPI(config=mock_config)
        
        # تنفيذ الاختبار
        results = api.scan_target("example.com", scan_type="general")
        
        # التحقق من النتائج
        assert results is not None
        assert "target" in results
        assert results["target"] == "example.com"
        assert "open_ports" in results
        assert "web_server" in results
        assert "wordpress" in results
        assert "joomla" in results
        
        # التحقق من استدعاء الدوال
        mock_vuln.assert_called_once()
        mock_web.assert_called_once()
        mock_wp.assert_called_once()
        mock_joomla.assert_called_once()

    @patch('modules.scanner.VulnerabilityScanner.scan')
    @patch('modules.web_scanner.WebServerScanner.scan')
    def test_scan_target_web_only(self, mock_web, mock_vuln, mock_config):
        """اختبار مسح الهدف لخادم الويب فقط"""
        # تكوين السلوك المزيف
        mock_vuln.return_value = {"target": "example.com", "open_ports": {"80": True, "443": True}}
        mock_web.return_value = {"server_info": {"server": "nginx"}, "security_headers": {}}
        
        # إنشاء كائن واجهة برمجة التطبيقات
        api = SaudiAttackAPI(config=mock_config)
        
        # تنفيذ الاختبار
        results = api.scan_target("example.com", scan_type="web_only")
        
        # التحقق من النتائج
        assert results is not None
        assert "target" in results
        assert results["target"] == "example.com"
        assert "open_ports" in results
        assert "web_server" in results
        
        # التحقق من استدعاء الدوال
        mock_vuln.assert_called_once()
        mock_web.assert_called_once()

    @patch('modules.scanner.VulnerabilityScanner.scan')
    @patch('modules.wordpress_scanner.WordPressScanner.scan')
    def test_scan_target_wordpress_only(self, mock_wp, mock_vuln, mock_config):
        """اختبار مسح الهدف لووردبريس فقط"""
        # تكوين السلوك المزيف
        mock_vuln.return_value = {"target": "example.com", "open_ports": {"80": True, "443": True}}
        mock_wp.return_value = {"is_wordpress": True, "version": "5.8.2"}
        
        # إنشاء كائن واجهة برمجة التطبيقات
        api = SaudiAttackAPI(config=mock_config)
        
        # تنفيذ الاختبار
        results = api.scan_target("example.com", scan_type="wordpress")
        
        # التحقق من النتائج
        assert results is not None
        assert "target" in results
        assert results["target"] == "example.com"
        assert "open_ports" in results
        assert "wordpress" in results
        assert results["wordpress"]["is_wordpress"] is True
        
        # التحقق من استدعاء الدوال
        mock_vuln.assert_called_once()
        mock_wp.assert_called_once()

    @patch('modules.scanner.VulnerabilityScanner.scan')
    @patch('modules.joomla_scanner.JoomlaScanner.scan')
    def test_scan_target_joomla_only(self, mock_joomla, mock_vuln, mock_config):
        """اختبار مسح الهدف لجوملا فقط"""
        # تكوين السلوك المزيف
        mock_vuln.return_value = {"target": "example.com", "open_ports": {"80": True, "443": True}}
        mock_joomla.return_value = {"is_joomla": True, "version": "3.9.26"}
        
        # إنشاء كائن واجهة برمجة التطبيقات
        api = SaudiAttackAPI(config=mock_config)
        
        # تنفيذ الاختبار
        results = api.scan_target("example.com", scan_type="joomla")
        
        # التحقق من النتائج
        assert results is not None
        assert "target" in results
        assert results["target"] == "example.com"
        assert "open_ports" in results
        assert "joomla" in results
        assert results["joomla"]["is_joomla"] is True
        
        # التحقق من استدعاء الدوال
        mock_vuln.assert_called_once()
        mock_joomla.assert_called_once()

    @patch('modules.report_generator.ReportGenerator.generate_report')
    def test_generate_report(self, mock_generate_report, mock_config, mock_scan_results):
        """اختبار توليد التقرير"""
        # تكوين السلوك المزيف
        mock_generate_report.return_value = ["report.html", "report.json"]
        
        # إنشاء كائن واجهة برمجة التطبيقات
        api = SaudiAttackAPI(config=mock_config)
        
        # تنفيذ الاختبار
        report_files = api.generate_report(mock_scan_results, formats=["html", "json"])
        
        # التحقق من النتائج
        assert report_files is not None
        assert len(report_files) == 2
        assert "report.html" in report_files
        assert "report.json" in report_files
        
        # التحقق من استدعاء الدوال
        mock_generate_report.assert_called_once_with(formats=["html", "json"])

    @patch('modules.vulnerability_database.VulnerabilityDatabase.check_wordpress_core_vulnerabilities')
    def test_check_vulnerabilities_wordpress(self, mock_check_wp_vulns, mock_config):
        """اختبار التحقق من ثغرات ووردبريس"""
        # تكوين السلوك المزيف
        mock_check_wp_vulns.return_value = [
            {
                "id": "CVE-2021-12345",
                "title": "XSS Vulnerability",
                "description": "Cross-site scripting vulnerability",
                "severity": "high",
                "cvss": 7.5,
                "affected_versions": ["<5.8.3"],
                "fixed_version": "5.8.3",
                "references": ["https://example.com/cve-2021-12345"]
            }
        ]
        
        # إنشاء كائن واجهة برمجة التطبيقات
        api = SaudiAttackAPI(config=mock_config)
        
        # تنفيذ الاختبار
        vulnerabilities = api.check_vulnerabilities("wordpress", "core", "5.8.2")
        
        # التحقق من النتائج
        assert vulnerabilities is not None
        assert len(vulnerabilities) == 1
        assert vulnerabilities[0]["id"] == "CVE-2021-12345"
        assert vulnerabilities[0]["severity"] == "high"
        
        # التحقق من استدعاء الدوال
        mock_check_wp_vulns.assert_called_once_with("5.8.2")

    @patch('modules.vulnerability_database.VulnerabilityDatabase.check_wordpress_plugin_vulnerabilities')
    def test_check_vulnerabilities_wordpress_plugin(self, mock_check_plugin_vulns, mock_config):
        """اختبار التحقق من ثغرات إضافات ووردبريس"""
        # تكوين السلوك المزيف
        mock_check_plugin_vulns.return_value = [
            {
                "id": "CVE-2021-54321",
                "title": "SQL Injection",
                "description": "SQL injection vulnerability",
                "severity": "critical",
                "cvss": 9.0,
                "affected_versions": ["<5.5.3"],
                "fixed_version": "5.5.3",
                "references": ["https://example.com/cve-2021-54321"]
            }
        ]
        
        # إنشاء كائن واجهة برمجة التطبيقات
        api = SaudiAttackAPI(config=mock_config)
        
        # تنفيذ الاختبار
        vulnerabilities = api.check_vulnerabilities("wordpress", "plugin", "5.5.2", component_name="contact-form-7")
        
        # التحقق من النتائج
        assert vulnerabilities is not None
        assert len(vulnerabilities) == 1
        assert vulnerabilities[0]["id"] == "CVE-2021-54321"
        assert vulnerabilities[0]["severity"] == "critical"
        
        # التحقق من استدعاء الدوال
        mock_check_plugin_vulns.assert_called_once_with("contact-form-7", "5.5.2")

    @patch('modules.api.SaudiAttackAPI.scan_target')
    def test_scan_multiple_targets(self, mock_scan_target, mock_config):
        """اختبار مسح أهداف متعددة"""
        # تكوين السلوك المزيف
        mock_scan_target.side_effect = [
            {"target": "example.com", "open_ports": {"80": True}},
            {"target": "example.org", "open_ports": {"443": True}}
        ]
        
        # إنشاء كائن واجهة برمجة التطبيقات
        api = SaudiAttackAPI(config=mock_config)
        
        # تنفيذ الاختبار
        results = api.scan_multiple_targets(["example.com", "example.org"], scan_type="general")
        
        # التحقق من النتائج
        assert results is not None
        assert len(results) == 2
        assert results[0]["target"] == "example.com"
        assert results[1]["target"] == "example.org"
        
        # التحقق من استدعاء الدوال
        assert mock_scan_target.call_count == 2
        mock_scan_target.assert_any_call("example.com", scan_type="general")
        mock_scan_target.assert_any_call("example.org", scan_type="general")

    @patch('modules.api.SaudiAttackAPI.scan_target')
    @patch('modules.api.SaudiAttackAPI.generate_report')
    def test_scan_and_report(self, mock_generate_report, mock_scan_target, mock_config, mock_scan_results):
        """اختبار المسح وتوليد التقرير"""
        # تكوين السلوك المزيف
        mock_scan_target.return_value = mock_scan_results
        mock_generate_report.return_value = ["report.html"]
        
        # إنشاء كائن واجهة برمجة التطبيقات
        api = SaudiAttackAPI(config=mock_config)
        
        # تنفيذ الاختبار
        results, report_files = api.scan_and_report("example.com", scan_type="general", formats=["html"])
        
        # التحقق من النتائج
        assert results is not None
        assert report_files is not None
        assert results == mock_scan_results
        assert len(report_files) == 1
        assert "report.html" in report_files
        
        # التحقق من استدعاء الدوال
        mock_scan_target.assert_called_once_with("example.com", scan_type="general")
        mock_generate_report.assert_called_once_with(mock_scan_results, formats=["html"])

    def test_get_config(self, mock_config):
        """اختبار الحصول على التكوين"""
        # إنشاء كائن واجهة برمجة التطبيقات
        api = SaudiAttackAPI(config=mock_config)
        
        # تنفيذ الاختبار
        config = api.get_config()
        
        # التحقق من النتائج
        assert config is not None
        assert config == mock_config

    def test_update_config(self, mock_config):
        """اختبار تحديث التكوين"""
        # إنشاء كائن واجهة برمجة التطبيقات
        api = SaudiAttackAPI(config=mock_config)
        
        # تكوين جديد
        new_config = {"general": {"threads": 10}}
        
        # تنفيذ الاختبار
        api.update_config(new_config)
        
        # التحقق من النتائج
        assert api.config["general"]["threads"] == 10
        
        # التحقق من الحفاظ على القيم الأخرى
        assert "timeout" in api.config["general"]
        assert api.config["general"]["timeout"] == 10

    @patch('json.dump')
    @patch('builtins.open', new_callable=MagicMock)
    def test_save_results_to_file(self, mock_open, mock_json_dump, mock_scan_results):
        """اختبار حفظ النتائج إلى ملف"""
        # إنشاء كائن واجهة برمجة التطبيقات
        api = SaudiAttackAPI()
        
        # تنفيذ الاختبار
        filename = api.save_results_to_file(mock_scan_results, "results.json")
        
        # التحقق من النتائج
        assert filename == "results.json"
        mock_open.assert_called_once_with("results.json", "w", encoding="utf-8")
        mock_json_dump.assert_called_once()
        assert mock_json_dump.call_args[0][0] == mock_scan_results

    @patch('json.load')
    @patch('builtins.open', new_callable=MagicMock)
    def test_load_results_from_file(self, mock_open, mock_json_load, mock_scan_results):
        """اختبار تحميل النتائج من ملف"""
        # تكوين السلوك المزيف
        mock_json_load.return_value = mock_scan_results
        
        # إنشاء كائن واجهة برمجة التطبيقات
        api = SaudiAttackAPI()
        
        # تنفيذ الاختبار
        results = api.load_results_from_file("results.json")
        
        # التحقق من النتائج
        assert results is not None
        assert results == mock_scan_results
        mock_open.assert_called_once_with("results.json", "r", encoding="utf-8")
        mock_json_load.assert_called_once()