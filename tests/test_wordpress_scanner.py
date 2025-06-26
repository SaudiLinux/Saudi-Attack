# -*- coding: utf-8 -*-

import pytest
import requests
from unittest.mock import patch, MagicMock, mock_open
import json
import os
from modules.wordpress_scanner import WordPressScanner
from rich.console import Console


class TestWordPressScanner:
    """اختبارات لوحدة فحص ووردبريس"""

    def setup_method(self):
        """إعداد بيئة الاختبار قبل كل اختبار"""
        self.target = "example.com"
        self.ports = [80, 443]
        self.threads = 5
        self.timeout = 3
        self.logger = MagicMock()
        self.scanner = WordPressScanner(self.target, self.ports, self.threads, self.timeout, self.logger)

    def test_initialization(self):
        """اختبار تهيئة الماسح"""
        assert self.scanner.target == self.target
        assert self.scanner.ports == self.ports
        assert self.scanner.threads == self.threads
        assert self.scanner.timeout == self.timeout
        assert self.scanner.logger == self.logger
        assert self.scanner.results["wordpress_info"]["is_wordpress"] is False
        assert self.scanner.results["wordpress_info"]["version"] == ""
        assert self.scanner.results["wordpress_info"]["themes"] == []
        assert self.scanner.results["wordpress_info"]["plugins"] == []
        assert self.scanner.results["wordpress_info"]["users"] == []
        assert self.scanner.results["wordpress_info"]["is_multisite"] is False
        assert self.scanner.results["wordpress_vulnerabilities"] == []

    @patch('modules.wordpress_scanner.requests.get')
    def test_is_wordpress_by_technology(self, mock_get):
        """اختبار اكتشاف ووردبريس من خلال التقنيات المكتشفة"""
        # تكوين السلوك المزيف
        self.scanner.results["web_info"] = {"technologies": ["WordPress"]}
        
        # التنفيذ
        result = self.scanner._is_wordpress()
        
        # التحقق
        assert result is True

    @patch('modules.wordpress_scanner.requests.get')
    def test_is_wordpress_by_links(self, mock_get):
        """اختبار اكتشاف ووردبريس من خلال الروابط"""
        # تكوين السلوك المزيف
        mock_response = MagicMock()
        mock_response.text = '<link rel="stylesheet" id="wp-block-library-css" href="/wp-includes/css/dist/block-library/style.min.css">'
        mock_get.return_value = mock_response
        self.scanner.results["web_info"] = {"technologies": []}
        
        # التنفيذ
        result = self.scanner._is_wordpress()
        
        # التحقق
        assert result is True

    @patch('modules.wordpress_scanner.requests.get')
    def test_get_wordpress_version(self, mock_get):
        """اختبار استخراج إصدار ووردبريس"""
        # تكوين السلوك المزيف
        mock_response = MagicMock()
        mock_response.text = '<meta name="generator" content="WordPress 5.8.1" />'
        mock_get.return_value = mock_response
        
        # التنفيذ
        self.scanner._get_wordpress_version()
        
        # التحقق
        assert self.scanner.results["wordpress_info"]["version"] == "5.8.1"

    @patch('modules.wordpress_scanner.requests.get')
    def test_get_wordpress_themes(self, mock_get):
        """اختبار استخراج قوالب ووردبريس"""
        # تكوين السلوك المزيف
        mock_response = MagicMock()
        mock_response.text = '<link rel="stylesheet" id="twentytwentyone-style-css" href="/wp-content/themes/twentytwentyone/style.css?ver=1.4" media="all">'
        mock_get.return_value = mock_response
        
        # التنفيذ
        self.scanner._get_wordpress_themes()
        
        # التحقق
        assert len(self.scanner.results["wordpress_info"]["themes"]) == 1
        assert self.scanner.results["wordpress_info"]["themes"][0]["name"] == "twentytwentyone"
        assert self.scanner.results["wordpress_info"]["themes"][0]["version"] == "1.4"

    @patch('modules.wordpress_scanner.requests.get')
    def test_get_wordpress_plugins(self, mock_get):
        """اختبار استخراج إضافات ووردبريس"""
        # تكوين السلوك المزيف
        mock_response = MagicMock()
        mock_response.text = '<script src="/wp-content/plugins/contact-form-7/includes/js/index.js?ver=5.5.3" id="contact-form-7-js"></script>'
        mock_get.return_value = mock_response
        
        # التنفيذ
        self.scanner._get_wordpress_plugins()
        
        # التحقق
        assert len(self.scanner.results["wordpress_info"]["plugins"]) == 1
        assert self.scanner.results["wordpress_info"]["plugins"][0]["name"] == "contact-form-7"
        assert self.scanner.results["wordpress_info"]["plugins"][0]["version"] == "5.5.3"

    @patch('modules.wordpress_scanner.requests.get')
    def test_get_wordpress_users(self, mock_get):
        """اختبار استخراج مستخدمي ووردبريس"""
        # تكوين السلوك المزيف للـ REST API
        rest_response = MagicMock()
        rest_response.status_code = 200
        rest_response.json.return_value = [
            {"id": 1, "name": "Admin", "slug": "admin"}
        ]
        
        # تكوين السلوك المزيف للتحقق من معلمة author
        author_response = MagicMock()
        author_response.status_code = 301
        author_response.headers = {"Location": "http://example.com/author/editor/"}
        
        # تكوين سلوك الاستدعاء المتعدد
        mock_get.side_effect = [rest_response, author_response]
        
        # التنفيذ
        self.scanner.base_url = "http://example.com"
        self.scanner._get_wordpress_users()
        
        # التحقق
        assert len(self.scanner.results["wordpress_info"]["users"]) == 2
        assert self.scanner.results["wordpress_info"]["users"][0]["username"] == "admin"
        assert self.scanner.results["wordpress_info"]["users"][0]["display_name"] == "Admin"
        assert self.scanner.results["wordpress_info"]["users"][1]["username"] == "editor"

    @patch.object(WordPressScanner, '_is_wordpress')
    @patch.object(WordPressScanner, '_gather_wordpress_info')
    @patch.object(WordPressScanner, '_scan_wordpress_vulnerabilities')
    def test_scan_wordpress_site(self, mock_scan_vulns, mock_gather_info, mock_is_wordpress):
        """اختبار مسح موقع ووردبريس"""
        # تكوين السلوك المزيف
        mock_is_wordpress.return_value = True
        
        # تنفيذ المسح
        self.scanner.scan()
        
        # التحقق
        assert self.scanner.results["wordpress_info"]["is_wordpress"] is True
        mock_gather_info.assert_called_once()
        mock_scan_vulns.assert_called_once()

    @patch.object(WordPressScanner, '_is_wordpress')
    def test_scan_not_wordpress_site(self, mock_is_wordpress):
        """اختبار مسح موقع غير ووردبريس"""
        # تكوين السلوك المزيف
        mock_is_wordpress.return_value = False
        
        # تنفيذ المسح
        self.scanner.scan()
        
        # التحقق
        assert self.scanner.results["wordpress_info"]["is_wordpress"] is False

    @patch.object(WordPressScanner, '_check_core_vulnerabilities')
    @patch.object(WordPressScanner, '_check_plugin_vulnerabilities')
    @patch.object(WordPressScanner, '_check_theme_vulnerabilities')
    @patch.object(WordPressScanner, '_check_other_vulnerabilities')
    def test_scan_wordpress_vulnerabilities(self, mock_other_vulns, mock_theme_vulns, mock_plugin_vulns, mock_core_vulns):
        """اختبار مسح ثغرات ووردبريس"""
        # تكوين بيانات ووردبريس في النتائج
        self.scanner.results["wordpress_info"] = {
            'version': '5.8.1',
            'themes': [{'name': 'twentytwentyone', 'version': '1.4'}],
            'plugins': [{'name': 'akismet', 'version': '4.2.1'}],
            'users': [{'username': 'admin', 'display_name': 'Admin'}],
            'is_multisite': False
        }

        # تكوين سلوك الدوال المزيفة
        mock_core_vulns.side_effect = lambda: self.scanner.results["wordpress_vulnerabilities"].extend([
            {'title': 'XSS in WordPress Core', 'severity': 'high', 'type': 'core'}
        ])
        mock_theme_vulns.side_effect = lambda: self.scanner.results["wordpress_vulnerabilities"].extend([
            {'title': 'CSS Injection in Twenty Twenty-One', 'severity': 'medium', 'type': 'theme'}
        ])
        mock_plugin_vulns.side_effect = lambda: self.scanner.results["wordpress_vulnerabilities"].extend([])
        mock_other_vulns.side_effect = lambda: self.scanner.results["wordpress_vulnerabilities"].extend([
            {'title': 'XML-RPC Enabled', 'severity': 'medium', 'type': 'xmlrpc'}
        ])

        # تنفيذ الفحص
        self.scanner._scan_wordpress_vulnerabilities()

        # التحقق من النتائج
        assert len(self.scanner.results["wordpress_vulnerabilities"]) == 3
        
        # التحقق من ثغرات النواة
        core_vulns = [v for v in self.scanner.results["wordpress_vulnerabilities"] if v.get('type') == 'core']
        assert len(core_vulns) == 1
        assert core_vulns[0]['title'] == 'XSS in WordPress Core'
        assert core_vulns[0]['severity'] == 'high'
        
        # التحقق من ثغرات القوالب
        theme_vulns = [v for v in self.scanner.results["wordpress_vulnerabilities"] if v.get('type') == 'theme']
        assert len(theme_vulns) == 1
        assert theme_vulns[0]['title'] == 'CSS Injection in Twenty Twenty-One'
        assert theme_vulns[0]['severity'] == 'medium'
        
        # التحقق من ثغرات أخرى
        other_vulns = [v for v in self.scanner.results["wordpress_vulnerabilities"] if v.get('type') == 'xmlrpc']
        assert len(other_vulns) == 1
        assert other_vulns[0]['title'] == 'XML-RPC Enabled'
        assert other_vulns[0]['severity'] == 'medium'

    @patch('modules.wordpress_scanner.requests.get')
    def test_check_multisite(self, mock_get):
        """اختبار التحقق من تثبيت متعدد المواقع"""
        # تكوين استجابة للتحقق من وجود /wp-admin/network/
        network_response = MagicMock()
        network_response.status_code = 200
        
        # تكوين استجابة للتحقق من وجود /wp-signup.php
        signup_response = MagicMock()
        signup_response.status_code = 404
        
        # تكوين سلوك الاستدعاء المتعدد
        mock_get.side_effect = [network_response, signup_response]
        
        # تنفيذ الاختبار
        self.scanner.base_url = "http://example.com"
        self.scanner._check_multisite()
        
        # التحقق
        assert self.scanner.results["wordpress_info"]["is_multisite"] == True

    def test_is_version_vulnerable(self):
        """اختبار التحقق من إصابة الإصدار بالثغرات"""
        # اختبار عندما يكون الإصدار الحالي أقل من الإصدار الضعيف
        assert self.scanner._is_version_vulnerable("5.8.1", "5.8.2") == True
        
        # اختبار عندما يكون الإصدار الحالي مساوٍ للإصدار الضعيف
        assert self.scanner._is_version_vulnerable("5.8.2", "5.8.2") == True
        
        # اختبار عندما يكون الإصدار الحالي أعلى من الإصدار الضعيف
        assert self.scanner._is_version_vulnerable("5.8.3", "5.8.2") == False
        
        # اختبار مع إصدارات ذات أطوال مختلفة
        assert self.scanner._is_version_vulnerable("5.8", "5.8.2") == True
        assert self.scanner._is_version_vulnerable("5.9", "5.8.2") == False
        
        # اختبار مع إصدار غير معروف
        assert self.scanner._is_version_vulnerable("", "5.8.2") == True

    @patch('modules.wordpress_scanner.requests.get')
    @patch('modules.wordpress_scanner.json.loads')
    def test_check_core_vulnerabilities(self, mock_json_loads, mock_get):
        """اختبار التحقق من ثغرات نواة ووردبريس"""
        # تكوين بيانات ووردبريس
        self.scanner.results["wordpress_info"]["version"] = "5.8.1"
        
        # تكوين استجابة قاعدة بيانات الثغرات
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = '{"wordpress":{"5.8.1":[{"title":"XSS Vulnerability","severity":"high"}]}}'
        mock_get.return_value = mock_response
        
        # تكوين استجابة تحليل JSON
        mock_json_loads.return_value = {
            "wordpress": {
                "5.8.1": [
                    {"title": "XSS Vulnerability", "severity": "high"}
                ]
            }
        }
        
        # تنفيذ الاختبار
        self.scanner._check_core_vulnerabilities()
        
        # التحقق
        assert len(self.scanner.results["wordpress_vulnerabilities"]) == 1
        assert self.scanner.results["wordpress_vulnerabilities"][0]["title"] == "XSS Vulnerability"
        assert self.scanner.results["wordpress_vulnerabilities"][0]["severity"] == "high"
        assert self.scanner.results["wordpress_vulnerabilities"][0]["type"] == "core"

    @patch('modules.wordpress_scanner.requests.get')
    @patch('modules.wordpress_scanner.json.loads')
    def test_check_plugin_vulnerabilities(self, mock_json_loads, mock_get):
        """اختبار التحقق من ثغرات إضافات ووردبريس"""
        # تكوين بيانات ووردبريس
        self.scanner.results["wordpress_info"]["plugins"] = [
            {"name": "contact-form-7", "version": "5.5.3"}
        ]
        
        # تكوين استجابة قاعدة بيانات الثغرات
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = '{"plugins":{"contact-form-7":{"5.5.3":[{"title":"SQL Injection","severity":"high"}]}}}'
        mock_get.return_value = mock_response
        
        # تكوين استجابة تحليل JSON
        mock_json_loads.return_value = {
            "plugins": {
                "contact-form-7": {
                    "5.5.3": [
                        {"title": "SQL Injection", "severity": "high"}
                    ]
                }
            }
        }
        
        # تنفيذ الاختبار
        self.scanner._check_plugin_vulnerabilities()
        
        # التحقق
        assert len(self.scanner.results["wordpress_vulnerabilities"]) == 1
        assert self.scanner.results["wordpress_vulnerabilities"][0]["title"] == "SQL Injection"
        assert self.scanner.results["wordpress_vulnerabilities"][0]["severity"] == "high"
        assert self.scanner.results["wordpress_vulnerabilities"][0]["type"] == "plugin"
        assert self.scanner.results["wordpress_vulnerabilities"][0]["plugin"] == "contact-form-7"

    @patch('modules.wordpress_scanner.requests.get')
    def test_check_other_vulnerabilities_xmlrpc(self, mock_get):
        """اختبار التحقق من ثغرات XML-RPC"""
        # تكوين استجابة للتحقق من وجود xmlrpc.php
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "XML-RPC server accepts POST requests only."
        mock_get.return_value = mock_response
        
        # تنفيذ الاختبار
        self.scanner.base_url = "http://example.com"
        self.scanner._check_other_vulnerabilities()
        
        # التحقق
        xmlrpc_vulns = [v for v in self.scanner.results["wordpress_vulnerabilities"] if v.get('type') == 'xmlrpc']
        assert len(xmlrpc_vulns) == 1
        assert xmlrpc_vulns[0]["title"] == "XML-RPC Interface Enabled"
        assert xmlrpc_vulns[0]["severity"] == "medium"

    @patch('modules.wordpress_scanner.requests.get')
    @patch('modules.wordpress_scanner.json.loads')
    def test_check_theme_vulnerabilities(self, mock_json_loads, mock_get):
        """اختبار التحقق من ثغرات قوالب ووردبريس"""
        # تكوين بيانات ووردبريس
        self.scanner.results["wordpress_info"]["themes"] = [
            {"name": "twentytwentyone", "version": "1.4"}
        ]
        
        # تكوين استجابة قاعدة بيانات الثغرات
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = '{"themes":{"twentytwentyone":{"1.4":[{"title":"XSS in Theme","severity":"medium"}]}}}'
        mock_get.return_value = mock_response
        
        # تكوين استجابة تحليل JSON
        mock_json_loads.return_value = {
            "themes": {
                "twentytwentyone": {
                    "1.4": [
                        {"title": "XSS in Theme", "severity": "medium"}
                    ]
                }
            }
        }
        
        # تنفيذ الاختبار
        self.scanner._check_theme_vulnerabilities()
        
        # التحقق
        assert len(self.scanner.results["wordpress_vulnerabilities"]) == 1
        assert self.scanner.results["wordpress_vulnerabilities"][0]["title"] == "XSS in Theme"
        assert self.scanner.results["wordpress_vulnerabilities"][0]["severity"] == "medium"
        assert self.scanner.results["wordpress_vulnerabilities"][0]["type"] == "theme"
        assert self.scanner.results["wordpress_vulnerabilities"][0]["theme"] == "twentytwentyone"