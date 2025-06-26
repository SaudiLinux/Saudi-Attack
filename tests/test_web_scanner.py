#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest
import sys
from unittest.mock import patch, MagicMock

# إضافة المجلد الرئيسي إلى مسار البحث
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from modules.web_scanner import WebServerScanner


class TestWebServerScanner(unittest.TestCase):
    """اختبارات لوحدة ماسح خادم الويب"""

    def setUp(self):
        """إعداد بيئة الاختبار"""
        self.logger = MagicMock()
        self.target = 'example.com'
        self.ports = [80, 443]
        self.threads = 5
        self.timeout = 10
        
        # إنشاء كائن الماسح
        with patch('modules.web_scanner.nmap.PortScanner'), \
             patch('modules.web_scanner.VulnerabilityScanner.__init__', return_value=None), \
             patch('modules.web_scanner.VulnerabilityScanner.scan'):
            self.web_scanner = WebServerScanner(
                target=self.target,
                ports=self.ports,
                threads=self.threads,
                timeout=self.timeout,
                logger=self.logger
            )
            self.web_scanner.target = self.target
            self.web_scanner.ports = self.ports
            self.web_scanner.threads = self.threads
            self.web_scanner.timeout = self.timeout
            self.web_scanner.logger = self.logger
            self.web_scanner.results = {
                'web_info': {},
                'web_vulnerabilities': []
            }

    def test_initialization(self):
        """اختبار تهيئة ماسح خادم الويب"""
        self.assertEqual(self.web_scanner.target, self.target)
        self.assertEqual(self.web_scanner.ports, self.ports)
        self.assertEqual(self.web_scanner.threads, self.threads)
        self.assertEqual(self.web_scanner.timeout, self.timeout)
        self.assertEqual(self.web_scanner.logger, self.logger)
        self.assertIn('web_info', self.web_scanner.results)
        self.assertIn('web_vulnerabilities', self.web_scanner.results)

    @patch('modules.web_scanner.WebServerScanner._get_web_server_info')
    @patch('modules.web_scanner.WebServerScanner._scan_web_vulnerabilities')
    @patch('modules.web_scanner.WebServerScanner._check_ssl_certificate')
    @patch('modules.web_scanner.VulnerabilityScanner.scan')
    def test_scan(self, mock_parent_scan, mock_check_ssl, mock_scan_web_vuln, mock_get_web_info):
        """اختبار وظيفة المسح الرئيسية"""
        # تهيئة البيانات المزيفة للاختبار
        mock_get_web_info.return_value = {
            'server': 'Apache/2.4.41',
            'technologies': ['PHP/7.4.3', 'jQuery/3.5.1'],
            'headers': {'Server': 'Apache/2.4.41', 'Content-Type': 'text/html'},
            'cookies': {'session': 'test-session-id'},
            'forms': [{'action': '/login', 'method': 'POST'}],
            'links': ['/about', '/contact'],
            'security_headers': {'X-XSS-Protection': '1; mode=block'}
        }
        
        # تنفيذ المسح
        self.web_scanner.scan()
        
        # التحقق من أن الوظائف الداخلية تم استدعاؤها
        mock_parent_scan.assert_called_once()
        mock_get_web_info.assert_called_once()
        mock_scan_web_vuln.assert_called_once()
        mock_check_ssl.assert_called_once()
        
        # التحقق من تسجيل الأحداث
        self.logger.info.assert_called_with('بدء مسح خادم الويب لـ example.com')

    @patch('modules.web_scanner.requests.get')
    def test_get_web_server_info(self, mock_get):
        """اختبار الحصول على معلومات خادم الويب"""
        # تهيئة البيانات المزيفة للاختبار
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {
            'Server': 'Apache/2.4.41',
            'Content-Type': 'text/html',
            'Set-Cookie': 'session=test-session-id'
        }
        mock_response.text = '<html><head><title>Test</title></head><body><form action="/login" method="POST"></form><a href="/about">About</a></body></html>'
        mock_get.return_value = mock_response
        
        # تنفيذ الوظيفة
        web_info = self.web_scanner._get_web_server_info()
        
        # التحقق من النتائج
        self.assertIsInstance(web_info, dict)
        self.assertEqual(web_info['server'], 'Apache/2.4.41')
        self.assertIn('headers', web_info)
        self.assertIn('forms', web_info)
        self.assertIn('links', web_info)
        
        # اختبار حالة الفشل
        mock_get.side_effect = Exception('Connection error')
        web_info = self.web_scanner._get_web_server_info()
        self.assertEqual(web_info, {})

    @patch('modules.web_scanner.requests.get')
    def test_check_security_headers(self, mock_get):
        """اختبار التحقق من رؤوس الأمان"""
        # تهيئة البيانات المزيفة للاختبار
        mock_response = MagicMock()
        mock_response.headers = {
            'X-XSS-Protection': '1; mode=block',
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY'
        }
        mock_get.return_value = mock_response
        
        # تنفيذ الوظيفة
        security_headers = self.web_scanner._check_security_headers('https://example.com')
        
        # التحقق من النتائج
        self.assertIsInstance(security_headers, dict)
        self.assertEqual(security_headers['X-XSS-Protection'], '1; mode=block')
        self.assertEqual(security_headers['X-Content-Type-Options'], 'nosniff')
        self.assertEqual(security_headers['X-Frame-Options'], 'DENY')
        
        # التحقق من الرؤوس المفقودة
        self.assertNotIn('Content-Security-Policy', security_headers)
        
        # اختبار حالة الفشل
        mock_get.side_effect = Exception('Connection error')
        security_headers = self.web_scanner._check_security_headers('https://example.com')
        self.assertEqual(security_headers, {})

    @patch('modules.web_scanner.ssl.create_default_context')
    @patch('modules.web_scanner.socket.create_connection')
    def test_check_ssl_certificate(self, mock_create_connection, mock_create_context):
        """اختبار التحقق من شهادة SSL"""
        # تهيئة البيانات المزيفة للاختبار
        mock_sock = MagicMock()
        mock_create_connection.return_value = mock_sock
        
        mock_context = MagicMock()
        mock_ssl_sock = MagicMock()
        mock_context.wrap_socket.return_value = mock_ssl_sock
        mock_create_context.return_value = mock_context
        
        mock_cert = MagicMock()
        mock_cert.get_notAfter.return_value = b'20301231235959Z'
        mock_cert.get_subject.return_value.get_components.return_value = [(b'CN', b'example.com')]
        mock_cert.get_issuer.return_value.get_components.return_value = [(b'CN', b'Example CA')]
        mock_ssl_sock.getpeercert.return_value = {'notAfter': 'Dec 31 23:59:59 2030 GMT'}
        
        # تنفيذ الوظيفة
        self.web_scanner.ports = [443]
        ssl_info = self.web_scanner._check_ssl_certificate()
        
        # التحقق من النتائج
        self.assertIsInstance(ssl_info, dict)
        self.assertIn('443', ssl_info)
        
        # اختبار حالة الفشل
        mock_create_connection.side_effect = Exception('Connection error')
        ssl_info = self.web_scanner._check_ssl_certificate()
        self.assertEqual(ssl_info, {})


if __name__ == '__main__':
    unittest.main()