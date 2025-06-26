#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest
import sys
from unittest.mock import patch, MagicMock

# إضافة المجلد الرئيسي إلى مسار البحث
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from modules.scanner import VulnerabilityScanner


class TestVulnerabilityScanner(unittest.TestCase):
    """اختبارات لوحدة الماسح الأمني"""

    def setUp(self):
        """إعداد بيئة الاختبار"""
        self.logger = MagicMock()
        self.target = 'example.com'
        self.ports = [80, 443]
        self.threads = 5
        self.timeout = 10
        
        # إنشاء كائن الماسح
        with patch('modules.scanner.nmap.PortScanner') as mock_port_scanner:
            self.scanner = VulnerabilityScanner(
                target=self.target,
                ports=self.ports,
                threads=self.threads,
                timeout=self.timeout,
                logger=self.logger
            )
            self.mock_port_scanner = mock_port_scanner

    def test_initialization(self):
        """اختبار تهيئة الماسح"""
        self.assertEqual(self.scanner.target, self.target)
        self.assertEqual(self.scanner.ports, self.ports)
        self.assertEqual(self.scanner.threads, self.threads)
        self.assertEqual(self.scanner.timeout, self.timeout)
        self.assertEqual(self.scanner.logger, self.logger)
        self.assertIsInstance(self.scanner.results, dict)

    @patch('modules.scanner.VulnerabilityScanner._run_nmap_scan')
    def test_scan(self, mock_run_nmap_scan):
        """اختبار وظيفة المسح الرئيسية"""
        # تهيئة البيانات المزيفة للاختبار
        mock_run_nmap_scan.return_value = {
            'scan': {
                'example.com': {
                    'tcp': {
                        80: {'state': 'open', 'name': 'http'},
                        443: {'state': 'open', 'name': 'https'}
                    },
                    'status': {'state': 'up'},
                    'osmatch': [{'name': 'Linux', 'accuracy': '95'}]
                }
            }
        }
        
        # تنفيذ المسح
        self.scanner.scan()
        
        # التحقق من أن وظيفة المسح الداخلية تم استدعاؤها
        mock_run_nmap_scan.assert_called_once()
        
        # التحقق من نتائج المسح
        self.assertIn('ports', self.scanner.results)
        self.assertIn('os_info', self.scanner.results)
        self.assertIn('vulnerabilities', self.scanner.results)
        
        # التحقق من تسجيل الأحداث
        self.logger.info.assert_called_with('بدء مسح الثغرات الأمنية لـ example.com')

    @patch('modules.scanner.requests.get')
    def test_get_whois_info(self, mock_get):
        """اختبار الحصول على معلومات WHOIS"""
        # تهيئة البيانات المزيفة للاختبار
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'domain': 'example.com',
            'registrar': 'Example Registrar',
            'created_date': '1995-08-14T04:00:00Z',
            'expiry_date': '2023-08-13T04:00:00Z'
        }
        mock_get.return_value = mock_response
        
        # تنفيذ الوظيفة
        whois_info = self.scanner._get_whois_info()
        
        # التحقق من النتائج
        self.assertIsInstance(whois_info, dict)
        self.assertEqual(whois_info['domain'], 'example.com')
        
        # اختبار حالة الفشل
        mock_get.side_effect = Exception('API error')
        whois_info = self.scanner._get_whois_info()
        self.assertEqual(whois_info, {})

    @patch('modules.scanner.socket.gethostbyname')
    @patch('modules.scanner.socket.gethostbyaddr')
    def test_get_dns_info(self, mock_gethostbyaddr, mock_gethostbyname):
        """اختبار الحصول على معلومات DNS"""
        # تهيئة البيانات المزيفة للاختبار
        mock_gethostbyname.return_value = '93.184.216.34'
        mock_gethostbyaddr.return_value = ('example.com', [], ['93.184.216.34'])
        
        # تنفيذ الوظيفة
        dns_info = self.scanner._get_dns_info()
        
        # التحقق من النتائج
        self.assertIsInstance(dns_info, dict)
        self.assertEqual(dns_info['ip'], '93.184.216.34')
        self.assertEqual(dns_info['hostname'], 'example.com')
        
        # اختبار حالة الفشل
        mock_gethostbyname.side_effect = Exception('DNS resolution failed')
        dns_info = self.scanner._get_dns_info()
        self.assertEqual(dns_info, {})


if __name__ == '__main__':
    unittest.main()