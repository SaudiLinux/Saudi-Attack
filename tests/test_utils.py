#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest
import sys
from unittest.mock import patch, MagicMock

# إضافة المجلد الرئيسي إلى مسار البحث
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from modules.utils import (
    is_valid_ip, is_valid_domain, get_target_type,
    resolve_domain_to_ip, get_severity_color, format_time
)


class TestUtils(unittest.TestCase):
    """اختبارات لوحدة الأدوات المساعدة"""

    def test_is_valid_ip(self):
        """اختبار التحقق من صحة عنوان IP"""
        self.assertTrue(is_valid_ip('192.168.1.1'))
        self.assertTrue(is_valid_ip('8.8.8.8'))
        self.assertTrue(is_valid_ip('255.255.255.255'))
        self.assertFalse(is_valid_ip('256.256.256.256'))
        self.assertFalse(is_valid_ip('192.168.1'))
        self.assertFalse(is_valid_ip('example.com'))
        self.assertFalse(is_valid_ip('not-an-ip'))

    def test_is_valid_domain(self):
        """اختبار التحقق من صحة اسم النطاق"""
        self.assertTrue(is_valid_domain('example.com'))
        self.assertTrue(is_valid_domain('sub.example.com'))
        self.assertTrue(is_valid_domain('sub.sub.example.co.uk'))
        self.assertFalse(is_valid_domain('192.168.1.1'))
        self.assertFalse(is_valid_domain('invalid domain'))
        self.assertFalse(is_valid_domain('example'))

    def test_get_target_type(self):
        """اختبار تحديد نوع الهدف"""
        self.assertEqual(get_target_type('192.168.1.1'), 'ip')
        self.assertEqual(get_target_type('example.com'), 'domain')
        self.assertEqual(get_target_type('invalid'), 'unknown')

    @patch('socket.gethostbyname')
    def test_resolve_domain_to_ip(self, mock_gethostbyname):
        """اختبار تحويل اسم النطاق إلى عنوان IP"""
        mock_gethostbyname.return_value = '93.184.216.34'
        self.assertEqual(resolve_domain_to_ip('example.com'), '93.184.216.34')
        
        # اختبار حالة الفشل
        mock_gethostbyname.side_effect = Exception('DNS resolution failed')
        self.assertIsNone(resolve_domain_to_ip('nonexistent.domain'))

    def test_get_severity_color(self):
        """اختبار الحصول على لون حسب مستوى الخطورة"""
        self.assertEqual(get_severity_color('critical'), 'red')
        self.assertEqual(get_severity_color('high'), 'red')
        self.assertEqual(get_severity_color('medium'), 'yellow')
        self.assertEqual(get_severity_color('low'), 'blue')
        self.assertEqual(get_severity_color('info'), 'green')
        self.assertEqual(get_severity_color('unknown'), 'white')

    def test_format_time(self):
        """اختبار تنسيق الوقت"""
        # اختبار تنسيق الثواني
        self.assertEqual(format_time(30), '30 ثانية')
        self.assertEqual(format_time(1), '1 ثانية')
        
        # اختبار تنسيق الدقائق والثواني
        self.assertEqual(format_time(90), '1 دقيقة و 30 ثانية')
        self.assertEqual(format_time(120), '2 دقيقة و 0 ثانية')
        
        # اختبار تنسيق الساعات والدقائق والثواني
        self.assertEqual(format_time(3600), '1 ساعة و 0 دقيقة و 0 ثانية')
        self.assertEqual(format_time(3661), '1 ساعة و 1 دقيقة و 1 ثانية')
        self.assertEqual(format_time(7322), '2 ساعة و 2 دقيقة و 2 ثانية')


if __name__ == '__main__':
    unittest.main()