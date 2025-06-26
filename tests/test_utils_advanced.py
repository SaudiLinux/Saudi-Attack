#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pytest
import os
import sys
import re
import json
import socket
import time
from unittest.mock import patch, MagicMock, mock_open

# إضافة المجلد الرئيسي إلى مسار البحث
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# استيراد وحدة الأدوات المساعدة
from modules.utils import (
    is_valid_ip, is_valid_domain, get_target_type, resolve_domain_to_ip,
    get_severity_color, format_time, setup_logger, parse_ports,
    load_json_file, save_json_file, extract_version_from_string,
    generate_random_string, calculate_cvss_severity, sanitize_filename,
    parse_nmap_output, get_current_timestamp
)


class TestUtilsAdvanced:
    """اختبارات متقدمة لوحدة الأدوات المساعدة"""

    def test_parse_ports(self):
        """اختبار تحليل سلسلة المنافذ"""
        # اختبار قائمة منافذ مفصولة بفواصل
        ports = parse_ports("80,443,8080")
        assert ports == [80, 443, 8080]
        
        # اختبار نطاق المنافذ
        ports = parse_ports("80-85")
        assert ports == [80, 81, 82, 83, 84, 85]
        
        # اختبار مزيج من القوائم والنطاقات
        ports = parse_ports("22,80-82,443")
        assert ports == [22, 80, 81, 82, 443]
        
        # اختبار قيمة فارغة
        ports = parse_ports("")
        assert ports == []
        
        # اختبار قيمة None
        ports = parse_ports(None)
        assert ports == []
        
        # اختبار قيمة غير صالحة
        with pytest.raises(ValueError):
            parse_ports("abc")

    @patch('builtins.open', new_callable=mock_open, read_data='{"key": "value"}')
    def test_load_json_file(self, mock_file):
        """اختبار تحميل ملف JSON"""
        data = load_json_file("test.json")
        mock_file.assert_called_once_with("test.json", "r", encoding="utf-8")
        assert data == {"key": "value"}

    @patch('builtins.open', new_callable=mock_open)
    @patch('json.dump')
    def test_save_json_file(self, mock_json_dump, mock_file):
        """اختبار حفظ ملف JSON"""
        data = {"key": "value"}
        save_json_file("test.json", data)
        mock_file.assert_called_once_with("test.json", "w", encoding="utf-8")
        mock_json_dump.assert_called_once_with(data, mock_file(), indent=4, ensure_ascii=False)

    def test_extract_version_from_string(self):
        """اختبار استخراج الإصدار من سلسلة نصية"""
        # اختبار أنماط مختلفة من الإصدارات
        assert extract_version_from_string("WordPress 5.8.2") == "5.8.2"
        assert extract_version_from_string("Version: 1.2.3") == "1.2.3"
        assert extract_version_from_string("v2.0.0-beta") == "2.0.0-beta"
        assert extract_version_from_string("Release 3.1") == "3.1"
        assert extract_version_from_string("No version here") is None

    def test_generate_random_string(self):
        """اختبار توليد سلسلة عشوائية"""
        # اختبار الطول الافتراضي
        random_str = generate_random_string()
        assert len(random_str) == 8
        assert isinstance(random_str, str)
        
        # اختبار طول مخصص
        random_str = generate_random_string(length=16)
        assert len(random_str) == 16
        
        # اختبار أن السلاسل المولدة مختلفة
        random_str1 = generate_random_string()
        random_str2 = generate_random_string()
        assert random_str1 != random_str2

    def test_calculate_cvss_severity(self):
        """اختبار حساب خطورة CVSS"""
        # اختبار نطاقات مختلفة من درجات CVSS
        assert calculate_cvss_severity(0.0) == "info"
        assert calculate_cvss_severity(2.5) == "low"
        assert calculate_cvss_severity(5.0) == "medium"
        assert calculate_cvss_severity(7.5) == "high"
        assert calculate_cvss_severity(9.5) == "critical"
        
        # اختبار القيم الحدية
        assert calculate_cvss_severity(3.9) == "low"
        assert calculate_cvss_severity(4.0) == "medium"
        assert calculate_cvss_severity(6.9) == "medium"
        assert calculate_cvss_severity(7.0) == "high"
        assert calculate_cvss_severity(8.9) == "high"
        assert calculate_cvss_severity(9.0) == "critical"
        
        # اختبار القيم غير الصالحة
        assert calculate_cvss_severity(-1.0) == "info"
        assert calculate_cvss_severity(11.0) == "critical"

    def test_sanitize_filename(self):
        """اختبار تنظيف اسم الملف"""
        # اختبار إزالة الأحرف غير الصالحة
        assert sanitize_filename("file/with\\invalid:chars*?") == "file_with_invalid_chars__"
        
        # اختبار الحفاظ على الأحرف الصالحة
        assert sanitize_filename("valid-file_name.txt") == "valid-file_name.txt"
        
        # اختبار تحويل المسافات
        assert sanitize_filename("file with spaces") == "file_with_spaces"
        
        # اختبار إزالة الأحرف الخاصة
        assert sanitize_filename("file<with>special&chars") == "file_with_special_chars"

    @patch('logging.FileHandler')
    @patch('logging.StreamHandler')
    @patch('logging.getLogger')
    def test_setup_logger_verbose(self, mock_get_logger, mock_stream_handler, mock_file_handler):
        """اختبار إعداد السجل في وضع التفصيل"""
        # تكوين السلوك المزيف
        mock_logger = MagicMock()
        mock_get_logger.return_value = mock_logger
        
        # تنفيذ الاختبار
        logger = setup_logger(verbose=True)
        
        # التحقق من النتائج
        mock_get_logger.assert_called_once_with('SaudiAttack')
        assert mock_logger.setLevel.call_count == 1
        assert mock_stream_handler.call_count == 1
        assert mock_file_handler.call_count == 1
        assert mock_logger.addHandler.call_count == 2
        assert logger == mock_logger

    @patch('logging.FileHandler')
    @patch('logging.StreamHandler')
    @patch('logging.getLogger')
    def test_setup_logger_non_verbose(self, mock_get_logger, mock_stream_handler, mock_file_handler):
        """اختبار إعداد السجل في وضع غير التفصيل"""
        # تكوين السلوك المزيف
        mock_logger = MagicMock()
        mock_get_logger.return_value = mock_logger
        
        # تنفيذ الاختبار
        logger = setup_logger(verbose=False)
        
        # التحقق من النتائج
        mock_get_logger.assert_called_once_with('SaudiAttack')
        assert mock_logger.setLevel.call_count == 1
        assert mock_stream_handler.call_count == 1
        assert mock_file_handler.call_count == 1
        assert mock_logger.addHandler.call_count == 2
        assert logger == mock_logger

    def test_parse_nmap_output(self):
        """اختبار تحليل مخرجات Nmap"""
        # تكوين مخرجات Nmap المزيفة
        nmap_output = '''
        Starting Nmap 7.91
        Nmap scan report for example.com (93.184.216.34)
        Host is up (0.15s latency).
        PORT    STATE SERVICE  VERSION
        80/tcp  open  http     nginx
        443/tcp open  https    nginx
        8080/tcp closed http
        
        Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
        Nmap done: 1 IP address (1 host up) scanned in 15.20 seconds
        '''
        
        # تنفيذ الاختبار
        result = parse_nmap_output(nmap_output)
        
        # التحقق من النتائج
        assert '80' in result
        assert result['80']['state'] == 'open'
        assert result['80']['service'] == 'http'
        assert result['80']['version'] == 'nginx'
        
        assert '443' in result
        assert result['443']['state'] == 'open'
        assert result['443']['service'] == 'https'
        assert result['443']['version'] == 'nginx'
        
        assert '8080' in result
        assert result['8080']['state'] == 'closed'
        assert result['8080']['service'] == 'http'
        assert 'version' not in result['8080']

    def test_get_current_timestamp(self):
        """اختبار الحصول على الطابع الزمني الحالي"""
        timestamp = get_current_timestamp()
        
        # التحقق من تنسيق الطابع الزمني
        assert re.match(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}', timestamp)
        
        # التحقق من أن الطابع الزمني قريب من الوقت الحالي
        current_time = time.time()
        timestamp_time = time.mktime(time.strptime(timestamp, "%Y-%m-%dT%H:%M:%S"))
        assert abs(current_time - timestamp_time) < 5  # تسامح 5 ثوانٍ