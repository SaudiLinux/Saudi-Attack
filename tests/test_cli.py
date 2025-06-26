#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pytest
import sys
import os
from unittest.mock import patch, MagicMock
import argparse

# إضافة المجلد الرئيسي إلى مسار البحث
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# استيراد الوحدة الرئيسية
import saudi_attack


class TestCLI:
    """اختبارات لواجهة سطر الأوامر"""

    def test_parser_creation(self):
        """اختبار إنشاء محلل الأوامر"""
        # افتراض أن هناك دالة create_parser في الوحدة الرئيسية
        parser = saudi_attack.create_parser()
        
        # التحقق من أن المحلل تم إنشاؤه بشكل صحيح
        assert isinstance(parser, argparse.ArgumentParser)
        
        # التحقق من وجود الخيارات الأساسية
        options = [action.dest for action in parser._actions]
        assert 'target' in options
        assert 'mode' in options
        assert 'output' in options
        assert 'ports' in options
        assert 'config' in options
        assert 'verbose' in options

    @patch('sys.argv', ['saudi_attack.py', '-h'])
    @patch('argparse.ArgumentParser.print_help')
    def test_help_option(self, mock_print_help):
        """اختبار خيار المساعدة"""
        # تكوين السلوك المزيف
        mock_print_help.return_value = None
        
        # تنفيذ الاختبار مع توقع استثناء SystemExit
        with pytest.raises(SystemExit):
            saudi_attack.create_parser().parse_args()
        
        # التحقق من أن دالة المساعدة تم استدعاؤها
        mock_print_help.assert_called_once()

    @patch('sys.argv', ['saudi_attack.py', '--target', 'example.com'])
    def test_target_option(self):
        """اختبار خيار الهدف"""
        parser = saudi_attack.create_parser()
        args = parser.parse_args()
        
        assert args.target == 'example.com'

    @patch('sys.argv', ['saudi_attack.py', '--target', 'example.com', '--mode', 'web'])
    def test_mode_option(self):
        """اختبار خيار وضع المسح"""
        parser = saudi_attack.create_parser()
        args = parser.parse_args()
        
        assert args.target == 'example.com'
        assert args.mode == 'web'

    @patch('sys.argv', ['saudi_attack.py', '--target', 'example.com', '--output', 'json'])
    def test_output_option(self):
        """اختبار خيار تنسيق الإخراج"""
        parser = saudi_attack.create_parser()
        args = parser.parse_args()
        
        assert args.target == 'example.com'
        assert args.output == 'json'

    @patch('sys.argv', ['saudi_attack.py', '--target', 'example.com', '--ports', '80,443,8080'])
    def test_ports_option(self):
        """اختبار خيار المنافذ"""
        parser = saudi_attack.create_parser()
        args = parser.parse_args()
        
        assert args.target == 'example.com'
        assert args.ports == '80,443,8080'

    @patch('sys.argv', ['saudi_attack.py', '--target', 'example.com', '--config', 'custom_config.yaml'])
    def test_config_option(self):
        """اختبار خيار ملف التكوين"""
        parser = saudi_attack.create_parser()
        args = parser.parse_args()
        
        assert args.target == 'example.com'
        assert args.config == 'custom_config.yaml'

    @patch('sys.argv', ['saudi_attack.py', '--target', 'example.com', '--verbose'])
    def test_verbose_option(self):
        """اختبار خيار التفصيل"""
        parser = saudi_attack.create_parser()
        args = parser.parse_args()
        
        assert args.target == 'example.com'
        assert args.verbose is True

    @patch('sys.argv', ['saudi_attack.py', '--target', 'example.com', '--mode', 'invalid'])
    def test_invalid_mode(self):
        """اختبار وضع غير صالح"""
        parser = saudi_attack.create_parser()
        
        # يجب أن يرفض المحلل الوضع غير الصالح
        with pytest.raises(SystemExit):
            parser.parse_args()

    @patch('sys.argv', ['saudi_attack.py', '--target', 'example.com', '--output', 'invalid'])
    def test_invalid_output_format(self):
        """اختبار تنسيق إخراج غير صالح"""
        parser = saudi_attack.create_parser()
        
        # يجب أن يرفض المحلل تنسيق الإخراج غير الصالح
        with pytest.raises(SystemExit):
            parser.parse_args()

    @patch('sys.argv', ['saudi_attack.py'])
    def test_missing_target(self):
        """اختبار عدم تحديد الهدف"""
        parser = saudi_attack.create_parser()
        
        # يجب أن يرفض المحلل عدم وجود هدف
        with pytest.raises(SystemExit):
            parser.parse_args()

    @patch('sys.argv', ['saudi_attack.py', '--target', 'example.com', '--mode', 'web', '--output', 'json', '--ports', '80,443', '--config', 'custom_config.yaml', '--verbose'])
    def test_all_options_together(self):
        """اختبار جميع الخيارات معًا"""
        parser = saudi_attack.create_parser()
        args = parser.parse_args()
        
        assert args.target == 'example.com'
        assert args.mode == 'web'
        assert args.output == 'json'
        assert args.ports == '80,443'
        assert args.config == 'custom_config.yaml'
        assert args.verbose is True