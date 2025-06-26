#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pytest
from unittest.mock import patch, MagicMock
import sys
import os

# إضافة المجلد الرئيسي إلى مسار البحث
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# استيراد الوحدة الرئيسية
import saudi_attack


class TestMain:
    """اختبارات للوظيفة الرئيسية للأداة"""

    @patch('argparse.ArgumentParser.parse_args')
    @patch('saudi_attack.run_scan')
    def test_main_function(self, mock_run_scan, mock_parse_args):
        """اختبار الوظيفة الرئيسية مع المعلمات الافتراضية"""
        # تكوين القيم المرجعة للدوال المزيفة
        mock_args = MagicMock()
        mock_args.target = 'example.com'
        mock_args.mode = 'general'
        mock_args.output = 'html'
        mock_args.ports = None
        mock_args.config = None
        mock_args.verbose = False
        mock_parse_args.return_value = mock_args

        # تنفيذ الاختبار
        saudi_attack.main()

        # التحقق من النتائج
        mock_run_scan.assert_called_once_with(
            target='example.com',
            mode='general',
            output_format='html',
            ports=None,
            config_file=None,
            verbose=False
        )

    @patch('argparse.ArgumentParser.parse_args')
    @patch('saudi_attack.run_scan')
    def test_main_function_with_custom_params(self, mock_run_scan, mock_parse_args):
        """اختبار الوظيفة الرئيسية مع معلمات مخصصة"""
        # تكوين القيم المرجعة للدوال المزيفة
        mock_args = MagicMock()
        mock_args.target = '192.168.1.1'
        mock_args.mode = 'web'
        mock_args.output = 'json'
        mock_args.ports = '80,443,8080'
        mock_args.config = 'custom_config.yaml'
        mock_args.verbose = True
        mock_parse_args.return_value = mock_args

        # تنفيذ الاختبار
        saudi_attack.main()

        # التحقق من النتائج
        mock_run_scan.assert_called_once_with(
            target='192.168.1.1',
            mode='web',
            output_format='json',
            ports='80,443,8080',
            config_file='custom_config.yaml',
            verbose=True
        )

    @patch('saudi_attack.ConfigManager')
    @patch('saudi_attack.VulnerabilityScanner')
    @patch('saudi_attack.WebServerScanner')
    @patch('saudi_attack.WordPressScanner')
    @patch('saudi_attack.JoomlaScanner')
    @patch('saudi_attack.ReportGenerator')
    @patch('saudi_attack.setup_logger')
    def test_run_scan_general_mode(self, mock_setup_logger, mock_report_gen, 
                                 mock_joomla, mock_wordpress, mock_web, 
                                 mock_scanner, mock_config):
        """اختبار وظيفة run_scan في وضع المسح العام"""
        # تكوين القيم المرجعة للدوال المزيفة
        mock_logger = MagicMock()
        mock_setup_logger.return_value = mock_logger
        
        mock_config_instance = MagicMock()
        mock_config_instance.get_config.return_value = {'general': {}, 'scan': {}}
        mock_config.return_value = mock_config_instance
        
        mock_scanner_instance = MagicMock()
        mock_scanner_instance.scan.return_value = {'target': 'example.com'}
        mock_scanner.return_value = mock_scanner_instance
        
        mock_web_instance = MagicMock()
        mock_web_instance.scan.return_value = {'web_info': {}}
        mock_web.return_value = mock_web_instance
        
        mock_wordpress_instance = MagicMock()
        mock_wordpress_instance.scan.return_value = {'wordpress_info': {}}
        mock_wordpress.return_value = mock_wordpress_instance
        
        mock_joomla_instance = MagicMock()
        mock_joomla_instance.scan.return_value = {'joomla_info': {}}
        mock_joomla.return_value = mock_joomla_instance
        
        mock_report_instance = MagicMock()
        mock_report_instance.generate_report.return_value = True
        mock_report_gen.return_value = mock_report_instance

        # تنفيذ الاختبار
        saudi_attack.run_scan(
            target='example.com',
            mode='general',
            output_format='html',
            ports=None,
            config_file=None,
            verbose=False
        )

        # التحقق من النتائج
        mock_setup_logger.assert_called_once()
        mock_config.assert_called_once_with(config_file=None)
        mock_scanner.assert_called_once()
        mock_scanner_instance.scan.assert_called_once_with('example.com', ports=None)
        mock_web.assert_called_once()
        mock_web_instance.scan.assert_called_once_with('example.com')
        mock_wordpress.assert_called_once()
        mock_wordpress_instance.scan.assert_called_once_with('example.com')
        mock_joomla.assert_called_once()
        mock_joomla_instance.scan.assert_called_once_with('example.com')
        mock_report_gen.assert_called_once()
        mock_report_instance.generate_report.assert_called_once()

    @patch('saudi_attack.ConfigManager')
    @patch('saudi_attack.VulnerabilityScanner')
    @patch('saudi_attack.WebServerScanner')
    @patch('saudi_attack.setup_logger')
    def test_run_scan_web_mode(self, mock_setup_logger, mock_web, 
                             mock_scanner, mock_config):
        """اختبار وظيفة run_scan في وضع مسح الويب"""
        # تكوين القيم المرجعة للدوال المزيفة
        mock_logger = MagicMock()
        mock_setup_logger.return_value = mock_logger
        
        mock_config_instance = MagicMock()
        mock_config_instance.get_config.return_value = {'general': {}, 'scan': {}}
        mock_config.return_value = mock_config_instance
        
        mock_scanner_instance = MagicMock()
        mock_scanner_instance.scan.return_value = {'target': 'example.com'}
        mock_scanner.return_value = mock_scanner_instance
        
        mock_web_instance = MagicMock()
        mock_web_instance.scan.return_value = {'web_info': {}}
        mock_web.return_value = mock_web_instance

        # تنفيذ الاختبار
        saudi_attack.run_scan(
            target='example.com',
            mode='web',
            output_format='json',
            ports='80,443',
            config_file=None,
            verbose=True
        )

        # التحقق من النتائج
        mock_setup_logger.assert_called_once()
        mock_config.assert_called_once_with(config_file=None)
        mock_scanner.assert_called_once()
        mock_scanner_instance.scan.assert_called_once_with('example.com', ports='80,443')
        mock_web.assert_called_once()
        mock_web_instance.scan.assert_called_once_with('example.com')