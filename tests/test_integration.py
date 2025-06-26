#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pytest
import os
import json
from unittest.mock import patch, MagicMock
import sys

# إضافة المجلد الرئيسي إلى مسار البحث
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# استيراد الوحدات المطلوبة
from modules.config import ConfigManager
from modules.scanner import VulnerabilityScanner
from modules.web_scanner import WebServerScanner
from modules.wordpress_scanner import WordPressScanner
from modules.joomla_scanner import JoomlaScanner
from modules.report_generator import ReportGenerator
import saudi_attack


class TestIntegration:
    """اختبارات تكاملية للأداة"""

    @pytest.fixture
    def setup_test_environment(self):
        """إعداد بيئة الاختبار"""
        # إنشاء مجلد للتقارير المؤقتة
        test_output_dir = os.path.join(os.path.dirname(__file__), 'test_output')
        os.makedirs(test_output_dir, exist_ok=True)
        
        # تكوين مخصص للاختبار
        test_config = {
            'general': {
                'threads': 2,
                'timeout': 5,
                'user_agent': 'SaudiAttack-Test/1.0',
                'output_dir': test_output_dir
            },
            'scan': {
                'ports': {
                    'general': [80, 443],
                    'web': [80, 443],
                    'wordpress': [80, 443],
                    'joomla': [80, 443]
                }
            },
            'web': {
                'paths_to_check': ['/'],
                'security_headers': ['X-XSS-Protection']
            },
            'wordpress': {
                'detection_paths': ['/wp-login.php']
            },
            'joomla': {
                'detection_paths': ['/administrator/']
            },
            'report': {
                'formats': ['json', 'txt', 'html', 'md'],
                'default_format': 'json',
                'template_dir': os.path.join(os.path.dirname(__file__), '..', 'templates')
            }
        }
        
        yield test_config, test_output_dir
        
        # تنظيف بعد الاختبار
        for file in os.listdir(test_output_dir):
            file_path = os.path.join(test_output_dir, file)
            if os.path.isfile(file_path):
                os.remove(file_path)
        os.rmdir(test_output_dir)

    @patch('modules.scanner.subprocess.run')
    @patch('modules.scanner.socket.gethostbyname')
    @patch('modules.scanner.socket.gethostbyaddr')
    @patch('modules.scanner.requests.get')
    @patch('modules.web_scanner.requests.get')
    @patch('modules.web_scanner.ssl.create_default_context')
    @patch('modules.web_scanner.socket.create_connection')
    @patch('modules.wordpress_scanner.requests.get')
    @patch('modules.joomla_scanner.requests.get')
    def test_full_scan_workflow(self, mock_joomla_get, mock_wp_get, mock_socket_conn, 
                              mock_ssl_context, mock_web_get, mock_scanner_get, 
                              mock_gethostbyaddr, mock_gethostbyname, mock_subprocess_run, 
                              setup_test_environment):
        """اختبار سير عمل المسح الكامل"""
        test_config, test_output_dir = setup_test_environment
        
        # تكوين السلوك المزيف للدوال
        mock_gethostbyname.return_value = '93.184.216.34'  # عنوان IP لـ example.com
        mock_gethostbyaddr.return_value = ('example.com', [], ['93.184.216.34'])
        
        # تزييف نتائج Nmap
        nmap_process = MagicMock()
        nmap_process.stdout = '''
        Starting Nmap 7.91
        Nmap scan report for example.com (93.184.216.34)
        Host is up (0.15s latency).
        PORT    STATE SERVICE  VERSION
        80/tcp  open  http     nginx
        443/tcp open  https    nginx
        '''
        nmap_process.returncode = 0
        mock_subprocess_run.return_value = nmap_process
        
        # تزييف استجابات HTTP للماسح العام
        mock_scanner_response = MagicMock()
        mock_scanner_response.status_code = 200
        mock_scanner_response.text = '<html><head><title>Example Domain</title></head><body>Example</body></html>'
        mock_scanner_response.headers = {'Server': 'nginx'}
        mock_scanner_get.return_value = mock_scanner_response
        
        # تزييف استجابات HTTP لماسح الويب
        mock_web_response = MagicMock()
        mock_web_response.status_code = 200
        mock_web_response.text = '<html><head><title>Example Domain</title></head><body>Example</body></html>'
        mock_web_response.headers = {
            'Server': 'nginx',
            'Content-Type': 'text/html',
            'X-XSS-Protection': '1; mode=block'
        }
        mock_web_get.return_value = mock_web_response
        
        # تزييف استجابات SSL
        mock_ssl_conn = MagicMock()
        mock_ssl_conn.getpeercert.return_value = {
            'subject': ((('commonName', 'example.com'),),),
            'issuer': ((('commonName', 'Let\'s Encrypt Authority X3'),),),
            'version': 3,
            'notBefore': 'Jan 1 00:00:00 2023 GMT',
            'notAfter': 'Dec 31 23:59:59 2023 GMT'
        }
        mock_ssl_context.return_value.wrap_socket.return_value = mock_ssl_conn
        
        # تزييف استجابات HTTP لماسح ووردبريس (سلبية)
        mock_wp_response = MagicMock()
        mock_wp_response.status_code = 404
        mock_wp_response.text = '<html><body>Not Found</body></html>'
        mock_wp_get.return_value = mock_wp_response
        
        # تزييف استجابات HTTP لماسح جوملا (سلبية)
        mock_joomla_response = MagicMock()
        mock_joomla_response.status_code = 404
        mock_joomla_response.text = '<html><body>Not Found</body></html>'
        mock_joomla_get.return_value = mock_joomla_response
        
        # إنشاء مدير التكوين
        config_manager = ConfigManager()
        config_manager.update_config(test_config)
        
        # إنشاء سجل مزيف
        logger = MagicMock()
        
        # إنشاء الماسحات
        scanner = VulnerabilityScanner(config_manager.get_config(), logger)
        web_scanner = WebServerScanner(config_manager.get_config(), logger)
        wp_scanner = WordPressScanner(config_manager.get_config(), logger)
        joomla_scanner = JoomlaScanner(config_manager.get_config(), logger)
        report_generator = ReportGenerator(config_manager.get_config())
        
        # تنفيذ المسح
        scan_results = scanner.scan('example.com')
        web_results = web_scanner.scan('example.com')
        wp_results = wp_scanner.scan('example.com')
        joomla_results = joomla_scanner.scan('example.com')
        
        # دمج النتائج
        scan_results.update(web_results)
        scan_results.update(wp_results)
        scan_results.update(joomla_results)
        
        # إنشاء التقرير
        report_file = report_generator.generate_report(scan_results, 'example.com', 'json')
        
        # التحقق من النتائج
        assert scan_results is not None
        assert 'target' in scan_results
        assert scan_results['target'] == 'example.com'
        assert 'ports' in scan_results
        assert '80' in scan_results['ports']
        assert '443' in scan_results['ports']
        
        # التحقق من معلومات الويب
        assert 'web_info' in scan_results
        assert 'server' in scan_results['web_info']
        assert scan_results['web_info']['server'] == 'nginx'
        assert 'security_headers' in scan_results['web_info']
        assert 'X-XSS-Protection' in scan_results['web_info']['security_headers']
        
        # التحقق من أن ووردبريس وجوملا لم يتم اكتشافهما
        assert wp_results == {}
        assert joomla_results == {}

    @patch('saudi_attack.ConfigManager')
    @patch('saudi_attack.VulnerabilityScanner')
    @patch('saudi_attack.WebServerScanner')
    @patch('saudi_attack.WordPressScanner')
    @patch('saudi_attack.JoomlaScanner')
    @patch('saudi_attack.ReportGenerator')
    @patch('saudi_attack.setup_logger')
    def test_integration_run_scan(self, mock_setup_logger, mock_report_gen, 
                                mock_joomla, mock_wordpress, mock_web, 
                                mock_scanner, mock_config, setup_test_environment):
        """اختبار تكاملي لوظيفة run_scan"""
        test_config, test_output_dir = setup_test_environment
        
        # تكوين القيم المرجعة للدوال المزيفة
        mock_logger = MagicMock()
        mock_setup_logger.return_value = mock_logger
        
        mock_config_instance = MagicMock()
        mock_config_instance.get_config.return_value = test_config
        mock_config.return_value = mock_config_instance
        
        # تكوين نتائج المسح المزيفة
        scan_results = {
            'target': 'example.com',
            'scan_time': {
                'start': '2023-12-01T12:00:00',
                'end': '2023-12-01T12:05:00',
                'duration': 300
            },
            'ports': {
                '80': {
                    'state': 'open',
                    'service': 'http',
                    'version': 'nginx'
                },
                '443': {
                    'state': 'open',
                    'service': 'https',
                    'version': 'nginx'
                }
            }
        }
        
        web_results = {
            'web_info': {
                'server': 'nginx',
                'technologies': ['nginx/1.18.0'],
                'headers': {'Server': 'nginx'},
                'security_headers': {
                    'X-XSS-Protection': '1; mode=block'
                },
                'ssl_certificate': {
                    '443': {
                        'issuer': 'Let\'s Encrypt Authority X3',
                        'subject': 'example.com',
                        'valid_from': '2023-01-01',
                        'valid_to': '2023-12-31',
                        'version': 3
                    }
                }
            },
            'web_vulnerabilities': [
                {
                    'name': 'Missing Security Headers',
                    'description': 'The website is missing important security headers',
                    'severity': 'medium',
                    'location': 'HTTP Headers',
                    'recommendation': 'Implement the missing security headers'
                }
            ]
        }
        
        # تكوين الماسحات المزيفة
        mock_scanner_instance = MagicMock()
        mock_scanner_instance.scan.return_value = scan_results
        mock_scanner.return_value = mock_scanner_instance
        
        mock_web_instance = MagicMock()
        mock_web_instance.scan.return_value = web_results
        mock_web.return_value = mock_web_instance
        
        mock_wordpress_instance = MagicMock()
        mock_wordpress_instance.scan.return_value = {}
        mock_wordpress.return_value = mock_wordpress_instance
        
        mock_joomla_instance = MagicMock()
        mock_joomla_instance.scan.return_value = {}
        mock_joomla.return_value = mock_joomla_instance
        
        mock_report_instance = MagicMock()
        mock_report_instance.generate_report.return_value = os.path.join(test_output_dir, 'example.com_scan_report.json')
        mock_report_gen.return_value = mock_report_instance

        # تنفيذ الاختبار
        saudi_attack.run_scan(
            target='example.com',
            mode='general',
            output_format='json',
            ports=None,
            config_file=None,
            verbose=True
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
        
        # التحقق من أن السجل تم استدعاؤه بشكل صحيح
        mock_logger.info.assert_any_call("Starting scan for target: example.com")