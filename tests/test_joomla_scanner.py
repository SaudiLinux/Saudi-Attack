#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pytest
from unittest.mock import patch, MagicMock

# افتراض أن وحدة فحص جوملا موجودة في المسار التالي
from modules.joomla_scanner import JoomlaScanner


class TestJoomlaScanner:
    """اختبارات لوحدة فحص جوملا"""

    def setup_method(self):
        """إعداد بيئة الاختبار قبل كل اختبار"""
        self.config = {
            'general': {
                'threads': 5,
                'timeout': 10,
                'user_agent': 'SaudiAttack/1.0.0 (Test)'
            },
            'joomla': {
                'detection_paths': ['/administrator/', '/components/']
            }
        }
        self.logger = MagicMock()
        self.joomla_scanner = JoomlaScanner(self.config, self.logger)

    def test_initialization(self):
        """اختبار تهيئة الماسح"""
        assert self.joomla_scanner.config == self.config
        assert self.joomla_scanner.logger == self.logger
        assert self.joomla_scanner.detection_paths == ['/administrator/', '/components/']
        assert self.joomla_scanner.user_agent == 'SaudiAttack/1.0.0 (Test)'
        assert self.joomla_scanner.timeout == 10

    @patch('requests.get')
    def test_is_joomla_site_positive(self, mock_get):
        """اختبار التعرف على موقع جوملا بشكل إيجابي"""
        # تكوين الاستجابة المزيفة للطلب الأول (/administrator/)
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = '<form action="index.php" method="post" id="form-login" class="form-inline"'
        mock_get.return_value = mock_response

        result = self.joomla_scanner._is_joomla_site('http://example.com')
        assert result is True
        mock_get.assert_called_once()
        assert 'administrator' in mock_get.call_args[0][0]

    @patch('requests.get')
    def test_is_joomla_site_negative(self, mock_get):
        """اختبار التعرف على موقع غير جوملا"""
        # تكوين الاستجابة المزيفة للطلبات (جميعها سلبية)
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response

        result = self.joomla_scanner._is_joomla_site('http://example.com')
        assert result is False
        # يجب أن يتم استدعاء الدالة مرتين (لكل مسار من مسارات الكشف)
        assert mock_get.call_count == 2

    @patch('requests.get')
    def test_get_joomla_version(self, mock_get):
        """اختبار استخراج إصدار جوملا"""
        # تكوين الاستجابة المزيفة للطلب
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = '<meta name="generator" content="Joomla! 3.9.24 - Open Source Content Management" />'
        mock_get.return_value = mock_response

        version = self.joomla_scanner._get_joomla_version('http://example.com')
        assert version == '3.9.24'
        mock_get.assert_called_once_with(
            'http://example.com',
            headers={'User-Agent': 'SaudiAttack/1.0.0 (Test)'},
            timeout=10,
            verify=False
        )

    @patch('requests.get')
    def test_get_joomla_version_not_found(self, mock_get):
        """اختبار عدم العثور على إصدار جوملا"""
        # تكوين الاستجابة المزيفة للطلب
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = '<html><body>No version info</body></html>'
        mock_get.return_value = mock_response

        version = self.joomla_scanner._get_joomla_version('http://example.com')
        assert version == 'Unknown'

    @patch('requests.get')
    def test_get_joomla_components(self, mock_get):
        """اختبار استخراج مكونات جوملا"""
        # تكوين الاستجابة المزيفة للطلب
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = '''
        <link rel="stylesheet" href="/components/com_content/assets/css/style.css?v=3.9.24" />
        <script src="/components/com_users/assets/js/script.js?v=3.9.24"></script>
        '''
        mock_get.return_value = mock_response

        components = self.joomla_scanner._get_joomla_components('http://example.com')
        assert len(components) == 2
        assert components[0]['name'] == 'com_content'
        assert components[0]['version'] == '3.9.24'
        assert components[1]['name'] == 'com_users'
        assert components[1]['version'] == '3.9.24'

    @patch('requests.get')
    def test_get_joomla_templates(self, mock_get):
        """اختبار استخراج قوالب جوملا"""
        # تكوين الاستجابة المزيفة للطلب
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = '''
        <link rel="stylesheet" href="/templates/protostar/css/template.css?v=3.9.24" />
        <link rel="stylesheet" href="/templates/protostar/css/custom.css" />
        '''
        mock_get.return_value = mock_response

        templates = self.joomla_scanner._get_joomla_templates('http://example.com')
        assert len(templates) == 1
        assert templates[0]['name'] == 'protostar'
        assert templates[0]['version'] == '3.9.24'

    @patch.object(JoomlaScanner, '_is_joomla_site')
    @patch.object(JoomlaScanner, '_get_joomla_version')
    @patch.object(JoomlaScanner, '_get_joomla_components')
    @patch.object(JoomlaScanner, '_get_joomla_templates')
    @patch.object(JoomlaScanner, '_check_vulnerabilities')
    def test_scan_joomla_site(self, mock_check_vulns, mock_get_templates, 
                             mock_get_components, mock_get_version, mock_is_joomla):
        """اختبار المسح الكامل لموقع جوملا"""
        # تكوين القيم المرجعة للدوال المزيفة
        mock_is_joomla.return_value = True
        mock_get_version.return_value = '3.9.24'
        mock_get_components.return_value = [{'name': 'com_content', 'version': '3.9.24'}]
        mock_get_templates.return_value = [{'name': 'protostar', 'version': '3.9.24'}]
        mock_check_vulns.return_value = [
            {
                'name': 'Joomla Core < 3.9.25 - Vulnerability',
                'description': 'A vulnerability in Joomla core',
                'severity': 'high',
                'component': 'core',
                'recommendation': 'Update to Joomla 3.9.25 or later'
            }
        ]

        # تنفيذ المسح
        result = self.joomla_scanner.scan('http://example.com')

        # التحقق من النتائج
        assert result['joomla_info']['version'] == '3.9.24'
        assert len(result['joomla_info']['components']) == 1
        assert result['joomla_info']['components'][0]['name'] == 'com_content'
        assert len(result['joomla_info']['templates']) == 1
        assert result['joomla_info']['templates'][0]['name'] == 'protostar'
        assert len(result['joomla_vulnerabilities']) == 1
        assert result['joomla_vulnerabilities'][0]['severity'] == 'high'

    @patch.object(JoomlaScanner, '_is_joomla_site')
    def test_scan_not_joomla_site(self, mock_is_joomla):
        """اختبار المسح لموقع غير جوملا"""
        # تكوين القيمة المرجعة للدالة المزيفة
        mock_is_joomla.return_value = False

        # تنفيذ المسح
        result = self.joomla_scanner.scan('http://example.com')

        # التحقق من النتائج
        assert result == {}
        self.logger.info.assert_called_with("Target is not a Joomla site: http://example.com")

    def test_check_vulnerabilities(self):
        """اختبار التحقق من الثغرات الأمنية"""
        # تكوين بيانات جوملا للفحص
        joomla_data = {
            'version': '3.9.24',
            'components': [{'name': 'com_content', 'version': '3.9.24'}],
            'templates': [{'name': 'protostar', 'version': '3.9.24'}]
        }

        # تزييف قاعدة بيانات الثغرات
        with patch.object(self.joomla_scanner, 'vuln_db', {
            'core': {
                '3.9.24': [
                    {
                        'name': 'Joomla Core < 3.9.25 - Vulnerability',
                        'description': 'A vulnerability in Joomla core',
                        'severity': 'high',
                        'recommendation': 'Update to Joomla 3.9.25 or later'
                    }
                ]
            },
            'components': {
                'com_content': {
                    '3.9.24': [
                        {
                            'name': 'com_content < 3.9.25 - Vulnerability',
                            'description': 'A vulnerability in the component',
                            'severity': 'medium',
                            'recommendation': 'Update to version 3.9.25 or later'
                        }
                    ]
                }
            },
            'templates': {}
        }):
            vulnerabilities = self.joomla_scanner._check_vulnerabilities(joomla_data)
            
            # التحقق من النتائج
            assert len(vulnerabilities) == 2
            assert vulnerabilities[0]['name'] == 'Joomla Core < 3.9.25 - Vulnerability'
            assert vulnerabilities[0]['severity'] == 'high'
            assert vulnerabilities[1]['name'] == 'com_content < 3.9.25 - Vulnerability'
            assert vulnerabilities[1]['severity'] == 'medium'