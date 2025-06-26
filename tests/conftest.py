#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pytest
import sys
import os
from unittest.mock import MagicMock

# إضافة المجلد الرئيسي إلى مسار البحث
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


@pytest.fixture
def mock_logger():
    """إنشاء سجل مزيف للاختبارات"""
    logger = MagicMock()
    logger.info = MagicMock()
    logger.warning = MagicMock()
    logger.error = MagicMock()
    logger.debug = MagicMock()
    logger.critical = MagicMock()
    return logger


@pytest.fixture
def sample_config():
    """إنشاء تكوين عينة للاختبارات"""
    return {
        'general': {
            'threads': 5,
            'timeout': 10,
            'user_agent': 'SaudiAttack/1.0.0 (Test)',
            'output_dir': './test_reports'
        },
        'scan': {
            'ports': {
                'general': [21, 22, 80, 443],
                'web': [80, 443],
                'wordpress': [80, 443],
                'joomla': [80, 443]
            },
            'nmap_scripts': ['default', 'vuln']
        },
        'web': {
            'paths_to_check': ['/admin', '/login'],
            'security_headers': [
                'Content-Security-Policy',
                'X-XSS-Protection',
                'X-Content-Type-Options'
            ]
        },
        'wordpress': {
            'detection_paths': ['/wp-login.php', '/wp-admin/']
        },
        'joomla': {
            'detection_paths': ['/administrator/', '/components/']
        },
        'report': {
            'formats': ['html', 'json', 'txt'],
            'default_format': 'html',
            'severity_levels': ['critical', 'high', 'medium', 'low', 'info'],
            'template_dir': './templates'
        }
    }


@pytest.fixture
def sample_scan_results():
    """إنشاء نتائج مسح عينة للاختبارات"""
    return {
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
                'version': 'Apache httpd 2.4.41'
            },
            '443': {
                'state': 'open',
                'service': 'https',
                'version': 'Apache httpd 2.4.41'
            }
        },
        'os_info': {
            'name': 'Linux',
            'accuracy': '95'
        },
        'vulnerabilities': [
            {
                'id': 'CVE-2021-12345',
                'name': 'Apache HTTP Server Vulnerability',
                'description': 'A vulnerability in Apache HTTP Server',
                'severity': 'high',
                'cvss': 7.5,
                'references': ['https://example.com/cve-2021-12345']
            }
        ],
        'web_info': {
            'server': 'Apache/2.4.41',
            'technologies': ['PHP/7.4.3', 'jQuery/3.5.1'],
            'headers': {'Server': 'Apache/2.4.41'},
            'security_headers': {
                'X-XSS-Protection': '1; mode=block',
                'X-Content-Type-Options': 'nosniff'
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
        ],
        'wordpress_info': {
            'version': '5.8.2',
            'themes': [
                {'name': 'twentytwentyone', 'version': '1.4'}
            ],
            'plugins': [
                {'name': 'akismet', 'version': '4.2.1'}
            ],
            'users': ['admin']
        },
        'wordpress_vulnerabilities': [
            {
                'name': 'WordPress Core < 5.8.3 - Vulnerability',
                'description': 'A vulnerability in WordPress core',
                'severity': 'high',
                'component': 'core',
                'recommendation': 'Update to WordPress 5.8.3 or later'
            }
        ],
        'joomla_info': {
            'version': '3.9.24',
            'components': [
                {'name': 'com_content', 'version': '3.9.24'}
            ],
            'templates': [
                {'name': 'protostar', 'version': '3.9.24'}
            ]
        },
        'joomla_vulnerabilities': [
            {
                'name': 'Joomla Core < 3.9.25 - Vulnerability',
                'description': 'A vulnerability in Joomla core',
                'severity': 'high',
                'component': 'core',
                'recommendation': 'Update to Joomla 3.9.25 or later'
            }
        ]
    }