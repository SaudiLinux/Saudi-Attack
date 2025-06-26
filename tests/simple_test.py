# -*- coding: utf-8 -*-

from unittest.mock import patch, MagicMock, mock_open
import json
import os
import sys

# إضافة المسار الصحيح للمشروع
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from modules.wordpress_scanner import WordPressScanner

# إنشاء كائن الاختبار
target = "example.com"
ports = [80, 443]
threads = 5
timeout = 3
logger = MagicMock()
scanner = WordPressScanner(target, ports, threads, timeout, logger)

# اختبار التهيئة
print("اختبار التهيئة:")
print(f"Target: {scanner.target == target}")
print(f"Ports: {scanner.ports == ports}")
print(f"Threads: {scanner.threads == threads}")
print(f"Timeout: {scanner.timeout == timeout}")
print(f"Logger: {scanner.logger == logger}")
print(f"is_wordpress: {scanner.results['wordpress_info']['is_wordpress'] is False}")
print(f"version: {scanner.results['wordpress_info']['version'] == ''}")
print(f"themes: {scanner.results['wordpress_info']['themes'] == []}")
print(f"plugins: {scanner.results['wordpress_info']['plugins'] == []}")
print(f"users: {scanner.results['wordpress_info']['users'] == []}")
print(f"is_multisite: {scanner.results['wordpress_info']['is_multisite'] is False}")
print(f"vulnerabilities: {scanner.results['wordpress_vulnerabilities'] == []}")

# اختبار _is_version_vulnerable
print("\nاختبار _is_version_vulnerable:")
print(f"5.8.1 < 5.8.2: {scanner._is_version_vulnerable('5.8.1', '5.8.2') == True}")
print(f"5.8.2 = 5.8.2: {scanner._is_version_vulnerable('5.8.2', '5.8.2') == True}")
print(f"5.8.3 > 5.8.2: {scanner._is_version_vulnerable('5.8.3', '5.8.2') == False}")
print(f"5.8 < 5.8.2: {scanner._is_version_vulnerable('5.8', '5.8.2') == True}")
print(f"5.9 > 5.8.2: {scanner._is_version_vulnerable('5.9', '5.8.2') == False}")
print(f"'' (unknown) vs 5.8.2: {scanner._is_version_vulnerable('', '5.8.2') == True}")

print("\nتم تنفيذ الاختبارات بنجاح!")