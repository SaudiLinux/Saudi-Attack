#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pytest
import os
import sys
import socket
import ssl
import requests
from unittest.mock import patch, MagicMock, mock_open

# إضافة المجلد الرئيسي إلى مسار البحث
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# استيراد وحدة أدوات الشبكة
from modules.network_utils import (
    get_ip_info, get_whois_info, get_dns_records, check_open_ports,
    get_ssl_certificate_info, get_http_headers, make_http_request,
    is_port_open, scan_port_range, get_geolocation, get_asn_info,
    get_reverse_dns, check_common_vulnerabilities
)


class TestNetworkUtils:
    """اختبارات لوحدة أدوات الشبكة"""

    @patch('requests.get')
    def test_get_ip_info(self, mock_requests_get):
        """اختبار الحصول على معلومات عنوان IP"""
        # تكوين السلوك المزيف
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "ip": "8.8.8.8",
            "hostname": "dns.google",
            "city": "Mountain View",
            "region": "California",
            "country": "US",
            "loc": "37.4056,-122.0775",
            "org": "AS15169 Google LLC",
            "postal": "94043",
            "timezone": "America/Los_Angeles"
        }
        mock_requests_get.return_value = mock_response
        
        # تنفيذ الاختبار
        result = get_ip_info("8.8.8.8")
        
        # التحقق من النتائج
        mock_requests_get.assert_called_once()
        assert "8.8.8.8" in mock_requests_get.call_args[0][0]
        assert result["ip"] == "8.8.8.8"
        assert result["hostname"] == "dns.google"
        assert result["city"] == "Mountain View"
        assert result["country"] == "US"

    @patch('requests.get')
    def test_get_ip_info_error(self, mock_requests_get):
        """اختبار التعامل مع الأخطاء عند الحصول على معلومات عنوان IP"""
        # تكوين السلوك المزيف
        mock_requests_get.side_effect = requests.exceptions.RequestException("Connection error")
        
        # تنفيذ الاختبار
        result = get_ip_info("8.8.8.8")
        
        # التحقق من النتائج
        assert result == {}

    @patch('requests.get')
    def test_get_whois_info(self, mock_requests_get):
        """اختبار الحصول على معلومات WHOIS"""
        # تكوين السلوك المزيف
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "Domain Name: EXAMPLE.COM\nRegistry Domain ID: 2336799_DOMAIN_COM-VRSN"
        mock_requests_get.return_value = mock_response
        
        # تنفيذ الاختبار
        result = get_whois_info("example.com")
        
        # التحقق من النتائج
        mock_requests_get.assert_called_once()
        assert "example.com" in mock_requests_get.call_args[0][0]
        assert "Domain Name: EXAMPLE.COM" in result

    @patch('socket.getaddrinfo')
    def test_get_dns_records(self, mock_getaddrinfo):
        """اختبار الحصول على سجلات DNS"""
        # تكوين السلوك المزيف
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 0)),
            (socket.AF_INET, socket.SOCK_DGRAM, 17, '', ('93.184.216.34', 0))
        ]
        
        # تنفيذ الاختبار
        result = get_dns_records("example.com")
        
        # التحقق من النتائج
        mock_getaddrinfo.assert_called_once_with("example.com", None)
        assert "93.184.216.34" in result

    @patch('socket.socket')
    def test_is_port_open(self, mock_socket):
        """اختبار التحقق من فتح المنفذ"""
        # تكوين السلوك المزيف للمنفذ المفتوح
        mock_socket_instance = MagicMock()
        mock_socket.return_value = mock_socket_instance
        
        # تنفيذ الاختبار للمنفذ المفتوح
        result = is_port_open("example.com", 80)
        
        # التحقق من النتائج
        mock_socket.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)
        mock_socket_instance.settimeout.assert_called_once_with(2)
        mock_socket_instance.connect_ex.assert_called_once()
        assert result is True
        
        # إعادة تعيين المحاكاة
        mock_socket.reset_mock()
        mock_socket_instance.reset_mock()
        
        # تكوين السلوك المزيف للمنفذ المغلق
        mock_socket_instance.connect_ex.return_value = 1
        mock_socket.return_value = mock_socket_instance
        
        # تنفيذ الاختبار للمنفذ المغلق
        result = is_port_open("example.com", 81)
        
        # التحقق من النتائج
        assert result is False

    @patch('modules.network_utils.is_port_open')
    def test_scan_port_range(self, mock_is_port_open):
        """اختبار مسح نطاق المنافذ"""
        # تكوين السلوك المزيف
        mock_is_port_open.side_effect = [True, False, True]
        
        # تنفيذ الاختبار
        result = scan_port_range("example.com", [80, 443, 8080])
        
        # التحقق من النتائج
        assert mock_is_port_open.call_count == 3
        assert result == {80: True, 443: False, 8080: True}

    @patch('modules.network_utils.scan_port_range')
    def test_check_open_ports(self, mock_scan_port_range):
        """اختبار التحقق من المنافذ المفتوحة"""
        # تكوين السلوك المزيف
        mock_scan_port_range.return_value = {80: True, 443: True, 22: False}
        
        # تنفيذ الاختبار
        result = check_open_ports("example.com", [80, 443, 22])
        
        # التحقق من النتائج
        mock_scan_port_range.assert_called_once_with("example.com", [80, 443, 22])
        assert result == {80: True, 443: True, 22: False}

    @patch('ssl.create_default_context')
    @patch('socket.create_connection')
    def test_get_ssl_certificate_info(self, mock_create_connection, mock_create_default_context):
        """اختبار الحصول على معلومات شهادة SSL"""
        # تكوين السلوك المزيف
        mock_socket = MagicMock()
        mock_create_connection.return_value = mock_socket
        
        mock_context = MagicMock()
        mock_create_default_context.return_value = mock_context
        
        mock_ssl_socket = MagicMock()
        mock_context.wrap_socket.return_value = mock_ssl_socket
        
        mock_cert = {
            "notBefore": "20200101000000Z",
            "notAfter": "20210101000000Z",
            "subject": ((('commonName', 'example.com'),),),
            "issuer": ((('commonName', 'Let\'s Encrypt Authority X3'),),),
            "version": 3,
            "serialNumber": "1234567890"
        }
        mock_ssl_socket.getpeercert.return_value = mock_cert
        
        # تنفيذ الاختبار
        result = get_ssl_certificate_info("example.com", 443)
        
        # التحقق من النتائج
        mock_create_connection.assert_called_once_with(("example.com", 443))
        mock_create_default_context.assert_called_once()
        mock_context.wrap_socket.assert_called_once_with(mock_socket, server_hostname="example.com")
        mock_ssl_socket.getpeercert.assert_called_once()
        
        assert result["subject"] == "example.com"
        assert result["issuer"] == "Let's Encrypt Authority X3"
        assert result["valid_from"] == "20200101000000Z"
        assert result["valid_until"] == "20210101000000Z"
        assert result["version"] == 3

    @patch('requests.get')
    def test_get_http_headers(self, mock_requests_get):
        """اختبار الحصول على رؤوس HTTP"""
        # تكوين السلوك المزيف
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {
            "Server": "nginx/1.18.0",
            "Content-Type": "text/html; charset=UTF-8",
            "X-Frame-Options": "SAMEORIGIN",
            "X-XSS-Protection": "1; mode=block"
        }
        mock_requests_get.return_value = mock_response
        
        # تنفيذ الاختبار
        result = get_http_headers("http://example.com")
        
        # التحقق من النتائج
        mock_requests_get.assert_called_once_with("http://example.com", timeout=5, verify=False, allow_redirects=True, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        })
        assert result["Server"] == "nginx/1.18.0"
        assert result["Content-Type"] == "text/html; charset=UTF-8"
        assert result["X-Frame-Options"] == "SAMEORIGIN"
        assert result["X-XSS-Protection"] == "1; mode=block"

    @patch('requests.get')
    def test_make_http_request(self, mock_requests_get):
        """اختبار إجراء طلب HTTP"""
        # تكوين السلوك المزيف
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<html><body>Example</body></html>"
        mock_response.headers = {"Content-Type": "text/html"}
        mock_requests_get.return_value = mock_response
        
        # تنفيذ الاختبار
        status_code, content, headers = make_http_request("http://example.com")
        
        # التحقق من النتائج
        mock_requests_get.assert_called_once()
        assert status_code == 200
        assert content == "<html><body>Example</body></html>"
        assert headers["Content-Type"] == "text/html"

    @patch('requests.get')
    def test_get_geolocation(self, mock_requests_get):
        """اختبار الحصول على الموقع الجغرافي"""
        # تكوين السلوك المزيف
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "ip": "8.8.8.8",
            "country_code": "US",
            "country_name": "United States",
            "region_code": "CA",
            "region_name": "California",
            "city": "Mountain View",
            "zip_code": "94043",
            "latitude": 37.4056,
            "longitude": -122.0775,
            "time_zone": "America/Los_Angeles"
        }
        mock_requests_get.return_value = mock_response
        
        # تنفيذ الاختبار
        result = get_geolocation("8.8.8.8")
        
        # التحقق من النتائج
        mock_requests_get.assert_called_once()
        assert "8.8.8.8" in mock_requests_get.call_args[0][0]
        assert result["country_name"] == "United States"
        assert result["city"] == "Mountain View"
        assert result["latitude"] == 37.4056
        assert result["longitude"] == -122.0775

    @patch('requests.get')
    def test_get_asn_info(self, mock_requests_get):
        """اختبار الحصول على معلومات ASN"""
        # تكوين السلوك المزيف
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "ip": "8.8.8.8",
            "asn": "AS15169",
            "name": "Google LLC",
            "route": "8.8.8.0/24",
            "domain": "google.com",
            "type": "business"
        }
        mock_requests_get.return_value = mock_response
        
        # تنفيذ الاختبار
        result = get_asn_info("8.8.8.8")
        
        # التحقق من النتائج
        mock_requests_get.assert_called_once()
        assert "8.8.8.8" in mock_requests_get.call_args[0][0]
        assert result["asn"] == "AS15169"
        assert result["name"] == "Google LLC"
        assert result["route"] == "8.8.8.0/24"
        assert result["domain"] == "google.com"

    @patch('socket.gethostbyaddr')
    def test_get_reverse_dns(self, mock_gethostbyaddr):
        """اختبار الحصول على DNS العكسي"""
        # تكوين السلوك المزيف
        mock_gethostbyaddr.return_value = ("dns.google", [], ["8.8.8.8"])
        
        # تنفيذ الاختبار
        result = get_reverse_dns("8.8.8.8")
        
        # التحقق من النتائج
        mock_gethostbyaddr.assert_called_once_with("8.8.8.8")
        assert result == "dns.google"

    @patch('socket.gethostbyaddr', side_effect=socket.herror)
    def test_get_reverse_dns_error(self, mock_gethostbyaddr):
        """اختبار التعامل مع الأخطاء عند الحصول على DNS العكسي"""
        # تنفيذ الاختبار
        result = get_reverse_dns("8.8.8.8")
        
        # التحقق من النتائج
        mock_gethostbyaddr.assert_called_once_with("8.8.8.8")
        assert result == ""

    @patch('modules.network_utils.get_http_headers')
    @patch('modules.network_utils.get_ssl_certificate_info')
    def test_check_common_vulnerabilities(self, mock_get_ssl_certificate_info, mock_get_http_headers):
        """اختبار التحقق من الثغرات الشائعة"""
        # تكوين السلوك المزيف
        mock_get_http_headers.return_value = {
            "Server": "nginx/1.18.0",
            "X-Frame-Options": "SAMEORIGIN",
            "X-XSS-Protection": "1; mode=block",
            "Content-Security-Policy": "default-src 'self'"
        }
        
        mock_get_ssl_certificate_info.return_value = {
            "subject": "example.com",
            "issuer": "Let's Encrypt Authority X3",
            "valid_from": "20200101000000Z",
            "valid_until": "20210101000000Z",
            "version": 3
        }
        
        # تنفيذ الاختبار
        result = check_common_vulnerabilities("example.com")
        
        # التحقق من النتائج
        mock_get_http_headers.assert_called_once_with("https://example.com")
        mock_get_ssl_certificate_info.assert_called_once_with("example.com", 443)
        
        assert "security_headers" in result
        assert "ssl_certificate" in result
        assert "missing_headers" in result["security_headers"]
        assert "present_headers" in result["security_headers"]
        assert "X-Frame-Options" in result["security_headers"]["present_headers"]
        assert "X-XSS-Protection" in result["security_headers"]["present_headers"]
        assert "Content-Security-Policy" in result["security_headers"]["present_headers"]