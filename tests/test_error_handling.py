#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pytest
import os
import sys
import tempfile
import shutil
from unittest.mock import patch, MagicMock, mock_open

# إضافة المجلد الرئيسي إلى مسار البحث
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# استيراد الوحدات المطلوبة للاختبار
from modules.utils import setup_logger
from modules.config import ConfigManager
from modules.scanner import VulnerabilityScanner
from modules.web_scanner import WebServerScanner
from modules.wordpress_scanner import WordPressScanner
from modules.joomla_scanner import JoomlaScanner
from modules.report_generator import ReportGenerator


@pytest.fixture
def temp_dir():
    """إنشاء مجلد مؤقت للاختبار"""
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    shutil.rmtree(temp_dir)


@pytest.fixture
def mock_logger():
    """إنشاء سجل مزيف للاختبار"""
    logger = MagicMock()
    with patch('modules.utils.setup_logger', return_value=logger):
        yield logger


@pytest.fixture
def mock_config():
    """تكوين مزيف للاختبار"""
    config = {
        "general": {
            "threads": 5,
            "timeout": 10,
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "output_dir": "./reports"
        },
        "scan": {
            "ports": {
                "general": [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080],
                "web": [80, 443, 8080, 8443],
                "wordpress": [80, 443, 8080, 8443],
                "joomla": [80, 443, 8080, 8443]
            },
            "nmap_scripts": ["banner", "http-headers", "http-title", "ssl-cert", "ssl-enum-ciphers"]
        },
        "web_server": {
            "paths": ["/", "/admin", "/login", "/wp-admin", "/administrator"],
            "security_headers": ["X-Frame-Options", "X-XSS-Protection", "Content-Security-Policy", "Strict-Transport-Security"]
        },
        "wordpress": {
            "detection_paths": ["/wp-login.php", "/wp-admin", "/wp-content"]
        },
        "joomla": {
            "detection_paths": ["/administrator", "/components", "/modules", "/templates"]
        },
        "report": {
            "formats": ["json", "html", "txt", "md"],
            "default_format": "html",
            "severity_levels": ["critical", "high", "medium", "low", "info"],
            "template_dir": "./templates"
        }
    }
    return config


class TestErrorHandling:
    """اختبارات معالجة الأخطاء للأداة"""

    def test_invalid_target_handling(self, mock_logger):
        """اختبار معالجة هدف غير صالح"""
        # إنشاء كائن الماسح مع هدف غير صالح
        with pytest.raises(ValueError) as excinfo:
            scanner = VulnerabilityScanner(target="invalid!@#$%^&*()")
        
        # التحقق من رسالة الخطأ
        assert "Invalid target" in str(excinfo.value) or "هدف غير صالح" in str(excinfo.value)

    def test_connection_timeout_handling(self, mock_logger):
        """اختبار معالجة انتهاء مهلة الاتصال"""
        # إنشاء كائن الماسح
        scanner = VulnerabilityScanner(target="example.com")
        
        # محاكاة انتهاء مهلة الاتصال أثناء المسح
        with patch('socket.socket.connect', side_effect=TimeoutError("Connection timed out")):
            # يجب أن يتم التقاط الخطأ ومعالجته بشكل صحيح
            result = scanner._get_dns_info()
            
            # التحقق من أن النتيجة تشير إلى فشل الاتصال
            assert result == [] or result is None
            
            # التحقق من تسجيل الخطأ
            mock_logger.error.assert_called_with(pytest.raises(TimeoutError))

    def test_dns_resolution_failure(self, mock_logger):
        """اختبار معالجة فشل تحليل DNS"""
        # إنشاء كائن الماسح
        scanner = VulnerabilityScanner(target="nonexistent-domain-12345.com")
        
        # محاكاة فشل تحليل DNS
        with patch('socket.gethostbyname', side_effect=socket.gaierror("[Errno 11001] getaddrinfo failed")):
            # يجب أن يتم التقاط الخطأ ومعالجته بشكل صحيح
            result = scanner._get_dns_info()
            
            # التحقق من أن النتيجة تشير إلى فشل تحليل DNS
            assert result == [] or result is None
            
            # التحقق من تسجيل الخطأ
            mock_logger.error.assert_called()

    def test_nmap_not_installed(self, mock_logger):
        """اختبار معالجة عدم تثبيت Nmap"""
        # إنشاء كائن الماسح
        scanner = VulnerabilityScanner(target="example.com")
        
        # محاكاة عدم تثبيت Nmap
        with patch('subprocess.Popen', side_effect=FileNotFoundError("[Errno 2] No such file or directory: 'nmap'")):
            # يجب أن يتم التقاط الخطأ ومعالجته بشكل صحيح
            result = scanner._run_nmap_scan()
            
            # التحقق من أن النتيجة تشير إلى فشل تشغيل Nmap
            assert result == {} or result is None
            
            # التحقق من تسجيل الخطأ
            mock_logger.error.assert_called_with(pytest.raises(FileNotFoundError))

    def test_http_request_failure(self, mock_logger):
        """اختبار معالجة فشل طلب HTTP"""
        # إنشاء كائن ماسح الويب
        web_scanner = WebServerScanner(target="example.com")
        
        # محاكاة فشل طلب HTTP
        with patch('requests.get', side_effect=Exception("Connection refused")):
            # يجب أن يتم التقاط الخطأ ومعالجته بشكل صحيح
            result = web_scanner._get_web_server_info()
            
            # التحقق من أن النتيجة تشير إلى فشل طلب HTTP
            assert result == {} or result is None
            
            # التحقق من تسجيل الخطأ
            mock_logger.error.assert_called()

    def test_ssl_certificate_error(self, mock_logger):
        """اختبار معالجة خطأ شهادة SSL"""
        # إنشاء كائن ماسح الويب
        web_scanner = WebServerScanner(target="example.com")
        
        # محاكاة خطأ شهادة SSL
        with patch('ssl.get_server_certificate', side_effect=ssl.SSLError("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed")):
            # يجب أن يتم التقاط الخطأ ومعالجته بشكل صحيح
            result = web_scanner._check_ssl_certificate()
            
            # التحقق من أن النتيجة تشير إلى فشل التحقق من شهادة SSL
            assert result == {"valid": False, "error": "Certificate verification failed"} or result is None
            
            # التحقق من تسجيل الخطأ
            mock_logger.error.assert_called()

    def test_wordpress_detection_error(self, mock_logger):
        """اختبار معالجة خطأ اكتشاف WordPress"""
        # إنشاء كائن ماسح WordPress
        wp_scanner = WordPressScanner(target="example.com")
        
        # محاكاة خطأ أثناء اكتشاف WordPress
        with patch('requests.get', side_effect=Exception("Connection refused")):
            # يجب أن يتم التقاط الخطأ ومعالجته بشكل صحيح
            result = wp_scanner.is_wordpress()
            
            # التحقق من أن النتيجة تشير إلى فشل اكتشاف WordPress
            assert result is False
            
            # التحقق من تسجيل الخطأ
            mock_logger.error.assert_called()

    def test_joomla_detection_error(self, mock_logger):
        """اختبار معالجة خطأ اكتشاف Joomla"""
        # إنشاء كائن ماسح Joomla
        joomla_scanner = JoomlaScanner(target="example.com")
        
        # محاكاة خطأ أثناء اكتشاف Joomla
        with patch('requests.get', side_effect=Exception("Connection refused")):
            # يجب أن يتم التقاط الخطأ ومعالجته بشكل صحيح
            result = joomla_scanner.is_joomla()
            
            # التحقق من أن النتيجة تشير إلى فشل اكتشاف Joomla
            assert result is False
            
            # التحقق من تسجيل الخطأ
            mock_logger.error.assert_called()

    def test_config_file_not_found(self, mock_logger):
        """اختبار معالجة عدم العثور على ملف التكوين"""
        # محاولة تحميل ملف تكوين غير موجود
        config_manager = ConfigManager()
        
        # يجب أن يتم التقاط الخطأ ومعالجته بشكل صحيح
        with patch('builtins.open', side_effect=FileNotFoundError("[Errno 2] No such file or directory: 'config.yaml'")):
            # يجب أن يتم استخدام التكوين الافتراضي
            config = config_manager.load_config("nonexistent_config.yaml")
            
            # التحقق من أن التكوين الافتراضي تم استخدامه
            assert config is not None
            assert "general" in config
            assert "scan" in config
            
            # التحقق من تسجيل الخطأ
            mock_logger.warning.assert_called()

    def test_invalid_config_format(self, mock_logger):
        """اختبار معالجة تنسيق تكوين غير صالح"""
        # محاولة تحميل ملف تكوين بتنسيق غير صالح
        config_manager = ConfigManager()
        
        # محاكاة ملف تكوين بتنسيق غير صالح
        with patch('builtins.open', mock_open(read_data="invalid: yaml: format:")), \
             patch('yaml.safe_load', side_effect=yaml.YAMLError("mapping values are not allowed here")):
            # يجب أن يتم التقاط الخطأ ومعالجته بشكل صحيح
            config = config_manager.load_config("invalid_config.yaml")
            
            # التحقق من أن التكوين الافتراضي تم استخدامه
            assert config is not None
            assert "general" in config
            assert "scan" in config
            
            # التحقق من تسجيل الخطأ
            mock_logger.error.assert_called()

    def test_report_directory_creation_error(self, mock_logger):
        """اختبار معالجة خطأ إنشاء مجلد التقارير"""
        # إنشاء كائن مولد التقارير مع مجلد غير قابل للكتابة
        with patch('os.makedirs', side_effect=PermissionError("[Errno 13] Permission denied: '/root/reports'")):
            # يجب أن يتم التقاط الخطأ ومعالجته بشكل صحيح
            generator = ReportGenerator({"target": "example.com"}, output_dir="/root/reports")
            
            # التحقق من أن مجلد التقارير الافتراضي تم استخدامه
            assert generator.output_dir != "/root/reports"
            
            # التحقق من تسجيل الخطأ
            mock_logger.error.assert_called()

    def test_invalid_report_format(self, mock_logger):
        """اختبار معالجة تنسيق تقرير غير صالح"""
        # إنشاء كائن مولد التقارير
        generator = ReportGenerator({"target": "example.com"})
        
        # محاولة توليد تقرير بتنسيق غير صالح
        result = generator.generate_report(format="invalid_format")
        
        # التحقق من أن تنسيق التقرير الافتراضي تم استخدامه
        assert result is not None
        assert "format" in result
        assert result["format"] != "invalid_format"
        
        # التحقق من تسجيل الخطأ
        mock_logger.warning.assert_called()

    def test_empty_scan_results(self, mock_logger):
        """اختبار معالجة نتائج مسح فارغة"""
        # إنشاء كائن مولد التقارير مع نتائج فارغة
        generator = ReportGenerator({})
        
        # محاولة توليد تقرير
        result = generator.generate_report()
        
        # التحقق من أن التقرير يشير إلى نتائج فارغة
        assert result is not None
        assert "error" in result or "warning" in result
        
        # التحقق من تسجيل الخطأ
        mock_logger.warning.assert_called()

    def test_keyboard_interrupt_handling(self, mock_logger):
        """اختبار معالجة مقاطعة لوحة المفاتيح"""
        # استيراد الوحدة المطلوبة للاختبار
        from modules.main import run_scan
        
        # محاكاة مقاطعة لوحة المفاتيح أثناء المسح
        with patch('modules.scanner.VulnerabilityScanner.scan', side_effect=KeyboardInterrupt()):
            # يجب أن يتم التقاط الخطأ ومعالجته بشكل صحيح
            with pytest.raises(SystemExit) as excinfo:
                run_scan(target="example.com")
            
            # التحقق من رمز الخروج
            assert excinfo.value.code == 1 or excinfo.value.code == 130
            
            # التحقق من تسجيل الخطأ
            mock_logger.info.assert_called_with("Scan interrupted by user")

    def test_memory_error_handling(self, mock_logger):
        """اختبار معالجة خطأ الذاكرة"""
        # استيراد الوحدة المطلوبة للاختبار
        from modules.main import run_scan
        
        # محاكاة خطأ الذاكرة أثناء المسح
        with patch('modules.scanner.VulnerabilityScanner.scan', side_effect=MemoryError("Out of memory")):
            # يجب أن يتم التقاط الخطأ ومعالجته بشكل صحيح
            with pytest.raises(SystemExit) as excinfo:
                run_scan(target="example.com")
            
            # التحقق من رمز الخروج
            assert excinfo.value.code != 0
            
            # التحقق من تسجيل الخطأ
            mock_logger.error.assert_called()

    def test_disk_space_error_handling(self, mock_logger):
        """اختبار معالجة خطأ مساحة القرص"""
        # استيراد الوحدة المطلوبة للاختبار
        from modules.report_generator import ReportGenerator
        
        # محاكاة خطأ مساحة القرص أثناء توليد التقرير
        with patch('builtins.open', side_effect=OSError("[Errno 28] No space left on device")):
            # إنشاء كائن مولد التقارير
            generator = ReportGenerator({"target": "example.com"})
            
            # محاولة توليد تقرير
            result = generator._generate_json_report()
            
            # التحقق من أن النتيجة تشير إلى فشل توليد التقرير
            assert result is None or "error" in result
            
            # التحقق من تسجيل الخطأ
            mock_logger.error.assert_called()

    def test_network_unreachable_error(self, mock_logger):
        """اختبار معالجة خطأ الشبكة غير قابلة للوصول"""
        # إنشاء كائن الماسح
        scanner = VulnerabilityScanner(target="example.com")
        
        # محاكاة خطأ الشبكة غير قابلة للوصول
        with patch('socket.socket.connect', side_effect=OSError("[Errno 51] Network is unreachable")):
            # يجب أن يتم التقاط الخطأ ومعالجته بشكل صحيح
            result = scanner._get_whois_info()
            
            # التحقق من أن النتيجة تشير إلى فشل الاتصال
            assert result == "" or result is None
            
            # التحقق من تسجيل الخطأ
            mock_logger.error.assert_called()

    def test_dependency_import_error(self, mock_logger):
        """اختبار معالجة خطأ استيراد التبعيات"""
        # محاكاة خطأ استيراد التبعيات
        with patch('importlib.import_module', side_effect=ImportError("No module named 'requests'")):
            # محاولة استيراد وحدة
            with pytest.raises(SystemExit) as excinfo:
                # استيراد الوحدة المطلوبة للاختبار
                from modules.main import check_dependencies
                check_dependencies()
            
            # التحقق من رمز الخروج
            assert excinfo.value.code != 0
            
            # التحقق من تسجيل الخطأ
            mock_logger.error.assert_called()

    def test_invalid_port_range(self, mock_logger):
        """اختبار معالجة نطاق منفذ غير صالح"""
        # استيراد الوحدة المطلوبة للاختبار
        from modules.utils import parse_ports
        
        # محاولة تحليل نطاق منفذ غير صالح
        with pytest.raises(ValueError) as excinfo:
            parse_ports("65536-65537")
        
        # التحقق من رسالة الخطأ
        assert "Invalid port" in str(excinfo.value) or "منفذ غير صالح" in str(excinfo.value)
        
        # التحقق من تسجيل الخطأ
        mock_logger.error.assert_called()

    def test_invalid_ip_format(self, mock_logger):
        """اختبار معالجة تنسيق IP غير صالح"""
        # استيراد الوحدة المطلوبة للاختبار
        from modules.utils import is_valid_ip
        
        # التحقق من تنسيق IP غير صالح
        assert not is_valid_ip("256.256.256.256")
        assert not is_valid_ip("192.168.1")
        assert not is_valid_ip("192.168.1.1.1")
        assert not is_valid_ip("192.168.1.a")

    def test_invalid_domain_format(self, mock_logger):
        """اختبار معالجة تنسيق المجال غير صالح"""
        # استيراد الوحدة المطلوبة للاختبار
        from modules.utils import is_valid_domain
        
        # التحقق من تنسيق المجال غير صالح
        assert not is_valid_domain("example")
        assert not is_valid_domain("example..com")
        assert not is_valid_domain("-example.com")
        assert not is_valid_domain("example-.com")
        assert not is_valid_domain("exam!ple.com")

    def test_timeout_value_handling(self, mock_config):
        """اختبار معالجة قيمة المهلة"""
        # تعديل قيمة المهلة إلى قيمة غير صالحة
        mock_config["general"]["timeout"] = -1
        
        # إنشاء كائن الماسح مع تكوين غير صالح
        scanner = VulnerabilityScanner(target="example.com", config=mock_config)
        
        # التحقق من أن قيمة المهلة تم تصحيحها
        assert scanner.timeout > 0

    def test_threads_value_handling(self, mock_config):
        """اختبار معالجة قيمة المواضيع"""
        # تعديل قيمة المواضيع إلى قيمة غير صالحة
        mock_config["general"]["threads"] = 0
        
        # إنشاء كائن الماسح مع تكوين غير صالح
        scanner = VulnerabilityScanner(target="example.com", config=mock_config)
        
        # التحقق من أن قيمة المواضيع تم تصحيحها
        assert scanner.threads > 0

    def test_missing_config_sections(self, mock_config):
        """اختبار معالجة أقسام التكوين المفقودة"""
        # إزالة قسم من التكوين
        del mock_config["scan"]
        
        # إنشاء كائن الماسح مع تكوين غير مكتمل
        scanner = VulnerabilityScanner(target="example.com", config=mock_config)
        
        # التحقق من أن القسم المفقود تم إضافته
        assert hasattr(scanner, "ports") or hasattr(scanner, "scan_ports")

    def test_invalid_output_directory(self, mock_logger, temp_dir):
        """اختبار معالجة مجلد الإخراج غير الصالح"""
        # إنشاء ملف عادي (وليس مجلد) في المجلد المؤقت
        invalid_dir = os.path.join(temp_dir, "not_a_directory")
        with open(invalid_dir, "w") as f:
            f.write("This is a file, not a directory")
        
        # إنشاء كائن مولد التقارير مع مجلد إخراج غير صالح
        generator = ReportGenerator({"target": "example.com"}, output_dir=invalid_dir)
        
        # التحقق من أن مجلد الإخراج تم تصحيحه
        assert generator.output_dir != invalid_dir
        
        # التحقق من تسجيل الخطأ
        mock_logger.error.assert_called()

    def test_empty_target_handling(self, mock_logger):
        """اختبار معالجة هدف فارغ"""
        # محاولة إنشاء كائن الماسح بدون هدف
        with pytest.raises(ValueError) as excinfo:
            scanner = VulnerabilityScanner(target="")
        
        # التحقق من رسالة الخطأ
        assert "Target cannot be empty" in str(excinfo.value) or "الهدف لا يمكن أن يكون فارغًا" in str(excinfo.value)
        
        # التحقق من تسجيل الخطأ
        mock_logger.error.assert_called()

    def test_invalid_scan_mode(self, mock_logger):
        """اختبار معالجة وضع مسح غير صالح"""
        # استيراد الوحدة المطلوبة للاختبار
        from modules.main import run_scan
        
        # محاولة تشغيل المسح بوضع غير صالح
        with pytest.raises(ValueError) as excinfo:
            run_scan(target="example.com", mode="invalid_mode")
        
        # التحقق من رسالة الخطأ
        assert "Invalid scan mode" in str(excinfo.value) or "وضع مسح غير صالح" in str(excinfo.value)
        
        # التحقق من تسجيل الخطأ
        mock_logger.error.assert_called()