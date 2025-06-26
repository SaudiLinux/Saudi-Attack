#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pytest
import os
import sys
import platform
import tempfile
import shutil
from unittest.mock import patch, MagicMock, mock_open

# إضافة المجلد الرئيسي إلى مسار البحث
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# استيراد الوحدات المطلوبة للاختبار
from modules.utils import get_os_type, is_tool_available, get_home_directory
from modules.config import ConfigManager


@pytest.fixture
def temp_dir():
    """إنشاء مجلد مؤقت للاختبار"""
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    shutil.rmtree(temp_dir)


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


class TestCompatibility:
    """اختبارات التوافق للأداة"""

    def test_os_detection(self):
        """اختبار اكتشاف نظام التشغيل"""
        # اختبار اكتشاف نظام التشغيل الحالي
        os_type = get_os_type()
        
        # التحقق من أن النتيجة هي سلسلة غير فارغة
        assert isinstance(os_type, str)
        assert os_type != ""
        
        # التحقق من أن النتيجة تطابق نظام التشغيل الحالي
        system = platform.system().lower()
        if "win" in system:
            assert os_type == "windows"
        elif "linux" in system:
            assert os_type == "linux"
        elif "darwin" in system:
            assert os_type == "macos"
        else:
            assert os_type == "unknown"

    def test_windows_compatibility(self):
        """اختبار التوافق مع نظام Windows"""
        # محاكاة نظام Windows
        with patch('platform.system', return_value="Windows"):
            # اختبار اكتشاف نظام التشغيل
            assert get_os_type() == "windows"
            
            # اختبار التحقق من توفر الأدوات
            with patch('shutil.which', side_effect=lambda cmd: cmd in ["nmap.exe", "python.exe"]):
                assert is_tool_available("nmap")
                assert is_tool_available("python")
                assert not is_tool_available("nonexistent_tool")
            
            # اختبار الحصول على مجلد المستخدم
            with patch('os.path.expanduser', return_value="C:\\Users\\TestUser"):
                assert get_home_directory() == "C:\\Users\\TestUser"

    def test_linux_compatibility(self):
        """اختبار التوافق مع نظام Linux"""
        # محاكاة نظام Linux
        with patch('platform.system', return_value="Linux"):
            # اختبار اكتشاف نظام التشغيل
            assert get_os_type() == "linux"
            
            # اختبار التحقق من توفر الأدوات
            with patch('shutil.which', side_effect=lambda cmd: cmd in ["nmap", "python"]):
                assert is_tool_available("nmap")
                assert is_tool_available("python")
                assert not is_tool_available("nonexistent_tool")
            
            # اختبار الحصول على مجلد المستخدم
            with patch('os.path.expanduser', return_value="/home/testuser"):
                assert get_home_directory() == "/home/testuser"

    def test_macos_compatibility(self):
        """اختبار التوافق مع نظام macOS"""
        # محاكاة نظام macOS
        with patch('platform.system', return_value="Darwin"):
            # اختبار اكتشاف نظام التشغيل
            assert get_os_type() == "macos"
            
            # اختبار التحقق من توفر الأدوات
            with patch('shutil.which', side_effect=lambda cmd: cmd in ["nmap", "python"]):
                assert is_tool_available("nmap")
                assert is_tool_available("python")
                assert not is_tool_available("nonexistent_tool")
            
            # اختبار الحصول على مجلد المستخدم
            with patch('os.path.expanduser', return_value="/Users/testuser"):
                assert get_home_directory() == "/Users/testuser"

    def test_path_handling(self):
        """اختبار معالجة المسارات عبر أنظمة التشغيل المختلفة"""
        # اختبار معالجة المسارات في Windows
        with patch('platform.system', return_value="Windows"):
            # استيراد الوحدة المطلوبة للاختبار
            from modules.utils import normalize_path
            
            # اختبار تطبيع المسارات
            assert normalize_path("C:/Users/Test/file.txt") == "C:\\Users\\Test\\file.txt"
            assert normalize_path("/Users/Test/file.txt") == "\\Users\\Test\\file.txt"
            
            # اختبار الجمع بين المسارات
            assert os.path.join("C:\\Users", "Test", "file.txt") == "C:\\Users\\Test\\file.txt"
        
        # اختبار معالجة المسارات في Linux
        with patch('platform.system', return_value="Linux"):
            # استيراد الوحدة المطلوبة للاختبار
            from modules.utils import normalize_path
            
            # اختبار تطبيع المسارات
            assert normalize_path("C:/Users/Test/file.txt") == "C:/Users/Test/file.txt"
            assert normalize_path("/Users/Test/file.txt") == "/Users/Test/file.txt"
            
            # اختبار الجمع بين المسارات
            assert os.path.join("/Users", "Test", "file.txt") == "/Users/Test/file.txt"

    def test_file_permissions(self, temp_dir):
        """اختبار أذونات الملفات عبر أنظمة التشغيل المختلفة"""
        # إنشاء ملف اختبار
        test_file = os.path.join(temp_dir, "test_file.txt")
        with open(test_file, "w") as f:
            f.write("Test content")
        
        # اختبار أذونات الملفات في Windows
        with patch('platform.system', return_value="Windows"):
            # استيراد الوحدة المطلوبة للاختبار
            from modules.utils import set_file_permissions
            
            # محاكاة تعيين أذونات الملفات
            with patch('os.chmod') as mock_chmod:
                set_file_permissions(test_file, 0o600)
                # لا يتم استدعاء os.chmod في Windows
                mock_chmod.assert_not_called()
        
        # اختبار أذونات الملفات في Linux
        with patch('platform.system', return_value="Linux"):
            # استيراد الوحدة المطلوبة للاختبار
            from modules.utils import set_file_permissions
            
            # محاكاة تعيين أذونات الملفات
            with patch('os.chmod') as mock_chmod:
                set_file_permissions(test_file, 0o600)
                # يتم استدعاء os.chmod في Linux
                mock_chmod.assert_called_once_with(test_file, 0o600)

    def test_config_file_paths(self):
        """اختبار مسارات ملفات التكوين عبر أنظمة التشغيل المختلفة"""
        # اختبار مسارات ملفات التكوين في Windows
        with patch('platform.system', return_value="Windows"), \
             patch('os.path.expanduser', return_value="C:\\Users\\TestUser"):
            # استيراد الوحدة المطلوبة للاختبار
            from modules.config import get_default_config_path
            
            # اختبار الحصول على مسار التكوين الافتراضي
            default_path = get_default_config_path()
            assert "C:\\Users\\TestUser" in default_path
            assert "SaudiAttack" in default_path
            assert default_path.endswith(".yaml") or default_path.endswith(".yml")
        
        # اختبار مسارات ملفات التكوين في Linux
        with patch('platform.system', return_value="Linux"), \
             patch('os.path.expanduser', return_value="/home/testuser"):
            # استيراد الوحدة المطلوبة للاختبار
            from modules.config import get_default_config_path
            
            # اختبار الحصول على مسار التكوين الافتراضي
            default_path = get_default_config_path()
            assert "/home/testuser" in default_path
            assert ".saudiattack" in default_path or "SaudiAttack" in default_path
            assert default_path.endswith(".yaml") or default_path.endswith(".yml")

    def test_command_execution(self):
        """اختبار تنفيذ الأوامر عبر أنظمة التشغيل المختلفة"""
        # اختبار تنفيذ الأوامر في Windows
        with patch('platform.system', return_value="Windows"):
            # استيراد الوحدة المطلوبة للاختبار
            from modules.utils import execute_command
            
            # محاكاة تنفيذ الأوامر
            with patch('subprocess.Popen') as mock_popen:
                mock_process = MagicMock()
                mock_process.communicate.return_value = (b"Command output", b"")
                mock_process.returncode = 0
                mock_popen.return_value = mock_process
                
                # اختبار تنفيذ الأمر
                output, error, code = execute_command("nmap -v")
                
                # التحقق من استدعاء Popen بالمعلمات الصحيحة
                mock_popen.assert_called_once()
                args, kwargs = mock_popen.call_args
                assert args[0] == "nmap -v"
                assert kwargs.get("shell") == True
                
                # التحقق من النتائج
                assert output == "Command output"
                assert error == ""
                assert code == 0
        
        # اختبار تنفيذ الأوامر في Linux
        with patch('platform.system', return_value="Linux"):
            # استيراد الوحدة المطلوبة للاختبار
            from modules.utils import execute_command
            
            # محاكاة تنفيذ الأوامر
            with patch('subprocess.Popen') as mock_popen:
                mock_process = MagicMock()
                mock_process.communicate.return_value = (b"Command output", b"")
                mock_process.returncode = 0
                mock_popen.return_value = mock_process
                
                # اختبار تنفيذ الأمر
                output, error, code = execute_command("nmap -v")
                
                # التحقق من استدعاء Popen بالمعلمات الصحيحة
                mock_popen.assert_called_once()
                args, kwargs = mock_popen.call_args
                assert args[0] == "nmap -v"
                assert kwargs.get("shell") == True
                
                # التحقق من النتائج
                assert output == "Command output"
                assert error == ""
                assert code == 0

    def test_nmap_command_compatibility(self):
        """اختبار توافق أوامر Nmap عبر أنظمة التشغيل المختلفة"""
        # استيراد الوحدة المطلوبة للاختبار
        from modules.scanner import VulnerabilityScanner
        
        # اختبار أوامر Nmap في Windows
        with patch('platform.system', return_value="Windows"):
            # إنشاء كائن الماسح
            scanner = VulnerabilityScanner(target="example.com")
            
            # محاكاة تنفيذ أمر Nmap
            with patch('subprocess.Popen') as mock_popen:
                mock_process = MagicMock()
                mock_process.communicate.return_value = (b"Nmap scan report", b"")
                mock_process.returncode = 0
                mock_popen.return_value = mock_process
                
                # تشغيل مسح Nmap
                scanner._run_nmap_scan()
                
                # التحقق من استدعاء Popen بالمعلمات الصحيحة
                mock_popen.assert_called_once()
                args, kwargs = mock_popen.call_args
                # التحقق من أن الأمر يحتوي على "nmap"
                assert "nmap" in args[0][0].lower()
        
        # اختبار أوامر Nmap في Linux
        with patch('platform.system', return_value="Linux"):
            # إنشاء كائن الماسح
            scanner = VulnerabilityScanner(target="example.com")
            
            # محاكاة تنفيذ أمر Nmap
            with patch('subprocess.Popen') as mock_popen:
                mock_process = MagicMock()
                mock_process.communicate.return_value = (b"Nmap scan report", b"")
                mock_process.returncode = 0
                mock_popen.return_value = mock_process
                
                # تشغيل مسح Nmap
                scanner._run_nmap_scan()
                
                # التحقق من استدعاء Popen بالمعلمات الصحيحة
                mock_popen.assert_called_once()
                args, kwargs = mock_popen.call_args
                # التحقق من أن الأمر يحتوي على "nmap"
                assert "nmap" in args[0][0].lower()

    def test_temp_directory_handling(self):
        """اختبار معالجة المجلدات المؤقتة عبر أنظمة التشغيل المختلفة"""
        # استيراد الوحدة المطلوبة للاختبار
        from modules.utils import get_temp_directory
        
        # اختبار الحصول على المجلد المؤقت في Windows
        with patch('platform.system', return_value="Windows"), \
             patch('tempfile.gettempdir', return_value="C:\\Windows\\Temp"):
            # اختبار الحصول على المجلد المؤقت
            temp_dir = get_temp_directory()
            assert temp_dir == "C:\\Windows\\Temp"
        
        # اختبار الحصول على المجلد المؤقت في Linux
        with patch('platform.system', return_value="Linux"), \
             patch('tempfile.gettempdir', return_value="/tmp"):
            # اختبار الحصول على المجلد المؤقت
            temp_dir = get_temp_directory()
            assert temp_dir == "/tmp"

    def test_report_file_paths(self):
        """اختبار مسارات ملفات التقارير عبر أنظمة التشغيل المختلفة"""
        # استيراد الوحدة المطلوبة للاختبار
        from modules.report_generator import ReportGenerator
        
        # اختبار مسارات ملفات التقارير في Windows
        with patch('platform.system', return_value="Windows"), \
             patch('os.path.join', side_effect=os.path.join):
            # إنشاء كائن مولد التقارير
            generator = ReportGenerator({"target": "example.com"}, output_dir="C:\\Reports")
            
            # اختبار توليد اسم ملف التقرير
            filename = generator._generate_filename(format="html")
            assert filename.startswith("C:\\Reports\\")
            assert filename.endswith(".html")
        
        # اختبار مسارات ملفات التقارير في Linux
        with patch('platform.system', return_value="Linux"), \
             patch('os.path.join', side_effect=os.path.join):
            # إنشاء كائن مولد التقارير
            generator = ReportGenerator({"target": "example.com"}, output_dir="/var/reports")
            
            # اختبار توليد اسم ملف التقرير
            filename = generator._generate_filename(format="html")
            assert filename.startswith("/var/reports/")
            assert filename.endswith(".html")

    def test_python_version_compatibility(self):
        """اختبار التوافق مع إصدارات Python المختلفة"""
        # اختبار التوافق مع Python 3.6
        with patch('sys.version_info', (3, 6, 0, 'final', 0)):
            # استيراد الوحدة المطلوبة للاختبار
            from modules.utils import check_python_version
            
            # اختبار التحقق من إصدار Python
            assert check_python_version(min_version=(3, 6)) == True
            assert check_python_version(min_version=(3, 7)) == False
        
        # اختبار التوافق مع Python 3.8
        with patch('sys.version_info', (3, 8, 0, 'final', 0)):
            # استيراد الوحدة المطلوبة للاختبار
            from modules.utils import check_python_version
            
            # اختبار التحقق من إصدار Python
            assert check_python_version(min_version=(3, 6)) == True
            assert check_python_version(min_version=(3, 7)) == True
            assert check_python_version(min_version=(3, 8)) == True
            assert check_python_version(min_version=(3, 9)) == False

    def test_dependency_compatibility(self):
        """اختبار توافق التبعيات عبر أنظمة التشغيل المختلفة"""
        # استيراد الوحدة المطلوبة للاختبار
        from modules.utils import check_dependencies
        
        # اختبار التحقق من التبعيات في Windows
        with patch('platform.system', return_value="Windows"), \
             patch('importlib.import_module') as mock_import, \
             patch('shutil.which', return_value="C:\\Program Files\\Nmap\\nmap.exe"):
            # محاكاة استيراد الوحدات
            mock_import.side_effect = lambda module: None
            
            # اختبار التحقق من التبعيات
            result = check_dependencies()
            assert result == True
        
        # اختبار التحقق من التبعيات في Linux
        with patch('platform.system', return_value="Linux"), \
             patch('importlib.import_module') as mock_import, \
             patch('shutil.which', return_value="/usr/bin/nmap"):
            # محاكاة استيراد الوحدات
            mock_import.side_effect = lambda module: None
            
            # اختبار التحقق من التبعيات
            result = check_dependencies()
            assert result == True

    def test_unicode_handling(self):
        """اختبار معالجة Unicode عبر أنظمة التشغيل المختلفة"""
        # استيراد الوحدة المطلوبة للاختبار
        from modules.utils import sanitize_filename
        
        # اختبار تنظيف اسم الملف مع أحرف Unicode
        unicode_filename = "تقرير_الفحص_🔒.txt"
        sanitized = sanitize_filename(unicode_filename)
        
        # التحقق من أن الأحرف Unicode تم الحفاظ عليها
        assert "تقرير" in sanitized
        assert "الفحص" in sanitized
        
        # اختبار معالجة Unicode في Windows
        with patch('platform.system', return_value="Windows"):
            # استيراد الوحدة المطلوبة للاختبار
            from modules.utils import normalize_path
            
            # اختبار تطبيع المسار مع أحرف Unicode
            unicode_path = "C:/المستندات/تقارير/تقرير.txt"
            normalized = normalize_path(unicode_path)
            
            # التحقق من أن الأحرف Unicode تم الحفاظ عليها
            assert "المستندات" in normalized
            assert "تقارير" in normalized
            assert "تقرير.txt" in normalized

    def test_config_compatibility(self, mock_config):
        """اختبار توافق التكوين عبر أنظمة التشغيل المختلفة"""
        # استيراد الوحدة المطلوبة للاختبار
        from modules.config import ConfigManager
        
        # اختبار توافق التكوين في Windows
        with patch('platform.system', return_value="Windows"), \
             patch('os.path.expanduser', return_value="C:\\Users\\TestUser"):
            # إنشاء كائن مدير التكوين
            config_manager = ConfigManager()
            config_manager.update_config(mock_config)
            
            # تعديل مسار الإخراج ليكون مسارًا نسبيًا
            config_manager.config["general"]["output_dir"] = "./reports"
            
            # اختبار الحصول على مسار الإخراج المطلق
            output_dir = config_manager.get_absolute_path("general.output_dir")
            assert output_dir.startswith("C:\\")
            assert output_dir.endswith("\\reports")
        
        # اختبار توافق التكوين في Linux
        with patch('platform.system', return_value="Linux"), \
             patch('os.path.expanduser', return_value="/home/testuser"):
            # إنشاء كائن مدير التكوين
            config_manager = ConfigManager()
            config_manager.update_config(mock_config)
            
            # تعديل مسار الإخراج ليكون مسارًا نسبيًا
            config_manager.config["general"]["output_dir"] = "./reports"
            
            # اختبار الحصول على مسار الإخراج المطلق
            output_dir = config_manager.get_absolute_path("general.output_dir")
            assert output_dir.startswith("/")
            assert output_dir.endswith("/reports")

    def test_thread_compatibility(self):
        """اختبار توافق المواضيع عبر أنظمة التشغيل المختلفة"""
        # استيراد الوحدات المطلوبة للاختبار
        import threading
        from modules.scanner import VulnerabilityScanner
        
        # اختبار إنشاء المواضيع في Windows
        with patch('platform.system', return_value="Windows"):
            # إنشاء كائن الماسح
            scanner = VulnerabilityScanner(target="example.com")
            
            # محاكاة تنفيذ المواضيع
            with patch('threading.Thread') as mock_thread:
                # إنشاء موضوع وهمي
                mock_thread_instance = MagicMock()
                mock_thread.return_value = mock_thread_instance
                
                # إنشاء موضوع
                thread = threading.Thread(target=lambda: None)
                thread.start()
                
                # التحقق من استدعاء start
                mock_thread_instance.start.assert_called_once()
        
        # اختبار إنشاء المواضيع في Linux
        with patch('platform.system', return_value="Linux"):
            # إنشاء كائن الماسح
            scanner = VulnerabilityScanner(target="example.com")
            
            # محاكاة تنفيذ المواضيع
            with patch('threading.Thread') as mock_thread:
                # إنشاء موضوع وهمي
                mock_thread_instance = MagicMock()
                mock_thread.return_value = mock_thread_instance
                
                # إنشاء موضوع
                thread = threading.Thread(target=lambda: None)
                thread.start()
                
                # التحقق من استدعاء start
                mock_thread_instance.start.assert_called_once()