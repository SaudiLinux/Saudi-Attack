#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pytest
import os
import sys
import logging
import tempfile
import shutil
from unittest.mock import patch, MagicMock, mock_open, call

# إضافة المجلد الرئيسي إلى مسار البحث
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# استيراد الوحدات المطلوبة للاختبار
from modules.utils import setup_logger


@pytest.fixture
def temp_dir():
    """إنشاء مجلد مؤقت للاختبار"""
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    shutil.rmtree(temp_dir)


class TestLogging:
    """اختبارات وظائف التسجيل للأداة"""

    def test_setup_logger_default(self):
        """اختبار إعداد المسجل بالإعدادات الافتراضية"""
        # إعادة تعيين المسجلين المسجلين مسبقًا
        for handler in logging.root.handlers[::]:
            logging.root.removeHandler(handler)
        
        # إنشاء مسجل بالإعدادات الافتراضية
        with patch('logging.FileHandler') as mock_file_handler, \
             patch('logging.StreamHandler') as mock_stream_handler, \
             patch('logging.getLogger', return_value=MagicMock()) as mock_get_logger:
            
            logger = setup_logger()
            
            # التحقق من أن المسجل تم إنشاؤه بشكل صحيح
            mock_get_logger.assert_called_once_with("SaudiAttack")
            
            # التحقق من إنشاء معالج الملف
            mock_file_handler.assert_called_once()
            
            # التحقق من إنشاء معالج التدفق
            mock_stream_handler.assert_called_once()
            
            # التحقق من إضافة المعالجات إلى المسجل
            logger.addHandler.call_count == 2
            
            # التحقق من مستوى التسجيل الافتراضي
            logger.setLevel.assert_called_once_with(logging.INFO)

    def test_setup_logger_verbose(self):
        """اختبار إعداد المسجل في وضع التفصيل"""
        # إعادة تعيين المسجلين المسجلين مسبقًا
        for handler in logging.root.handlers[::]:
            logging.root.removeHandler(handler)
        
        # إنشاء مسجل في وضع التفصيل
        with patch('logging.FileHandler') as mock_file_handler, \
             patch('logging.StreamHandler') as mock_stream_handler, \
             patch('logging.getLogger', return_value=MagicMock()) as mock_get_logger:
            
            logger = setup_logger(verbose=True)
            
            # التحقق من أن المسجل تم إنشاؤه بشكل صحيح
            mock_get_logger.assert_called_once_with("SaudiAttack")
            
            # التحقق من إنشاء معالج الملف
            mock_file_handler.assert_called_once()
            
            # التحقق من إنشاء معالج التدفق
            mock_stream_handler.assert_called_once()
            
            # التحقق من إضافة المعالجات إلى المسجل
            logger.addHandler.call_count == 2
            
            # التحقق من مستوى التسجيل في وضع التفصيل
            logger.setLevel.assert_called_once_with(logging.DEBUG)

    def test_setup_logger_custom_log_file(self, temp_dir):
        """اختبار إعداد المسجل مع ملف سجل مخصص"""
        # إعادة تعيين المسجلين المسجلين مسبقًا
        for handler in logging.root.handlers[::]:
            logging.root.removeHandler(handler)
        
        # إنشاء مسار ملف سجل مخصص
        custom_log_file = os.path.join(temp_dir, "custom.log")
        
        # إنشاء مسجل مع ملف سجل مخصص
        with patch('logging.FileHandler') as mock_file_handler, \
             patch('logging.StreamHandler') as mock_stream_handler, \
             patch('logging.getLogger', return_value=MagicMock()) as mock_get_logger:
            
            logger = setup_logger(log_file=custom_log_file)
            
            # التحقق من أن المسجل تم إنشاؤه بشكل صحيح
            mock_get_logger.assert_called_once_with("SaudiAttack")
            
            # التحقق من إنشاء معالج الملف مع المسار المخصص
            mock_file_handler.assert_called_once_with(custom_log_file)
            
            # التحقق من إنشاء معالج التدفق
            mock_stream_handler.assert_called_once()
            
            # التحقق من إضافة المعالجات إلى المسجل
            logger.addHandler.call_count == 2

    def test_setup_logger_no_file_handler(self):
        """اختبار إعداد المسجل بدون معالج ملف"""
        # إعادة تعيين المسجلين المسجلين مسبقًا
        for handler in logging.root.handlers[::]:
            logging.root.removeHandler(handler)
        
        # إنشاء مسجل بدون معالج ملف
        with patch('logging.FileHandler') as mock_file_handler, \
             patch('logging.StreamHandler') as mock_stream_handler, \
             patch('logging.getLogger', return_value=MagicMock()) as mock_get_logger:
            
            logger = setup_logger(log_to_file=False)
            
            # التحقق من أن المسجل تم إنشاؤه بشكل صحيح
            mock_get_logger.assert_called_once_with("SaudiAttack")
            
            # التحقق من عدم إنشاء معالج الملف
            mock_file_handler.assert_not_called()
            
            # التحقق من إنشاء معالج التدفق
            mock_stream_handler.assert_called_once()
            
            # التحقق من إضافة معالج واحد فقط إلى المسجل
            logger.addHandler.call_count == 1

    def test_setup_logger_no_console_handler(self):
        """اختبار إعداد المسجل بدون معالج وحدة التحكم"""
        # إعادة تعيين المسجلين المسجلين مسبقًا
        for handler in logging.root.handlers[::]:
            logging.root.removeHandler(handler)
        
        # إنشاء مسجل بدون معالج وحدة التحكم
        with patch('logging.FileHandler') as mock_file_handler, \
             patch('logging.StreamHandler') as mock_stream_handler, \
             patch('logging.getLogger', return_value=MagicMock()) as mock_get_logger:
            
            logger = setup_logger(log_to_console=False)
            
            # التحقق من أن المسجل تم إنشاؤه بشكل صحيح
            mock_get_logger.assert_called_once_with("SaudiAttack")
            
            # التحقق من إنشاء معالج الملف
            mock_file_handler.assert_called_once()
            
            # التحقق من عدم إنشاء معالج التدفق
            mock_stream_handler.assert_not_called()
            
            # التحقق من إضافة معالج واحد فقط إلى المسجل
            logger.addHandler.call_count == 1

    def test_setup_logger_custom_name(self):
        """اختبار إعداد المسجل باسم مخصص"""
        # إعادة تعيين المسجلين المسجلين مسبقًا
        for handler in logging.root.handlers[::]:
            logging.root.removeHandler(handler)
        
        # إنشاء مسجل باسم مخصص
        with patch('logging.FileHandler') as mock_file_handler, \
             patch('logging.StreamHandler') as mock_stream_handler, \
             patch('logging.getLogger', return_value=MagicMock()) as mock_get_logger:
            
            logger = setup_logger(name="CustomLogger")
            
            # التحقق من أن المسجل تم إنشاؤه بالاسم المخصص
            mock_get_logger.assert_called_once_with("CustomLogger")
            
            # التحقق من إنشاء معالج الملف
            mock_file_handler.assert_called_once()
            
            # التحقق من إنشاء معالج التدفق
            mock_stream_handler.assert_called_once()
            
            # التحقق من إضافة المعالجات إلى المسجل
            logger.addHandler.call_count == 2

    def test_setup_logger_custom_level(self):
        """اختبار إعداد المسجل بمستوى مخصص"""
        # إعادة تعيين المسجلين المسجلين مسبقًا
        for handler in logging.root.handlers[::]:
            logging.root.removeHandler(handler)
        
        # إنشاء مسجل بمستوى مخصص
        with patch('logging.FileHandler') as mock_file_handler, \
             patch('logging.StreamHandler') as mock_stream_handler, \
             patch('logging.getLogger', return_value=MagicMock()) as mock_get_logger:
            
            logger = setup_logger(level=logging.WARNING)
            
            # التحقق من أن المسجل تم إنشاؤه بشكل صحيح
            mock_get_logger.assert_called_once_with("SaudiAttack")
            
            # التحقق من إنشاء معالج الملف
            mock_file_handler.assert_called_once()
            
            # التحقق من إنشاء معالج التدفق
            mock_stream_handler.assert_called_once()
            
            # التحقق من مستوى التسجيل المخصص
            logger.setLevel.assert_called_once_with(logging.WARNING)

    def test_setup_logger_custom_format(self):
        """اختبار إعداد المسجل بتنسيق مخصص"""
        # إعادة تعيين المسجلين المسجلين مسبقًا
        for handler in logging.root.handlers[::]:
            logging.root.removeHandler(handler)
        
        # تنسيق مخصص
        custom_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        
        # إنشاء مسجل بتنسيق مخصص
        with patch('logging.FileHandler') as mock_file_handler, \
             patch('logging.StreamHandler') as mock_stream_handler, \
             patch('logging.getLogger', return_value=MagicMock()) as mock_get_logger, \
             patch('logging.Formatter') as mock_formatter:
            
            logger = setup_logger(log_format=custom_format)
            
            # التحقق من أن المسجل تم إنشاؤه بشكل صحيح
            mock_get_logger.assert_called_once_with("SaudiAttack")
            
            # التحقق من إنشاء المنسق بالتنسيق المخصص
            mock_formatter.assert_called_once_with(custom_format)
            
            # التحقق من إنشاء معالج الملف
            mock_file_handler.assert_called_once()
            
            # التحقق من إنشاء معالج التدفق
            mock_stream_handler.assert_called_once()

    def test_logger_file_creation(self, temp_dir):
        """اختبار إنشاء ملف السجل"""
        # إعادة تعيين المسجلين المسجلين مسبقًا
        for handler in logging.root.handlers[::]:
            logging.root.removeHandler(handler)
        
        # إنشاء مسار ملف سجل
        log_file = os.path.join(temp_dir, "test.log")
        
        # إنشاء مسجل مع ملف سجل
        logger = setup_logger(log_file=log_file)
        
        # كتابة رسالة في السجل
        logger.info("Test log message")
        
        # التحقق من إنشاء ملف السجل
        assert os.path.exists(log_file)
        
        # التحقق من محتوى ملف السجل
        with open(log_file, "r") as f:
            log_content = f.read()
            assert "Test log message" in log_content

    def test_logger_different_levels(self):
        """اختبار مستويات التسجيل المختلفة"""
        # إعادة تعيين المسجلين المسجلين مسبقًا
        for handler in logging.root.handlers[::]:
            logging.root.removeHandler(handler)
        
        # إنشاء مسجل مزيف
        mock_logger = MagicMock()
        
        # محاكاة إنشاء المسجل
        with patch('logging.getLogger', return_value=mock_logger), \
             patch('logging.FileHandler'), \
             patch('logging.StreamHandler'):
            
            logger = setup_logger()
            
            # كتابة رسائل بمستويات مختلفة
            logger.debug("Debug message")
            logger.info("Info message")
            logger.warning("Warning message")
            logger.error("Error message")
            logger.critical("Critical message")
            
            # التحقق من استدعاء الدوال المناسبة
            mock_logger.debug.assert_called_once_with("Debug message")
            mock_logger.info.assert_called_once_with("Info message")
            mock_logger.warning.assert_called_once_with("Warning message")
            mock_logger.error.assert_called_once_with("Error message")
            mock_logger.critical.assert_called_once_with("Critical message")

    def test_logger_exception_handling(self):
        """اختبار معالجة الاستثناءات في المسجل"""
        # إعادة تعيين المسجلين المسجلين مسبقًا
        for handler in logging.root.handlers[::]:
            logging.root.removeHandler(handler)
        
        # إنشاء مسجل مزيف
        mock_logger = MagicMock()
        
        # محاكاة إنشاء المسجل
        with patch('logging.getLogger', return_value=mock_logger), \
             patch('logging.FileHandler'), \
             patch('logging.StreamHandler'):
            
            logger = setup_logger()
            
            # محاولة تسجيل استثناء
            try:
                raise ValueError("Test exception")
            except Exception as e:
                logger.exception("An error occurred: %s", str(e))
            
            # التحقق من استدعاء دالة الاستثناء
            mock_logger.exception.assert_called_once_with("An error occurred: %s", "Test exception")

    def test_logger_formatting(self, temp_dir):
        """اختبار تنسيق رسائل السجل"""
        # إعادة تعيين المسجلين المسجلين مسبقًا
        for handler in logging.root.handlers[::]:
            logging.root.removeHandler(handler)
        
        # إنشاء مسار ملف سجل
        log_file = os.path.join(temp_dir, "format_test.log")
        
        # تنسيق مخصص للاختبار
        test_format = "[%(levelname)s] %(message)s"
        
        # إنشاء مسجل مع تنسيق مخصص
        logger = setup_logger(log_file=log_file, log_format=test_format)
        
        # كتابة رسالة في السجل
        logger.warning("Test warning message")
        
        # التحقق من تنسيق الرسالة في ملف السجل
        with open(log_file, "r") as f:
            log_content = f.read()
            assert "[WARNING] Test warning message" in log_content

    def test_logger_multiple_instances(self):
        """اختبار إنشاء عدة نسخ من المسجل"""
        # إعادة تعيين المسجلين المسجلين مسبقًا
        for handler in logging.root.handlers[::]:
            logging.root.removeHandler(handler)
        
        # محاكاة إنشاء المسجل
        with patch('logging.getLogger') as mock_get_logger, \
             patch('logging.FileHandler'), \
             patch('logging.StreamHandler'):
            
            # إنشاء عدة نسخ من المسجل بنفس الاسم
            logger1 = setup_logger(name="TestLogger")
            logger2 = setup_logger(name="TestLogger")
            
            # التحقق من أن المسجل تم استدعاؤه مرتين بنفس الاسم
            assert mock_get_logger.call_count == 2
            mock_get_logger.assert_has_calls([call("TestLogger"), call("TestLogger")])

    def test_logger_directory_creation(self, temp_dir):
        """اختبار إنشاء مجلد السجل"""
        # إعادة تعيين المسجلين المسجلين مسبقًا
        for handler in logging.root.handlers[::]:
            logging.root.removeHandler(handler)
        
        # إنشاء مسار ملف سجل في مجلد غير موجود
        log_dir = os.path.join(temp_dir, "logs")
        log_file = os.path.join(log_dir, "test.log")
        
        # إنشاء مسجل مع ملف سجل في مجلد غير موجود
        with patch('os.makedirs') as mock_makedirs:
            logger = setup_logger(log_file=log_file)
            
            # التحقق من إنشاء المجلد
            mock_makedirs.assert_called_once_with(log_dir, exist_ok=True)

    def test_logger_file_permission_error(self):
        """اختبار معالجة خطأ أذونات الملف"""
        # إعادة تعيين المسجلين المسجلين مسبقًا
        for handler in logging.root.handlers[::]:
            logging.root.removeHandler(handler)
        
        # محاكاة خطأ أذونات الملف
        with patch('logging.FileHandler', side_effect=PermissionError("Permission denied")), \
             patch('logging.StreamHandler') as mock_stream_handler, \
             patch('logging.getLogger', return_value=MagicMock()) as mock_get_logger, \
             patch('sys.stderr.write') as mock_stderr_write:
            
            logger = setup_logger()
            
            # التحقق من أن المسجل تم إنشاؤه بشكل صحيح
            mock_get_logger.assert_called_once_with("SaudiAttack")
            
            # التحقق من إنشاء معالج التدفق
            mock_stream_handler.assert_called_once()
            
            # التحقق من كتابة رسالة الخطأ إلى stderr
            mock_stderr_write.assert_called()

    def test_logger_rotation(self, temp_dir):
        """اختبار تدوير ملفات السجل"""
        # إعادة تعيين المسجلين المسجلين مسبقًا
        for handler in logging.root.handlers[::]:
            logging.root.removeHandler(handler)
        
        # إنشاء مسار ملف سجل
        log_file = os.path.join(temp_dir, "rotating.log")
        
        # محاكاة إنشاء المسجل مع تدوير الملفات
        with patch('logging.handlers.RotatingFileHandler') as mock_rotating_handler, \
             patch('logging.StreamHandler'), \
             patch('logging.getLogger', return_value=MagicMock()):
            
            # إنشاء مسجل مع تدوير الملفات
            logger = setup_logger(log_file=log_file, max_log_size=1024*1024, backup_count=5)
            
            # التحقق من إنشاء معالج التدوير
            mock_rotating_handler.assert_called_once_with(
                log_file, maxBytes=1024*1024, backupCount=5
            )

    def test_logger_null_handler(self):
        """اختبار إنشاء مسجل بدون معالجات"""
        # إعادة تعيين المسجلين المسجلين مسبقًا
        for handler in logging.root.handlers[::]:
            logging.root.removeHandler(handler)
        
        # إنشاء مسجل بدون معالجات
        with patch('logging.NullHandler') as mock_null_handler, \
             patch('logging.getLogger', return_value=MagicMock()) as mock_get_logger:
            
            logger = setup_logger(log_to_file=False, log_to_console=False)
            
            # التحقق من أن المسجل تم إنشاؤه بشكل صحيح
            mock_get_logger.assert_called_once_with("SaudiAttack")
            
            # التحقق من إنشاء معالج فارغ
            mock_null_handler.assert_called_once()
            
            # التحقق من إضافة المعالج الفارغ إلى المسجل
            logger.addHandler.call_count == 1