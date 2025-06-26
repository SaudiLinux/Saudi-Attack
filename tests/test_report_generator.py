#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import pytest
from unittest.mock import patch, mock_open, MagicMock

# افتراض أن وحدة إنشاء التقارير موجودة في المسار التالي
from modules.report_generator import ReportGenerator


class TestReportGenerator:
    """اختبارات لوحدة إنشاء التقارير"""

    def setup_method(self):
        """إعداد بيئة الاختبار قبل كل اختبار"""
        self.config = {
            'report': {
                'formats': ['html', 'json', 'txt', 'md'],
                'default_format': 'html',
                'severity_levels': ['critical', 'high', 'medium', 'low', 'info'],
                'template_dir': './templates'
            }
        }
        self.report_generator = ReportGenerator(self.config)

    @pytest.mark.parametrize(
        "report_format,expected_method",
        [
            ("html", "_generate_html_report"),
            ("json", "_generate_json_report"),
            ("txt", "_generate_txt_report"),
            ("md", "_generate_md_report"),
            ("invalid", None),
        ],
    )
    def test_generate_report_format_selection(self, report_format, expected_method, sample_scan_results):
        """اختبار اختيار تنسيق التقرير المناسب"""
        with patch.object(ReportGenerator, '_generate_html_report', return_value=True) as html_mock, \
             patch.object(ReportGenerator, '_generate_json_report', return_value=True) as json_mock, \
             patch.object(ReportGenerator, '_generate_txt_report', return_value=True) as txt_mock, \
             patch.object(ReportGenerator, '_generate_md_report', return_value=True) as md_mock:
            
            if expected_method is None:
                # يجب أن يرفع استثناء عند استخدام تنسيق غير صالح
                with pytest.raises(ValueError):
                    self.report_generator.generate_report(sample_scan_results, report_format)
            else:
                # يجب أن يستدعي الطريقة المناسبة لتنسيق التقرير
                result = self.report_generator.generate_report(sample_scan_results, report_format)
                assert result is True
                
                # التحقق من استدعاء الطريقة المناسبة
                if expected_method == "_generate_html_report":
                    html_mock.assert_called_once()
                elif expected_method == "_generate_json_report":
                    json_mock.assert_called_once()
                elif expected_method == "_generate_txt_report":
                    txt_mock.assert_called_once()
                elif expected_method == "_generate_md_report":
                    md_mock.assert_called_once()

    def test_generate_json_report(self, sample_scan_results, tmp_path):
        """اختبار إنشاء تقرير بتنسيق JSON"""
        # تعديل مسار الإخراج للاختبار
        output_dir = tmp_path / "reports"
        output_dir.mkdir()
        self.report_generator.config['general'] = {'output_dir': str(output_dir)}
        
        # تنفيذ الاختبار مع تزييف فتح الملف
        m = mock_open()
        with patch("builtins.open", m):
            result = self.report_generator._generate_json_report(sample_scan_results, "example.com")
            assert result is True
            
            # التحقق من فتح الملف بالاسم الصحيح
            m.assert_called_once()
            file_path = m.call_args[0][0]
            assert file_path.endswith(".json")
            assert "example.com" in file_path
            
            # التحقق من كتابة البيانات الصحيحة
            written_data = m().write.call_args[0][0]
            assert json.loads(written_data) == sample_scan_results

    def test_generate_txt_report(self, sample_scan_results, tmp_path):
        """اختبار إنشاء تقرير بتنسيق نصي"""
        # تعديل مسار الإخراج للاختبار
        output_dir = tmp_path / "reports"
        output_dir.mkdir()
        self.report_generator.config['general'] = {'output_dir': str(output_dir)}
        
        # تزييف قراءة قالب التقرير
        template_content = "Target: {{ target }}\nVulnerabilities: {{ vulnerabilities|length }}"
        
        # تنفيذ الاختبار مع تزييف فتح الملف وقراءة القالب
        with patch("builtins.open", mock_open(read_data=template_content)) as m:
            with patch("jinja2.Template") as template_mock:
                # تكوين الكائن المزيف لقالب Jinja2
                template_instance = MagicMock()
                template_instance.render.return_value = "Target: example.com\nVulnerabilities: 1"
                template_mock.return_value = template_instance
                
                result = self.report_generator._generate_txt_report(sample_scan_results, "example.com")
                assert result is True
                
                # التحقق من فتح الملف بالاسم الصحيح للكتابة
                write_call = [call for call in m.call_args_list if 'w' in call[0][1]][0]
                file_path = write_call[0][0]
                assert file_path.endswith(".txt")
                assert "example.com" in file_path
                
                # التحقق من استدعاء طريقة render بالبيانات الصحيحة
                template_instance.render.assert_called_once()
                render_args = template_instance.render.call_args[0][0]
                assert render_args == sample_scan_results

    def test_generate_html_report(self, sample_scan_results, tmp_path):
        """اختبار إنشاء تقرير بتنسيق HTML"""
        # تعديل مسار الإخراج للاختبار
        output_dir = tmp_path / "reports"
        output_dir.mkdir()
        self.report_generator.config['general'] = {'output_dir': str(output_dir)}
        
        # تزييف قراءة قالب التقرير
        template_content = "<html><body>Target: {{ target }}</body></html>"
        
        # تنفيذ الاختبار مع تزييف فتح الملف وقراءة القالب
        with patch("builtins.open", mock_open(read_data=template_content)) as m:
            with patch("jinja2.Template") as template_mock:
                # تكوين الكائن المزيف لقالب Jinja2
                template_instance = MagicMock()
                template_instance.render.return_value = "<html><body>Target: example.com</body></html>"
                template_mock.return_value = template_instance
                
                result = self.report_generator._generate_html_report(sample_scan_results, "example.com")
                assert result is True
                
                # التحقق من فتح الملف بالاسم الصحيح للكتابة
                write_call = [call for call in m.call_args_list if 'w' in call[0][1]][0]
                file_path = write_call[0][0]
                assert file_path.endswith(".html")
                assert "example.com" in file_path
                
                # التحقق من استدعاء طريقة render بالبيانات الصحيحة
                template_instance.render.assert_called_once()
                render_args = template_instance.render.call_args[0][0]
                assert render_args == sample_scan_results

    def test_generate_md_report(self, sample_scan_results, tmp_path):
        """اختبار إنشاء تقرير بتنسيق Markdown"""
        # تعديل مسار الإخراج للاختبار
        output_dir = tmp_path / "reports"
        output_dir.mkdir()
        self.report_generator.config['general'] = {'output_dir': str(output_dir)}
        
        # تزييف قراءة قالب التقرير
        template_content = "# تقرير المسح لـ {{ target }}\n## الثغرات: {{ vulnerabilities|length }}"
        
        # تنفيذ الاختبار مع تزييف فتح الملف وقراءة القالب
        with patch("builtins.open", mock_open(read_data=template_content)) as m:
            with patch("jinja2.Template") as template_mock:
                # تكوين الكائن المزيف لقالب Jinja2
                template_instance = MagicMock()
                template_instance.render.return_value = "# تقرير المسح لـ example.com\n## الثغرات: 1"
                template_mock.return_value = template_instance
                
                result = self.report_generator._generate_md_report(sample_scan_results, "example.com")
                assert result is True
                
                # التحقق من فتح الملف بالاسم الصحيح للكتابة
                write_call = [call for call in m.call_args_list if 'w' in call[0][1]][0]
                file_path = write_call[0][0]
                assert file_path.endswith(".md")
                assert "example.com" in file_path
                
                # التحقق من استدعاء طريقة render بالبيانات الصحيحة
                template_instance.render.assert_called_once()
                render_args = template_instance.render.call_args[0][0]
                assert render_args == sample_scan_results

    def test_get_output_filename(self):
        """اختبار إنشاء اسم ملف الإخراج"""
        # تعديل مسار الإخراج للاختبار
        self.report_generator.config['general'] = {'output_dir': '/tmp/reports'}
        
        # اختبار مع اسم نطاق
        filename = self.report_generator._get_output_filename("example.com", "html")
        assert "example.com" in filename
        assert filename.endswith(".html")
        assert "/tmp/reports" in filename
        
        # اختبار مع عنوان IP
        filename = self.report_generator._get_output_filename("192.168.1.1", "json")
        assert "192.168.1.1" in filename
        assert filename.endswith(".json")
        
        # اختبار مع تاريخ في اسم الملف
        with patch("time.strftime", return_value="20231201-120000"):
            filename = self.report_generator._get_output_filename("example.com", "txt")
            assert "20231201-120000" in filename
            assert filename.endswith(".txt")