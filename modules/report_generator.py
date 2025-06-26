#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
وحدة مولد التقارير لأداة SaudiAttack
"""

import os
import json
import time
import datetime
from jinja2 import Template
import markdown
import yaml
from rich.console import Console
from .utils import get_severity_color, format_time

console = Console()

class ReportGenerator:
    """
    فئة مولد التقارير
    """
    
    def __init__(self, results, output_file=None, logger=None):
        """
        تهيئة مولد التقارير
        
        المعطيات:
            results (dict): نتائج المسح
            output_file (str): مسار ملف الإخراج
            logger (Logger): كائن المسجل
        """
        self.results = results
        self.output_file = output_file
        self.logger = logger
        self.report_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports")
        
        # إنشاء دليل التقارير إذا لم يكن موجودًا
        if not os.path.exists(self.report_dir):
            os.makedirs(self.report_dir)
    
    def generate_report(self, format_type="html"):
        """
        إنشاء تقرير بالتنسيق المحدد
        
        المعطيات:
            format_type (str): نوع تنسيق التقرير (html، json، txt، md، yaml)
            
        المخرجات:
            str: مسار ملف التقرير
        """
        self.logger.info(f"إنشاء تقرير بتنسيق {format_type}")
        console.print(f"[bold]إنشاء تقرير بتنسيق {format_type}[/bold]")
        
        # تحديد مسار ملف الإخراج
        if self.output_file:
            output_path = self.output_file
        else:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            target_name = self.results.get("target", "unknown")
            output_path = os.path.join(self.report_dir, f"saudi_attack_report_{target_name}_{timestamp}.{format_type}")
        
        # إنشاء التقرير بالتنسيق المحدد
        if format_type.lower() == "html":
            report_content = self._generate_html_report()
        elif format_type.lower() == "json":
            report_content = self._generate_json_report()
        elif format_type.lower() == "txt":
            report_content = self._generate_text_report()
        elif format_type.lower() == "md":
            report_content = self._generate_markdown_report()
        elif format_type.lower() == "yaml":
            report_content = self._generate_yaml_report()
        else:
            self.logger.error(f"تنسيق التقرير غير مدعوم: {format_type}")
            console.print(f"[bold red]تنسيق التقرير غير مدعوم: {format_type}[/bold red]")
            return None
        
        # كتابة التقرير إلى الملف
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(report_content)
            
            self.logger.info(f"تم إنشاء التقرير بنجاح: {output_path}")
            console.print(f"[bold green]تم إنشاء التقرير بنجاح: {output_path}[/bold green]")
            return output_path
        except Exception as e:
            self.logger.error(f"خطأ أثناء كتابة التقرير: {str(e)}")
            console.print(f"[bold red]خطأ أثناء كتابة التقرير: {str(e)}[/bold red]")
            return None
    
    def _generate_html_report(self):
        """
        إنشاء تقرير HTML
        
        المخرجات:
            str: محتوى تقرير HTML
        """
        # قالب HTML
        html_template = """
        <!DOCTYPE html>
        <html lang="ar" dir="rtl">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>تقرير SaudiAttack - {{ results.target }}</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    line-height: 1.6;
                    margin: 0;
                    padding: 20px;
                    color: #333;
                    direction: rtl;
                }
                h1, h2, h3, h4 {
                    color: #2c3e50;
                    margin-top: 20px;
                }
                .container {
                    max-width: 1200px;
                    margin: 0 auto;
                    padding: 20px;
                    background-color: #fff;
                    box-shadow: 0 0 10px rgba(0,0,0,0.1);
                }
                .header {
                    background-color: #2c3e50;
                    color: white;
                    padding: 20px;
                    text-align: center;
                    margin-bottom: 20px;
                }
                .summary {
                    background-color: #f8f9fa;
                    padding: 15px;
                    border-radius: 5px;
                    margin-bottom: 20px;
                }
                table {
                    width: 100%;
                    border-collapse: collapse;
                    margin-bottom: 20px;
                }
                th, td {
                    padding: 12px 15px;
                    border: 1px solid #ddd;
                    text-align: right;
                }
                th {
                    background-color: #f2f2f2;
                }
                tr:nth-child(even) {
                    background-color: #f9f9f9;
                }
                .severity-critical {
                    background-color: #ff5252;
                    color: white;
                    padding: 3px 8px;
                    border-radius: 3px;
                }
                .severity-high {
                    background-color: #ff9800;
                    color: white;
                    padding: 3px 8px;
                    border-radius: 3px;
                }
                .severity-medium {
                    background-color: #ffeb3b;
                    color: black;
                    padding: 3px 8px;
                    border-radius: 3px;
                }
                .severity-low {
                    background-color: #4caf50;
                    color: white;
                    padding: 3px 8px;
                    border-radius: 3px;
                }
                .severity-info {
                    background-color: #2196f3;
                    color: white;
                    padding: 3px 8px;
                    border-radius: 3px;
                }
                .footer {
                    text-align: center;
                    margin-top: 30px;
                    padding-top: 10px;
                    border-top: 1px solid #eee;
                    color: #777;
                }
                .vulnerability-details {
                    margin-bottom: 10px;
                    padding: 10px;
                    border: 1px solid #ddd;
                    border-radius: 5px;
                }
                .section {
                    margin-bottom: 30px;
                }
                .port-open {
                    color: #4caf50;
                    font-weight: bold;
                }
                .port-closed {
                    color: #ff5252;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>تقرير SaudiAttack</h1>
                    <p>تقرير مسح الثغرات الأمنية</p>
                </div>
                
                <div class="section">
                    <h2>ملخص المسح</h2>
                    <div class="summary">
                        <p><strong>الهدف:</strong> {{ results.target }}</p>
                        <p><strong>نوع الهدف:</strong> {{ results.target_type }}</p>
                        <p><strong>تاريخ المسح:</strong> {{ results.scan_time }}</p>
                        <p><strong>مدة المسح:</strong> {{ results.scan_duration }}</p>
                        <p><strong>عدد الثغرات المكتشفة:</strong> {{ vulnerability_count }}</p>
                    </div>
                </div>
                
                {% if results.host_info %}
                <div class="section">
                    <h2>معلومات المضيف</h2>
                    <table>
                        <tr>
                            <th>المعلومة</th>
                            <th>القيمة</th>
                        </tr>
                        {% if results.host_info.ip %}
                        <tr>
                            <td>عنوان IP</td>
                            <td>{{ results.host_info.ip }}</td>
                        </tr>
                        {% endif %}
                        {% if results.host_info.hostname %}
                        <tr>
                            <td>اسم المضيف</td>
                            <td>{{ results.host_info.hostname }}</td>
                        </tr>
                        {% endif %}
                        {% if results.host_info.os %}
                        <tr>
                            <td>نظام التشغيل</td>
                            <td>{{ results.host_info.os }}</td>
                        </tr>
                        {% endif %}
                        {% if results.host_info.mac_address %}
                        <tr>
                            <td>عنوان MAC</td>
                            <td>{{ results.host_info.mac_address }}</td>
                        </tr>
                        {% endif %}
                        {% if results.host_info.dns_records %}
                        <tr>
                            <td>سجلات DNS</td>
                            <td>
                                <ul>
                                {% for record in results.host_info.dns_records %}
                                    <li>{{ record }}</li>
                                {% endfor %}
                                </ul>
                            </td>
                        </tr>
                        {% endif %}
                        {% if results.host_info.geolocation %}
                        <tr>
                            <td>الموقع الجغرافي</td>
                            <td>{{ results.host_info.geolocation }}</td>
                        </tr>
                        {% endif %}
                    </table>
                </div>
                {% endif %}
                
                {% if results.open_ports %}
                <div class="section">
                    <h2>المنافذ المفتوحة</h2>
                    <table>
                        <tr>
                            <th>المنفذ</th>
                            <th>البروتوكول</th>
                            <th>الحالة</th>
                            <th>الخدمة</th>
                            <th>الإصدار</th>
                        </tr>
                        {% for port in results.open_ports %}
                        <tr>
                            <td>{{ port.port }}</td>
                            <td>{{ port.protocol }}</td>
                            <td class="port-open">{{ port.state }}</td>
                            <td>{{ port.service }}</td>
                            <td>{{ port.version }}</td>
                        </tr>
                        {% endfor %}
                    </table>
                </div>
                {% endif %}
                
                {% if results.web_info %}
                <div class="section">
                    <h2>معلومات خادم الويب</h2>
                    
                    {% if results.web_info.servers %}
                    <h3>خوادم الويب</h3>
                    <table>
                        <tr>
                            <th>URL</th>
                            <th>الخادم</th>
                        </tr>
                        {% for url, server in results.web_info.servers.items() %}
                        <tr>
                            <td>{{ url }}</td>
                            <td>{{ server }}</td>
                        </tr>
                        {% endfor %}
                    </table>
                    {% endif %}
                    
                    {% if results.web_info.technologies %}
                    <h3>التقنيات المكتشفة</h3>
                    <ul>
                        {% for tech in results.web_info.technologies %}
                        <li>{{ tech }}</li>
                        {% endfor %}
                    </ul>
                    {% endif %}
                    
                    {% if results.web_info.security_headers %}
                    <h3>ترويسات الأمان</h3>
                    <table>
                        <tr>
                            <th>الترويسة</th>
                            <th>القيمة</th>
                        </tr>
                        {% for header, value in results.web_info.security_headers.items() %}
                        <tr>
                            <td>{{ header }}</td>
                            <td>{{ value }}</td>
                        </tr>
                        {% endfor %}
                    </table>
                    {% endif %}
                </div>
                {% endif %}
                
                {% if results.wordpress_info %}
                <div class="section">
                    <h2>معلومات ووردبريس</h2>
                    
                    {% if results.wordpress_info.version %}
                    <p><strong>الإصدار:</strong> {{ results.wordpress_info.version }}</p>
                    {% endif %}
                    
                    {% if results.wordpress_info.themes %}
                    <h3>القوالب المثبتة</h3>
                    <ul>
                        {% for theme in results.wordpress_info.themes %}
                        <li>{{ theme.name }} {% if theme.version %}(الإصدار: {{ theme.version }}){% endif %}</li>
                        {% endfor %}
                    </ul>
                    {% endif %}
                    
                    {% if results.wordpress_info.plugins %}
                    <h3>الإضافات المثبتة</h3>
                    <ul>
                        {% for plugin in results.wordpress_info.plugins %}
                        <li>{{ plugin.name }} {% if plugin.version %}(الإصدار: {{ plugin.version }}){% endif %}</li>
                        {% endfor %}
                    </ul>
                    {% endif %}
                    
                    {% if results.wordpress_info.users %}
                    <h3>المستخدمون</h3>
                    <ul>
                        {% for user in results.wordpress_info.users %}
                        <li>{{ user.name }} {% if user.id %}(المعرف: {{ user.id }}){% endif %}</li>
                        {% endfor %}
                    </ul>
                    {% endif %}
                </div>
                {% endif %}
                
                {% if results.joomla_info %}
                <div class="section">
                    <h2>معلومات جوملا</h2>
                    
                    {% if results.joomla_info.version %}
                    <p><strong>الإصدار:</strong> {{ results.joomla_info.version }}</p>
                    {% endif %}
                    
                    {% if results.joomla_info.components %}
                    <h3>المكونات المثبتة</h3>
                    <ul>
                        {% for component in results.joomla_info.components %}
                        <li>{{ component.name }}</li>
                        {% endfor %}
                    </ul>
                    {% endif %}
                    
                    {% if results.joomla_info.modules %}
                    <h3>الوحدات المثبتة</h3>
                    <ul>
                        {% for module in results.joomla_info.modules %}
                        <li>{{ module.name }}</li>
                        {% endfor %}
                    </ul>
                    {% endif %}
                    
                    {% if results.joomla_info.templates %}
                    <h3>القوالب المثبتة</h3>
                    <ul>
                        {% for template in results.joomla_info.templates %}
                        <li>{{ template.name }}</li>
                        {% endfor %}
                    </ul>
                    {% endif %}
                    
                    {% if results.joomla_info.users %}
                    <h3>المستخدمون</h3>
                    <ul>
                        {% for user in results.joomla_info.users %}
                        <li>{{ user.name }} {% if user.id %}(المعرف: {{ user.id }}){% endif %}</li>
                        {% endfor %}
                    </ul>
                    {% endif %}
                </div>
                {% endif %}
                
                {% if vulnerabilities %}
                <div class="section">
                    <h2>الثغرات المكتشفة</h2>
                    
                    <h3>ملخص الثغرات حسب الخطورة</h3>
                    <table>
                        <tr>
                            <th>مستوى الخطورة</th>
                            <th>العدد</th>
                        </tr>
                        <tr>
                            <td><span class="severity-critical">حرجة</span></td>
                            <td>{{ severity_counts.critical }}</td>
                        </tr>
                        <tr>
                            <td><span class="severity-high">عالية</span></td>
                            <td>{{ severity_counts.high }}</td>
                        </tr>
                        <tr>
                            <td><span class="severity-medium">متوسطة</span></td>
                            <td>{{ severity_counts.medium }}</td>
                        </tr>
                        <tr>
                            <td><span class="severity-low">منخفضة</span></td>
                            <td>{{ severity_counts.low }}</td>
                        </tr>
                        <tr>
                            <td><span class="severity-info">معلومات</span></td>
                            <td>{{ severity_counts.info }}</td>
                        </tr>
                    </table>
                    
                    <h3>تفاصيل الثغرات</h3>
                    {% for vuln in vulnerabilities %}
                    <div class="vulnerability-details">
                        <h4>{{ vuln.name }}</h4>
                        <p><strong>الخطورة:</strong> <span class="severity-{{ vuln.severity }}">{{ vuln.severity_label }}</span></p>
                        <p><strong>الوصف:</strong> {{ vuln.description }}</p>
                        {% if vuln.type %}
                        <p><strong>النوع:</strong> {{ vuln.type }}</p>
                        {% endif %}
                        {% if vuln.url %}
                        <p><strong>URL:</strong> <a href="{{ vuln.url }}" target="_blank">{{ vuln.url }}</a></p>
                        {% endif %}
                        {% if vuln.affected_version %}
                        <p><strong>الإصدار المتأثر:</strong> {{ vuln.affected_version }}</p>
                        {% endif %}
                        {% if vuln.fixed_in %}
                        <p><strong>تم إصلاحه في:</strong> {{ vuln.fixed_in }}</p>
                        {% endif %}
                    </div>
                    {% endfor %}
                </div>
                {% endif %}
                
                <div class="footer">
                    <p>تم إنشاء هذا التقرير بواسطة أداة SaudiAttack</p>
                    <p>المطور: Saudi Linux - SaudiLinux7@gmail.com</p>
                    <p>{{ current_time }}</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        # تجميع الثغرات من جميع المصادر
        vulnerabilities = []
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        
        # إضافة ثغرات المسح العام
        if "vulnerabilities" in self.results:
            for vuln in self.results["vulnerabilities"]:
                severity = vuln.get("severity", "info").lower()
                severity_label = self._get_severity_label(severity)
                vulnerabilities.append({
                    "name": vuln.get("name", "ثغرة غير معروفة"),
                    "description": vuln.get("description", "لا يوجد وصف"),
                    "severity": severity,
                    "severity_label": severity_label,
                    "type": vuln.get("type", ""),
                    "url": vuln.get("url", "")
                })
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # إضافة ثغرات خادم الويب
        if "web_vulnerabilities" in self.results:
            for vuln in self.results["web_vulnerabilities"]:
                severity = vuln.get("severity", "info").lower()
                severity_label = self._get_severity_label(severity)
                vulnerabilities.append({
                    "name": vuln.get("name", "ثغرة غير معروفة"),
                    "description": vuln.get("description", "لا يوجد وصف"),
                    "severity": severity,
                    "severity_label": severity_label,
                    "type": vuln.get("type", ""),
                    "url": vuln.get("url", "")
                })
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # إضافة ثغرات ووردبريس
        if "wordpress_vulnerabilities" in self.results:
            for vuln in self.results["wordpress_vulnerabilities"]:
                severity = vuln.get("severity", "info").lower()
                severity_label = self._get_severity_label(severity)
                vulnerabilities.append({
                    "name": vuln.get("name", "ثغرة غير معروفة"),
                    "description": vuln.get("description", "لا يوجد وصف"),
                    "severity": severity,
                    "severity_label": severity_label,
                    "type": vuln.get("type", ""),
                    "url": vuln.get("url", ""),
                    "affected_version": vuln.get("affected_version", ""),
                    "fixed_in": vuln.get("fixed_in", "")
                })
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # إضافة ثغرات جوملا
        if "joomla_vulnerabilities" in self.results:
            for vuln in self.results["joomla_vulnerabilities"]:
                severity = vuln.get("severity", "info").lower()
                severity_label = self._get_severity_label(severity)
                vulnerabilities.append({
                    "name": vuln.get("name", "ثغرة غير معروفة"),
                    "description": vuln.get("description", "لا يوجد وصف"),
                    "severity": severity,
                    "severity_label": severity_label,
                    "type": vuln.get("type", ""),
                    "url": vuln.get("url", ""),
                    "affected_version": vuln.get("affected_version", ""),
                    "fixed_in": vuln.get("fixed_in", "")
                })
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # ترتيب الثغرات حسب الخطورة
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        vulnerabilities.sort(key=lambda x: severity_order.get(x["severity"], 5))
        
        # إعداد بيانات القالب
        template_data = {
            "results": self.results,
            "vulnerabilities": vulnerabilities,
            "vulnerability_count": len(vulnerabilities),
            "severity_counts": severity_counts,
            "current_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        # تطبيق القالب
        template = Template(html_template)
        return template.render(**template_data)
    
    def _generate_json_report(self):
        """
        إنشاء تقرير JSON
        
        المخرجات:
            str: محتوى تقرير JSON
        """
        # إضافة معلومات إضافية للتقرير
        report_data = self.results.copy()
        report_data["report_generated_at"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        report_data["report_generator"] = "SaudiAttack"
        report_data["report_version"] = "1.0"
        
        # تحويل البيانات إلى JSON
        return json.dumps(report_data, indent=4, ensure_ascii=False)
    
    def _generate_text_report(self):
        """
        إنشاء تقرير نصي
        
        المخرجات:
            str: محتوى تقرير نصي
        """
        report = []
        
        # إضافة العنوان
        report.append("="*80)
        report.append("تقرير SaudiAttack - مسح الثغرات الأمنية")
        report.append("="*80)
        report.append("")
        
        # إضافة معلومات المسح
        report.append("معلومات المسح:")
        report.append("-"*80)
        report.append(f"الهدف: {self.results.get('target', 'غير معروف')}")
        report.append(f"نوع الهدف: {self.results.get('target_type', 'غير معروف')}")
        report.append(f"تاريخ المسح: {self.results.get('scan_time', 'غير معروف')}")
        report.append(f"مدة المسح: {self.results.get('scan_duration', 'غير معروف')}")
        report.append("")
        
        # إضافة معلومات المضيف
        if "host_info" in self.results:
            report.append("معلومات المضيف:")
            report.append("-"*80)
            host_info = self.results["host_info"]
            if "ip" in host_info:
                report.append(f"عنوان IP: {host_info['ip']}")
            if "hostname" in host_info:
                report.append(f"اسم المضيف: {host_info['hostname']}")
            if "os" in host_info:
                report.append(f"نظام التشغيل: {host_info['os']}")
            if "mac_address" in host_info:
                report.append(f"عنوان MAC: {host_info['mac_address']}")
            report.append("")
        
        # إضافة المنافذ المفتوحة
        if "open_ports" in self.results and self.results["open_ports"]:
            report.append("المنافذ المفتوحة:")
            report.append("-"*80)
            for port in self.results["open_ports"]:
                report.append(f"المنفذ: {port.get('port', '')} | البروتوكول: {port.get('protocol', '')} | الحالة: {port.get('state', '')} | الخدمة: {port.get('service', '')} | الإصدار: {port.get('version', '')}")
            report.append("")
        
        # إضافة معلومات خادم الويب
        if "web_info" in self.results:
            report.append("معلومات خادم الويب:")
            report.append("-"*80)
            web_info = self.results["web_info"]
            
            if "servers" in web_info and web_info["servers"]:
                report.append("خوادم الويب:")
                for url, server in web_info["servers"].items():
                    report.append(f"  {url}: {server}")
                report.append("")
            
            if "technologies" in web_info and web_info["technologies"]:
                report.append("التقنيات المكتشفة:")
                for tech in web_info["technologies"]:
                    report.append(f"  - {tech}")
                report.append("")
        
        # إضافة معلومات ووردبريس
        if "wordpress_info" in self.results:
            report.append("معلومات ووردبريس:")
            report.append("-"*80)
            wp_info = self.results["wordpress_info"]
            
            if "version" in wp_info and wp_info["version"]:
                report.append(f"الإصدار: {wp_info['version']}")
            
            if "themes" in wp_info and wp_info["themes"]:
                report.append("القوالب المثبتة:")
                for theme in wp_info["themes"]:
                    theme_info = f"  - {theme.get('name', '')}"
                    if "version" in theme and theme["version"]:
                        theme_info += f" (الإصدار: {theme['version']})"
                    report.append(theme_info)
                report.append("")
            
            if "plugins" in wp_info and wp_info["plugins"]:
                report.append("الإضافات المثبتة:")
                for plugin in wp_info["plugins"]:
                    plugin_info = f"  - {plugin.get('name', '')}"
                    if "version" in plugin and plugin["version"]:
                        plugin_info += f" (الإصدار: {plugin['version']})"
                    report.append(plugin_info)
                report.append("")
        
        # إضافة معلومات جوملا
        if "joomla_info" in self.results:
            report.append("معلومات جوملا:")
            report.append("-"*80)
            joomla_info = self.results["joomla_info"]
            
            if "version" in joomla_info and joomla_info["version"]:
                report.append(f"الإصدار: {joomla_info['version']}")
            
            if "components" in joomla_info and joomla_info["components"]:
                report.append("المكونات المثبتة:")
                for component in joomla_info["components"]:
                    report.append(f"  - {component.get('name', '')}")
                report.append("")
            
            if "modules" in joomla_info and joomla_info["modules"]:
                report.append("الوحدات المثبتة:")
                for module in joomla_info["modules"]:
                    report.append(f"  - {module.get('name', '')}")
                report.append("")
        
        # تجميع الثغرات من جميع المصادر
        vulnerabilities = []
        
        # إضافة ثغرات المسح العام
        if "vulnerabilities" in self.results:
            vulnerabilities.extend(self.results["vulnerabilities"])
        
        # إضافة ثغرات خادم الويب
        if "web_vulnerabilities" in self.results:
            vulnerabilities.extend(self.results["web_vulnerabilities"])
        
        # إضافة ثغرات ووردبريس
        if "wordpress_vulnerabilities" in self.results:
            vulnerabilities.extend(self.results["wordpress_vulnerabilities"])
        
        # إضافة ثغرات جوملا
        if "joomla_vulnerabilities" in self.results:
            vulnerabilities.extend(self.results["joomla_vulnerabilities"])
        
        # إضافة الثغرات المكتشفة
        if vulnerabilities:
            report.append("الثغرات المكتشفة:")
            report.append("-"*80)
            
            # ترتيب الثغرات حسب الخطورة
            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            vulnerabilities.sort(key=lambda x: severity_order.get(x.get("severity", "info").lower(), 5))
            
            for i, vuln in enumerate(vulnerabilities, 1):
                report.append(f"[{i}] {vuln.get('name', 'ثغرة غير معروفة')}")
                report.append(f"  الخطورة: {self._get_severity_label(vuln.get('severity', 'info').lower())}")
                report.append(f"  الوصف: {vuln.get('description', 'لا يوجد وصف')}")
                if "type" in vuln and vuln["type"]:
                    report.append(f"  النوع: {vuln['type']}")
                if "url" in vuln and vuln["url"]:
                    report.append(f"  URL: {vuln['url']}")
                if "affected_version" in vuln and vuln["affected_version"]:
                    report.append(f"  الإصدار المتأثر: {vuln['affected_version']}")
                if "fixed_in" in vuln and vuln["fixed_in"]:
                    report.append(f"  تم إصلاحه في: {vuln['fixed_in']}")
                report.append("")
        
        # إضافة التذييل
        report.append("="*80)
        report.append("تم إنشاء هذا التقرير بواسطة أداة SaudiAttack")
        report.append("المطور: Saudi Linux - SaudiLinux7@gmail.com")
        report.append(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        report.append("="*80)
        
        return "\n".join(report)
    
    def _generate_markdown_report(self):
        """
        إنشاء تقرير Markdown
        
        المخرجات:
            str: محتوى تقرير Markdown
        """
        report = []
        
        # إضافة العنوان
        report.append("# تقرير SaudiAttack - مسح الثغرات الأمنية")
        report.append("")
        
        # إضافة معلومات المسح
        report.append("## ملخص المسح")
        report.append("")
        report.append(f"**الهدف:** {self.results.get('target', 'غير معروف')}")
        report.append(f"**نوع الهدف:** {self.results.get('target_type', 'غير معروف')}")
        report.append(f"**تاريخ المسح:** {self.results.get('scan_time', 'غير معروف')}")
        report.append(f"**مدة المسح:** {self.results.get('scan_duration', 'غير معروف')}")
        report.append("")
        
        # إضافة معلومات المضيف
        if "host_info" in self.results:
            report.append("## معلومات المضيف")
            report.append("")
            host_info = self.results["host_info"]
            if "ip" in host_info:
                report.append(f"**عنوان IP:** {host_info['ip']}")
            if "hostname" in host_info:
                report.append(f"**اسم المضيف:** {host_info['hostname']}")
            if "os" in host_info:
                report.append(f"**نظام التشغيل:** {host_info['os']}")
            if "mac_address" in host_info:
                report.append(f"**عنوان MAC:** {host_info['mac_address']}")
            report.append("")
        
        # إضافة المنافذ المفتوحة
        if "open_ports" in self.results and self.results["open_ports"]:
            report.append("## المنافذ المفتوحة")
            report.append("")
            report.append("| المنفذ | البروتوكول | الحالة | الخدمة | الإصدار |")
            report.append("| ----- | ---------- | ------ | ------- | ------- |")
            for port in self.results["open_ports"]:
                report.append(f"| {port.get('port', '')} | {port.get('protocol', '')} | {port.get('state', '')} | {port.get('service', '')} | {port.get('version', '')} |")
            report.append("")
        
        # إضافة معلومات خادم الويب
        if "web_info" in self.results:
            report.append("## معلومات خادم الويب")
            report.append("")
            web_info = self.results["web_info"]
            
            if "servers" in web_info and web_info["servers"]:
                report.append("### خوادم الويب")
                report.append("")
                report.append("| URL | الخادم |")
                report.append("| --- | ------ |")
                for url, server in web_info["servers"].items():
                    report.append(f"| {url} | {server} |")
                report.append("")
            
            if "technologies" in web_info and web_info["technologies"]:
                report.append("### التقنيات المكتشفة")
                report.append("")
                for tech in web_info["technologies"]:
                    report.append(f"- {tech}")
                report.append("")
        
        # إضافة معلومات ووردبريس
        if "wordpress_info" in self.results:
            report.append("## معلومات ووردبريس")
            report.append("")
            wp_info = self.results["wordpress_info"]
            
            if "version" in wp_info and wp_info["version"]:
                report.append(f"**الإصدار:** {wp_info['version']}")
                report.append("")
            
            if "themes" in wp_info and wp_info["themes"]:
                report.append("### القوالب المثبتة")
                report.append("")
                for theme in wp_info["themes"]:
                    theme_info = f"- {theme.get('name', '')}"
                    if "version" in theme and theme["version"]:
                        theme_info += f" (الإصدار: {theme['version']})"
                    report.append(theme_info)
                report.append("")
            
            if "plugins" in wp_info and wp_info["plugins"]:
                report.append("### الإضافات المثبتة")
                report.append("")
                for plugin in wp_info["plugins"]:
                    plugin_info = f"- {plugin.get('name', '')}"
                    if "version" in plugin and plugin["version"]:
                        plugin_info += f" (الإصدار: {plugin['version']})"
                    report.append(plugin_info)
                report.append("")
        
        # إضافة معلومات جوملا
        if "joomla_info" in self.results:
            report.append("## معلومات جوملا")
            report.append("")
            joomla_info = self.results["joomla_info"]
            
            if "version" in joomla_info and joomla_info["version"]:
                report.append(f"**الإصدار:** {joomla_info['version']}")
                report.append("")
            
            if "components" in joomla_info and joomla_info["components"]:
                report.append("### المكونات المثبتة")
                report.append("")
                for component in joomla_info["components"]:
                    report.append(f"- {component.get('name', '')}")
                report.append("")
            
            if "modules" in joomla_info and joomla_info["modules"]:
                report.append("### الوحدات المثبتة")
                report.append("")
                for module in joomla_info["modules"]:
                    report.append(f"- {module.get('name', '')}")
                report.append("")
        
        # تجميع الثغرات من جميع المصادر
        vulnerabilities = []
        
        # إضافة ثغرات المسح العام
        if "vulnerabilities" in self.results:
            vulnerabilities.extend(self.results["vulnerabilities"])
        
        # إضافة ثغرات خادم الويب
        if "web_vulnerabilities" in self.results:
            vulnerabilities.extend(self.results["web_vulnerabilities"])
        
        # إضافة ثغرات ووردبريس
        if "wordpress_vulnerabilities" in self.results:
            vulnerabilities.extend(self.results["wordpress_vulnerabilities"])
        
        # إضافة ثغرات جوملا
        if "joomla_vulnerabilities" in self.results:
            vulnerabilities.extend(self.results["joomla_vulnerabilities"])
        
        # إضافة الثغرات المكتشفة
        if vulnerabilities:
            report.append("## الثغرات المكتشفة")
            report.append("")
            
            # ترتيب الثغرات حسب الخطورة
            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            vulnerabilities.sort(key=lambda x: severity_order.get(x.get("severity", "info").lower(), 5))
            
            # إحصاء الثغرات حسب الخطورة
            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            for vuln in vulnerabilities:
                severity = vuln.get("severity", "info").lower()
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            report.append("### ملخص الثغرات حسب الخطورة")
            report.append("")
            report.append("| مستوى الخطورة | العدد |")
            report.append("| ------------- | ----- |")
            report.append(f"| 🔴 حرجة | {severity_counts.get('critical', 0)} |")
            report.append(f"| 🟠 عالية | {severity_counts.get('high', 0)} |")
            report.append(f"| 🟡 متوسطة | {severity_counts.get('medium', 0)} |")
            report.append(f"| 🟢 منخفضة | {severity_counts.get('low', 0)} |")
            report.append(f"| 🔵 معلومات | {severity_counts.get('info', 0)} |")
            report.append("")
            
            report.append("### تفاصيل الثغرات")
            report.append("")
            
            for i, vuln in enumerate(vulnerabilities, 1):
                severity = vuln.get("severity", "info").lower()
                severity_emoji = self._get_severity_emoji(severity)
                
                report.append(f"#### {i}. {vuln.get('name', 'ثغرة غير معروفة')} {severity_emoji}")
                report.append("")
                report.append(f"**الخطورة:** {self._get_severity_label(severity)}")
                report.append(f"**الوصف:** {vuln.get('description', 'لا يوجد وصف')}")
                if "type" in vuln and vuln["type"]:
                    report.append(f"**النوع:** {vuln['type']}")
                if "url" in vuln and vuln["url"]:
                    report.append(f"**URL:** {vuln['url']}")
                if "affected_version" in vuln and vuln["affected_version"]:
                    report.append(f"**الإصدار المتأثر:** {vuln['affected_version']}")
                if "fixed_in" in vuln and vuln["fixed_in"]:
                    report.append(f"**تم إصلاحه في:** {vuln['fixed_in']}")
                report.append("")
                report.append("---")
                report.append("")
        
        # إضافة التذييل
        report.append("---")
        report.append("")
        report.append("*تم إنشاء هذا التقرير بواسطة أداة SaudiAttack*")
        report.append("")
        report.append("*المطور: Saudi Linux - SaudiLinux7@gmail.com*")
        report.append("")
        report.append(f"*{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*")
        
        return "\n".join(report)
    
    def _generate_yaml_report(self):
        """
        إنشاء تقرير YAML
        
        المخرجات:
            str: محتوى تقرير YAML
        """
        # إضافة معلومات إضافية للتقرير
        report_data = self.results.copy()
        report_data["report_generated_at"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        report_data["report_generator"] = "SaudiAttack"
        report_data["report_version"] = "1.0"
        
        # تحويل البيانات إلى YAML
        return yaml.dump(report_data, allow_unicode=True, sort_keys=False)
    
    def _get_severity_label(self, severity):
        """
        الحصول على تسمية مستوى الخطورة
        
        المعطيات:
            severity (str): مستوى الخطورة
            
        المخرجات:
            str: تسمية مستوى الخطورة
        """
        severity_labels = {
            "critical": "حرجة",
            "high": "عالية",
            "medium": "متوسطة",
            "low": "منخفضة",
            "info": "معلومات"
        }
        return severity_labels.get(severity.lower(), "غير معروف")
    
    def _get_severity_emoji(self, severity):
        """
        الحصول على رمز تعبيري لمستوى الخطورة
        
        المعطيات:
            severity (str): مستوى الخطورة
            
        المخرجات:
            str: رمز تعبيري لمستوى الخطورة
        """
        severity_emojis = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🟢",
            "info": "🔵"
        }
        return severity_emojis.get(severity.lower(), "")