#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
وحدة ماسح جوملا لأداة SaudiAttack
"""

import re
import requests
import json
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
from rich.console import Console
from .web_scanner import WebServerScanner
from .utils import get_severity_color

console = Console()

class JoomlaScanner(WebServerScanner):
    """
    فئة ماسح جوملا
    """
    
    def __init__(self, target, ports=[80, 443], threads=5, timeout=30, logger=None):
        """
        تهيئة ماسح جوملا
        
        المعطيات:
            target (str): الهدف (عنوان IP أو اسم النطاق)
            ports (list): قائمة المنافذ للفحص (افتراضيًا: 80, 443)
            threads (int): عدد مسارات التنفيذ المتوازية
            timeout (int): مهلة الاتصال بالثواني
            logger (Logger): كائن المسجل
        """
        super().__init__(target, ports, threads, timeout, logger)
        
        # إضافة معلومات خاصة بجوملا إلى النتائج
        self.results["joomla_info"] = {
            "version": "",
            "components": [],
            "modules": [],
            "templates": [],
            "users": []
        }
        self.results["joomla_vulnerabilities"] = []
        
        # قائمة الثغرات المعروفة في جوملا
        self.known_vulnerabilities = self._load_known_vulnerabilities()
    
    def scan(self):
        """
        تنفيذ مسح جوملا
        
        المخرجات:
            dict: نتائج المسح
        """
        self.logger.info(f"بدء مسح جوملا على الهدف: {self.target}")
        console.print(f"[bold]بدء مسح جوملا على الهدف: {self.target}[/bold]")
        
        # تنفيذ المسح الأساسي لخادم الويب أولاً
        super().scan()
        
        # التحقق مما إذا كان الموقع يستخدم جوملا
        if not self._is_joomla():
            self.logger.warning(f"الهدف {self.target} لا يبدو أنه يستخدم جوملا.")
            console.print(f"[bold yellow]الهدف {self.target} لا يبدو أنه يستخدم جوملا.[/bold yellow]")
            return self.results
        
        # تحديد عنوان URL الأساسي
        self.base_url = self._get_joomla_base_url()
        if not self.base_url:
            self.logger.error("لم يتم العثور على عنوان URL أساسي صالح لجوملا.")
            console.print("[bold red]لم يتم العثور على عنوان URL أساسي صالح لجوملا.[/bold red]")
            return self.results
        
        self.logger.info(f"تم اكتشاف موقع جوملا على: {self.base_url}")
        console.print(f"[bold green]تم اكتشاف موقع جوملا على: {self.base_url}[/bold green]")
        
        # جمع معلومات جوملا
        self._gather_joomla_info()
        
        # فحص الثغرات الأمنية في جوملا
        self._scan_joomla_vulnerabilities()
        
        self.logger.info(f"اكتمل مسح جوملا على الهدف: {self.target}")
        console.print(f"[bold green]اكتمل مسح جوملا على الهدف: {self.target}[/bold green]")
        
        return self.results
    
    def _load_known_vulnerabilities(self):
        """
        تحميل قاعدة بيانات الثغرات المعروفة في جوملا
        
        المخرجات:
            dict: قاعدة بيانات الثغرات المعروفة
        """
        # هذه مجرد قاعدة بيانات بسيطة للثغرات المعروفة
        # في التطبيق الحقيقي، يمكن تحميلها من ملف أو API
        return {
            "core": {
                "4.0.0": [
                    {
                        "name": "CVE-2021-23132",
                        "description": "ثغرة XSS في محرر المحتوى",
                        "severity": "medium",
                        "fixed_in": "4.0.1"
                    }
                ],
                "3.9.0": [
                    {
                        "name": "CVE-2020-35616",
                        "description": "ثغرة في إدارة الجلسات تسمح بتجاوز المصادقة",
                        "severity": "high",
                        "fixed_in": "3.9.24"
                    }
                ],
                "3.8.0": [
                    {
                        "name": "CVE-2020-14693",
                        "description": "ثغرة CSRF في واجهة المستخدم الإدارية",
                        "severity": "medium",
                        "fixed_in": "3.8.10"
                    }
                ],
                "3.7.0": [
                    {
                        "name": "CVE-2017-8917",
                        "description": "ثغرة SQL Injection في مكون com_fields",
                        "severity": "high",
                        "fixed_in": "3.7.1"
                    }
                ],
                "3.6.0": [
                    {
                        "name": "CVE-2016-9081",
                        "description": "ثغرة في مكون com_users تسمح بتسجيل المستخدمين غير المصرح به",
                        "severity": "medium",
                        "fixed_in": "3.6.4"
                    }
                ],
                "3.4.0": [
                    {
                        "name": "CVE-2015-8562",
                        "description": "ثغرة في معالجة User-Agent تسمح بتنفيذ التعليمات البرمجية عن بُعد",
                        "severity": "critical",
                        "fixed_in": "3.4.6"
                    }
                ]
            },
            "components": {
                "com_contact": {
                    "3.5.0": [
                        {
                            "name": "CVE-2017-9934",
                            "description": "ثغرة XSS في نماذج الاتصال",
                            "severity": "medium",
                            "fixed_in": "3.5.1"
                        }
                    ]
                },
                "com_content": {
                    "3.7.0": [
                        {
                            "name": "CVE-2017-8917",
                            "description": "ثغرة SQL Injection في معالجة المحتوى",
                            "severity": "high",
                            "fixed_in": "3.7.1"
                        }
                    ]
                },
                "com_users": {
                    "3.6.0": [
                        {
                            "name": "CVE-2016-8870",
                            "description": "ثغرة في إعادة تعيين كلمة المرور",
                            "severity": "medium",
                            "fixed_in": "3.6.4"
                        }
                    ]
                },
                "com_media": {
                    "3.5.0": [
                        {
                            "name": "CVE-2016-9836",
                            "description": "ثغرة في رفع الملفات تسمح بتنفيذ التعليمات البرمجية",
                            "severity": "high",
                            "fixed_in": "3.5.1"
                        }
                    ]
                },
                "com_fields": {
                    "3.7.0": [
                        {
                            "name": "CVE-2017-8917",
                            "description": "ثغرة SQL Injection في معالجة الحقول المخصصة",
                            "severity": "high",
                            "fixed_in": "3.7.1"
                        }
                    ]
                }
            },
            "modules": {
                "mod_menu": {
                    "3.6.0": [
                        {
                            "name": "CVE-2016-9837",
                            "description": "ثغرة XSS في عرض القائمة",
                            "severity": "low",
                            "fixed_in": "3.6.5"
                        }
                    ]
                },
                "mod_articles_latest": {
                    "3.5.0": [
                        {
                            "name": "CVE-2016-9838",
                            "description": "ثغرة في عرض المقالات الأخيرة",
                            "severity": "low",
                            "fixed_in": "3.5.1"
                        }
                    ]
                }
            },
            "templates": {
                "beez3": {
                    "3.6.0": [
                        {
                            "name": "CVE-2016-9839",
                            "description": "ثغرة XSS في قالب Beez3",
                            "severity": "medium",
                            "fixed_in": "3.6.5"
                        }
                    ]
                },
                "protostar": {
                    "3.5.0": [
                        {
                            "name": "CVE-2016-9840",
                            "description": "ثغرة في قالب Protostar",
                            "severity": "low",
                            "fixed_in": "3.5.1"
                        }
                    ]
                }
            }
        }
    
    def _is_joomla(self):
        """
        التحقق مما إذا كان الموقع يستخدم جوملا
        
        المخرجات:
            bool: True إذا كان الموقع يستخدم جوملا، False خلاف ذلك
        """
        # التحقق من التقنيات المكتشفة
        if "Joomla" in self.results["web_info"]["technologies"]:
            return True
        
        # التحقق من الروابط
        joomla_patterns = [
            r"administrator/index.php",
            r"component/",
            r"option=com_",
            r"templates/",
            r"media/jui/",
            r"media/system/"
        ]
        
        for link in self.results["web_info"]["links"]:
            for pattern in joomla_patterns:
                if re.search(pattern, link, re.IGNORECASE):
                    return True
        
        # التحقق من ترويسات HTTP
        for url, headers in self.results["web_info"]["headers"].items():
            if "X-Content-Encoded-By" in headers and "Joomla" in headers["X-Content-Encoded-By"]:
                return True
        
        # التحقق من محتوى HTML
        for url in self.results["web_info"]["headers"].keys():
            try:
                response = requests.get(url, timeout=self.timeout, verify=False)
                if "joomla" in response.text.lower() or "com_content" in response.text.lower():
                    return True
                
                # التحقق من العلامات الوصفية
                soup = BeautifulSoup(response.text, "html.parser")
                meta_generator = soup.find("meta", {"name": "generator"})
                if meta_generator and "Joomla" in meta_generator.get("content", ""):
                    return True
                
                # التحقق من وجود ملفات جوملا المميزة
                if "Joomla!" in response.text or "window.JoomlaInitReCaptcha" in response.text:
                    return True
            except:
                pass
        
        return False
    
    def _get_joomla_base_url(self):
        """
        الحصول على عنوان URL الأساسي لموقع جوملا
        
        المخرجات:
            str: عنوان URL الأساسي
        """
        # البحث عن روابط تحتوي على مكونات جوملا
        for link in self.results["web_info"]["links"]:
            if "component" in link or "option=com_" in link or "templates" in link:
                parsed_url = urlparse(link)
                return f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        # إذا لم يتم العثور على روابط، استخدام أول عنوان URL تم فحصه
        for url in self.results["web_info"]["headers"].keys():
            parsed_url = urlparse(url)
            return f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        # إذا لم يتم العثور على أي عنوان URL، استخدام الهدف مع بروتوكول HTTP
        return f"http://{self.target}"
    
    def _gather_joomla_info(self):
        """
        جمع معلومات جوملا
        """
        self.logger.info(f"جمع معلومات جوملا من: {self.base_url}")
        console.print(f"[bold]جمع معلومات جوملا من: {self.base_url}[/bold]")
        
        try:
            # الحصول على إصدار جوملا
            self._get_joomla_version()
            
            # الحصول على المكونات المثبتة
            self._get_joomla_components()
            
            # الحصول على الوحدات المثبتة
            self._get_joomla_modules()
            
            # الحصول على القوالب المثبتة
            self._get_joomla_templates()
            
            # الحصول على المستخدمين
            self._get_joomla_users()
            
            self.logger.info("اكتمل جمع معلومات جوملا.")
            console.print("[bold]اكتمل جمع معلومات جوملا.[/bold]")
            
        except Exception as e:
            self.logger.error(f"خطأ أثناء جمع معلومات جوملا: {str(e)}")
            console.print(f"[bold red]خطأ أثناء جمع معلومات جوملا: {str(e)}[/bold red]")
    
    def _get_joomla_version(self):
        """
        الحصول على إصدار جوملا
        """
        try:
            # طريقة 1: من ملف XML
            xml_files = [
                "/administrator/manifests/files/joomla.xml",
                "/language/en-GB/en-GB.xml",
                "/administrator/components/com_admin/sql/updates/mysql/"
            ]
            
            for xml_file in xml_files:
                response = requests.get(f"{self.base_url}{xml_file}", timeout=self.timeout, verify=False)
                if response.status_code == 200:
                    version_match = re.search(r"<version>([\d.]+)</version>", response.text)
                    if version_match:
                        self.results["joomla_info"]["version"] = version_match.group(1)
                        self.logger.info(f"إصدار جوملا: {self.results['joomla_info']['version']}")
                        console.print(f"[green]إصدار جوملا: {self.results['joomla_info']['version']}[/green]")
                        return
            
            # طريقة 2: من الصفحة الرئيسية
            response = requests.get(self.base_url, timeout=self.timeout, verify=False)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, "html.parser")
                meta_generator = soup.find("meta", {"name": "generator"})
                if meta_generator and "Joomla" in meta_generator.get("content", ""):
                    version_match = re.search(r"Joomla!\s+([\d.]+)", meta_generator.get("content", ""))
                    if version_match:
                        self.results["joomla_info"]["version"] = version_match.group(1)
                        self.logger.info(f"إصدار جوملا: {self.results['joomla_info']['version']}")
                        console.print(f"[green]إصدار جوملا: {self.results['joomla_info']['version']}[/green]")
                        return
            
            # طريقة 3: من ملف README.txt
            response = requests.get(f"{self.base_url}/README.txt", timeout=self.timeout, verify=False)
            if response.status_code == 200 and "Joomla!" in response.text:
                version_match = re.search(r"Joomla!\s+([\d.]+)", response.text)
                if version_match:
                    self.results["joomla_info"]["version"] = version_match.group(1)
                    self.logger.info(f"إصدار جوملا: {self.results['joomla_info']['version']}")
                    console.print(f"[green]إصدار جوملا: {self.results['joomla_info']['version']}[/green]")
                    return
            
            self.logger.warning("لم يتم العثور على إصدار جوملا.")
            console.print("[yellow]لم يتم العثور على إصدار جوملا.[/yellow]")
            
        except Exception as e:
            self.logger.error(f"خطأ أثناء الحصول على إصدار جوملا: {str(e)}")
            console.print(f"[bold red]خطأ أثناء الحصول على إصدار جوملا: {str(e)}[/bold red]")
    
    def _get_joomla_components(self):
        """
        الحصول على المكونات المثبتة
        """
        try:
            # البحث عن روابط المكونات في الصفحة الرئيسية
            response = requests.get(self.base_url, timeout=self.timeout, verify=False)
            if response.status_code == 200:
                # البحث عن روابط المكونات
                component_pattern = r"option=com_([a-zA-Z0-9_]+)"
                component_matches = re.findall(component_pattern, response.text)
                
                for component_name in set(component_matches):
                    component_info = {
                        "name": f"com_{component_name}",
                        "url": f"{self.base_url}/index.php?option=com_{component_name}"
                    }
                    
                    if component_info not in self.results["joomla_info"]["components"]:
                        self.results["joomla_info"]["components"].append(component_info)
                        self.logger.info(f"تم اكتشاف مكون: com_{component_name}")
                        console.print(f"[green]تم اكتشاف مكون: com_{component_name}[/green]")
            
            # فحص المكونات الشائعة
            common_components = [
                "com_content", "com_users", "com_contact", "com_banners", "com_categories",
                "com_config", "com_finder", "com_media", "com_menus", "com_modules",
                "com_newsfeeds", "com_plugins", "com_search", "com_tags", "com_templates"
            ]
            
            for component in common_components:
                component_url = f"{self.base_url}/index.php?option={component}"
                try:
                    response = requests.get(component_url, timeout=self.timeout, verify=False)
                    if response.status_code == 200 and "404" not in response.text:
                        component_info = {
                            "name": component,
                            "url": component_url
                        }
                        
                        if component_info not in self.results["joomla_info"]["components"]:
                            self.results["joomla_info"]["components"].append(component_info)
                            self.logger.info(f"تم اكتشاف مكون: {component}")
                            console.print(f"[green]تم اكتشاف مكون: {component}[/green]")
                except:
                    pass
            
            if not self.results["joomla_info"]["components"]:
                self.logger.warning("لم يتم العثور على مكونات جوملا.")
                console.print("[yellow]لم يتم العثور على مكونات جوملا.[/yellow]")
            
        except Exception as e:
            self.logger.error(f"خطأ أثناء الحصول على مكونات جوملا: {str(e)}")
            console.print(f"[bold red]خطأ أثناء الحصول على مكونات جوملا: {str(e)}[/bold red]")
    
    def _get_joomla_modules(self):
        """
        الحصول على الوحدات المثبتة
        """
        try:
            # البحث عن روابط الوحدات في الصفحة الرئيسية
            response = requests.get(self.base_url, timeout=self.timeout, verify=False)
            if response.status_code == 200:
                # البحث عن روابط الوحدات
                module_pattern = r"mod_([a-zA-Z0-9_]+)"
                module_matches = re.findall(module_pattern, response.text)
                
                for module_name in set(module_matches):
                    module_info = {
                        "name": f"mod_{module_name}"
                    }
                    
                    if module_info not in self.results["joomla_info"]["modules"]:
                        self.results["joomla_info"]["modules"].append(module_info)
                        self.logger.info(f"تم اكتشاف وحدة: mod_{module_name}")
                        console.print(f"[green]تم اكتشاف وحدة: mod_{module_name}[/green]")
            
            if not self.results["joomla_info"]["modules"]:
                self.logger.warning("لم يتم العثور على وحدات جوملا.")
                console.print("[yellow]لم يتم العثور على وحدات جوملا.[/yellow]")
            
        except Exception as e:
            self.logger.error(f"خطأ أثناء الحصول على وحدات جوملا: {str(e)}")
            console.print(f"[bold red]خطأ أثناء الحصول على وحدات جوملا: {str(e)}[/bold red]")
    
    def _get_joomla_templates(self):
        """
        الحصول على القوالب المثبتة
        """
        try:
            # البحث عن روابط القوالب في الصفحة الرئيسية
            response = requests.get(self.base_url, timeout=self.timeout, verify=False)
            if response.status_code == 200:
                # البحث عن روابط القوالب
                template_pattern = r"templates/([a-zA-Z0-9_-]+)/"
                template_matches = re.findall(template_pattern, response.text)
                
                for template_name in set(template_matches):
                    template_info = {
                        "name": template_name,
                        "url": f"{self.base_url}/templates/{template_name}/"
                    }
                    
                    if template_info not in self.results["joomla_info"]["templates"]:
                        self.results["joomla_info"]["templates"].append(template_info)
                        self.logger.info(f"تم اكتشاف قالب: {template_name}")
                        console.print(f"[green]تم اكتشاف قالب: {template_name}[/green]")
            
            if not self.results["joomla_info"]["templates"]:
                self.logger.warning("لم يتم العثور على قوالب جوملا.")
                console.print("[yellow]لم يتم العثور على قوالب جوملا.[/yellow]")
            
        except Exception as e:
            self.logger.error(f"خطأ أثناء الحصول على قوالب جوملا: {str(e)}")
            console.print(f"[bold red]خطأ أثناء الحصول على قوالب جوملا: {str(e)}[/bold red]")
    
    def _get_joomla_users(self):
        """
        الحصول على المستخدمين
        """
        try:
            # محاولة استخراج المستخدمين من خلال مكون com_users
            for i in range(1, 10):  # فحص أول 10 معرفات
                user_url = f"{self.base_url}/index.php?option=com_users&view=profile&id={i}"
                response = requests.get(user_url, timeout=self.timeout, verify=False)
                if response.status_code == 200 and "404" not in response.text and "not found" not in response.text.lower():
                    # محاولة استخراج اسم المستخدم
                    soup = BeautifulSoup(response.text, "html.parser")
                    username = ""
                    
                    # البحث عن العنوان
                    title_tag = soup.find("title")
                    if title_tag and ":" in title_tag.text:
                        username = title_tag.text.split(":")[0].strip()
                    
                    # إذا لم يتم العثور على اسم المستخدم، استخدام المعرف
                    if not username:
                        username = f"User {i}"
                    
                    user_info = {
                        "id": i,
                        "name": username,
                        "url": user_url
                    }
                    
                    self.results["joomla_info"]["users"].append(user_info)
                    self.logger.info(f"تم اكتشاف مستخدم: {username} (المعرف: {i})")
                    console.print(f"[green]تم اكتشاف مستخدم: {username} (المعرف: {i})[/green]")
            
            if not self.results["joomla_info"]["users"]:
                self.logger.warning("لم يتم العثور على مستخدمي جوملا.")
                console.print("[yellow]لم يتم العثور على مستخدمي جوملا.[/yellow]")
            
        except Exception as e:
            self.logger.error(f"خطأ أثناء الحصول على مستخدمي جوملا: {str(e)}")
            console.print(f"[bold red]خطأ أثناء الحصول على مستخدمي جوملا: {str(e)}[/bold red]")
    
    def _scan_joomla_vulnerabilities(self):
        """
        فحص الثغرات الأمنية في جوملا
        """
        self.logger.info("بدء فحص الثغرات الأمنية في جوملا.")
        console.print("[bold]بدء فحص الثغرات الأمنية في جوملا.[/bold]")
        
        try:
            # فحص ثغرات النواة
            self._check_core_vulnerabilities()
            
            # فحص ثغرات المكونات
            self._check_component_vulnerabilities()
            
            # فحص ثغرات الوحدات
            self._check_module_vulnerabilities()
            
            # فحص ثغرات القوالب
            self._check_template_vulnerabilities()
            
            # فحص ثغرات أخرى
            self._check_other_vulnerabilities()
            
            self.logger.info(f"اكتمل فحص الثغرات الأمنية في جوملا. تم العثور على {len(self.results['joomla_vulnerabilities'])} ثغرة.")
            console.print(f"[bold]اكتمل فحص الثغرات الأمنية في جوملا. تم العثور على {len(self.results['joomla_vulnerabilities'])} ثغرة.[/bold]")
            
        except Exception as e:
            self.logger.error(f"خطأ أثناء فحص الثغرات الأمنية في جوملا: {str(e)}")
            console.print(f"[bold red]خطأ أثناء فحص الثغرات الأمنية في جوملا: {str(e)}[/bold red]")
    
    def _check_core_vulnerabilities(self):
        """
        فحص ثغرات نواة جوملا
        """
        if not self.results["joomla_info"]["version"]:
            self.logger.warning("لا يمكن فحص ثغرات النواة: الإصدار غير معروف.")
            console.print("[yellow]لا يمكن فحص ثغرات النواة: الإصدار غير معروف.[/yellow]")
            return
        
        version = self.results["joomla_info"]["version"]
        
        # البحث عن الثغرات المعروفة للإصدار الحالي أو الإصدارات السابقة
        for ver, vulns in self.known_vulnerabilities["core"].items():
            if self._is_version_vulnerable(version, ver):
                for vuln in vulns:
                    vuln_info = {
                        "type": "core",
                        "name": vuln["name"],
                        "description": vuln["description"],
                        "severity": vuln["severity"],
                        "affected_version": ver,
                        "fixed_in": vuln["fixed_in"]
                    }
                    self.results["joomla_vulnerabilities"].append(vuln_info)
                    self.logger.warning(f"تم اكتشاف ثغرة في نواة جوملا: {vuln['name']} (خطورة: {vuln['severity']})")
                    console.print(f"[{get_severity_color(vuln['severity'])}]تم اكتشاف ثغرة في نواة جوملا: {vuln['name']} (خطورة: {vuln['severity']})[/{get_severity_color(vuln['severity'])}]")
        
        # فحص ملفات حساسة
        sensitive_files = [
            "/configuration.php",
            "/htaccess.txt",
            "/web.config.txt",
            "/administrator/manifests/files/joomla.xml",
            "/administrator/logs/",
            "/installation/"
        ]
        
        for file in sensitive_files:
            file_url = f"{self.base_url}{file}"
            try:
                response = requests.get(file_url, timeout=self.timeout, verify=False)
                if response.status_code == 200:
                    vuln_info = {
                        "type": "sensitive_file",
                        "name": "Sensitive File Exposure",
                        "description": f"تم العثور على ملف حساس: {file_url}",
                        "severity": "high",
                        "url": file_url
                    }
                    self.results["joomla_vulnerabilities"].append(vuln_info)
                    self.logger.warning(f"تم العثور على ملف حساس: {file_url}")
                    console.print(f"[red]تم العثور على ملف حساس: {file_url}[/red]")
            except:
                pass
    
    def _check_component_vulnerabilities(self):
        """
        فحص ثغرات مكونات جوملا
        """
        if not self.results["joomla_info"]["components"]:
            self.logger.warning("لا يمكن فحص ثغرات المكونات: لم يتم العثور على مكونات.")
            console.print("[yellow]لا يمكن فحص ثغرات المكونات: لم يتم العثور على مكونات.[/yellow]")
            return
        
        for component in self.results["joomla_info"]["components"]:
            component_name = component["name"]
            
            # التحقق مما إذا كان المكون معروفًا في قاعدة البيانات
            if component_name in self.known_vulnerabilities["components"]:
                # البحث عن الثغرات المعروفة للمكون
                for ver, vulns in self.known_vulnerabilities["components"][component_name].items():
                    # نفترض أن المكون عرضة للثغرات لأننا لا نعرف إصداره
                    for vuln in vulns:
                        vuln_info = {
                            "type": "component",
                            "name": vuln["name"],
                            "description": vuln["description"],
                            "severity": vuln["severity"],
                            "component": component_name,
                            "affected_version": ver,
                            "fixed_in": vuln["fixed_in"]
                        }
                        self.results["joomla_vulnerabilities"].append(vuln_info)
                        self.logger.warning(f"تم اكتشاف ثغرة في مكون {component_name}: {vuln['name']} (خطورة: {vuln['severity']})")
                        console.print(f"[{get_severity_color(vuln['severity'])}]تم اكتشاف ثغرة في مكون {component_name}: {vuln['name']} (خطورة: {vuln['severity']})[/{get_severity_color(vuln['severity'])}]")
            
            # فحص ثغرات SQL Injection في المكونات
            if "url" in component:
                sql_injection_params = ["id", "catid", "cid", "sid", "uid", "itemid", "section"]
                for param in sql_injection_params:
                    test_url = f"{component['url']}&{param}=1'"
                    try:
                        response = requests.get(test_url, timeout=self.timeout, verify=False)
                        if response.status_code == 200 and ("SQL syntax" in response.text or "mysql_fetch" in response.text or "You have an error in your SQL syntax" in response.text):
                            vuln_info = {
                                "type": "sql_injection",
                                "name": "SQL Injection Vulnerability",
                                "description": f"تم اكتشاف ثغرة SQL Injection في مكون {component_name} في المعلمة {param}",
                                "severity": "high",
                                "component": component_name,
                                "url": test_url
                            }
                            self.results["joomla_vulnerabilities"].append(vuln_info)
                            self.logger.warning(f"تم اكتشاف ثغرة SQL Injection في مكون {component_name} في المعلمة {param}")
                            console.print(f"[red]تم اكتشاف ثغرة SQL Injection في مكون {component_name} في المعلمة {param}[/red]")
                    except:
                        pass
    
    def _check_module_vulnerabilities(self):
        """
        فحص ثغرات وحدات جوملا
        """
        if not self.results["joomla_info"]["modules"]:
            self.logger.warning("لا يمكن فحص ثغرات الوحدات: لم يتم العثور على وحدات.")
            console.print("[yellow]لا يمكن فحص ثغرات الوحدات: لم يتم العثور على وحدات.[/yellow]")
            return
        
        for module in self.results["joomla_info"]["modules"]:
            module_name = module["name"]
            
            # التحقق مما إذا كانت الوحدة معروفة في قاعدة البيانات
            if module_name in self.known_vulnerabilities["modules"]:
                # البحث عن الثغرات المعروفة للوحدة
                for ver, vulns in self.known_vulnerabilities["modules"][module_name].items():
                    # نفترض أن الوحدة عرضة للثغرات لأننا لا نعرف إصدارها
                    for vuln in vulns:
                        vuln_info = {
                            "type": "module",
                            "name": vuln["name"],
                            "description": vuln["description"],
                            "severity": vuln["severity"],
                            "module": module_name,
                            "affected_version": ver,
                            "fixed_in": vuln["fixed_in"]
                        }
                        self.results["joomla_vulnerabilities"].append(vuln_info)
                        self.logger.warning(f"تم اكتشاف ثغرة في وحدة {module_name}: {vuln['name']} (خطورة: {vuln['severity']})")
                        console.print(f"[{get_severity_color(vuln['severity'])}]تم اكتشاف ثغرة في وحدة {module_name}: {vuln['name']} (خطورة: {vuln['severity']})[/{get_severity_color(vuln['severity'])}]")
    
    def _check_template_vulnerabilities(self):
        """
        فحص ثغرات قوالب جوملا
        """
        if not self.results["joomla_info"]["templates"]:
            self.logger.warning("لا يمكن فحص ثغرات القوالب: لم يتم العثور على قوالب.")
            console.print("[yellow]لا يمكن فحص ثغرات القوالب: لم يتم العثور على قوالب.[/yellow]")
            return
        
        for template in self.results["joomla_info"]["templates"]:
            template_name = template["name"]
            
            # التحقق مما إذا كان القالب معروفًا في قاعدة البيانات
            if template_name in self.known_vulnerabilities["templates"]:
                # البحث عن الثغرات المعروفة للقالب
                for ver, vulns in self.known_vulnerabilities["templates"][template_name].items():
                    # نفترض أن القالب عرضة للثغرات لأننا لا نعرف إصداره
                    for vuln in vulns:
                        vuln_info = {
                            "type": "template",
                            "name": vuln["name"],
                            "description": vuln["description"],
                            "severity": vuln["severity"],
                            "template": template_name,
                            "affected_version": ver,
                            "fixed_in": vuln["fixed_in"]
                        }
                        self.results["joomla_vulnerabilities"].append(vuln_info)
                        self.logger.warning(f"تم اكتشاف ثغرة في قالب {template_name}: {vuln['name']} (خطورة: {vuln['severity']})")
                        console.print(f"[{get_severity_color(vuln['severity'])}]تم اكتشاف ثغرة في قالب {template_name}: {vuln['name']} (خطورة: {vuln['severity']})[/{get_severity_color(vuln['severity'])}]")
            
            # فحص ملفات حساسة للقالب
            if "url" in template:
                sensitive_files = [
                    "templateDetails.xml",
                    "params.ini",
                    "index.php",
                    "css/template.css",
                    "js/template.js"
                ]
                
                for file in sensitive_files:
                    file_url = f"{template['url']}{file}"
                    try:
                        response = requests.get(file_url, timeout=self.timeout, verify=False)
                        if response.status_code == 200:
                            vuln_info = {
                                "type": "information_disclosure",
                                "name": "Template Information Disclosure",
                                "description": f"تم العثور على ملف معلومات للقالب {template_name}: {file_url}",
                                "severity": "low",
                                "template": template_name,
                                "url": file_url
                            }
                            self.results["joomla_vulnerabilities"].append(vuln_info)
                            self.logger.info(f"تم العثور على ملف معلومات للقالب {template_name}: {file_url}")
                            console.print(f"[green]تم العثور على ملف معلومات للقالب {template_name}: {file_url}[/green]")
                    except:
                        pass
    
    def _check_other_vulnerabilities(self):
        """
        فحص ثغرات أخرى في جوملا
        """
        # فحص صفحة تسجيل الدخول الإدارية
        admin_url = f"{self.base_url}/administrator/"
        try:
            response = requests.get(admin_url, timeout=self.timeout, verify=False)
            if response.status_code == 200 and ("Joomla" in response.text or "Administration Login" in response.text):
                vuln_info = {
                    "type": "admin_login",
                    "name": "Admin Login Page Accessible",
                    "description": "صفحة تسجيل الدخول الإدارية متاحة للوصول العام",
                    "severity": "low",
                    "url": admin_url
                }
                self.results["joomla_vulnerabilities"].append(vuln_info)
                self.logger.info("صفحة تسجيل الدخول الإدارية متاحة للوصول العام.")
                console.print("[green]صفحة تسجيل الدخول الإدارية متاحة للوصول العام.[/green]")
        except:
            pass
        
        # فحص دليل التثبيت
        install_url = f"{self.base_url}/installation/"
        try:
            response = requests.get(install_url, timeout=self.timeout, verify=False)
            if response.status_code == 200 and ("Joomla" in response.text and "Installation" in response.text):
                vuln_info = {
                    "type": "installation_directory",
                    "name": "Installation Directory Present",
                    "description": "دليل التثبيت لا يزال موجودًا، مما قد يسمح بإعادة تثبيت الموقع",
                    "severity": "high",
                    "url": install_url
                }
                self.results["joomla_vulnerabilities"].append(vuln_info)
                self.logger.warning("دليل التثبيت لا يزال موجودًا.")
                console.print("[red]دليل التثبيت لا يزال موجودًا.[/red]")
        except:
            pass
        
        # فحص ثغرات تعداد المستخدمين
        for i in range(1, 5):  # فحص أول 5 معرفات
            user_url = f"{self.base_url}/index.php?option=com_users&view=profile&id={i}"
            try:
                response = requests.get(user_url, timeout=self.timeout, verify=False)
                if response.status_code == 200 and "404" not in response.text and "not found" not in response.text.lower():
                    vuln_info = {
                        "type": "user_enumeration",
                        "name": "User Enumeration",
                        "description": "يمكن تعداد المستخدمين من خلال معلمة id في com_users",
                        "severity": "medium",
                        "url": user_url
                    }
                    self.results["joomla_vulnerabilities"].append(vuln_info)
                    self.logger.warning("يمكن تعداد المستخدمين من خلال معلمة id في com_users")
                    console.print("[yellow]يمكن تعداد المستخدمين من خلال معلمة id في com_users[/yellow]")
                    break
            except:
                pass
        
        # فحص ثغرات الإصدار القديم
        if self.results["joomla_info"]["version"] and self.results["joomla_info"]["version"].startswith("1.") or self.results["joomla_info"]["version"].startswith("2."):
            vuln_info = {
                "type": "outdated_version",
                "name": "Outdated Joomla Version",
                "description": f"إصدار جوملا {self.results['joomla_info']['version']} قديم وغير مدعوم، ويحتوي على العديد من الثغرات الأمنية",
                "severity": "critical",
                "version": self.results["joomla_info"]["version"]
            }
            self.results["joomla_vulnerabilities"].append(vuln_info)
            self.logger.critical(f"إصدار جوملا {self.results['joomla_info']['version']} قديم وغير مدعوم.")
            console.print(f"[bold red]إصدار جوملا {self.results['joomla_info']['version']} قديم وغير مدعوم.[/bold red]")
    
    def _is_version_vulnerable(self, current_version, vulnerable_version):
        """
        التحقق مما إذا كان الإصدار الحالي عرضة للثغرات
        
        المعطيات:
            current_version (str): الإصدار الحالي
            vulnerable_version (str): الإصدار المعرض للثغرات
            
        المخرجات:
            bool: True إذا كان الإصدار الحالي عرضة للثغرات، False خلاف ذلك
        """
        # تحويل الإصدارات إلى قوائم من الأرقام
        current_parts = [int(part) for part in current_version.split(".")]
        vulnerable_parts = [int(part) for part in vulnerable_version.split(".")]
        
        # إضافة أصفار إذا كانت القوائم غير متساوية في الطول
        while len(current_parts) < len(vulnerable_parts):
            current_parts.append(0)
        while len(vulnerable_parts) < len(current_parts):
            vulnerable_parts.append(0)
        
        # مقارنة الإصدارات
        for i in range(len(current_parts)):
            if current_parts[i] < vulnerable_parts[i]:
                return False
            elif current_parts[i] > vulnerable_parts[i]:
                return False
        
        # الإصدارات متطابقة
        return True