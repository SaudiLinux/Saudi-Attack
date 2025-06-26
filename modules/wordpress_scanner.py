#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
وحدة ماسح ووردبريس لأداة SaudiAttack
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

class WordPressScanner(WebServerScanner):
    """
    فئة ماسح ووردبريس
    """
    
    def __init__(self, target, ports=[80, 443], threads=5, timeout=30, logger=None):
        """
        تهيئة ماسح ووردبريس
        
        المعطيات:
            target (str): الهدف (عنوان IP أو اسم النطاق)
            ports (list): قائمة المنافذ للفحص (افتراضيًا: 80, 443)
            threads (int): عدد مسارات التنفيذ المتوازية
            timeout (int): مهلة الاتصال بالثواني
            logger (Logger): كائن المسجل
        """
        super().__init__(target, ports, threads, timeout, logger)
        
        # إضافة معلومات خاصة بووردبريس إلى النتائج
        self.results["wordpress_info"] = {
            "version": "",
            "themes": [],
            "plugins": [],
            "users": [],
            "is_multisite": False
        }
        self.results["wordpress_vulnerabilities"] = []
        
        # قائمة الثغرات المعروفة في ووردبريس
        self.known_vulnerabilities = self._load_known_vulnerabilities()
    
    def scan(self):
        """
        تنفيذ مسح ووردبريس
        
        المخرجات:
            dict: نتائج المسح
        """
        self.logger.info(f"بدء مسح ووردبريس على الهدف: {self.target}")
        console.print(f"[bold]بدء مسح ووردبريس على الهدف: {self.target}[/bold]")
        
        # تنفيذ المسح الأساسي لخادم الويب أولاً
        super().scan()
        
        # التحقق مما إذا كان الموقع يستخدم ووردبريس
        if not self._is_wordpress():
            self.logger.warning(f"الهدف {self.target} لا يبدو أنه يستخدم ووردبريس.")
            console.print(f"[bold yellow]الهدف {self.target} لا يبدو أنه يستخدم ووردبريس.[/bold yellow]")
            return self.results
        
        # تحديد عنوان URL الأساسي
        self.base_url = self._get_wordpress_base_url()
        if not self.base_url:
            self.logger.error("لم يتم العثور على عنوان URL أساسي صالح لووردبريس.")
            console.print("[bold red]لم يتم العثور على عنوان URL أساسي صالح لووردبريس.[/bold red]")
            return self.results
        
        self.logger.info(f"تم اكتشاف موقع ووردبريس على: {self.base_url}")
        console.print(f"[bold green]تم اكتشاف موقع ووردبريس على: {self.base_url}[/bold green]")
        
        # جمع معلومات ووردبريس
        self._gather_wordpress_info()
        
        # فحص الثغرات الأمنية في ووردبريس
        self._scan_wordpress_vulnerabilities()
        
        self.logger.info(f"اكتمل مسح ووردبريس على الهدف: {self.target}")
        console.print(f"[bold green]اكتمل مسح ووردبريس على الهدف: {self.target}[/bold green]")
        
        return self.results
    
    def _load_known_vulnerabilities(self):
        """
        تحميل قاعدة بيانات الثغرات المعروفة في ووردبريس
        
        المخرجات:
            dict: قاعدة بيانات الثغرات المعروفة
        """
        # هذه مجرد قاعدة بيانات بسيطة للثغرات المعروفة
        # في التطبيق الحقيقي، يمكن تحميلها من ملف أو API
        return {
            "core": {
                "5.8.0": [
                    {
                        "name": "CVE-2021-44223",
                        "description": "ثغرة XSS في محرر المحتوى",
                        "severity": "medium",
                        "fixed_in": "5.8.1"
                    }
                ],
                "5.7.0": [
                    {
                        "name": "CVE-2021-29447",
                        "description": "ثغرة XXE في معالج الوسائط",
                        "severity": "high",
                        "fixed_in": "5.7.1"
                    }
                ],
                "5.6.0": [
                    {
                        "name": "CVE-2021-29450",
                        "description": "ثغرة CSRF في واجهة المستخدم الإدارية",
                        "severity": "medium",
                        "fixed_in": "5.6.2"
                    }
                ],
                "5.4.0": [
                    {
                        "name": "CVE-2020-35489",
                        "description": "ثغرة SQL Injection في استعلامات قاعدة البيانات",
                        "severity": "high",
                        "fixed_in": "5.4.2"
                    }
                ],
                "4.9.0": [
                    {
                        "name": "CVE-2020-11027",
                        "description": "ثغرة XSS في لوحة التحكم",
                        "severity": "medium",
                        "fixed_in": "4.9.16"
                    }
                ],
                "4.7.0": [
                    {
                        "name": "CVE-2017-6514",
                        "description": "ثغرة في واجهة REST API تسمح بالوصول غير المصرح به",
                        "severity": "high",
                        "fixed_in": "4.7.2"
                    }
                ]
            },
            "plugins": {
                "contact-form-7": {
                    "5.4.0": [
                        {
                            "name": "CVE-2020-35489",
                            "description": "ثغرة XSS في نماذج الاتصال",
                            "severity": "medium",
                            "fixed_in": "5.4.2"
                        }
                    ]
                },
                "woocommerce": {
                    "5.5.0": [
                        {
                            "name": "CVE-2021-32052",
                            "description": "ثغرة SQL Injection في معالجة الطلبات",
                            "severity": "high",
                            "fixed_in": "5.5.1"
                        }
                    ]
                },
                "yoast-seo": {
                    "16.0.0": [
                        {
                            "name": "CVE-2021-25118",
                            "description": "ثغرة XSS في محرر العلامات الوصفية",
                            "severity": "medium",
                            "fixed_in": "16.0.2"
                        }
                    ]
                },
                "elementor": {
                    "3.1.0": [
                        {
                            "name": "CVE-2021-24175",
                            "description": "ثغرة في إدارة الصلاحيات تسمح بتصعيد الامتيازات",
                            "severity": "high",
                            "fixed_in": "3.1.4"
                        }
                    ]
                },
                "wp-super-cache": {
                    "1.7.0": [
                        {
                            "name": "CVE-2021-24340",
                            "description": "ثغرة في معالجة ملفات التخزين المؤقت",
                            "severity": "medium",
                            "fixed_in": "1.7.2"
                        }
                    ]
                }
            },
            "themes": {
                "twentytwenty": {
                    "1.5": [
                        {
                            "name": "CVE-2021-24499",
                            "description": "ثغرة XSS في معالجة التعليقات",
                            "severity": "low",
                            "fixed_in": "1.6"
                        }
                    ]
                },
                "astra": {
                    "2.5.0": [
                        {
                            "name": "CVE-2020-35848",
                            "description": "ثغرة في معالجة الإعدادات",
                            "severity": "medium",
                            "fixed_in": "2.5.2"
                        }
                    ]
                }
            }
        }
    
    def _is_wordpress(self):
        """
        التحقق مما إذا كان الموقع يستخدم ووردبريس
        
        المخرجات:
            bool: True إذا كان الموقع يستخدم ووردبريس، False خلاف ذلك
        """
        # التحقق من التقنيات المكتشفة
        if "WordPress" in self.results["web_info"]["technologies"]:
            return True
        
        # التحقق من الروابط
        wp_patterns = [
            r"wp-content",
            r"wp-includes",
            r"wp-admin",
            r"wp-login",
            r"wp-json"
        ]
        
        for link in self.results["web_info"]["links"]:
            for pattern in wp_patterns:
                if re.search(pattern, link, re.IGNORECASE):
                    return True
        
        # التحقق من ترويسات HTTP
        for url, headers in self.results["web_info"]["headers"].items():
            if "X-Powered-By" in headers and "WordPress" in headers["X-Powered-By"]:
                return True
        
        # التحقق من محتوى HTML
        for url in self.results["web_info"]["headers"].keys():
            try:
                response = requests.get(url, timeout=self.timeout, verify=False)
                if "wp-content" in response.text or "wp-includes" in response.text:
                    return True
                
                # التحقق من العلامات الوصفية
                soup = BeautifulSoup(response.text, "html.parser")
                meta_generator = soup.find("meta", {"name": "generator"})
                if meta_generator and "WordPress" in meta_generator.get("content", ""):
                    return True
                
                # التحقق من وجود ملف feed
                if "<link rel=\"alternate\" type=\"application/rss+xml\"" in response.text:
                    return True
            except:
                pass
        
        return False
    
    def _get_wordpress_base_url(self):
        """
        الحصول على عنوان URL الأساسي لموقع ووردبريس
        
        المخرجات:
            str: عنوان URL الأساسي
        """
        # البحث عن روابط تحتوي على wp-content أو wp-includes
        for link in self.results["web_info"]["links"]:
            if "wp-content" in link or "wp-includes" in link:
                parsed_url = urlparse(link)
                return f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        # إذا لم يتم العثور على روابط، استخدام أول عنوان URL تم فحصه
        for url in self.results["web_info"]["headers"].keys():
            parsed_url = urlparse(url)
            return f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        # إذا لم يتم العثور على أي عنوان URL، استخدام الهدف مع بروتوكول HTTP
        return f"http://{self.target}"
    
    def _gather_wordpress_info(self):
        """
        جمع معلومات ووردبريس
        """
        self.logger.info(f"جمع معلومات ووردبريس من: {self.base_url}")
        console.print(f"[bold]جمع معلومات ووردبريس من: {self.base_url}[/bold]")
        
        try:
            # الحصول على إصدار ووردبريس
            self._get_wordpress_version()
            
            # الحصول على القوالب المثبتة
            self._get_wordpress_themes()
            
            # الحصول على الإضافات المثبتة
            self._get_wordpress_plugins()
            
            # الحصول على المستخدمين
            self._get_wordpress_users()
            
            # التحقق مما إذا كان الموقع متعدد المواقع
            self._check_multisite()
            
            self.logger.info("اكتمل جمع معلومات ووردبريس.")
            console.print("[bold]اكتمل جمع معلومات ووردبريس.[/bold]")
            
        except Exception as e:
            self.logger.error(f"خطأ أثناء جمع معلومات ووردبريس: {str(e)}")
            console.print(f"[bold red]خطأ أثناء جمع معلومات ووردبريس: {str(e)}[/bold red]")
    
    def _get_wordpress_version(self):
        """
        الحصول على إصدار ووردبريس
        """
        try:
            # طريقة 1: من ملف readme.html
            response = requests.get(f"{self.base_url}/readme.html", timeout=self.timeout, verify=False)
            if response.status_code == 200:
                version_match = re.search(r"Version\s+([\d.]+)", response.text)
                if version_match:
                    self.results["wordpress_info"]["version"] = version_match.group(1)
                    self.logger.info(f"إصدار ووردبريس: {self.results['wordpress_info']['version']}")
                    console.print(f"[green]إصدار ووردبريس: {self.results['wordpress_info']['version']}[/green]")
                    return
            
            # طريقة 2: من ملف feed
            response = requests.get(f"{self.base_url}/feed/", timeout=self.timeout, verify=False)
            if response.status_code == 200:
                version_match = re.search(r'generator="WordPress\s+([\d.]+)"', response.text)
                if version_match:
                    self.results["wordpress_info"]["version"] = version_match.group(1)
                    self.logger.info(f"إصدار ووردبريس: {self.results['wordpress_info']['version']}")
                    console.print(f"[green]إصدار ووردبريس: {self.results['wordpress_info']['version']}[/green]")
                    return
            
            # طريقة 3: من الصفحة الرئيسية
            response = requests.get(self.base_url, timeout=self.timeout, verify=False)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, "html.parser")
                meta_generator = soup.find("meta", {"name": "generator"})
                if meta_generator and "WordPress" in meta_generator.get("content", ""):
                    version_match = re.search(r"WordPress\s+([\d.]+)", meta_generator.get("content", ""))
                    if version_match:
                        self.results["wordpress_info"]["version"] = version_match.group(1)
                        self.logger.info(f"إصدار ووردبريس: {self.results['wordpress_info']['version']}")
                        console.print(f"[green]إصدار ووردبريس: {self.results['wordpress_info']['version']}[/green]")
                        return
            
            self.logger.warning("لم يتم العثور على إصدار ووردبريس.")
            console.print("[yellow]لم يتم العثور على إصدار ووردبريس.[/yellow]")
            
        except Exception as e:
            self.logger.error(f"خطأ أثناء الحصول على إصدار ووردبريس: {str(e)}")
            console.print(f"[bold red]خطأ أثناء الحصول على إصدار ووردبريس: {str(e)}[/bold red]")
    
    def _get_wordpress_themes(self):
        """
        الحصول على القوالب المثبتة
        """
        try:
            # البحث عن روابط القوالب في الصفحة الرئيسية
            response = requests.get(self.base_url, timeout=self.timeout, verify=False)
            if response.status_code == 200:
                # البحث عن روابط القوالب
                theme_pattern = r"wp-content/themes/([^/]+)/"
                theme_matches = re.findall(theme_pattern, response.text)
                
                for theme_name in set(theme_matches):
                    # محاولة الحصول على إصدار القالب من ملف style.css
                    theme_url = f"{self.base_url}/wp-content/themes/{theme_name}/style.css"
                    try:
                        theme_response = requests.get(theme_url, timeout=self.timeout, verify=False)
                        if theme_response.status_code == 200:
                            version_match = re.search(r"Version:\s*([\d.]+)", theme_response.text)
                            version = version_match.group(1) if version_match else "غير معروف"
                            
                            theme_info = {
                                "name": theme_name,
                                "version": version,
                                "url": f"{self.base_url}/wp-content/themes/{theme_name}/"
                            }
                            
                            if theme_info not in self.results["wordpress_info"]["themes"]:
                                self.results["wordpress_info"]["themes"].append(theme_info)
                                self.logger.info(f"تم اكتشاف قالب: {theme_name} (الإصدار: {version})")
                                console.print(f"[green]تم اكتشاف قالب: {theme_name} (الإصدار: {version})[/green]")
                    except:
                        pass
            
            if not self.results["wordpress_info"]["themes"]:
                self.logger.warning("لم يتم العثور على قوالب ووردبريس.")
                console.print("[yellow]لم يتم العثور على قوالب ووردبريس.[/yellow]")
            
        except Exception as e:
            self.logger.error(f"خطأ أثناء الحصول على قوالب ووردبريس: {str(e)}")
            console.print(f"[bold red]خطأ أثناء الحصول على قوالب ووردبريس: {str(e)}[/bold red]")
    
    def _get_wordpress_plugins(self):
        """
        الحصول على الإضافات المثبتة
        """
        try:
            # البحث عن روابط الإضافات في الصفحة الرئيسية
            response = requests.get(self.base_url, timeout=self.timeout, verify=False)
            if response.status_code == 200:
                # البحث عن روابط الإضافات
                plugin_pattern = r"wp-content/plugins/([^/]+)/"
                plugin_matches = re.findall(plugin_pattern, response.text)
                
                for plugin_name in set(plugin_matches):
                    # محاولة الحصول على إصدار الإضافة من ملف readme.txt
                    plugin_url = f"{self.base_url}/wp-content/plugins/{plugin_name}/readme.txt"
                    try:
                        plugin_response = requests.get(plugin_url, timeout=self.timeout, verify=False)
                        if plugin_response.status_code == 200:
                            version_match = re.search(r"Stable tag:\s*([\d.]+)", plugin_response.text)
                            version = version_match.group(1) if version_match else "غير معروف"
                            
                            plugin_info = {
                                "name": plugin_name,
                                "version": version,
                                "url": f"{self.base_url}/wp-content/plugins/{plugin_name}/"
                            }
                            
                            if plugin_info not in self.results["wordpress_info"]["plugins"]:
                                self.results["wordpress_info"]["plugins"].append(plugin_info)
                                self.logger.info(f"تم اكتشاف إضافة: {plugin_name} (الإصدار: {version})")
                                console.print(f"[green]تم اكتشاف إضافة: {plugin_name} (الإصدار: {version})[/green]")
                    except:
                        # إذا لم يتم العثور على ملف readme.txt، إضافة الإضافة بدون إصدار
                        plugin_info = {
                            "name": plugin_name,
                            "version": "غير معروف",
                            "url": f"{self.base_url}/wp-content/plugins/{plugin_name}/"
                        }
                        
                        if plugin_info not in self.results["wordpress_info"]["plugins"]:
                            self.results["wordpress_info"]["plugins"].append(plugin_info)
                            self.logger.info(f"تم اكتشاف إضافة: {plugin_name} (الإصدار: غير معروف)")
                            console.print(f"[green]تم اكتشاف إضافة: {plugin_name} (الإصدار: غير معروف)[/green]")
            
            if not self.results["wordpress_info"]["plugins"]:
                self.logger.warning("لم يتم العثور على إضافات ووردبريس.")
                console.print("[yellow]لم يتم العثور على إضافات ووردبريس.[/yellow]")
            
        except Exception as e:
            self.logger.error(f"خطأ أثناء الحصول على إضافات ووردبريس: {str(e)}")
            console.print(f"[bold red]خطأ أثناء الحصول على إضافات ووردبريس: {str(e)}[/bold red]")
    
    def _get_wordpress_users(self):
        """
        الحصول على المستخدمين
        """
        try:
            # طريقة 1: من خلال REST API
            api_url = f"{self.base_url}/wp-json/wp/v2/users"
            response = requests.get(api_url, timeout=self.timeout, verify=False)
            if response.status_code == 200:
                users_data = response.json()
                for user in users_data:
                    user_info = {
                        "id": user.get("id"),
                        "name": user.get("name"),
                        "slug": user.get("slug"),
                        "url": user.get("link")
                    }
                    self.results["wordpress_info"]["users"].append(user_info)
                    self.logger.info(f"تم اكتشاف مستخدم: {user_info['name']} (المعرف: {user_info['id']})")
                    console.print(f"[green]تم اكتشاف مستخدم: {user_info['name']} (المعرف: {user_info['id']})[/green]")
                return
            
            # طريقة 2: من خلال ?author=1
            for i in range(1, 10):  # فحص أول 10 معرفات
                author_url = f"{self.base_url}/?author={i}"
                response = requests.get(author_url, timeout=self.timeout, verify=False, allow_redirects=True)
                if response.status_code == 200:
                    # التحقق من إعادة التوجيه إلى صفحة المؤلف
                    if "/author/" in response.url:
                        author_name = response.url.split("/author/")[1].strip("/")
                        user_info = {
                            "id": i,
                            "name": author_name,
                            "slug": author_name,
                            "url": response.url
                        }
                        self.results["wordpress_info"]["users"].append(user_info)
                        self.logger.info(f"تم اكتشاف مستخدم: {user_info['name']} (المعرف: {user_info['id']})")
                        console.print(f"[green]تم اكتشاف مستخدم: {user_info['name']} (المعرف: {user_info['id']})[/green]")
            
            if not self.results["wordpress_info"]["users"]:
                self.logger.warning("لم يتم العثور على مستخدمي ووردبريس.")
                console.print("[yellow]لم يتم العثور على مستخدمي ووردبريس.[/yellow]")
            
        except Exception as e:
            self.logger.error(f"خطأ أثناء الحصول على مستخدمي ووردبريس: {str(e)}")
            console.print(f"[bold red]خطأ أثناء الحصول على مستخدمي ووردبريس: {str(e)}[/bold red]")
    
    def _check_multisite(self):
        """
        التحقق مما إذا كان الموقع متعدد المواقع
        """
        try:
            # التحقق من وجود مسار /wp-admin/network/
            network_url = f"{self.base_url}/wp-admin/network/"
            response = requests.get(network_url, timeout=self.timeout, verify=False, allow_redirects=False)
            if response.status_code == 302 and "wp-login.php" in response.headers.get("Location", ""):
                self.results["wordpress_info"]["is_multisite"] = True
                self.logger.info("الموقع هو موقع ووردبريس متعدد المواقع.")
                console.print("[green]الموقع هو موقع ووردبريس متعدد المواقع.[/green]")
                return
            
            # التحقق من وجود مسار /wp-signup.php
            signup_url = f"{self.base_url}/wp-signup.php"
            response = requests.get(signup_url, timeout=self.timeout, verify=False)
            if response.status_code == 200 and "Multisite Network" in response.text:
                self.results["wordpress_info"]["is_multisite"] = True
                self.logger.info("الموقع هو موقع ووردبريس متعدد المواقع.")
                console.print("[green]الموقع هو موقع ووردبريس متعدد المواقع.[/green]")
                return
            
            self.results["wordpress_info"]["is_multisite"] = False
            self.logger.info("الموقع ليس موقع ووردبريس متعدد المواقع.")
            console.print("[blue]الموقع ليس موقع ووردبريس متعدد المواقع.[/blue]")
            
        except Exception as e:
            self.logger.error(f"خطأ أثناء التحقق من تعدد المواقع: {str(e)}")
            console.print(f"[bold red]خطأ أثناء التحقق من تعدد المواقع: {str(e)}[/bold red]")
    
    def _scan_wordpress_vulnerabilities(self):
        """
        فحص الثغرات الأمنية في ووردبريس
        """
        self.logger.info("بدء فحص الثغرات الأمنية في ووردبريس.")
        console.print("[bold]بدء فحص الثغرات الأمنية في ووردبريس.[/bold]")
        
        try:
            # فحص ثغرات النواة
            self._check_core_vulnerabilities()
            
            # فحص ثغرات الإضافات
            self._check_plugin_vulnerabilities()
            
            # فحص ثغرات القوالب
            self._check_theme_vulnerabilities()
            
            # فحص ثغرات أخرى
            self._check_other_vulnerabilities()
            
            self.logger.info(f"اكتمل فحص الثغرات الأمنية في ووردبريس. تم العثور على {len(self.results['wordpress_vulnerabilities'])} ثغرة.")
            console.print(f"[bold]اكتمل فحص الثغرات الأمنية في ووردبريس. تم العثور على {len(self.results['wordpress_vulnerabilities'])} ثغرة.[/bold]")
            
        except Exception as e:
            self.logger.error(f"خطأ أثناء فحص الثغرات الأمنية في ووردبريس: {str(e)}")
            console.print(f"[bold red]خطأ أثناء فحص الثغرات الأمنية في ووردبريس: {str(e)}[/bold red]")
    
    def _check_core_vulnerabilities(self):
        """
        فحص ثغرات نواة ووردبريس
        """
        if not self.results["wordpress_info"]["version"]:
            self.logger.warning("لا يمكن فحص ثغرات النواة: الإصدار غير معروف.")
            console.print("[yellow]لا يمكن فحص ثغرات النواة: الإصدار غير معروف.[/yellow]")
            return
        
        version = self.results["wordpress_info"]["version"]
        
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
                    self.results["wordpress_vulnerabilities"].append(vuln_info)
                    self.logger.warning(f"تم اكتشاف ثغرة في نواة ووردبريس: {vuln['name']} (خطورة: {vuln['severity']})")
                    console.print(f"[{get_severity_color(vuln['severity'])}]تم اكتشاف ثغرة في نواة ووردبريس: {vuln['name']} (خطورة: {vuln['severity']})[/{get_severity_color(vuln['severity'])}]")
        
        # فحص ملفات حساسة
        sensitive_files = [
            "/wp-config.php",
            "/wp-config-sample.php",
            "/wp-content/debug.log",
            "/.wp-config.php.swp",
            "/wp-content/uploads/wp-config.php"
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
                    self.results["wordpress_vulnerabilities"].append(vuln_info)
                    self.logger.warning(f"تم العثور على ملف حساس: {file_url}")
                    console.print(f"[red]تم العثور على ملف حساس: {file_url}[/red]")
            except:
                pass
    
    def _check_plugin_vulnerabilities(self):
        """
        فحص ثغرات إضافات ووردبريس
        """
        if not self.results["wordpress_info"]["plugins"]:
            self.logger.warning("لا يمكن فحص ثغرات الإضافات: لم يتم العثور على إضافات.")
            console.print("[yellow]لا يمكن فحص ثغرات الإضافات: لم يتم العثور على إضافات.[/yellow]")
            return
        
        for plugin in self.results["wordpress_info"]["plugins"]:
            plugin_name = plugin["name"]
            plugin_version = plugin["version"]
            
            # التحقق مما إذا كانت الإضافة معروفة في قاعدة البيانات
            if plugin_name in self.known_vulnerabilities["plugins"]:
                # البحث عن الثغرات المعروفة للإصدار الحالي أو الإصدارات السابقة
                for ver, vulns in self.known_vulnerabilities["plugins"][plugin_name].items():
                    if plugin_version == "غير معروف" or self._is_version_vulnerable(plugin_version, ver):
                        for vuln in vulns:
                            vuln_info = {
                                "type": "plugin",
                                "name": vuln["name"],
                                "description": vuln["description"],
                                "severity": vuln["severity"],
                                "plugin": plugin_name,
                                "plugin_version": plugin_version,
                                "affected_version": ver,
                                "fixed_in": vuln["fixed_in"]
                            }
                            self.results["wordpress_vulnerabilities"].append(vuln_info)
                            self.logger.warning(f"تم اكتشاف ثغرة في إضافة {plugin_name}: {vuln['name']} (خطورة: {vuln['severity']})")
                            console.print(f"[{get_severity_color(vuln['severity'])}]تم اكتشاف ثغرة في إضافة {plugin_name}: {vuln['name']} (خطورة: {vuln['severity']})[/{get_severity_color(vuln['severity'])}]")
            
            # فحص ملفات حساسة للإضافة
            sensitive_files = [
                f"/wp-content/plugins/{plugin_name}/README.txt",
                f"/wp-content/plugins/{plugin_name}/readme.txt",
                f"/wp-content/plugins/{plugin_name}/changelog.txt",
                f"/wp-content/plugins/{plugin_name}/CHANGELOG.txt"
            ]
            
            for file in sensitive_files:
                file_url = f"{self.base_url}{file}"
                try:
                    response = requests.get(file_url, timeout=self.timeout, verify=False)
                    if response.status_code == 200:
                        vuln_info = {
                            "type": "information_disclosure",
                            "name": "Plugin Information Disclosure",
                            "description": f"تم العثور على ملف معلومات للإضافة {plugin_name}: {file_url}",
                            "severity": "low",
                            "plugin": plugin_name,
                            "url": file_url
                        }
                        self.results["wordpress_vulnerabilities"].append(vuln_info)
                        self.logger.info(f"تم العثور على ملف معلومات للإضافة {plugin_name}: {file_url}")
                        console.print(f"[green]تم العثور على ملف معلومات للإضافة {plugin_name}: {file_url}[/green]")
                except:
                    pass
    
    def _check_theme_vulnerabilities(self):
        """
        فحص ثغرات قوالب ووردبريس
        """
        if not self.results["wordpress_info"]["themes"]:
            self.logger.warning("لا يمكن فحص ثغرات القوالب: لم يتم العثور على قوالب.")
            console.print("[yellow]لا يمكن فحص ثغرات القوالب: لم يتم العثور على قوالب.[/yellow]")
            return
        
        for theme in self.results["wordpress_info"]["themes"]:
            theme_name = theme["name"]
            theme_version = theme["version"]
            
            # التحقق مما إذا كان القالب معروفًا في قاعدة البيانات
            if theme_name in self.known_vulnerabilities["themes"]:
                # البحث عن الثغرات المعروفة للإصدار الحالي أو الإصدارات السابقة
                for ver, vulns in self.known_vulnerabilities["themes"][theme_name].items():
                    if theme_version == "غير معروف" or self._is_version_vulnerable(theme_version, ver):
                        for vuln in vulns:
                            vuln_info = {
                                "type": "theme",
                                "name": vuln["name"],
                                "description": vuln["description"],
                                "severity": vuln["severity"],
                                "theme": theme_name,
                                "theme_version": theme_version,
                                "affected_version": ver,
                                "fixed_in": vuln["fixed_in"]
                            }
                            self.results["wordpress_vulnerabilities"].append(vuln_info)
                            self.logger.warning(f"تم اكتشاف ثغرة في قالب {theme_name}: {vuln['name']} (خطورة: {vuln['severity']})")
                            console.print(f"[{get_severity_color(vuln['severity'])}]تم اكتشاف ثغرة في قالب {theme_name}: {vuln['name']} (خطورة: {vuln['severity']})[/{get_severity_color(vuln['severity'])}]")
            
            # فحص ملفات حساسة للقالب
            sensitive_files = [
                f"/wp-content/themes/{theme_name}/README.txt",
                f"/wp-content/themes/{theme_name}/readme.txt",
                f"/wp-content/themes/{theme_name}/changelog.txt",
                f"/wp-content/themes/{theme_name}/CHANGELOG.txt",
                f"/wp-content/themes/{theme_name}/screenshot.png"
            ]
            
            for file in sensitive_files:
                file_url = f"{self.base_url}{file}"
                try:
                    response = requests.get(file_url, timeout=self.timeout, verify=False)
                    if response.status_code == 200:
                        vuln_info = {
                            "type": "information_disclosure",
                            "name": "Theme Information Disclosure",
                            "description": f"تم العثور على ملف معلومات للقالب {theme_name}: {file_url}",
                            "severity": "low",
                            "theme": theme_name,
                            "url": file_url
                        }
                        self.results["wordpress_vulnerabilities"].append(vuln_info)
                        self.logger.info(f"تم العثور على ملف معلومات للقالب {theme_name}: {file_url}")
                        console.print(f"[green]تم العثور على ملف معلومات للقالب {theme_name}: {file_url}[/green]")
                except:
                    pass
    
    def _check_other_vulnerabilities(self):
        """
        فحص ثغرات أخرى في ووردبريس
        """
        # فحص XML-RPC
        xmlrpc_url = f"{self.base_url}/xmlrpc.php"
        try:
            response = requests.post(xmlrpc_url, data="", timeout=self.timeout, verify=False)
            if response.status_code == 200 and "XML-RPC server accepts POST requests only." in response.text:
                vuln_info = {
                    "type": "xmlrpc",
                    "name": "XML-RPC Enabled",
                    "description": "واجهة XML-RPC مفعلة، مما قد يسمح بهجمات القوة الغاشمة وهجمات DDoS",
                    "severity": "medium",
                    "url": xmlrpc_url
                }
                self.results["wordpress_vulnerabilities"].append(vuln_info)
                self.logger.warning("واجهة XML-RPC مفعلة.")
                console.print("[yellow]واجهة XML-RPC مفعلة.[/yellow]")
                
                # اختبار هجوم pingback
                pingback_data = """<?xml version="1.0" encoding="iso-8859-1"?>
                <methodCall>
                <methodName>pingback.ping</methodName>
                <params>
                <param><value><string>http://example.com/</string></value></param>
                <param><value><string>{}</string></value></param>
                </params>
                </methodCall>""".format(self.base_url)
                
                response = requests.post(xmlrpc_url, data=pingback_data, timeout=self.timeout, verify=False)
                if response.status_code == 200 and ("<fault>" not in response.text or "pingback error" in response.text.lower()):
                    vuln_info = {
                        "type": "xmlrpc_pingback",
                        "name": "XML-RPC Pingback Vulnerability",
                        "description": "واجهة XML-RPC تسمح بهجمات pingback، مما قد يسمح بهجمات DDoS وفحص الشبكة الداخلية",
                        "severity": "high",
                        "url": xmlrpc_url
                    }
                    self.results["wordpress_vulnerabilities"].append(vuln_info)
                    self.logger.warning("ثغرة pingback في XML-RPC.")
                    console.print("[red]ثغرة pingback في XML-RPC.[/red]")
        except:
            pass
        
        # فحص REST API
        rest_api_url = f"{self.base_url}/wp-json/"
        try:
            response = requests.get(rest_api_url, timeout=self.timeout, verify=False)
            if response.status_code == 200:
                vuln_info = {
                    "type": "rest_api",
                    "name": "REST API Enabled",
                    "description": "واجهة REST API مفعلة، تحقق من إعدادات الأمان",
                    "severity": "low",
                    "url": rest_api_url
                }
                self.results["wordpress_vulnerabilities"].append(vuln_info)
                self.logger.info("واجهة REST API مفعلة.")
                console.print("[green]واجهة REST API مفعلة.[/green]")
                
                # التحقق من إمكانية الوصول إلى المستخدمين
                users_api_url = f"{self.base_url}/wp-json/wp/v2/users"
                response = requests.get(users_api_url, timeout=self.timeout, verify=False)
                if response.status_code == 200:
                    vuln_info = {
                        "type": "rest_api_users",
                        "name": "REST API Users Enumeration",
                        "description": "يمكن استخدام REST API لاستخراج معلومات المستخدمين",
                        "severity": "medium",
                        "url": users_api_url
                    }
                    self.results["wordpress_vulnerabilities"].append(vuln_info)
                    self.logger.warning("يمكن استخدام REST API لاستخراج معلومات المستخدمين.")
                    console.print("[yellow]يمكن استخدام REST API لاستخراج معلومات المستخدمين.[/yellow]")
        except:
            pass
        
        # فحص تعداد المستخدمين
        for i in range(1, 5):  # فحص أول 5 معرفات
            author_url = f"{self.base_url}/?author={i}"
            try:
                response = requests.get(author_url, timeout=self.timeout, verify=False, allow_redirects=True)
                if response.status_code == 200 and "/author/" in response.url:
                    vuln_info = {
                        "type": "user_enumeration",
                        "name": "User Enumeration",
                        "description": "يمكن تعداد المستخدمين من خلال معلمة ?author=",
                        "severity": "medium",
                        "url": author_url
                    }
                    self.results["wordpress_vulnerabilities"].append(vuln_info)
                    self.logger.warning("يمكن تعداد المستخدمين من خلال معلمة ?author=")
                    console.print("[yellow]يمكن تعداد المستخدمين من خلال معلمة ?author=[/yellow]")
                    break
            except:
                pass
    
    def _is_version_vulnerable(self, current_version, vulnerable_version):
        """
        التحقق مما إذا كان الإصدار الحالي عرضة للثغرات
        
        المعطيات:
            current_version (str): الإصدار الحالي
            vulnerable_version (str): الإصدار المعرض للثغرات
            
        المخرجات:
            bool: True إذا كان الإصدار الحالي عرضة للثغرات، False خلاف ذلك
        """
        if current_version == "غير معروف":
            return True
        
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