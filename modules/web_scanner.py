#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
وحدة ماسح خادم الويب لأداة SaudiAttack
"""

import requests
import ssl
import socket
import json
import re
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
from rich.console import Console
from .scanner import VulnerabilityScanner
from .utils import get_severity_color

console = Console()

class WebServerScanner(VulnerabilityScanner):
    """
    فئة ماسح خادم الويب
    """
    
    def __init__(self, target, ports=[80, 443], threads=5, timeout=30, logger=None):
        """
        تهيئة ماسح خادم الويب
        
        المعطيات:
            target (str): الهدف (عنوان IP أو اسم النطاق)
            ports (list): قائمة المنافذ للفحص (افتراضيًا: 80, 443)
            threads (int): عدد مسارات التنفيذ المتوازية
            timeout (int): مهلة الاتصال بالثواني
            logger (Logger): كائن المسجل
        """
        super().__init__(target, ports, threads, timeout, logger)
        
        # إضافة معلومات خاصة بخادم الويب إلى النتائج
        self.results["web_info"] = {
            "server": "",
            "technologies": [],
            "headers": {},
            "cookies": [],
            "forms": [],
            "links": [],
            "security_headers": {}
        }
        self.results["web_vulnerabilities"] = []
    
    def scan(self):
        """
        تنفيذ مسح خادم الويب
        
        المخرجات:
            dict: نتائج المسح
        """
        self.logger.info(f"بدء مسح خادم الويب على الهدف: {self.target}")
        console.print(f"[bold]بدء مسح خادم الويب على الهدف: {self.target}[/bold]")
        
        # تنفيذ المسح الأساسي أولاً
        super().scan()
        
        # تحديد منافذ الويب المفتوحة
        web_ports = [port_info["port"] for port_info in self.results["open_ports"]
                    if port_info["service"] in ["http", "https"]]
        
        if not web_ports:
            self.logger.warning("لم يتم العثور على منافذ ويب مفتوحة.")
            console.print("[bold yellow]لم يتم العثور على منافذ ويب مفتوحة.[/bold yellow]")
            return self.results
        
        # مسح كل منفذ ويب مفتوح
        for port in web_ports:
            protocol = "https" if port == 443 else "http"
            url = f"{protocol}://{self.target}:{port}"
            
            self.logger.info(f"مسح خادم الويب على: {url}")
            console.print(f"[bold]مسح خادم الويب على: {url}[/bold]")
            
            # جمع معلومات خادم الويب
            self._gather_web_info(url)
            
            # فحص الثغرات الأمنية لخادم الويب
            self._scan_web_vulnerabilities(url)
        
        self.logger.info(f"اكتمل مسح خادم الويب على الهدف: {self.target}")
        console.print(f"[bold green]اكتمل مسح خادم الويب على الهدف: {self.target}[/bold green]")
        
        return self.results
    
    def _gather_web_info(self, url):
        """
        جمع معلومات خادم الويب
        
        المعطيات:
            url (str): عنوان URL للفحص
        """
        self.logger.info(f"جمع معلومات خادم الويب: {url}")
        console.print(f"[bold]جمع معلومات خادم الويب: {url}[/bold]")
        
        try:
            # إجراء طلب HTTP
            response = requests.get(url, timeout=self.timeout, verify=False, allow_redirects=True)
            
            # تحليل الاستجابة
            self._analyze_response(url, response)
            
            # تحليل محتوى الصفحة
            self._analyze_page_content(url, response)
            
            # فحص شهادة SSL (إذا كان HTTPS)
            if url.startswith("https"):
                self._check_ssl_certificate(url)
            
            self.logger.info(f"اكتمل جمع معلومات خادم الويب: {url}")
            console.print(f"[bold]اكتمل جمع معلومات خادم الويب: {url}[/bold]")
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"خطأ أثناء الاتصال بـ {url}: {str(e)}")
            console.print(f"[bold red]خطأ أثناء الاتصال بـ {url}: {str(e)}[/bold red]")
    
    def _analyze_response(self, url, response):
        """
        تحليل استجابة HTTP
        
        المعطيات:
            url (str): عنوان URL
            response (Response): كائن الاستجابة
        """
        # تحليل الترويسات
        headers = dict(response.headers)
        self.results["web_info"]["headers"][url] = headers
        
        # تحديد نوع خادم الويب
        if "Server" in headers:
            self.results["web_info"]["server"] = headers["Server"]
            self.logger.info(f"خادم الويب: {headers['Server']}")
            console.print(f"[green]خادم الويب: {headers['Server']}[/green]")
        
        # فحص ترويسات الأمان
        security_headers = {
            "Strict-Transport-Security": headers.get("Strict-Transport-Security", "غير موجود"),
            "Content-Security-Policy": headers.get("Content-Security-Policy", "غير موجود"),
            "X-Content-Type-Options": headers.get("X-Content-Type-Options", "غير موجود"),
            "X-Frame-Options": headers.get("X-Frame-Options", "غير موجود"),
            "X-XSS-Protection": headers.get("X-XSS-Protection", "غير موجود")
        }
        self.results["web_info"]["security_headers"][url] = security_headers
        
        # تحليل الكوكيز
        cookies = response.cookies
        for cookie in cookies:
            cookie_info = {
                "name": cookie.name,
                "value": cookie.value,
                "domain": cookie.domain,
                "path": cookie.path,
                "secure": cookie.secure,
                "httponly": "HttpOnly" in cookie._rest
            }
            self.results["web_info"]["cookies"].append(cookie_info)
    
    def _analyze_page_content(self, url, response):
        """
        تحليل محتوى الصفحة
        
        المعطيات:
            url (str): عنوان URL
            response (Response): كائن الاستجابة
        """
        try:
            # تحليل HTML
            soup = BeautifulSoup(response.text, "html.parser")
            
            # استخراج النماذج
            forms = soup.find_all("form")
            for form in forms:
                form_info = {
                    "action": form.get("action", ""),
                    "method": form.get("method", "get").upper(),
                    "inputs": []
                }
                
                # استخراج حقول الإدخال
                inputs = form.find_all(["input", "textarea", "select"])
                for input_field in inputs:
                    input_info = {
                        "name": input_field.get("name", ""),
                        "type": input_field.get("type", "text") if input_field.name == "input" else input_field.name,
                        "required": input_field.has_attr("required")
                    }
                    form_info["inputs"].append(input_info)
                
                self.results["web_info"]["forms"].append(form_info)
            
            # استخراج الروابط
            links = soup.find_all("a")
            for link in links:
                href = link.get("href")
                if href and not href.startswith("#") and not href.startswith("javascript:"):
                    # تحويل الروابط النسبية إلى مطلقة
                    if not href.startswith("http"):
                        parsed_url = urlparse(url)
                        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
                        if href.startswith("/"):
                            href = f"{base_url}{href}"
                        else:
                            href = f"{base_url}/{href}"
                    
                    if href not in self.results["web_info"]["links"]:
                        self.results["web_info"]["links"].append(href)
            
            # اكتشاف التقنيات المستخدمة
            self._detect_technologies(response.text, soup)
            
        except Exception as e:
            self.logger.error(f"خطأ أثناء تحليل محتوى الصفحة: {str(e)}")
            console.print(f"[bold red]خطأ أثناء تحليل محتوى الصفحة: {str(e)}[/bold red]")
    
    def _detect_technologies(self, html, soup):
        """
        اكتشاف التقنيات المستخدمة في الموقع
        
        المعطيات:
            html (str): محتوى HTML
            soup (BeautifulSoup): كائن BeautifulSoup
        """
        technologies = []
        
        # فحص إطار العمل/المكتبات الشائعة
        tech_patterns = {
            "jQuery": r"jquery[.-]\d+\.\d+\.\d+\.min\.js",
            "Bootstrap": r"bootstrap[.-]\d+\.\d+\.\d+\.min\.css",
            "React": r"react[.-]\d+\.\d+\.\d+\.min\.js",
            "Angular": r"angular[.-]\d+\.\d+\.\d+\.min\.js",
            "Vue.js": r"vue[.-]\d+\.\d+\.\d+\.min\.js",
            "Font Awesome": r"font-awesome[.-]\d+\.\d+\.\d+\.min\.css",
            "WordPress": r"wp-content|wp-includes",
            "Joomla": r"joomla",
            "Drupal": r"drupal",
            "Magento": r"magento",
            "Laravel": r"laravel",
            "Django": r"django",
            "ASP.NET": r"asp\.net"
        }
        
        for tech, pattern in tech_patterns.items():
            if re.search(pattern, html, re.IGNORECASE):
                technologies.append(tech)
        
        # فحص العلامات الوصفية
        meta_tags = soup.find_all("meta")
        for meta in meta_tags:
            if meta.get("name") == "generator" and meta.get("content"):
                generator = meta.get("content")
                technologies.append(f"Generator: {generator}")
        
        # فحص نصوص JavaScript
        scripts = soup.find_all("script")
        for script in scripts:
            src = script.get("src", "")
            if src:
                for tech, pattern in tech_patterns.items():
                    if re.search(pattern, src, re.IGNORECASE) and tech not in technologies:
                        technologies.append(tech)
        
        # إضافة التقنيات المكتشفة إلى النتائج
        for tech in technologies:
            if tech not in self.results["web_info"]["technologies"]:
                self.results["web_info"]["technologies"].append(tech)
                self.logger.info(f"تم اكتشاف تقنية: {tech}")
                console.print(f"[green]تم اكتشاف تقنية: {tech}[/green]")
    
    def _check_ssl_certificate(self, url):
        """
        فحص شهادة SSL
        
        المعطيات:
            url (str): عنوان URL
        """
        try:
            parsed_url = urlparse(url)
            hostname = parsed_url.netloc.split(":")[0]
            port = parsed_url.port or 443
            
            # إنشاء اتصال SSL
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # استخراج معلومات الشهادة
                    cert_info = {
                        "subject": dict(x[0] for x in cert["subject"]),
                        "issuer": dict(x[0] for x in cert["issuer"]),
                        "version": cert["version"],
                        "notBefore": cert["notBefore"],
                        "notAfter": cert["notAfter"],
                        "serialNumber": cert["serialNumber"]
                    }
                    
                    # إضافة معلومات الشهادة إلى النتائج
                    self.results["web_info"]["ssl_certificate"] = cert_info
                    
                    self.logger.info(f"تم فحص شهادة SSL: {hostname}")
                    console.print(f"[green]تم فحص شهادة SSL: {hostname}[/green]")
                    
                    # التحقق من صلاحية الشهادة
                    import datetime
                    not_after = ssl.cert_time_to_seconds(cert["notAfter"])
                    not_before = ssl.cert_time_to_seconds(cert["notBefore"])
                    now = datetime.datetime.now().timestamp()
                    
                    if now > not_after:
                        vuln_info = {
                            "type": "ssl",
                            "name": "Expired SSL Certificate",
                            "description": f"شهادة SSL منتهية الصلاحية: {cert['notAfter']}",
                            "severity": "high"
                        }
                        self.results["web_vulnerabilities"].append(vuln_info)
                        self.logger.warning(f"شهادة SSL منتهية الصلاحية: {cert['notAfter']}")
                        console.print(f"[bold red]شهادة SSL منتهية الصلاحية: {cert['notAfter']}[/bold red]")
                    
                    if now < not_before:
                        vuln_info = {
                            "type": "ssl",
                            "name": "Not Yet Valid SSL Certificate",
                            "description": f"شهادة SSL غير صالحة بعد: {cert['notBefore']}",
                            "severity": "high"
                        }
                        self.results["web_vulnerabilities"].append(vuln_info)
                        self.logger.warning(f"شهادة SSL غير صالحة بعد: {cert['notBefore']}")
                        console.print(f"[bold red]شهادة SSL غير صالحة بعد: {cert['notBefore']}[/bold red]")
        
        except ssl.SSLError as e:
            vuln_info = {
                "type": "ssl",
                "name": "SSL Certificate Error",
                "description": f"خطأ في شهادة SSL: {str(e)}",
                "severity": "high"
            }
            self.results["web_vulnerabilities"].append(vuln_info)
            self.logger.error(f"خطأ في شهادة SSL: {str(e)}")
            console.print(f"[bold red]خطأ في شهادة SSL: {str(e)}[/bold red]")
            
        except Exception as e:
            self.logger.error(f"خطأ أثناء فحص شهادة SSL: {str(e)}")
            console.print(f"[bold red]خطأ أثناء فحص شهادة SSL: {str(e)}[/bold red]")
    
    def _scan_web_vulnerabilities(self, url):
        """
        فحص الثغرات الأمنية لخادم الويب
        
        المعطيات:
            url (str): عنوان URL للفحص
        """
        self.logger.info(f"فحص الثغرات الأمنية لخادم الويب: {url}")
        console.print(f"[bold]فحص الثغرات الأمنية لخادم الويب: {url}[/bold]")
        
        try:
            # فحص ترويسات الأمان المفقودة
            self._check_missing_security_headers(url)
            
            # فحص ثغرات XSS البسيطة
            self._check_xss_vulnerabilities(url)
            
            # فحص ثغرات SQL Injection البسيطة
            self._check_sql_injection(url)
            
            # فحص ثغرات Directory Traversal
            self._check_directory_traversal(url)
            
            # فحص ثغرات Information Disclosure
            self._check_information_disclosure(url)
            
            self.logger.info(f"اكتمل فحص الثغرات الأمنية لخادم الويب: {url}")
            console.print(f"[bold]اكتمل فحص الثغرات الأمنية لخادم الويب: {url}[/bold]")
            
        except Exception as e:
            self.logger.error(f"خطأ أثناء فحص الثغرات الأمنية لخادم الويب: {str(e)}")
            console.print(f"[bold red]خطأ أثناء فحص الثغرات الأمنية لخادم الويب: {str(e)}[/bold red]")
    
    def _check_missing_security_headers(self, url):
        """
        فحص ترويسات الأمان المفقودة
        
        المعطيات:
            url (str): عنوان URL للفحص
        """
        if url not in self.results["web_info"]["security_headers"]:
            return
        
        security_headers = self.results["web_info"]["security_headers"][url]
        
        # قائمة ترويسات الأمان المهمة
        important_headers = {
            "Strict-Transport-Security": "يحمي من هجمات downgrade وإعادة التوجيه",
            "Content-Security-Policy": "يحمي من هجمات XSS وحقن البيانات",
            "X-Content-Type-Options": "يمنع تخمين MIME من المتصفح",
            "X-Frame-Options": "يحمي من هجمات Clickjacking",
            "X-XSS-Protection": "يوفر حماية إضافية ضد هجمات XSS"
        }
        
        for header, description in important_headers.items():
            if security_headers.get(header) == "غير موجود":
                vuln_info = {
                    "type": "header",
                    "name": f"Missing {header} Header",
                    "description": f"ترويسة الأمان {header} مفقودة. {description}",
                    "severity": "medium",
                    "url": url
                }
                self.results["web_vulnerabilities"].append(vuln_info)
                self.logger.warning(f"ترويسة الأمان {header} مفقودة على {url}")
                console.print(f"[yellow]ترويسة الأمان {header} مفقودة على {url}[/yellow]")
    
    def _check_xss_vulnerabilities(self, url):
        """
        فحص ثغرات XSS البسيطة
        
        المعطيات:
            url (str): عنوان URL للفحص
        """
        # فحص النماذج للثغرات المحتملة
        for form in self.results["web_info"]["forms"]:
            if form["method"] == "GET":
                # فحص حقول الإدخال للثغرات المحتملة
                for input_field in form["inputs"]:
                    if input_field["type"] in ["text", "search", "url", "email", "textarea"]:
                        vuln_info = {
                            "type": "xss",
                            "name": "Potential XSS Vulnerability",
                            "description": f"نموذج GET مع حقل إدخال '{input_field['name']}' قد يكون عرضة لهجمات XSS",
                            "severity": "medium",
                            "url": url,
                            "form": form
                        }
                        self.results["web_vulnerabilities"].append(vuln_info)
                        self.logger.warning(f"ثغرة XSS محتملة في نموذج على {url}")
                        console.print(f"[yellow]ثغرة XSS محتملة في نموذج على {url}[/yellow]")
                        break  # تسجيل ثغرة واحدة فقط لكل نموذج
    
    def _check_sql_injection(self, url):
        """
        فحص ثغرات SQL Injection البسيطة
        
        المعطيات:
            url (str): عنوان URL للفحص
        """
        # فحص النماذج للثغرات المحتملة
        for form in self.results["web_info"]["forms"]:
            # فحص حقول الإدخال للثغرات المحتملة
            for input_field in form["inputs"]:
                if input_field["type"] in ["text", "search", "hidden"] and input_field["name"].lower() in [
                    "id", "user_id", "userid", "product_id", "productid", "item_id", "itemid"
                ]:
                    vuln_info = {
                        "type": "sqli",
                        "name": "Potential SQL Injection Vulnerability",
                        "description": f"نموذج مع حقل إدخال '{input_field['name']}' قد يكون عرضة لهجمات SQL Injection",
                        "severity": "high",
                        "url": url,
                        "form": form
                    }
                    self.results["web_vulnerabilities"].append(vuln_info)
                    self.logger.warning(f"ثغرة SQL Injection محتملة في نموذج على {url}")
                    console.print(f"[red]ثغرة SQL Injection محتملة في نموذج على {url}[/red]")
                    break  # تسجيل ثغرة واحدة فقط لكل نموذج
    
    def _check_directory_traversal(self, url):
        """
        فحص ثغرات Directory Traversal
        
        المعطيات:
            url (str): عنوان URL للفحص
        """
        # فحص الروابط للثغرات المحتملة
        for link in self.results["web_info"]["links"]:
            parsed_link = urlparse(link)
            query = parsed_link.query
            
            # البحث عن معلمات قد تكون عرضة للثغرات
            if any(param in query for param in ["file=", "path=", "dir=", "directory=", "include="]):
                vuln_info = {
                    "type": "directory_traversal",
                    "name": "Potential Directory Traversal Vulnerability",
                    "description": f"رابط مع معلمات مشبوهة قد يكون عرضة لهجمات Directory Traversal: {link}",
                    "severity": "high",
                    "url": link
                }
                self.results["web_vulnerabilities"].append(vuln_info)
                self.logger.warning(f"ثغرة Directory Traversal محتملة في رابط: {link}")
                console.print(f"[red]ثغرة Directory Traversal محتملة في رابط: {link}[/red]")
    
    def _check_information_disclosure(self, url):
        """
        فحص ثغرات Information Disclosure
        
        المعطيات:
            url (str): عنوان URL للفحص
        """
        # قائمة المسارات الحساسة للفحص
        sensitive_paths = [
            "/robots.txt",
            "/.git/",
            "/.svn/",
            "/.env",
            "/config.php",
            "/wp-config.php",
            "/phpinfo.php",
            "/server-status",
            "/server-info",
            "/admin/",
            "/backup/",
            "/db/",
            "/logs/"
        ]
        
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        for path in sensitive_paths:
            test_url = f"{base_url}{path}"
            try:
                response = requests.get(test_url, timeout=self.timeout, verify=False, allow_redirects=False)
                
                # التحقق من الاستجابة
                if response.status_code == 200:
                    vuln_info = {
                        "type": "information_disclosure",
                        "name": "Information Disclosure",
                        "description": f"تم العثور على ملف/مسار حساس: {test_url}",
                        "severity": "medium",
                        "url": test_url
                    }
                    self.results["web_vulnerabilities"].append(vuln_info)
                    self.logger.warning(f"تم العثور على ملف/مسار حساس: {test_url}")
                    console.print(f"[yellow]تم العثور على ملف/مسار حساس: {test_url}[/yellow]")
            
            except requests.exceptions.RequestException:
                # تجاهل أخطاء الاتصال
                pass