#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
وحدة الماسح الأساسي لأداة SaudiAttack
"""

import nmap
import socket
import threading
import time
import json
import requests
from concurrent.futures import ThreadPoolExecutor
from rich.console import Console
from .utils import get_target_type, resolve_domain_to_ip, get_severity_color

console = Console()

class VulnerabilityScanner:
    """
    فئة الماسح الأساسي للثغرات الأمنية
    """
    
    def __init__(self, target, ports, threads=5, timeout=30, logger=None):
        """
        تهيئة الماسح
        
        المعطيات:
            target (str): الهدف (عنوان IP أو اسم النطاق)
            ports (list): قائمة المنافذ للفحص
            threads (int): عدد مسارات التنفيذ المتوازية
            timeout (int): مهلة الاتصال بالثواني
            logger (Logger): كائن المسجل
        """
        self.target = target
        self.ports = ports
        self.threads = threads
        self.timeout = timeout
        self.logger = logger
        self.target_type = get_target_type(target)
        self.nm = nmap.PortScanner()
        self.results = {
            "target_info": {},
            "open_ports": [],
            "services": [],
            "vulnerabilities": [],
            "os_info": {},
            "additional_info": {}
        }
        
        # تحويل النطاق إلى IP إذا لزم الأمر
        if self.target_type == "domain":
            self.ip = resolve_domain_to_ip(target)
            if not self.ip:
                raise ValueError(f"لا يمكن تحليل النطاق: {target}")
            self.results["target_info"]["domain"] = target
            self.results["target_info"]["ip"] = self.ip
        else:
            self.ip = target
            self.results["target_info"]["ip"] = self.ip
    
    def scan(self):
        """
        تنفيذ المسح الأساسي
        
        المخرجات:
            dict: نتائج المسح
        """
        self.logger.info(f"بدء المسح الأساسي على الهدف: {self.target}")
        console.print(f"[bold]بدء المسح الأساسي على الهدف: {self.target}[/bold]")
        
        # مسح المنافذ
        self._scan_ports()
        
        # مسح نظام التشغيل
        self._scan_os()
        
        # مسح الثغرات الأمنية
        self._scan_vulnerabilities()
        
        # جمع معلومات إضافية
        self._gather_additional_info()
        
        self.logger.info(f"اكتمل المسح الأساسي على الهدف: {self.target}")
        console.print(f"[bold green]اكتمل المسح الأساسي على الهدف: {self.target}[/bold green]")
        
        return self.results
    
    def _scan_ports(self):
        """
        مسح المنافذ المفتوحة والخدمات
        """
        self.logger.info(f"بدء مسح المنافذ على الهدف: {self.ip}")
        console.print(f"[bold]بدء مسح المنافذ على الهدف: {self.ip}[/bold]")
        
        try:
            # تحويل قائمة المنافذ إلى سلسلة نصية
            ports_str = ",".join(map(str, self.ports))
            
            # تنفيذ مسح المنافذ باستخدام nmap
            self.nm.scan(self.ip, ports_str, arguments="-sV -T4")
            
            # معالجة النتائج
            if self.ip in self.nm.all_hosts():
                for port in self.nm[self.ip]['tcp']:
                    if self.nm[self.ip]['tcp'][port]['state'] == 'open':
                        port_info = {
                            "port": port,
                            "service": self.nm[self.ip]['tcp'][port]['name'],
                            "version": self.nm[self.ip]['tcp'][port]['product'] + " " + self.nm[self.ip]['tcp'][port]['version'],
                            "state": "open"
                        }
                        self.results["open_ports"].append(port_info)
                        
                        service_info = {
                            "port": port,
                            "name": self.nm[self.ip]['tcp'][port]['name'],
                            "product": self.nm[self.ip]['tcp'][port]['product'],
                            "version": self.nm[self.ip]['tcp'][port]['version'],
                            "extra_info": self.nm[self.ip]['tcp'][port]['extrainfo']
                        }
                        self.results["services"].append(service_info)
                        
                        self.logger.info(f"منفذ مفتوح: {port} - {self.nm[self.ip]['tcp'][port]['name']}")
                        console.print(f"[green]منفذ مفتوح: {port} - {self.nm[self.ip]['tcp'][port]['name']}[/green]")
            
            self.logger.info(f"اكتمل مسح المنافذ. تم العثور على {len(self.results['open_ports'])} منفذ مفتوح.")
            console.print(f"[bold]اكتمل مسح المنافذ. تم العثور على {len(self.results['open_ports'])} منفذ مفتوح.[/bold]")
            
        except Exception as e:
            self.logger.error(f"خطأ أثناء مسح المنافذ: {str(e)}")
            console.print(f"[bold red]خطأ أثناء مسح المنافذ: {str(e)}[/bold red]")
    
    def _scan_os(self):
        """
        مسح نظام التشغيل
        """
        self.logger.info(f"بدء مسح نظام التشغيل على الهدف: {self.ip}")
        console.print(f"[bold]بدء مسح نظام التشغيل على الهدف: {self.ip}[/bold]")
        
        try:
            # تنفيذ مسح نظام التشغيل باستخدام nmap
            self.nm.scan(self.ip, arguments="-O")
            
            # معالجة النتائج
            if self.ip in self.nm.all_hosts() and 'osmatch' in self.nm[self.ip]:
                for os_match in self.nm[self.ip]['osmatch']:
                    os_info = {
                        "name": os_match['name'],
                        "accuracy": os_match['accuracy'],
                        "type": ""
                    }
                    
                    # تحديد نوع نظام التشغيل
                    if "windows" in os_match['name'].lower():
                        os_info["type"] = "Windows"
                    elif "linux" in os_match['name'].lower():
                        os_info["type"] = "Linux"
                    elif "mac" in os_match['name'].lower() or "darwin" in os_match['name'].lower():
                        os_info["type"] = "MacOS"
                    else:
                        os_info["type"] = "Other"
                    
                    self.results["os_info"] = os_info
                    break  # أخذ أول نتيجة فقط
            
            self.logger.info(f"اكتمل مسح نظام التشغيل.")
            console.print(f"[bold]اكتمل مسح نظام التشغيل.[/bold]")
            
            if self.results["os_info"]:
                self.logger.info(f"نظام التشغيل المحتمل: {self.results['os_info']['name']} (دقة: {self.results['os_info']['accuracy']}%)")
                console.print(f"[green]نظام التشغيل المحتمل: {self.results['os_info']['name']} (دقة: {self.results['os_info']['accuracy']}%)[/green]")
            else:
                self.logger.info("لم يتم التعرف على نظام التشغيل.")
                console.print("[yellow]لم يتم التعرف على نظام التشغيل.[/yellow]")
            
        except Exception as e:
            self.logger.error(f"خطأ أثناء مسح نظام التشغيل: {str(e)}")
            console.print(f"[bold red]خطأ أثناء مسح نظام التشغيل: {str(e)}[/bold red]")
    
    def _scan_vulnerabilities(self):
        """
        مسح الثغرات الأمنية
        """
        self.logger.info(f"بدء مسح الثغرات الأمنية على الهدف: {self.ip}")
        console.print(f"[bold]بدء مسح الثغرات الأمنية على الهدف: {self.ip}[/bold]")
        
        try:
            # تنفيذ مسح الثغرات باستخدام nmap
            self.nm.scan(self.ip, arguments="-sV --script vuln")
            
            # معالجة النتائج
            if self.ip in self.nm.all_hosts():
                for port in self.nm[self.ip]['tcp']:
                    if self.nm[self.ip]['tcp'][port]['state'] == 'open' and 'script' in self.nm[self.ip]['tcp'][port]:
                        for script_name, script_output in self.nm[self.ip]['tcp'][port]['script'].items():
                            if 'VULNERABLE' in script_output:
                                # تحديد مستوى الخطورة
                                severity = "medium"  # افتراضي
                                if "high" in script_output.lower() or "critical" in script_output.lower():
                                    severity = "high"
                                elif "low" in script_output.lower():
                                    severity = "low"
                                
                                # إنشاء معلومات الثغرة
                                vuln_info = {
                                    "port": port,
                                    "service": self.nm[self.ip]['tcp'][port]['name'],
                                    "vulnerability": script_name,
                                    "description": script_output.strip(),
                                    "severity": severity
                                }
                                
                                self.results["vulnerabilities"].append(vuln_info)
                                
                                self.logger.info(f"تم اكتشاف ثغرة: {script_name} على المنفذ {port} (خطورة: {severity})")
                                console.print(f"[{get_severity_color(severity)}]تم اكتشاف ثغرة: {script_name} على المنفذ {port} (خطورة: {severity})[/{get_severity_color(severity)}]")
            
            self.logger.info(f"اكتمل مسح الثغرات الأمنية. تم العثور على {len(self.results['vulnerabilities'])} ثغرة.")
            console.print(f"[bold]اكتمل مسح الثغرات الأمنية. تم العثور على {len(self.results['vulnerabilities'])} ثغرة.[/bold]")
            
        except Exception as e:
            self.logger.error(f"خطأ أثناء مسح الثغرات الأمنية: {str(e)}")
            console.print(f"[bold red]خطأ أثناء مسح الثغرات الأمنية: {str(e)}[/bold red]")
    
    def _gather_additional_info(self):
        """
        جمع معلومات إضافية عن الهدف
        """
        self.logger.info(f"جمع معلومات إضافية عن الهدف: {self.target}")
        console.print(f"[bold]جمع معلومات إضافية عن الهدف: {self.target}[/bold]")
        
        try:
            # الحصول على معلومات DNS
            if self.target_type == "domain":
                try:
                    dns_info = socket.getaddrinfo(self.target, None)
                    self.results["additional_info"]["dns_records"] = []
                    for info in dns_info:
                        if info[4][0] not in [record["ip"] for record in self.results["additional_info"]["dns_records"]]:
                            self.results["additional_info"]["dns_records"].append({
                                "type": "A" if info[0] == socket.AF_INET else "AAAA",
                                "ip": info[4][0]
                            })
                except Exception as e:
                    self.logger.error(f"خطأ أثناء الحصول على معلومات DNS: {str(e)}")
            
            # الحصول على معلومات WHOIS (تنفيذ بسيط)
            if self.target_type == "domain":
                try:
                    import whois
                    whois_info = whois.whois(self.target)
                    self.results["additional_info"]["whois"] = {
                        "registrar": whois_info.registrar,
                        "creation_date": str(whois_info.creation_date),
                        "expiration_date": str(whois_info.expiration_date),
                        "name_servers": whois_info.name_servers
                    }
                except ImportError:
                    self.logger.warning("حزمة python-whois غير متوفرة. تخطي معلومات WHOIS.")
                except Exception as e:
                    self.logger.error(f"خطأ أثناء الحصول على معلومات WHOIS: {str(e)}")
            
            # الحصول على معلومات الموقع الجغرافي للـ IP
            try:
                geo_response = requests.get(f"https://ipinfo.io/{self.ip}/json", timeout=self.timeout)
                if geo_response.status_code == 200:
                    geo_data = geo_response.json()
                    self.results["additional_info"]["geolocation"] = {
                        "country": geo_data.get("country", "Unknown"),
                        "region": geo_data.get("region", "Unknown"),
                        "city": geo_data.get("city", "Unknown"),
                        "loc": geo_data.get("loc", "Unknown"),
                        "org": geo_data.get("org", "Unknown")
                    }
            except Exception as e:
                self.logger.error(f"خطأ أثناء الحصول على معلومات الموقع الجغرافي: {str(e)}")
            
            self.logger.info("اكتمل جمع المعلومات الإضافية.")
            console.print("[bold]اكتمل جمع المعلومات الإضافية.[/bold]")
            
        except Exception as e:
            self.logger.error(f"خطأ أثناء جمع المعلومات الإضافية: {str(e)}")
            console.print(f"[bold red]خطأ أثناء جمع المعلومات الإضافية: {str(e)}[/bold red]")