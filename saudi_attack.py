#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SaudiAttack - أداة إدارة سطح الهجوم وفحص الثغرات الأمنية

المطور: Saudi Linux
البريد الإلكتروني: SaudiLinux7@gmail.com
"""

import argparse
import sys
import os
import time
import json
import yaml
import logging
from datetime import datetime
from rich.console import Console
from rich.progress import Progress
from rich.panel import Panel
from rich.text import Text
from colorama import init, Fore, Style

# استيراد الوحدات الخاصة بالأداة
from modules.scanner import VulnerabilityScanner
from modules.web_scanner import WebServerScanner
from modules.wordpress_scanner import WordPressScanner
from modules.joomla_scanner import JoomlaScanner
from modules.report_generator import ReportGenerator
from modules.utils import banner, check_requirements, setup_logger

# تهيئة الألوان
init(autoreset=True)
console = Console()

# تعريف الإصدار
VERSION = "1.0.0"

def parse_arguments():
    """
    تحليل معطيات سطر الأوامر
    """
    parser = argparse.ArgumentParser(
        description="SaudiAttack - أداة إدارة سطح الهجوم وفحص الثغرات الأمنية",
        epilog="المطور: Saudi Linux - SaudiLinux7@gmail.com"
    )
    
    parser.add_argument("-t", "--target", required=True, help="الهدف (عنوان IP أو اسم النطاق)")
    parser.add_argument("-m", "--mode", required=True, choices=["general", "webserver", "wordpress", "joomla"],
                        help="وضع المسح (general, webserver, wordpress, joomla)")
    parser.add_argument("-o", "--output", help="اسم ملف التقرير المخرج")
    parser.add_argument("-p", "--ports", default="80,443", help="المنافذ للفحص (افتراضيًا: 80,443)")
    parser.add_argument("-v", "--verbose", action="store_true", help="عرض معلومات تفصيلية أثناء المسح")
    parser.add_argument("--version", action="version", version=f"SaudiAttack v{VERSION}")
    parser.add_argument("--config", help="ملف التكوين (YAML)")
    parser.add_argument("--threads", type=int, default=5, help="عدد مسارات التنفيذ المتوازية")
    parser.add_argument("--timeout", type=int, default=30, help="مهلة الاتصال بالثواني")
    
    return parser.parse_args()

def load_config(config_file):
    """
    تحميل إعدادات التكوين من ملف YAML
    """
    try:
        with open(config_file, 'r') as file:
            return yaml.safe_load(file)
    except Exception as e:
        console.print(f"[bold red]خطأ في تحميل ملف التكوين: {str(e)}[/bold red]")
        sys.exit(1)

def main():
    """
    الدالة الرئيسية للبرنامج
    """
    # عرض الشعار
    banner(VERSION)
    
    # التحقق من المتطلبات
    check_requirements()
    
    # تحليل المعطيات
    args = parse_arguments()
    
    # إعداد السجل
    log_file = f"saudi_attack_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    logger = setup_logger(args.verbose, log_file)
    
    # تحميل التكوين إذا تم تحديده
    config = {}
    if args.config:
        config = load_config(args.config)
    
    # تحديد اسم ملف التقرير
    output_file = args.output if args.output else f"report_{args.target.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    
    # تحويل المنافذ إلى قائمة
    ports = [int(port.strip()) for port in args.ports.split(',')]
    
    # بدء المسح
    start_time = time.time()
    console.print(Panel(f"[bold green]بدء المسح على الهدف: {args.target}[/bold green]"))
    console.print(f"[bold blue]الوضع: {args.mode}[/bold blue]")
    console.print(f"[bold blue]المنافذ: {args.ports}[/bold blue]")
    console.print(f"[bold blue]ملف التقرير: {output_file}[/bold blue]")
    
    # إنشاء كائن مولد التقارير
    report_generator = ReportGenerator(output_file)
    
    # تنفيذ المسح حسب الوضع المحدد
    results = {}
    with Progress() as progress:
        task = progress.add_task(f"[cyan]جاري المسح...", total=100)
        
        try:
            if args.mode == "general":
                scanner = VulnerabilityScanner(args.target, ports, args.threads, args.timeout, logger)
                results = scanner.scan()
                progress.update(task, completed=100)
                
            elif args.mode == "webserver":
                scanner = WebServerScanner(args.target, ports, args.threads, args.timeout, logger)
                results = scanner.scan()
                progress.update(task, completed=100)
                
            elif args.mode == "wordpress":
                scanner = WordPressScanner(args.target, ports, args.threads, args.timeout, logger)
                results = scanner.scan()
                progress.update(task, completed=100)
                
            elif args.mode == "joomla":
                scanner = JoomlaScanner(args.target, ports, args.threads, args.timeout, logger)
                results = scanner.scan()
                progress.update(task, completed=100)
        
        except KeyboardInterrupt:
            console.print("\n[bold yellow]تم إيقاف المسح بواسطة المستخدم[/bold yellow]")
            progress.update(task, completed=100)
        except Exception as e:
            console.print(f"\n[bold red]حدث خطأ أثناء المسح: {str(e)}[/bold red]")
            logger.error(f"حدث خطأ أثناء المسح: {str(e)}")
            progress.update(task, completed=100)
    
    # حساب الوقت المستغرق
    elapsed_time = time.time() - start_time
    
    # إضافة معلومات المسح إلى النتائج
    scan_info = {
        "target": args.target,
        "mode": args.mode,
        "ports": ports,
        "start_time": datetime.fromtimestamp(start_time).strftime("%Y-%m-%d %H:%M:%S"),
        "end_time": datetime.fromtimestamp(time.time()).strftime("%Y-%m-%d %H:%M:%S"),
        "elapsed_time": f"{elapsed_time:.2f} ثانية",
        "scanner_version": VERSION
    }
    
    # إنشاء التقرير
    if results:
        report_generator.generate(results, scan_info)
        console.print(f"\n[bold green]تم إنشاء التقرير بنجاح: {output_file}[/bold green]")
    else:
        console.print("\n[bold yellow]لم يتم العثور على نتائج للمسح[/bold yellow]")
    
    # عرض ملخص النتائج
    if results.get("vulnerabilities"):
        vuln_count = len(results["vulnerabilities"])
        high_count = sum(1 for v in results["vulnerabilities"] if v.get("severity") == "high")
        medium_count = sum(1 for v in results["vulnerabilities"] if v.get("severity") == "medium")
        low_count = sum(1 for v in results["vulnerabilities"] if v.get("severity") == "low")
        
        console.print("\n[bold]ملخص النتائج:[/bold]")
        console.print(f"إجمالي الثغرات: {vuln_count}")
        console.print(f"ثغرات خطيرة: [bold red]{high_count}[/bold red]")
        console.print(f"ثغرات متوسطة: [bold yellow]{medium_count}[/bold yellow]")
        console.print(f"ثغرات منخفضة: [bold green]{low_count}[/bold green]")
    
    console.print(f"\n[bold blue]الوقت المستغرق: {elapsed_time:.2f} ثانية[/bold blue]")
    console.print("\n[bold green]تم الانتهاء من المسح[/bold green]")

if __name__ == "__main__":
    main()