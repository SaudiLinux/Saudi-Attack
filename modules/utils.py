#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
وحدة الوظائف المساعدة لأداة SaudiAttack
"""

import os
import sys
import logging
import pkg_resources
import platform
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from colorama import Fore, Style

console = Console()

def banner(version):
    """
    عرض شعار الأداة
    """
    banner_text = f"""
    ███████╗ █████╗ ██╗   ██╗██████╗ ██╗ █████╗ ████████╗████████╗ █████╗  ██████╗██╗  ██╗
    ██╔════╝██╔══██╗██║   ██║██╔══██╗██║██╔══██╗╚══██╔══╝╚══██╔══╝██╔══██╗██╔════╝██║ ██╔╝
    ███████╗███████║██║   ██║██║  ██║██║███████║   ██║      ██║   ███████║██║     █████╔╝ 
    ╚════██║██╔══██║██║   ██║██║  ██║██║██╔══██║   ██║      ██║   ██╔══██║██║     ██╔═██╗ 
    ███████║██║  ██║╚██████╔╝██████╔╝██║██║  ██║   ██║      ██║   ██║  ██║╚██████╗██║  ██╗
    ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
                                                                                v{version}
    """
    
    panel = Panel(
        Text(banner_text, style="bold green"),
        subtitle="[bold blue]المطور: Saudi Linux - SaudiLinux7@gmail.com[/bold blue]",
        subtitle_align="center"
    )
    console.print(panel)

def check_requirements():
    """
    التحقق من توفر المتطلبات اللازمة
    """
    console.print("[bold]التحقق من المتطلبات...[/bold]")
    
    # التحقق من إصدار Python
    python_version = platform.python_version()
    if int(python_version.split('.')[0]) < 3 or (int(python_version.split('.')[0]) == 3 and int(python_version.split('.')[1]) < 8):
        console.print(f"[bold red]خطأ: يتطلب البرنامج Python 3.8 أو أحدث. الإصدار الحالي: {python_version}[/bold red]")
        sys.exit(1)
    else:
        console.print(f"[green]إصدار Python: {python_version} ✓[/green]")
    
    # التحقق من الحزم المطلوبة
    required_packages = [
        'requests', 'beautifulsoup4', 'colorama', 'rich', 'tqdm', 'pyyaml', 'jinja2', 'markdown'
    ]
    
    missing_packages = []
    
    for package in required_packages:
        try:
            pkg_resources.get_distribution(package)
            console.print(f"[green]حزمة {package} متوفرة ✓[/green]")
        except pkg_resources.DistributionNotFound:
            missing_packages.append(package)
            console.print(f"[red]حزمة {package} غير متوفرة ✗[/red]")
    
    if missing_packages:
        console.print("\n[bold yellow]تحذير: بعض الحزم المطلوبة غير متوفرة.[/bold yellow]")
        console.print("[bold yellow]يمكنك تثبيتها باستخدام الأمر التالي:[/bold yellow]")
        console.print(f"[bold]pip install {' '.join(missing_packages)}[/bold]")
        
        choice = input("\nهل ترغب في الاستمرار على أي حال؟ (y/n): ")
        if choice.lower() != 'y':
            sys.exit(1)
    else:
        console.print("[bold green]جميع المتطلبات متوفرة ✓[/bold green]")

def setup_logger(verbose, log_file):
    """
    إعداد نظام التسجيل
    """
    # إنشاء مجلد للسجلات إذا لم يكن موجودًا
    logs_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'logs')
    if not os.path.exists(logs_dir):
        os.makedirs(logs_dir)
    
    log_path = os.path.join(logs_dir, log_file)
    
    # إعداد المسجل
    logger = logging.getLogger('saudi_attack')
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    
    # مُعالج الملف
    file_handler = logging.FileHandler(log_path)
    file_handler.setLevel(logging.DEBUG)
    
    # مُعالج وحدة التحكم
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    
    # تنسيق السجل
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    
    # إضافة المعالجات إلى المسجل
    logger.addHandler(file_handler)
    if verbose:
        logger.addHandler(console_handler)
    
    return logger

def is_valid_ip(ip):
    """
    التحقق من صحة عنوان IP
    """
    import re
    pattern = re.compile(
        r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    )
    return bool(pattern.match(ip))

def is_valid_domain(domain):
    """
    التحقق من صحة اسم النطاق
    """
    import re
    pattern = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )
    return bool(pattern.match(domain))

def get_target_type(target):
    """
    تحديد نوع الهدف (IP أو نطاق)
    """
    if is_valid_ip(target):
        return "ip"
    elif is_valid_domain(target):
        return "domain"
    else:
        return "unknown"

def resolve_domain_to_ip(domain):
    """
    تحويل اسم النطاق إلى عنوان IP
    """
    import socket
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None

def get_severity_color(severity):
    """
    الحصول على لون حسب مستوى الخطورة
    """
    if severity.lower() == "high":
        return "red"
    elif severity.lower() == "medium":
        return "yellow"
    elif severity.lower() == "low":
        return "green"
    else:
        return "blue"

def format_time(seconds):
    """
    تنسيق الوقت بالثواني إلى صيغة مقروءة
    """
    if seconds < 60:
        return f"{seconds:.2f} ثانية"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.2f} دقيقة"
    else:
        hours = seconds / 3600
        return f"{hours:.2f} ساعة"