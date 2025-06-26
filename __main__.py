#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
نقطة الدخول الرئيسية لأداة SaudiAttack عند تشغيلها كحزمة Python
"""

import sys
import os

# إضافة الدليل الحالي إلى مسار البحث عن الوحدات
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# استيراد الملف الرئيسي وتشغيله
from saudi_attack import main

if __name__ == "__main__":
    main()