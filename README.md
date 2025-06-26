# SaudiAttack

<div dir="rtl">

## أداة إدارة سطح الهجوم وفحص الثغرات الأمنية

SaudiAttack هي أداة برمجية متكاملة لتحديد الثغرات الأمنية داخل أنظمة الكمبيوتر والشبكات والتطبيقات. تقوم الأداة بأتمتة عملية اختبار الاختراق وفحص الثغرات الأمنية وفقًا للنطاق المحدد، ثم تقوم بإنشاء تقارير تسلط الضوء على نقاط الضعف وعمليات الاستغلال المحتملة.

## الميزات الرئيسية

- **مسح الثغرات الأمنية**: فحص النظام المستهدف لاكتشاف نقاط الضعف المعروفة
- **فحص خادم الويب**: اختبار مركز لثغرات خادم الويب وتطبيقات الويب
- **مسح ووردبريس**: اختبار الثغرات الأمنية المعروفة في WordPress (المنفذان 80 و443)
- **مسح جوملا**: اختبار الثغرات الأمنية المعروفة في Joomla (المنفذان 80 و443)
- **إنشاء تقارير**: توليد تقارير مفصلة عن الثغرات المكتشفة

## المتطلبات

- Python 3.8+
- نظام تشغيل Linux/Windows/MacOS
- حزم Python المطلوبة (مذكورة في ملف requirements.txt)

## التثبيت

### من مصدر البرنامج

```bash
# استنساخ المستودع
git clone https://github.com/SaudiLinux/SaudiAttack.git

# الانتقال إلى مجلد المشروع
cd SaudiAttack

# تثبيت المتطلبات
pip install -r requirements.txt

# تثبيت الأداة
pip install -e .
```

### باستخدام pip

```bash
pip install saudi-attack
```

## الاستخدام

### الأوامر الأساسية

```bash
# عرض المساعدة
saudi-attack --help

# فحص هدف محدد
saudi-attack --target example.com

# تحديد وضع الفحص
saudi-attack --target example.com --mode general
saudi-attack --target example.com --mode web
saudi-attack --target example.com --mode wordpress
saudi-attack --target example.com --mode joomla

# تحديد ملف الإخراج
saudi-attack --target example.com --output report.html

# تحديد المنافذ للفحص
saudi-attack --target example.com --ports 80,443,8080

# تحديد مستوى التفاصيل
saudi-attack --target example.com --verbose

# عرض إصدار الأداة
saudi-attack --version

# استخدام ملف تكوين مخصص
saudi-attack --target example.com --config config.yaml

# تحديد عدد الخيوط
saudi-attack --target example.com --threads 10

# تحديد مهلة الاتصال
saudi-attack --target example.com --timeout 30
```

### أمثلة متقدمة

```bash
# فحص شامل لموقع ووردبريس مع تقرير HTML
saudi-attack --target wordpress-site.com --mode wordpress --output report.html --verbose

# فحص موقع جوملا مع تحديد المنافذ
saudi-attack --target joomla-site.com --mode joomla --ports 80,443 --threads 5 --timeout 20

# فحص عام لخادم ويب مع تقرير JSON
saudi-attack --target webserver.com --mode web --output report.json --verbose
```

## هيكل المشروع

```
SaudiAttack/
├── data/
│   ├── joomla_vulnerabilities.json
│   └── wordpress_vulnerabilities.json
├── modules/
│   ├── __init__.py
│   ├── config.py
│   ├── joomla_scanner.py
│   ├── report_generator.py
│   ├── scanner.py
│   ├── utils.py
│   ├── web_scanner.py
│   └── wordpress_scanner.py
├── templates/
│   ├── report_template.html
│   ├── report_template.md
│   └── report_template.txt
├── __main__.py
├── LICENSE
├── README.md
├── requirements.txt
├── saudi_attack.py
└── setup.py
```

## المساهمة

نرحب بالمساهمات من المجتمع! يرجى قراءة [دليل المساهمة](CONTRIBUTING.md) للحصول على مزيد من المعلومات حول كيفية المساهمة في المشروع.

## المطور

- **المطور**: Saudi Linux
- **البريد الإلكتروني**: SaudiLinux7@gmail.com

## الترخيص

هذا المشروع مرخص تحت رخصة MIT - انظر ملف [LICENSE](LICENSE) للتفاصيل.

</div>