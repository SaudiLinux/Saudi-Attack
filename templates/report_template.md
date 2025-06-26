# تقرير فحص الثغرات الأمنية - {{ report_title }}

**تاريخ المسح:** {{ scan_date }}  
**وقت المسح:** {{ scan_time }}  
**مدة المسح:** {{ scan_duration }}  

## معلومات الهدف

- **الهدف:** {{ target }}
- **نوع الهدف:** {{ target_type }}
- **عنوان IP:** {{ target_ip }}

## معلومات المسح

- **نوع المسح:** {{ scan_type }}
- **المنافذ المفحوصة:** {{ scanned_ports }}
- **عدد المواضيع:** {{ threads }}

## ملخص النتائج

{{ summary_text }}

### إحصائيات الثغرات

- **حرجة:** {{ critical_count }}
- **عالية:** {{ high_count }}
- **متوسطة:** {{ medium_count }}
- **منخفضة:** {{ low_count }}
- **معلومات:** {{ info_count }}

## الثغرات المكتشفة

{% if vulnerabilities.critical %}
### ثغرات حرجة

{% for vuln in vulnerabilities.critical %}
#### {{ vuln.name }}

- **الوصف:** {{ vuln.description }}
- **الموقع:** {{ vuln.location }}
{% if vuln.evidence %}- **الدليل:** {{ vuln.evidence }}{% endif %}
- **التأثير:** {{ vuln.impact }}
- **التوصية:** {{ vuln.recommendation }}
{% if vuln.references %}
- **المراجع:**
{% for ref in vuln.references %}
  - {{ ref }}
{% endfor %}
{% endif %}

{% endfor %}
{% endif %}

{% if vulnerabilities.high %}
### ثغرات عالية

{% for vuln in vulnerabilities.high %}
#### {{ vuln.name }}

- **الوصف:** {{ vuln.description }}
- **الموقع:** {{ vuln.location }}
{% if vuln.evidence %}- **الدليل:** {{ vuln.evidence }}{% endif %}
- **التأثير:** {{ vuln.impact }}
- **التوصية:** {{ vuln.recommendation }}
{% if vuln.references %}
- **المراجع:**
{% for ref in vuln.references %}
  - {{ ref }}
{% endfor %}
{% endif %}

{% endfor %}
{% endif %}

{% if vulnerabilities.medium %}
### ثغرات متوسطة

{% for vuln in vulnerabilities.medium %}
#### {{ vuln.name }}

- **الوصف:** {{ vuln.description }}
- **الموقع:** {{ vuln.location }}
{% if vuln.evidence %}- **الدليل:** {{ vuln.evidence }}{% endif %}
- **التأثير:** {{ vuln.impact }}
- **التوصية:** {{ vuln.recommendation }}
{% if vuln.references %}
- **المراجع:**
{% for ref in vuln.references %}
  - {{ ref }}
{% endfor %}
{% endif %}

{% endfor %}
{% endif %}

{% if vulnerabilities.low %}
### ثغرات منخفضة

{% for vuln in vulnerabilities.low %}
#### {{ vuln.name }}

- **الوصف:** {{ vuln.description }}
- **الموقع:** {{ vuln.location }}
{% if vuln.evidence %}- **الدليل:** {{ vuln.evidence }}{% endif %}
- **التأثير:** {{ vuln.impact }}
- **التوصية:** {{ vuln.recommendation }}
{% if vuln.references %}
- **المراجع:**
{% for ref in vuln.references %}
  - {{ ref }}
{% endfor %}
{% endif %}

{% endfor %}
{% endif %}

{% if vulnerabilities.info %}
### معلومات

{% for vuln in vulnerabilities.info %}
#### {{ vuln.name }}

- **الوصف:** {{ vuln.description }}
- **الموقع:** {{ vuln.location }}
{% if vuln.evidence %}- **الدليل:** {{ vuln.evidence }}{% endif %}
{% if vuln.impact %}- **التأثير:** {{ vuln.impact }}{% endif %}
{% if vuln.recommendation %}- **التوصية:** {{ vuln.recommendation }}{% endif %}
{% if vuln.references %}
- **المراجع:**
{% for ref in vuln.references %}
  - {{ ref }}
{% endfor %}
{% endif %}

{% endfor %}
{% endif %}

## معلومات النظام

| المعلومة | القيمة |
|----------|--------|
{% for info in system_info %}
| {{ info.name }} | {{ info.value }} |
{% endfor %}

{% if port_info %}
## معلومات المنافذ

| المنفذ | البروتوكول | الحالة | الخدمة | الإصدار |
|--------|------------|--------|---------|----------|
{% for port in port_info %}
| {{ port.port }} | {{ port.protocol }} | {{ port.state }} | {{ port.service }} | {{ port.version }} |
{% endfor %}
{% endif %}

{% if web_info %}
## معلومات خادم الويب

| المعلومة | القيمة |
|----------|--------|
{% for info in web_info %}
| {{ info.name }} | {{ info.value }} |
{% endfor %}
{% endif %}

## التوصيات

{% for rec in recommendations %}
### {{ rec.title }}

{{ rec.description }}

{% endfor %}

---

*تم إنشاء هذا التقرير بواسطة أداة SaudiAttack*  
*المطور: Saudi Linux*  
*البريد الإلكتروني: SaudiLinux7@gmail.com*