FROM python:3.13-slim

LABEL maintainer="Saudi Linux <SaudiLinux7@gmail.com>"
LABEL description="SaudiAttack - أداة لإدارة سطح الهجوم وفحص الثغرات الأمنية"

# تعيين متغيرات البيئة
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# تثبيت حزم النظام المطلوبة
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    libxml2-dev \
    libxslt1-dev \
    zlib1g-dev \
    gcc \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# إنشاء مستخدم غير جذري
RUN groupadd -r saudiattack && useradd -r -g saudiattack saudiattack

# إنشاء دليل العمل
WORKDIR /app

# نسخ ملفات المشروع
COPY . /app/

# تثبيت متطلبات البايثون
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir -e .

# تغيير ملكية الملفات إلى المستخدم غير الجذري
RUN chown -R saudiattack:saudiattack /app

# التبديل إلى المستخدم غير الجذري
USER saudiattack

# تعيين نقطة الدخول
ENTRYPOINT ["saudi-attack"]

# الأمر الافتراضي
CMD ["--help"]