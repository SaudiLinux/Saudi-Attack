.PHONY: help install dev-install lint test clean build docker-build docker-run

help:
	@echo "الأوامر المتاحة:"
	@echo "  help        - عرض هذه المساعدة"
	@echo "  install     - تثبيت الحزمة"
	@echo "  dev-install - تثبيت الحزمة في وضع التطوير"
	@echo "  lint        - تشغيل أدوات التحقق من جودة الكود"
	@echo "  test        - تشغيل الاختبارات"
	@echo "  clean       - تنظيف ملفات البناء"
	@echo "  build       - بناء حزمة التوزيع"
	@echo "  docker-build - بناء صورة Docker"
	@echo "  docker-run  - تشغيل الأداة في حاوية Docker"

install:
	pip install .

dev-install:
	pip install -e .

lint:
	pylint saudi_attack modules
	flake8 saudi_attack modules
	black --check saudi_attack modules
	isort --check-only saudi_attack modules
	mypy saudi_attack modules

# تشغيل الاختبارات
test:
	pytest

# تنظيف ملفات البناء
clean:
	rm -rf build/ dist/ *.egg-info/ __pycache__/ .pytest_cache/ .coverage htmlcov/
	find . -name "__pycache__" -exec rm -rf {} +
	find . -name "*.pyc" -delete
	find . -name "*.pyo" -delete
	find . -name "*.pyd" -delete

# بناء حزمة التوزيع
build: clean
	python setup.py sdist bdist_wheel

# بناء صورة Docker
docker-build:
	docker build -t saudiattack:latest .

# تشغيل الأداة في حاوية Docker
docker-run:
	docker run --rm -it saudiattack:latest