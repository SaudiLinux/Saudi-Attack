#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import pytest
import yaml
from unittest.mock import patch, mock_open

# افتراض أن وحدة التكوين موجودة في المسار التالي
from modules.config import ConfigManager


class TestConfigManager:
    """اختبارات لوحدة إدارة التكوين"""

    def test_initialization_default(self):
        """اختبار تهيئة مدير التكوين بالقيم الافتراضية"""
        config_manager = ConfigManager()
        
        # التحقق من القيم الافتراضية
        assert config_manager.config is not None
        assert 'general' in config_manager.config
        assert 'scan' in config_manager.config
        assert 'web' in config_manager.config
        assert 'wordpress' in config_manager.config
        assert 'joomla' in config_manager.config
        assert 'report' in config_manager.config

    @patch('os.path.exists')
    @patch('builtins.open', new_callable=mock_open)
    @patch('yaml.safe_load')
    def test_load_config_from_file(self, mock_yaml_load, mock_file_open, mock_path_exists):
        """اختبار تحميل التكوين من ملف"""
        # تكوين السلوك المزيف
        mock_path_exists.return_value = True
        mock_yaml_load.return_value = {
            'general': {
                'threads': 10,
                'timeout': 15,
                'user_agent': 'CustomAgent/1.0',
                'output_dir': './custom_reports'
            }
        }
        
        # تنفيذ الاختبار
        config_manager = ConfigManager(config_file='custom_config.yaml')
        
        # التحقق من النتائج
        mock_path_exists.assert_called_once_with('custom_config.yaml')
        mock_file_open.assert_called_once_with('custom_config.yaml', 'r', encoding='utf-8')
        mock_yaml_load.assert_called_once()
        
        assert config_manager.config['general']['threads'] == 10
        assert config_manager.config['general']['timeout'] == 15
        assert config_manager.config['general']['user_agent'] == 'CustomAgent/1.0'
        assert config_manager.config['general']['output_dir'] == './custom_reports'

    @patch('os.path.exists')
    def test_load_config_file_not_found(self, mock_path_exists):
        """اختبار سلوك عدم وجود ملف التكوين"""
        # تكوين السلوك المزيف
        mock_path_exists.return_value = False
        
        # تنفيذ الاختبار
        config_manager = ConfigManager(config_file='nonexistent_config.yaml')
        
        # التحقق من النتائج - يجب أن يستخدم التكوين الافتراضي
        assert config_manager.config is not None
        assert 'general' in config_manager.config
        assert 'scan' in config_manager.config

    def test_update_config(self):
        """اختبار تحديث التكوين"""
        config_manager = ConfigManager()
        
        # تحديث التكوين
        new_config = {
            'general': {
                'threads': 15,
                'timeout': 20
            },
            'scan': {
                'ports': {
                    'general': [25, 80, 443]
                }
            }
        }
        config_manager.update_config(new_config)
        
        # التحقق من النتائج
        assert config_manager.config['general']['threads'] == 15
        assert config_manager.config['general']['timeout'] == 20
        assert config_manager.config['scan']['ports']['general'] == [25, 80, 443]
        
        # التحقق من أن الحقول الأخرى لم تتغير
        assert 'user_agent' in config_manager.config['general']
        assert 'web' in config_manager.config

    def test_get_config(self):
        """اختبار الحصول على التكوين"""
        config_manager = ConfigManager()
        
        # الحصول على التكوين
        config = config_manager.get_config()
        
        # التحقق من النتائج
        assert config is not None
        assert config is config_manager.config
        assert 'general' in config
        assert 'scan' in config
        assert 'web' in config
        assert 'wordpress' in config
        assert 'joomla' in config
        assert 'report' in config

    @patch('os.path.exists')
    @patch('os.makedirs')
    @patch('builtins.open', new_callable=mock_open)
    @patch('yaml.dump')
    def test_save_config(self, mock_yaml_dump, mock_file_open, mock_makedirs, mock_path_exists):
        """اختبار حفظ التكوين إلى ملف"""
        # تكوين السلوك المزيف
        mock_path_exists.return_value = False
        
        # تنفيذ الاختبار
        config_manager = ConfigManager()
        config_manager.save_config('saved_config.yaml')
        
        # التحقق من النتائج
        mock_path_exists.assert_called_once()
        mock_makedirs.assert_called_once()
        mock_file_open.assert_called_once_with('saved_config.yaml', 'w', encoding='utf-8')
        mock_yaml_dump.assert_called_once_with(config_manager.config, mock_file_open())

    def test_merge_configs(self):
        """اختبار دمج التكوينات"""
        # تكوين الأساس
        base_config = {
            'general': {
                'threads': 5,
                'timeout': 10,
                'user_agent': 'BaseAgent/1.0'
            },
            'scan': {
                'ports': {
                    'general': [21, 22, 80, 443]
                }
            }
        }
        
        # تكوين التحديث
        update_config = {
            'general': {
                'threads': 10,
                'new_option': 'value'
            },
            'new_section': {
                'option1': 'value1'
            }
        }
        
        # تنفيذ الاختبار
        config_manager = ConfigManager()
        merged_config = config_manager._merge_configs(base_config, update_config)
        
        # التحقق من النتائج
        assert merged_config['general']['threads'] == 10  # تم التحديث
        assert merged_config['general']['timeout'] == 10  # لم يتغير
        assert merged_config['general']['user_agent'] == 'BaseAgent/1.0'  # لم يتغير
        assert merged_config['general']['new_option'] == 'value'  # تمت إضافته
        assert merged_config['scan']['ports']['general'] == [21, 22, 80, 443]  # لم يتغير
        assert merged_config['new_section']['option1'] == 'value1'  # تمت إضافته

    def test_get_default_config(self):
        """اختبار الحصول على التكوين الافتراضي"""
        config_manager = ConfigManager()
        default_config = config_manager._get_default_config()
        
        # التحقق من النتائج
        assert default_config is not None
        assert 'general' in default_config
        assert 'scan' in default_config
        assert 'web' in default_config
        assert 'wordpress' in default_config
        assert 'joomla' in default_config
        assert 'report' in default_config
        
        # التحقق من بعض القيم الافتراضية المتوقعة
        assert default_config['general']['threads'] > 0
        assert default_config['general']['timeout'] > 0
        assert 'SaudiAttack' in default_config['general']['user_agent']
        assert len(default_config['scan']['ports']['general']) > 0
        assert len(default_config['web']['security_headers']) > 0
        assert len(default_config['wordpress']['detection_paths']) > 0
        assert len(default_config['joomla']['detection_paths']) > 0
        assert len(default_config['report']['formats']) > 0