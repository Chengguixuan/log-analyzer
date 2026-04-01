#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
import json
from pathlib import Path

class LogParser:
    """日志解析器：支持多种日志格式，配置在 log_formats.json"""
    
    def __init__(self, log_type='nginx', formats_file='config/log_formats.json'):
        """
        初始化解析器
        :param log_type: 日志类型，如 nginx, apache_combined, apache_common
        :param formats_file: 日志格式配置文件路径
        """
        self.log_type = log_type
        self.formats = self._load_formats(formats_file)
        
        if log_type not in self.formats:
            raise ValueError(f"不支持的日志类型: {log_type}。支持的: {list(self.formats.keys())}")
        
        # 预编译正则
        pattern_str = self.formats[log_type]['pattern']
        self.pattern = re.compile(pattern_str)
        self.fields = self.formats[log_type]['fields']
    
    def _load_formats(self, formats_file):
        """加载日志格式配置文件"""
        try:
            path = Path(formats_file)
            if not path.exists():
                print(f"[-] 警告: 找不到格式文件 {formats_file}")
                return {}
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            print(f"[-] 错误: 格式文件 JSON 解析失败 {e}")
            return {}
    
    def parse(self, line):
        """
        解析单行日志
        :param line: 原始日志行
        :return: 解析后的字典，解析失败返回 None
        """
        if not line or not line.strip():
            return None
        
        match = self.pattern.search(line.strip())
        if not match:
            return None
        
        # 根据 fields 构建字典
        result = {}
        for i, field_name in enumerate(self.fields, start=1):
            result[field_name] = match.group(i)
        
        result['raw_line'] = line
        result['type'] = self.log_type
        return result
    
    def get_supported_types(self):
        """获取支持的日志类型列表"""
        return list(self.formats.keys())