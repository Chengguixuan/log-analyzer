#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re

class LogParser:
    """日志解析器：支持多种日志格式"""
    
    # 预编译正则表达式，提高性能
    _nginx_pattern = re.compile(
        r'^(\S+) - - \[(.*?)\] "(\S+) (\S+) [^"]+" (\d+) (\d+) "([^"]*)" "([^"]*)"'
    )
    
    _apache_pattern = re.compile(
        r'^(\S+) - - \[(.*?)\] "(\S+) (\S+) [^"]+" (\d+) (\d+)(?: "([^"]*)" "([^"]*)")?'
    )
    
    _syslog_pattern = re.compile(
        r'^(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+)\[(\d+)\]:\s+(.*)$'
    )
    
    def __init__(self, log_type='nginx'):
        """
        初始化解析器
        :param log_type: 日志类型，支持 nginx/apache/syslog
        """
        self.log_type = log_type.lower()
    
    def parse(self, line):
        """
        解析单行日志
        :param line: 原始日志行
        :return: 解析后的字典，包含字段，解析失败返回 None
        """
        if not line or not line.strip():
            return None
        
        line = line.strip()
        
        # 根据日志类型选择解析方法
        parsers = {
            'nginx': self._parse_nginx,
            'apache': self._parse_apache,
            'syslog': self._parse_syslog
        }
        
        parser = parsers.get(self.log_type)
        if not parser:
            raise ValueError(f"不支持的日志类型: {self.log_type}")
        
        return parser(line)
    
    def _parse_nginx(self, line):
        """解析 Nginx 日志格式"""
        match = self._nginx_pattern.search(line)
        if not match:
            return None
        
        return {
            'ip': match.group(1),
            'time': match.group(2),
            'method': match.group(3),
            'url': match.group(4),
            'status': match.group(5),
            'size': match.group(6),
            'referer': match.group(7),
            'ua': match.group(8),
            'raw_line': line,
            'type': 'nginx'
        }
    
    def _parse_apache(self, line):
        """解析 Apache 日志格式（支持 Common 和 Combined）"""
        match = self._apache_pattern.search(line)
        if not match:
            return None
        
        result = {
            'ip': match.group(1),
            'time': match.group(2),
            'method': match.group(3),
            'url': match.group(4),
            'status': match.group(5),
            'size': match.group(6),
            'raw_line': line,
            'type': 'apache'
        }
        
        # Apache Combined 格式有 referer 和 ua
        if match.group(7) is not None:
            result['referer'] = match.group(7)
        if match.group(8) is not None:
            result['ua'] = match.group(8)
        
        return result
    
    def _parse_syslog(self, line):
        """解析系统日志格式"""
        match = self._syslog_pattern.search(line)
        if not match:
            return None
        
        return {
            'timestamp': match.group(1),
            'hostname': match.group(2),
            'process': match.group(3),
            'pid': match.group(4),
            'message': match.group(5),
            'raw_line': line,
            'type': 'syslog'
        }
    
    def get_supported_types(self):
        """返回支持的日志类型列表"""
        return ['nginx', 'apache', 'syslog']