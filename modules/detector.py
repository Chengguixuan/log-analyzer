#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
import json
from pathlib import Path

class AttackDetector:
    """攻击检测器：加载规则文件，检测日志中的攻击"""
    
    def __init__(self, rules_path='config/attack_patterns.json'):
        """
        初始化检测器
        :param rules_path: 规则文件路径（支持相对路径和绝对路径）
        """
        self.rules_path = rules_path
        self.rules = self._load_rules()
        self.compiled_rules = self._compile_rules()
        self.stats = {
            'total_matches': 0,
            'matches_by_type': {}
        }
    
    def _load_rules(self):
        """加载规则文件"""
        try:
            # 使用 Path 处理路径，兼容 Windows/Linux
            path = Path(self.rules_path)
            if not path.exists():
                print(f"[-] 警告: 规则文件不存在 {self.rules_path}")
                return {}
            
            with open(path, 'r', encoding='utf-8') as f:
                rules = json.load(f)
            print(f"[+] 加载规则: {list(rules.keys())}")
            return rules
        except json.JSONDecodeError as e:
            print(f"[-] 错误: 规则文件格式错误 {e}")
            return {}
        except Exception as e:
            print(f"[-] 错误: 读取规则文件失败 {e}")
            return {}
    
    def _compile_rules(self):
        """
        预编译所有正则表达式
        返回格式: {
            'sql_injection': [ compiled_pattern1, compiled_pattern2 ],
            'xss': [ ... ]
        }
        """
        compiled = {}
        
        for attack_type, patterns in self.rules.items():
            # 处理两种格式：纯列表 或 {description, patterns}
            if isinstance(patterns, dict) and 'patterns' in patterns:
                pattern_list = patterns['patterns']
            else:
                pattern_list = patterns
            
            # 编译该类型的所有正则
            compiled_patterns = []
            for pattern in pattern_list:
                try:
                    # 预编译正则，忽略大小写
                    compiled_pattern = re.compile(pattern, re.IGNORECASE)
                    compiled_patterns.append(compiled_pattern)
                except re.error as e:
                    print(f"[-] 警告: 正则编译失败 {attack_type}: {pattern} - {e}")
                    continue
            
            if compiled_patterns:
                compiled[attack_type] = compiled_patterns
        
        return compiled
    
    def detect(self, log_entry):
        """
        检测单条日志中的攻击
        :param log_entry: 解析后的日志字典，必须包含 'url' 或 'message' 字段
        :return: 攻击类型列表
        """
        if not log_entry:
            return []
        
        # 获取要检测的字段（优先用 URL，没有就用 message）
        target = log_entry.get('url') or log_entry.get('message') or ''
        if not target:
            return []
        
        found_attacks = []
        
        # 遍历所有攻击类型
        for attack_type, patterns in self.compiled_rules.items():
            for pattern in patterns:
                if pattern.search(target):
                    found_attacks.append(attack_type)
                    self.stats['total_matches'] += 1
                    self.stats['matches_by_type'][attack_type] = \
                        self.stats['matches_by_type'].get(attack_type, 0) + 1
                    break  # 一个类型只记一次
        
        return found_attacks
    
    def detect_batch(self, log_entries):
        """
        批量检测多条日志
        :param log_entries: 日志字典列表
        :return: 每条日志对应的攻击类型列表
        """
        results = []
        for entry in log_entries:
            results.append(self.detect(entry))
        return results
    
    def get_stats(self):
        """获取检测统计信息"""
        return self.stats
    
    def reload_rules(self):
        """重新加载规则文件（热更新用）"""
        self.rules = self._load_rules()
        self.compiled_rules = self._compile_rules()
        print("[+] 规则重新加载完成")
    
    def get_supported_attacks(self):
        """获取支持的攻击类型列表"""
        return list(self.compiled_rules.keys())


# 简单的测试代码
if __name__ == '__main__':
    # 测试检测器
    detector = AttackDetector('../config/attack_patterns.json')
    
    test_cases = [
        {'url': '/products?id=1 union select 1,2,3'},
        {'url': '/search?q=<script>alert(1)</script>'},
        {'url': '/images/../../../etc/passwd'},
        {'message': 'Failed password for root from 192.168.1.1'},
        {'url': '/normal/page.html'}
    ]
    
    for test in test_cases:
        attacks = detector.detect(test)
        if attacks:
            print(f"[!] 发现攻击 {attacks}: {test.get('url') or test.get('message')}")
        else:
            print(f"[+] 安全: {test.get('url') or test.get('message')}")