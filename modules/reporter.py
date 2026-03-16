#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
from collections import Counter, defaultdict
from datetime import datetime
import os

class ReportGenerator:
    """报告生成器：统计攻击数据，生成多种格式的报告"""
    
    def __init__(self):
        """初始化报告生成器"""
        self.total_lines = 0
        self.attack_lines = 0
        self.attack_counter = Counter()
        self.ip_attack_counter = defaultdict(Counter)
        self.url_attack_counter = defaultdict(Counter)
        self.detailed_logs = []
        self.start_time = datetime.now()
    
    def increment_total(self):
        """增加总日志行数"""
        self.total_lines += 1
    
    def add_attack(self, log_entry, attack_types):
        """
        添加一条攻击记录
        :param log_entry: 解析后的日志字典
        :param attack_types: 攻击类型列表
        """
        if not log_entry or not attack_types:
            return
        
        self.attack_lines += 1
        ip = log_entry.get('ip', 'unknown')
        url = log_entry.get('url', log_entry.get('message', 'unknown'))
        
        # 更新各类计数器
        for attack_type in attack_types:
            self.attack_counter[attack_type] += 1
            self.ip_attack_counter[ip][attack_type] += 1
            self.url_attack_counter[url][attack_type] += 1
        
        # 保存详细日志
        self.detailed_logs.append({
            **log_entry,
            'attacks': attack_types,
            'detected_at': datetime.now().isoformat()
        })
    
    def get_summary_stats(self):
        """获取统计摘要"""
        return {
            'total_lines': self.total_lines,
            'attack_lines': self.attack_lines,
            'attack_rate': (self.attack_lines / self.total_lines * 100) if self.total_lines > 0 else 0,
            'unique_ips': len(self.ip_attack_counter),
            'unique_urls': len(self.url_attack_counter),
            'attack_types': dict(self.attack_counter.most_common()),
            'start_time': self.start_time.isoformat(),
            'end_time': datetime.now().isoformat()
        }
    
    def generate_text_report(self):
        """生成文本报告（控制台输出用）"""
        lines = []
        lines.append("\n" + "="*60)
        lines.append(" 日志分析报告")
        lines.append("="*60)
        lines.append(f"分析时间: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"总日志行数: {self.total_lines}")
        lines.append(f"发现攻击行数: {self.attack_lines}")
        
        if self.total_lines > 0:
            rate = self.attack_lines / self.total_lines * 100
            lines.append(f"攻击占比: {rate:.2f}%")
        
        lines.append(f"独立IP数: {len(self.ip_attack_counter)}")
        lines.append(f"被攻击URL数: {len(self.url_attack_counter)}")
        
        # 攻击类型统计
        if self.attack_counter:
            lines.append("\n[+] 攻击类型统计:")
            for attack_type, count in self.attack_counter.most_common():
                lines.append(f"  {attack_type}: {count}次")
        
        # TOP 5 攻击IP
        if self.ip_attack_counter:
            lines.append("\n[+] 攻击源IP TOP5:")
            sorted_ips = sorted(
                self.ip_attack_counter.items(),
                key=lambda x: sum(x[1].values()),
                reverse=True
            )[:5]
            
            for ip, attacks in sorted_ips:
                total = sum(attacks.values())
                main_attack = attacks.most_common(1)[0][0] if attacks else '未知'
                lines.append(f"  {ip}: 共{total}次攻击 (主要: {main_attack})")
                
                # 显示该IP的前3种攻击类型
                for attack_type, count in attacks.most_common(3):
                    lines.append(f"    - {attack_type}: {count}次")
        
        # TOP 5 被攻击URL
        if self.url_attack_counter:
            lines.append("\n[+] 被攻击URL TOP5:")
            sorted_urls = sorted(
                self.url_attack_counter.items(),
                key=lambda x: sum(x[1].values()),
                reverse=True
            )[:5]
            
            for url, attacks in sorted_urls:
                total = sum(attacks.values())
                short_url = url[:50] + '...' if len(url) > 50 else url
                lines.append(f"  {short_url}: 共{total}次攻击")
        
        # 最近攻击
        if self.detailed_logs:
            lines.append("\n[+] 最近5条攻击:")
            for log in self.detailed_logs[-5:]:
                ip = log.get('ip', 'unknown')
                url = log.get('url', log.get('message', 'unknown'))[:40]
                attacks = ', '.join(log.get('attacks', []))
                lines.append(f"  {ip} | {url}... | {attacks}")
        
        return "\n".join(lines)
    
    def generate_html_report(self, output_file):
        """
        生成HTML报告
        :param output_file: 输出文件路径
        """
        stats = self.get_summary_stats()
        
        html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>日志分析报告</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
            color: #333;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        h1, h2, h3 {{
            color: #2c3e50;
        }}
        .summary {{
            background-color: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 10px;
        }}
        .summary-item {{
            background-color: white;
            padding: 10px;
            border-radius: 5px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}
        .summary-item .label {{
            font-size: 12px;
            color: #7f8c8d;
        }}
        .summary-item .value {{
            font-size: 24px;
            font-weight: bold;
            color: #2c3e50;
        }}
        .attack-type {{
            color: #e74c3c;
            font-weight: bold;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            border: 1px solid #ddd;
            padding: 12px;
            text-align: left;
        }}
        th {{
            background-color: #3498db;
            color: white;
        }}
        tr:nth-child(even) {{
            background-color: #f9f9f9;
        }}
        tr:hover {{
            background-color: #f1f1f1;
        }}
        .chart-container {{
            height: 300px;
            margin: 20px 0;
        }}
        .footer {{
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            text-align: center;
            color: #7f8c8d;
        }}
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <div class="container">
        <h1>📊 日志分析报告</h1>
        
        <div class="summary">
            <div class="summary-item">
                <div class="label">总日志行数</div>
                <div class="value">{stats['total_lines']:,}</div>
            </div>
            <div class="summary-item">
                <div class="label">攻击行数</div>
                <div class="value">{stats['attack_lines']:,}</div>
            </div>
            <div class="summary-item">
                <div class="label">攻击占比</div>
                <div class="value">{stats['attack_rate']:.2f}%</div>
            </div>
            <div class="summary-item">
                <div class="label">独立IP数</div>
                <div class="value">{stats['unique_ips']:,}</div>
            </div>
            <div class="summary-item">
                <div class="label">被攻击URL</div>
                <div class="value">{stats['unique_urls']:,}</div>
            </div>
        </div>
        
        <h2>📈 攻击类型分布</h2>
        <div class="chart-container">
            <canvas id="attackChart"></canvas>
        </div>
        
        <table>
            <tr>
                <th>攻击类型</th>
                <th>次数</th>
                <th>占比</th>
            </tr>
"""
        
        # 攻击类型表格
        for attack_type, count in self.attack_counter.most_common():
            percentage = (count / self.attack_lines * 100) if self.attack_lines > 0 else 0
            html += f"""
            <tr>
                <td class="attack-type">{attack_type}</td>
                <td>{count}</td>
                <td>{percentage:.1f}%</td>
            </tr>"""
        
        html += """
        </table>
        
        <h2>🔍 攻击源IP TOP10</h2>
        <table>
            <tr>
                <th>IP地址</th>
                <th>总攻击次数</th>
                <th>主要攻击类型</th>
                <th>详情</th>
            </tr>
"""
        
        # TOP 10 IP
        sorted_ips = sorted(
            self.ip_attack_counter.items(),
            key=lambda x: sum(x[1].values()),
            reverse=True
        )[:10]
        
        for ip, attacks in sorted_ips:
            total = sum(attacks.values())
            main_attack = attacks.most_common(1)[0][0] if attacks else '未知'
            details = ', '.join([f"{k}({v})" for k, v in attacks.most_common(3)])
            html += f"""
            <tr>
                <td>{ip}</td>
                <td>{total}</td>
                <td>{main_attack}</td>
                <td>{details}</td>
            </tr>"""
        
        html += """
        </table>
        
        <h2>📝 最近20条攻击详情</h2>
        <table>
            <tr>
                <th>时间</th>
                <th>IP</th>
                <th>方法</th>
                <th>URL/消息</th>
                <th>攻击类型</th>
            </tr>
"""
        
        # 最近20条攻击
        for log in self.detailed_logs[-20:]:
            time = log.get('time', log.get('timestamp', ''))[:16]
            ip = log.get('ip', log.get('hostname', 'unknown'))
            method = log.get('method', '-')
            url = log.get('url', log.get('message', 'unknown'))[:50]
            attacks = ', '.join(log.get('attacks', []))
            html += f"""
            <tr>
                <td>{time}</td>
                <td>{ip}</td>
                <td>{method}</td>
                <td>{url}{'...' if len(log.get('url', '')) > 50 else ''}</td>
                <td class="attack-type">{attacks}</td>
            </tr>"""
        
        html += f"""
        </table>
        
        <div class="footer">
            报告生成时间: {stats['end_time']} | 分析耗时: {self._get_elapsed_time()}
        </div>
    </div>
    
    <script>
        const ctx = document.getElementById('attackChart').getContext('2d');
        new Chart(ctx, {{
            type: 'bar',
            data: {{
                labels: {json.dumps([a for a, _ in self.attack_counter.most_common(10)])},
                datasets: [{{
                    label: '攻击次数',
                    data: {json.dumps([c for _, c in self.attack_counter.most_common(10)])},
                    backgroundColor: 'rgba(52, 152, 219, 0.8)',
                    borderColor: 'rgba(41, 128, 185, 1)',
                    borderWidth: 1
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                scales: {{
                    y: {{
                        beginAtZero: true,
                        ticks: {{
                            stepSize: 1
                        }}
                    }}
                }}
            }}
        }});
    </script>
</body>
</html>"""
        
        # 确保目录存在
        os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html)
        
        print(f"[+] HTML报告已生成: {output_file}")
    
    def save_json(self, output_file):
        """
        保存详细日志为JSON
        :param output_file: 输出文件路径
        """
        output = {
            'summary': self.get_summary_stats(),
            'attack_types': dict(self.attack_counter.most_common()),
            'top_ips': self._get_top_ips(20),
            'top_urls': self._get_top_urls(20),
            'detailed_logs': self.detailed_logs
        }
        
        # 确保目录存在
        os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(output, f, indent=2, ensure_ascii=False)
        
        print(f"[+] JSON报告已保存: {output_file}")
    
    def _get_top_ips(self, n=10):
        """获取TOP N攻击IP"""
        sorted_ips = sorted(
            self.ip_attack_counter.items(),
            key=lambda x: sum(x[1].values()),
            reverse=True
        )[:n]
        
        return [
            {
                'ip': ip,
                'total': sum(attacks.values()),
                'attacks': dict(attacks.most_common())
            }
            for ip, attacks in sorted_ips
        ]
    
    def _get_top_urls(self, n=10):
        """获取TOP N被攻击URL"""
        sorted_urls = sorted(
            self.url_attack_counter.items(),
            key=lambda x: sum(x[1].values()),
            reverse=True
        )[:n]
        
        return [
            {
                'url': url,
                'total': sum(attacks.values()),
                'attacks': dict(attacks.most_common())
            }
            for url, attacks in sorted_urls
        ]
    
    def _get_elapsed_time(self):
        """获取运行时长（秒）"""
        elapsed = datetime.now() - self.start_time
        seconds = int(elapsed.total_seconds())
        if seconds < 60:
            return f"{seconds}秒"
        elif seconds < 3600:
            return f"{seconds // 60}分{seconds % 60}秒"
        else:
            return f"{seconds // 3600}时{(seconds % 3600) // 60}分{seconds % 60}秒"
    
    def reset(self):
        """重置所有统计数据"""
        self.__init__()