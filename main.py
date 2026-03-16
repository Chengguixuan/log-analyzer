import re
import argparse
import json
from collections import Counter, defaultdict

parser = argparse.ArgumentParser(description='日志分析工具')
parser.add_argument('-f', '--file', help='日志文件路径')
parser.add_argument('-t', '--type', default='nginx', choices=['nginx', 'apache'], help='日志类型')
parser.add_argument('-o', '--output', help='输出报告文件')
args = parser.parse_args()

nginx_pattern = r'^(\S+) - - \[(.*?)\] "(\S+) (\S+) [^"]+" (\d+) (\d+) "([^"]*)" "([^"]*)"'

RULES_FILE = 'attack_patterns.json'
try:
    with open(RULES_FILE, 'r', encoding='utf-8') as f:
        attack_patterns = json.load(f)
    print(f"[+] 加载规则: {list(attack_patterns.keys())}")
except FileNotFoundError:
    print(f"[-] 错误: 找不到规则文件 {RULES_FILE}")
    exit(1)
except json.JSONDecodeError:
    print(f"[-] 错误: 规则文件不是有效的JSON格式")
    exit(1)

total_lines = 0
attack_lines = 0
attack_counter = Counter()
ip_attack_counter = defaultdict(Counter)
url_attack_counter = defaultdict(Counter)
detailed_logs = []

# 分析日志
print(f"[+] 开始分析文件: {args.file}")
try:
    with open(args.file, "r", encoding="utf-8") as f:
        for line in f:
            total_lines += 1
            line = line.strip()
            if not line:
                continue
            
            if args.type == "nginx":
                match = re.search(nginx_pattern, line)
                if match:
                    ip = match.group(1)
                    time_str = match.group(2)
                    method = match.group(3)
                    url = match.group(4)
                    status = match.group(5)
                    
                    found_attacks = []
                    for attack_type, patterns in attack_patterns.items():
                        if isinstance(patterns, dict) and 'patterns' in patterns:
                            pattern_list = patterns['patterns']
                        else:
                            pattern_list = patterns
                        
                        for pattern in pattern_list:
                            if re.search(pattern, url, re.IGNORECASE):
                                found_attacks.append(attack_type)
                                break
                    
                    if found_attacks:
                        attack_lines += 1
                        for attack_type in found_attacks:
                            attack_counter[attack_type] += 1
                            ip_attack_counter[ip][attack_type] += 1
                            url_attack_counter[url][attack_type] += 1
                        
                        detailed_logs.append({
                            'ip': ip,
                            'time': time_str,
                            'method': method,
                            'url': url,
                            'status': status,
                            'attacks': found_attacks
                        })
                        
                        print(f"    [!] 发现 {found_attacks} | {ip} | {url}")
                    
except FileNotFoundError:
    print(f"[-] 错误: 找不到日志文件 {args.file}")
    exit(1)

# 输出报告
print("\n" + "="*60)
print(" 日志分析报告")
print("="*60)
print(f"总日志行数: {total_lines}")
print(f"发现攻击行数: {attack_lines}")
if total_lines > 0:
    print(f"攻击占比: {attack_lines/total_lines*100:.2f}%")

print("\n[+] 攻击类型统计:")
for attack_type, count in attack_counter.most_common():
    print(f"  {attack_type}: {count}次")

print("\n[+] 攻击源IP TOP5:")
for ip, attacks in sorted(ip_attack_counter.items(), 
                         key=lambda x: sum(x[1].values()), reverse=True)[:5]:
    total = sum(attacks.values())
    print(f"  {ip}: 共{total}次攻击")
    for attack_type, count in attacks.most_common(3):
        print(f"    - {attack_type}: {count}次")

print("\n[+] 被攻击URL TOP5:")
for url, attacks in sorted(url_attack_counter.items(),
                          key=lambda x: sum(x[1].values()), reverse=True)[:5]:
    total = sum(attacks.values())
    print(f"  {url[:50]}...: {total}次攻击")

if detailed_logs and args.output:
    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(detailed_logs, f, indent=2, ensure_ascii=False)
    print(f"\n[+] 详细攻击日志已保存到: {args.output}")

print("\n[+] 分析完成！")