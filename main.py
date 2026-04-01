import argparse
from modules.parser import LogParser
from modules.detector import AttackDetector
from modules.reporter import ReportGenerator
from modules.chart import ChartGenerator

def main():
    parser = argparse.ArgumentParser(description='智能日志分析系统')
    parser.add_argument('-f', '--file', required=True, help='日志文件路径')
    parser.add_argument('-t', '--type', default='nginx', 
                   choices=['nginx', 'apache_combined', 'apache_common'], 
                   help='日志类型 (nginx/apache_combined/apache_common)')
    parser.add_argument('-o', '--output', help='输出JSON文件')
    parser.add_argument('--html', help='输出HTML报告文件')
    parser.add_argument('--chart', help='输出图表文件（如 chart.png）')
    args = parser.parse_args()

    # 初始化模块
    log_parser = LogParser(args.type)
    detector = AttackDetector('config/attack_patterns.json')
    reporter = ReportGenerator()

    # 分析日志
    with open(args.file, 'r', encoding='utf-8') as f:
        for line in f:
            reporter.increment_total()
            log_entry = log_parser.parse(line)
            if log_entry:
                attacks = detector.detect(log_entry)
                if attacks:
                    reporter.add_attack(log_entry, attacks)
                    print(f"    [!] 发现 {attacks} | {log_entry.get('ip')} | {log_entry.get('url')}")

    # 输出报告
    print(reporter.generate_text_report())
    
    if args.output:
        reporter.save_json(args.output)
    
    if args.html:
        reporter.generate_html_report(args.html)

    if args.chart:
        chart_gen = ChartGenerator()
        chart_gen.generate_attack_bar_chart(reporter.attack_counter, args.chart)

if __name__ == '__main__':
    main()