# 智能日志分析系统

一个用 Python 写的日志分析工具，能自动检测 Web 日志中的攻击痕迹。

## ✨ 功能特点

- 支持 Nginx 日志格式
- 检测 SQL注入、XSS、路径遍历等多种攻击
- 输出统计报告（命令行 + HTML）
- 可自定义攻击规则

## 🚀 快速开始

```bash
# 分析日志
python main.py -f samples/access.log -t nginx

# 生成HTML报告
python main.py -f samples/access.log -t nginx --html report.html