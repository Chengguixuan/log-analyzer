import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')  # 非交互式后端，不弹窗

plt.rcParams['font.sans-serif'] = ['Microsoft YaHei', 'SimHei', 'DejaVu Sans']
plt.rcParams['axes.unicode_minus'] = False  # 解决负号显示问题

class ChartGenerator:
    """图表生成器：负责将统计数据可视化"""
    
    def __init__(self):
        """初始化图表生成器"""
        pass
    
    def generate_attack_bar_chart(self, attack_counter, output_file, top_n=10):
        """
        生成攻击类型柱状图
        :param attack_counter: Counter 对象，攻击类型统计
        :param output_file: 输出文件路径
        :param top_n: 显示前 N 种攻击类型
        """
        if not attack_counter:
            print("[-] 没有攻击数据，无法生成图表")
            return False
        
        # 准备数据
        labels = []
        counts = []
        for attack_type, count in attack_counter.most_common(top_n):
            labels.append(attack_type)
            counts.append(count)
        
        # 画图
        plt.figure(figsize=(10, 6))
        bars = plt.bar(labels, counts, color='#3498db')
        
        # 在柱子上方显示数字
        for bar, count in zip(bars, counts):
            plt.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
                     str(count), ha='center', va='bottom')
        
        plt.title(f'攻击类型分布 TOP {top_n}', fontsize=14)
        plt.xlabel('攻击类型')
        plt.ylabel('次数')
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        
        # 保存
        plt.savefig(output_file, dpi=100, bbox_inches='tight')
        plt.close()
        print(f"[+] 攻击类型图表已保存: {output_file}")
        return True
    
    def generate_ip_bar_chart(self, ip_attack_counter, output_file, top_n=10):
        """
        生成攻击源 IP 柱状图
        :param ip_attack_counter: defaultdict(Counter)，IP 攻击统计
        :param output_file: 输出文件路径
        :param top_n: 显示前 N 个 IP
        """
        if not ip_attack_counter:
            print("[-] 没有攻击数据，无法生成图表")
            return False
        
        # 准备数据：按总攻击次数排序
        ip_list = []
        count_list = []
        for ip, attacks in sorted(ip_attack_counter.items(),
                                  key=lambda x: sum(x[1].values()),
                                  reverse=True)[:top_n]:
            ip_list.append(ip)
            count_list.append(sum(attacks.values()))
        
        # 画图
        plt.figure(figsize=(10, 6))
        plt.bar(ip_list, count_list, color='#e74c3c')
        
        plt.title(f'攻击源 IP TOP {top_n}', fontsize=14)
        plt.xlabel('IP 地址')
        plt.ylabel('攻击次数')
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        
        plt.savefig(output_file, dpi=100, bbox_inches='tight')
        plt.close()
        print(f"[+] IP 攻击图表已保存: {output_file}")
        return True