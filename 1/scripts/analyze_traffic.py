# scripts/analyze_traffic.py

import re
from collections import defaultdict

def parse_ether_line(line):
    """
    解析每一行的ETHER数据，提取关键信息。
    """
    pattern = r'ETHERNET\s+([\d:.,]+)\s+ETHER\s+\|0\s+\|([0-9a-f|]+)\|'
    match = re.search(pattern, line, re.IGNORECASE)
    if match:
        timestamp = match.group(1)
        data = match.group(2).replace('|', '')
        return timestamp, data
    return None, None

def analyze_traffic(file_path):
    """
    分析流量日志，识别异常IP和端口活动。
    """
    source_ips = defaultdict(int)
    destination_ips = defaultdict(int)
    protocols = defaultdict(int)
    
    with open(file_path, 'r') as file:
        for line in file:
            timestamp, data = parse_ether_line(line)
            if data:
                # 解析IP头部
                try:
                    ip_header = data[14:34]  # 假设以太网头部长度为14字节
                    src_ip = '.'.join(str(int(ip_header[i:i+2], 16)) for i in range(24, 32, 2))
                    dst_ip = '.'.join(str(int(ip_header[i:i+2], 16)) for i in range(32, 40, 2))
                    protocol = ip_header[18:20]
                    
                    source_ips[src_ip] += 1
                    destination_ips[dst_ip] += 1
                    protocols[protocol] += 1
                except Exception as e:
                    print(f"解析错误在时间 {timestamp}: {e}")

    # 输出分析结果
    print("源IP地址出现频率：")
    for ip, count in source_ips.items():
        print(f"{ip}: {count} 次")

    print("\n目标IP地址出现频率：")
    for ip, count in destination_ips.items():
        print(f"{ip}: {count} 次")
    
    print("\n使用的协议类型：")
    for proto, count in protocols.items():
        print(f"协议 {proto}: {count} 次")

if __name__ == "__main__":
    log_file = '../analyse/11.txt'
    analyze_traffic(log_file)