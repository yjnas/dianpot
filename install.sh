#!/bin/bash

TOKEN="$1"
PORT="${PORT:-37218}"

if [ -z "$TOKEN" ]; then
  echo "错误: 请提供Token参数"
  echo "用法: curl -fsSL http://面板地址/install.sh | bash -s -- <TOKEN>"
  exit 1
fi

echo "=========================================="
echo "      🚀 昱君探针 - 客户端安装程序"
echo "=========================================="
echo "Token: $TOKEN"
echo "端口: $PORT"
echo ""

# 检测并安装Python
echo "检查Python环境..."
if ! command -v python3 &>/dev/null; then
  echo "未找到Python3，正在安装..."
  if command -v apt &>/dev/null; then
    apt update && apt install -y python3
  elif command -v yum &>/dev/null; then
    yum install -y python3
  elif command -v apk &>/dev/null; then
    apk add python3
  else
    echo "错误: 无法自动安装Python3，请手动安装"
    exit 1
  fi
fi

PYTHON_CMD=$(command -v python3 || command -v python)
echo "✅ Python: $PYTHON_CMD"
echo ""

# 创建Python探针脚本
cat > /usr/local/bin/yujun-agent.py <<'PYTHON_EOF'
#!/usr/bin/env python3
import os
import sys
import json
import socket
import subprocess
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime

PORT = int(os.environ.get('PORT', 37218))
TOKEN = os.environ.get('TOKEN', '')

if not TOKEN:
    print("错误: 请设置 TOKEN 环境变量")
    sys.exit(1)

def get_system_info():
    """获取系统信息"""
    try:
        return {
            'host': socket.gethostname(),
            'os': subprocess.getoutput('uname -s'),
            'arch': subprocess.getoutput('uname -m'),
            'kernel': subprocess.getoutput('uname -r'),
            'cpu_model': subprocess.getoutput("grep -m1 'model name' /proc/cpuinfo | cut -d: -f2").strip(),
            'cpu_cores': int(subprocess.getoutput('nproc')),
            'total_memory': int(subprocess.getoutput("awk '/MemTotal/ {print $2}' /proc/meminfo")),
            'total_disk': int(subprocess.getoutput("df / | awk 'NR==2 {print $2}'")),
            'uptime': int(float(subprocess.getoutput("awk '{print $1}' /proc/uptime")))
        }
    except Exception as e:
        print(f"获取系统信息失败: {e}", file=sys.stderr)
        return {}

def get_metrics():
    """获取实时指标"""
    try:
        cpu = float(subprocess.getoutput("top -bn1 | grep 'Cpu(s)' | awk '{print $2}' | cut -d'%' -f1"))
        mem_total = int(subprocess.getoutput("awk '/MemTotal/ {print $2}' /proc/meminfo"))
        mem_avail = int(subprocess.getoutput("awk '/MemAvailable/ {print $2}' /proc/meminfo"))
        mem_used = mem_total - mem_avail
        mem_percent = (mem_used / mem_total) * 100
        
        disk_info = subprocess.getoutput("df / | awk 'NR==2 {print $2,$3,$5}'").split()
        disk_total = int(disk_info[0])
        disk_used = int(disk_info[1])
        disk_percent = int(disk_info[2].rstrip('%'))
        
        net_in = int(subprocess.getoutput("cat /sys/class/net/eth0/statistics/rx_bytes 2>/dev/null || echo 0"))
        net_out = int(subprocess.getoutput("cat /sys/class/net/eth0/statistics/tx_bytes 2>/dev/null || echo 0"))
        
        load = subprocess.getoutput("cat /proc/loadavg | awk '{print $1,$2,$3}'").split()
        tcp = int(subprocess.getoutput("ss -tan | grep -c ESTAB"))
        udp = int(subprocess.getoutput("ss -uan | wc -l"))
        procs = int(subprocess.getoutput("ps aux | wc -l"))
        
        return {
            'cpu': cpu,
            'memory': mem_percent,
            'memory_used': mem_used,
            'disk': disk_percent,
            'disk_used': disk_used,
            'network_in': net_in,
            'network_out': net_out,
            'load_1': float(load[0]),
            'load_5': float(load[1]),
            'load_15': float(load[2]),
            'tcp_count': tcp,
            'udp_count': udp,
            'process_count': procs
        }
    except Exception as e:
        print(f"获取指标失败: {e}", file=sys.stderr)
        return {}

class ProbeHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        """自定义日志格式"""
        sys.stderr.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {format % args}\n")
    
    def check_auth(self):
        """检查Token认证"""
        auth_header = self.headers.get('Authorization', '')
        expected = f'Bearer {TOKEN}'
        return auth_header == expected
    
    def send_json(self, data, status=200):
        """发送JSON响应"""
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())
    
    def do_GET(self):
        """处理GET请求"""
        if not self.check_auth():
            self.send_json({'error': 'Unauthorized'}, 401)
            return
        
        if self.path == '/info':
            self.send_json(get_system_info())
        elif self.path == '/metrics':
            self.send_json(get_metrics())
        else:
            self.send_json({'error': 'Not Found'}, 404)
    
    def do_POST(self):
        """处理POST请求"""
        if not self.check_auth():
            self.send_json({'error': 'Unauthorized'}, 401)
            return
        
        if self.path == '/reboot':
            self.send_json({'success': True, 'message': 'Rebooting...'})
            subprocess.Popen(['sh', '-c', 'sleep 2 && reboot'], 
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        elif self.path == '/shutdown':
            self.send_json({'success': True, 'message': 'Shutting down...'})
            subprocess.Popen(['sh', '-c', 'sleep 2 && shutdown -h now'],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            self.send_json({'error': 'Not Found'}, 404)

if __name__ == '__main__':
    server = HTTPServer(('0.0.0.0', PORT), ProbeHandler)
    print(f'🚀 昱君探针 API服务启动在端口 {PORT}')
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\n服务已停止')
        sys.exit(0)
PYTHON_EOF

chmod +x /usr/local/bin/yujun-agent.py

# 创建systemd服务
cat > /etc/systemd/system/yujun-probe.service <<EOF
[Unit]
Description=YuJun Probe API Service
After=network.target

[Service]
Type=simple
User=root
Environment="PORT=$PORT"
Environment="TOKEN=$TOKEN"
ExecStart=$PYTHON_CMD /usr/local/bin/yujun-agent.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# 创建管理脚本
cat > /usr/local/bin/yujun-manage <<'MANAGE_EOF'
#!/bin/bash

show_banner() {
  echo "=========================================="
  echo "      🚀 昱君探针 - 管理面板"
  echo "=========================================="
  echo ""
}

show_status() {
  echo "📊 服务状态:"
  systemctl status yujun-probe --no-pager | head -10
  echo ""
  echo "📡 监听端口:"
  netstat -tlnp | grep yujun-agent || ss -tlnp | grep python
  echo ""
}

show_logs() {
  echo "📋 最近日志:"
  journalctl -u yujun-probe -n 50 --no-pager
}

uninstall() {
  echo "⚠️  确定要卸载昱君探针吗? (y/N)"
  read -r confirm
  if [ "$confirm" = "y" ] || [ "$confirm" = "Y" ]; then
    echo "正在停止服务..."
    systemctl stop yujun-probe
    systemctl disable yujun-probe

    echo "正在删除文件..."
    rm -f /etc/systemd/system/yujun-probe.service
    rm -f /usr/local/bin/yujun-agent.py
    rm -f /usr/local/bin/yujun-manage

    systemctl daemon-reload

    echo "✅ 昱君探针已卸载"
  else
    echo "取消卸载"
  fi
}

while true; do
  show_banner
  echo "1) 查看状态"
  echo "2) 查看日志"
  echo "3) 重启服务"
  echo "4) 停止服务"
  echo "5) 启动服务"
  echo "6) 卸载探针"
  echo "0) 退出"
  echo ""
  read -p "请选择操作 [0-6]: " choice

  case $choice in
    1)
      show_status
      read -p "按回车继续..."
      ;;
    2)
      show_logs
      read -p "按回车继续..."
      ;;
    3)
      echo "正在重启服务..."
      systemctl restart yujun-probe
      echo "✅ 服务已重启"
      sleep 2
      ;;
    4)
      echo "正在停止服务..."
      systemctl stop yujun-probe
      echo "✅ 服务已停止"
      sleep 2
      ;;
    5)
      echo "正在启动服务..."
      systemctl start yujun-probe
      echo "✅ 服务已启动"
      sleep 2
      ;;
    6)
      uninstall
      exit 0
      ;;
    0)
      echo "再见!"
      exit 0
      ;;
    *)
      echo "无效选择"
      sleep 1
      ;;
  esac
done
MANAGE_EOF

chmod +x /usr/local/bin/yujun-manage

# 启动服务
systemctl daemon-reload
systemctl enable yujun-probe
systemctl start yujun-probe

echo ""
echo "=========================================="
echo "      ✅ 昱君探针安装完成!"
echo "=========================================="
echo "服务端口: $PORT"
echo ""
echo "📋 管理命令:"
echo "  yujun-manage                  - 打开管理面板"
echo "  systemctl status yujun-probe  - 查看服务状态"
echo "  journalctl -u yujun-probe -f  - 查看实时日志"
echo "=========================================="
