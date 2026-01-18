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

# 清理旧安装
echo "检查并清理旧安装..."
systemctl stop yj 2>/dev/null
systemctl stop yj 2>/dev/null
systemctl disable yj 2>/dev/null

# 杀死占用端口的进程
if command -v lsof &>/dev/null; then
  lsof -ti:$PORT | xargs kill -9 2>/dev/null
elif command -v fuser &>/dev/null; then
  fuser -k ${PORT}/tcp 2>/dev/null
fi

# 杀死相关进程
killall yj.sh 2>/dev/null
pkill -f yj.py 2>/dev/null

# 等待端口释放
sleep 2

# 确认端口已释放
if netstat -tlnp 2>/dev/null | grep -q ":$PORT " || ss -tlnp 2>/dev/null | grep -q ":$PORT "; then
  echo "⚠️  警告: 端口 $PORT 仍被占用，尝试强制清理..."
  fuser -k ${PORT}/tcp 2>/dev/null
  sleep 2
fi

echo "✅ 清理完成"
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
cat > /usr/local/bin/yj.py <<'PYTHON_EOF'
#!/usr/bin/env python3
import os
import sys
import json
import socket
import subprocess
import base64
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime
from urllib.parse import urlparse, parse_qs

PORT = int(os.environ.get('PORT', 37218))
TOKEN = os.environ.get('TOKEN', '')

if not TOKEN:
    print("错误: 请设置 TOKEN 环境变量")
    sys.exit(1)

def run_cmd(cmd):
    """执行命令并返回输出"""
    try:
        return subprocess.getoutput(cmd)
    except Exception as e:
        return ""

def get_system_info():
    """获取系统信息"""
    try:
        return {
            'host': socket.gethostname(),
            'os': run_cmd('uname -s'),
            'arch': run_cmd('uname -m'),
            'kernel': run_cmd('uname -r'),
            'cpu_model': run_cmd("grep -m1 'model name' /proc/cpuinfo | cut -d: -f2").strip(),
            'cpu_cores': int(run_cmd('nproc') or 0),
            'total_memory': int(run_cmd("awk '/MemTotal/ {print $2}' /proc/meminfo") or 0),
            'total_disk': int(run_cmd("df / | awk 'NR==2 {print $2}'") or 0),
            'uptime': int(float(run_cmd("awk '{print $1}' /proc/uptime") or 0))
        }
    except Exception as e:
        print(f"获取系统信息失败: {e}", file=sys.stderr)
        return {}

def get_metrics():
    """获取实时指标"""
    try:
        cpu = float(run_cmd("top -bn1 | grep 'Cpu(s)' | awk '{print $2}' | cut -d'%' -f1") or 0)
        mem_total = int(run_cmd("awk '/MemTotal/ {print $2}' /proc/meminfo") or 0)
        mem_avail = int(run_cmd("awk '/MemAvailable/ {print $2}' /proc/meminfo") or 0)
        mem_used = mem_total - mem_avail
        mem_percent = (mem_used / mem_total) * 100 if mem_total > 0 else 0
        
        disk_info = run_cmd("df / | awk 'NR==2 {print $2,$3,$5}'").split()
        disk_total = int(disk_info[0]) if len(disk_info) > 0 else 0
        disk_used = int(disk_info[1]) if len(disk_info) > 1 else 0
        disk_percent = int(disk_info[2].rstrip('%')) if len(disk_info) > 2 else 0
        
        net_in = int(run_cmd("cat /sys/class/net/eth0/statistics/rx_bytes 2>/dev/null || echo 0") or 0)
        net_out = int(run_cmd("cat /sys/class/net/eth0/statistics/tx_bytes 2>/dev/null || echo 0") or 0)
        
        load = run_cmd("cat /proc/loadavg | awk '{print $1,$2,$3}'").split()
        tcp = int(run_cmd("ss -tan | grep -c ESTAB") or 0)
        udp = int(run_cmd("ss -uan | wc -l") or 0)
        procs = int(run_cmd("ps aux | wc -l") or 0)
        
        return {
            'cpu': cpu,
            'memory': mem_percent,
            'memory_used': mem_used,
            'disk': disk_percent,
            'disk_used': disk_used,
            'network_in': net_in,
            'network_out': net_out,
            'load_1': float(load[0]) if len(load) > 0 else 0,
            'load_5': float(load[1]) if len(load) > 1 else 0,
            'load_15': float(load[2]) if len(load) > 2 else 0,
            'tcp_count': tcp,
            'udp_count': udp,
            'process_count': procs
        }
    except Exception as e:
        print(f"获取指标失败: {e}", file=sys.stderr)
        return {}

def get_containers():
    """获取Docker容器列表"""
    try:
        if not run_cmd('command -v docker'):
            return []
        output = run_cmd('docker ps -a --format \'{"id":"{{.ID}}","name":"{{.Names}}","image":"{{.Image}}","status":"{{.Status}}","created":"{{.CreatedAt}}"}\'')
        if not output:
            return []
        lines = output.strip().split('\n')
        return [json.loads(line) for line in lines if line]
    except Exception as e:
        print(f"获取容器列表失败: {e}", file=sys.stderr)
        return []

def get_processes():
    """获取进程列表"""
    try:
        output = run_cmd('ps aux --sort=-%cpu | head -20 | awk \'NR>1 {printf "{\\"pid\\":%s,\\"name\\":\\"%s\\",\\"cpu\\":%s,\\"memory\\":%s},", $2, $11, $3, $4}\'')
        if not output:
            return []
        output = '[' + output.rstrip(',') + ']'
        return json.loads(output)
    except Exception as e:
        print(f"获取进程列表失败: {e}", file=sys.stderr)
        return []

def get_network():
    """获取网络连接"""
    try:
        output = run_cmd('ss -tunap 2>/dev/null | awk \'NR>1 && $1!="Netid" {printf "{\\"protocol\\":\\"%s\\",\\"local_addr\\":\\"%s\\",\\"remote_addr\\":\\"%s\\",\\"state\\":\\"%s\\",\\"pid\\":0,\\"program\\":\\"\\"},", tolower($1), $5, $6, $2}\'')
        if not output:
            return []
        output = '[' + output.rstrip(',') + ']'
        return json.loads(output)
    except Exception as e:
        print(f"获取网络连接失败: {e}", file=sys.stderr)
        return []

def get_disks():
    """获取磁盘分区"""
    try:
        output = run_cmd('df -T | awk \'NR>1 && $1!="tmpfs" {printf "{\\"device\\":\\"%s\\",\\"mount_point\\":\\"%s\\",\\"fs_type\\":\\"%s\\",\\"total\\":%s,\\"used\\":%s,\\"available\\":%s,\\"use_percent\\":%s},", $1, $7, $2, $3, $4, $5, substr($6,1,length($6)-1)}\'')
        if not output:
            return []
        output = '[' + output.rstrip(',') + ']'
        return json.loads(output)
    except Exception as e:
        print(f"获取磁盘分区失败: {e}", file=sys.stderr)
        return []

def get_services():
    """获取系统服务"""
    try:
        if not run_cmd('command -v systemctl'):
            return []
        output = run_cmd('systemctl list-units --type=service --all --no-pager --no-legend | awk \'{printf "{\\"name\\":\\"%s\\",\\"status\\":\\"%s\\",\\"enabled\\":1},", $1, $3}\'')
        if not output:
            return []
        output = '[' + output.rstrip(',') + ']'
        return json.loads(output)
    except Exception as e:
        print(f"获取服务列表失败: {e}", file=sys.stderr)
        return []

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
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())
    
    def do_GET(self):
        """处理GET请求"""
        if not self.check_auth():
            self.send_json({'error': 'Unauthorized'}, 401)
            return
        
        parsed = urlparse(self.path)
        path = parsed.path
        
        # 查询接口
        if path == '/info':
            self.send_json(get_system_info())
        elif path == '/metrics':
            self.send_json(get_metrics())
        elif path == '/containers':
            self.send_json(get_containers())
        elif path == '/processes':
            self.send_json(get_processes())
        elif path == '/network':
            self.send_json(get_network())
        elif path == '/disks':
            self.send_json(get_disks())
        elif path == '/services':
            self.send_json(get_services())
        
        # 文件操作
        elif path.startswith('/files/list'):
            dir_path = path.replace('/files/list', '') or '/'
            try:
                output = run_cmd(f'ls -lAh "{dir_path}" 2>/dev/null | awk \'NR>1 {{printf "{{\\"name\\":\\"%s\\",\\"size\\":\\"%s\\",\\"date\\":\\"%s %s %s\\",\\"perm\\":\\"%s\\",\\"type\\":\\"%s\\"}},", $9, $5, $6, $7, $8, $1, substr($1,1,1)}}\'')
                if output:
                    output = '[' + output.rstrip(',') + ']'
                    self.send_json(json.loads(output))
                else:
                    self.send_json([])
            except Exception as e:
                self.send_json({'error': str(e)}, 500)
        
        elif path.startswith('/files/read'):
            file_path = path.replace('/files/read', '')
            try:
                if os.path.isfile(file_path):
                    with open(file_path, 'rb') as f:
                        content = base64.b64encode(f.read()).decode()
                    self.send_json({'success': True, 'content': content})
                else:
                    self.send_json({'success': False, 'error': 'File not found'})
            except Exception as e:
                self.send_json({'success': False, 'error': str(e)})
        
        # 日志查看
        elif path.startswith('/logs/service/'):
            svc = path.replace('/logs/service/', '')
            try:
                content = run_cmd(f'journalctl -u "{svc}" -n 100 --no-pager 2>/dev/null')
                content_b64 = base64.b64encode(content.encode()).decode()
                self.send_json({'success': True, 'content': content_b64})
            except Exception as e:
                self.send_json({'success': False, 'error': str(e)})
        
        elif path.startswith('/logs'):
            log_path = path.replace('/logs', '')
            try:
                if os.path.isfile(log_path):
                    content = run_cmd(f'tail -n 100 "{log_path}" 2>/dev/null')
                    content_b64 = base64.b64encode(content.encode()).decode()
                    self.send_json({'success': True, 'content': content_b64})
                else:
                    self.send_json({'success': False, 'error': 'Log file not found'})
            except Exception as e:
                self.send_json({'success': False, 'error': str(e)})
        
        # Docker高级操作
        elif path.startswith('/container/logs/'):
            cid = path.replace('/container/logs/', '')
            try:
                logs = run_cmd(f'docker logs --tail 100 "{cid}" 2>&1')
                logs_b64 = base64.b64encode(logs.encode()).decode()
                self.send_json({'success': True, 'logs': logs_b64})
            except Exception as e:
                self.send_json({'success': False, 'error': str(e)})
        
        else:
            self.send_json({'error': 'Not Found'}, 404)
    
    def do_POST(self):
        """处理POST请求"""
        if not self.check_auth():
            self.send_json({'error': 'Unauthorized'}, 401)
            return
        
        parsed = urlparse(self.path)
        path = parsed.path
        
        # 读取请求体
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode() if content_length > 0 else ''
        
        # 系统操作
        if path == '/reboot':
            self.send_json({'success': True, 'message': 'Rebooting...'})
            subprocess.Popen(['sh', '-c', 'sleep 2 && reboot'], 
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        elif path == '/shutdown':
            self.send_json({'success': True, 'message': 'Shutting down...'})
            subprocess.Popen(['sh', '-c', 'sleep 2 && shutdown -h now'],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # 容器操作
        elif path.startswith('/container/start/'):
            cid = path.replace('/container/start/', '')
            run_cmd(f'docker start "{cid}"')
            self.send_json({'success': True})
        
        elif path.startswith('/container/stop/'):
            cid = path.replace('/container/stop/', '')
            run_cmd(f'docker stop "{cid}"')
            self.send_json({'success': True})
        
        elif path.startswith('/container/restart/'):
            cid = path.replace('/container/restart/', '')
            run_cmd(f'docker restart "{cid}"')
            self.send_json({'success': True})
        
        elif path.startswith('/container/remove/'):
            cid = path.replace('/container/remove/', '')
            run_cmd(f'docker rm -f "{cid}"')
            self.send_json({'success': True})
        
        elif path.startswith('/container/exec/'):
            cid = path.replace('/container/exec/', '')
            try:
                data = json.loads(body) if body else {}
                cmd = data.get('cmd', '')
                output = run_cmd(f'docker exec "{cid}" sh -c "{cmd}" 2>&1')
                output_b64 = base64.b64encode(output.encode()).decode()
                self.send_json({'success': True, 'output': output_b64})
            except Exception as e:
                self.send_json({'success': False, 'error': str(e)})
        
        # 服务操作
        elif path.startswith('/service/start/'):
            svc = path.replace('/service/start/', '')
            run_cmd(f'systemctl start "{svc}"')
            self.send_json({'success': True})
        
        elif path.startswith('/service/stop/'):
            svc = path.replace('/service/stop/', '')
            run_cmd(f'systemctl stop "{svc}"')
            self.send_json({'success': True})
        
        elif path.startswith('/service/restart/'):
            svc = path.replace('/service/restart/', '')
            run_cmd(f'systemctl restart "{svc}"')
            self.send_json({'success': True})
        
        # 进程操作
        elif path.startswith('/process/kill/'):
            pid = path.replace('/process/kill/', '')
            run_cmd(f'kill -9 {pid}')
            self.send_json({'success': True})
        
        # 文件操作
        elif path.startswith('/files/write'):
            file_path = path.replace('/files/write', '')
            try:
                data = json.loads(body) if body else {}
                content = data.get('content', '')
                content_decoded = base64.b64decode(content)
                with open(file_path, 'wb') as f:
                    f.write(content_decoded)
                self.send_json({'success': True})
            except Exception as e:
                self.send_json({'success': False, 'error': str(e)})
        
        elif path.startswith('/files/delete'):
            target = path.replace('/files/delete', '')
            try:
                run_cmd(f'rm -rf "{target}"')
                self.send_json({'success': True})
            except Exception as e:
                self.send_json({'success': False, 'error': str(e)})
        
        elif path.startswith('/files/mkdir'):
            dir_path = path.replace('/files/mkdir', '')
            try:
                run_cmd(f'mkdir -p "{dir_path}"')
                self.send_json({'success': True})
            except Exception as e:
                self.send_json({'success': False, 'error': str(e)})
        
        # 命令执行
        elif path == '/exec':
            try:
                data = json.loads(body) if body else {}
                cmd = data.get('cmd', '')
                output = run_cmd(cmd)
                output_b64 = base64.b64encode(output.encode()).decode()
                self.send_json({'success': True, 'output': output_b64})
            except Exception as e:
                self.send_json({'success': False, 'error': str(e)})
        
        else:
            self.send_json({'error': 'Not Found'}, 404)

if __name__ == '__main__':
    server = HTTPServer(('0.0.0.0', PORT), ProbeHandler)
    print(f'🚀 昱君探针 API服务启动在端口 {PORT}')
    print(f'✅ 支持 {len([m for m in dir(ProbeHandler) if m.startswith("do_")])} 种HTTP方法')
    print(f'📡 监听地址: 0.0.0.0:{PORT}')
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\n服务已停止')
        sys.exit(0)
PYTHON_EOF

chmod +x /usr/local/bin/yj.py

# 创建systemd服务
cat > /etc/systemd/system/yj.service <<EOF
[Unit]
Description=YuJun Probe API Service
After=network.target

[Service]
Type=simple
User=root
Environment="PORT=$PORT"
Environment="TOKEN=$TOKEN"
ExecStart=$PYTHON_CMD /usr/local/bin/yj.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# 创建管理脚本
cat > /usr/local/bin/yj <<'MANAGE_EOF'
#!/bin/bash

show_banner() {
  echo "=========================================="
  echo "      🚀 昱君探针 - 管理面板"
  echo "=========================================="
  echo ""
}

show_status() {
  echo "📊 服务状态:"
  systemctl status yj --no-pager | head -10
  echo ""
  echo "📡 监听端口:"
  netstat -tlnp | grep yj || ss -tlnp | grep python
  echo ""
}

show_logs() {
  echo "📋 最近日志:"
  journalctl -u yj -n 50 --no-pager
}

uninstall() {
  echo "⚠️  确定要卸载昱君探针吗? (y/N)"
  read -r confirm
  if [ "$confirm" = "y" ] || [ "$confirm" = "Y" ]; then
    echo "正在停止服务..."
    systemctl stop yj
    systemctl disable yj

    echo "正在删除文件..."
    rm -f /etc/systemd/system/yj.service
    rm -f /usr/local/bin/yj.py
    rm -f /usr/local/bin/yj

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
      systemctl restart yj
      echo "✅ 服务已重启"
      sleep 2
      ;;
    4)
      echo "正在停止服务..."
      systemctl stop yj
      echo "✅ 服务已停止"
      sleep 2
      ;;
    5)
      echo "正在启动服务..."
      systemctl start yj
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

chmod +x /usr/local/bin/yj

# 启动服务
systemctl daemon-reload
systemctl enable yj
systemctl start yj

echo ""
echo "=========================================="
echo "      ✅ 昱君探针安装完成!"
echo "=========================================="
echo "服务端口: $PORT"
echo ""
echo "📋 管理命令:"
echo "  yj                  - 打开管理面板"
echo "  systemctl status yj  - 查看服务状态"
echo "  journalctl -u yj -f  - 查看实时日志"
echo "=========================================="
