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

# 清理旧安装（如果存在）
echo "🔍 检查旧安装..."
if systemctl is-active --quiet yj 2>/dev/null; then
  echo "⚠️  发现旧服务正在运行，正在停止..."
  systemctl stop yj 2>/dev/null
  systemctl disable yj 2>/dev/null
fi

# 杀死占用端口的进程
if command -v lsof &>/dev/null; then
  OLD_PID=$(lsof -ti:$PORT 2>/dev/null)
  if [ -n "$OLD_PID" ]; then
    echo "⚠️  发现端口 $PORT 被进程 $OLD_PID 占用，正在终止..."
    kill -9 $OLD_PID 2>/dev/null
  fi
elif command -v ss &>/dev/null; then
  OLD_PID=$(ss -tlnp | grep ":$PORT " | grep -oP 'pid=\K[0-9]+' | head -1)
  if [ -n "$OLD_PID" ]; then
    echo "⚠️  发现端口 $PORT 被进程 $OLD_PID 占用，正在终止..."
    kill -9 $OLD_PID 2>/dev/null
  fi
fi

# 删除旧文件
if [ -f /usr/local/bin/yj.sh ]; then
  echo "🗑️  删除旧的探针脚本..."
  rm -f /usr/local/bin/yj.sh
fi
if [ -f /usr/local/bin/yj ]; then
  echo "🗑️  删除旧的管理脚本..."
  rm -f /usr/local/bin/yj
fi
if [ -f /etc/systemd/system/yj.service ]; then
  echo "🗑️  删除旧的systemd服务..."
  rm -f /etc/systemd/system/yj.service
  systemctl daemon-reload 2>/dev/null
fi

echo "✅ 旧安装清理完成"
echo ""

# 安装依赖
if command -v apt &>/dev/null; then
  apt update && apt install -y curl jq netcat-openbsd
elif command -v yum &>/dev/null; then
  yum install -y curl jq nc
elif command -v apk &>/dev/null; then
  apk add curl jq netcat-openbsd
else
  echo "不支持的系统"
  exit 1
fi

# 创建探针脚本
cat > /usr/local/bin/yj.sh <<'SCRIPT_EOF'
#!/bin/bash

PORT="${PORT:-37218}"
TOKEN="${TOKEN:-}"

if [ -z "$TOKEN" ]; then
  echo "错误: 请设置 TOKEN 环境变量"
  exit 1
fi

get_system_info() {
  cat <<EOF
{"host":"$(hostname)","os":"$(uname -s)","arch":"$(uname -m)","kernel":"$(uname -r)","cpu_model":"$(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs)","cpu_cores":$(nproc),"total_memory":$(awk '/MemTotal/ {print $2}' /proc/meminfo),"total_disk":$(df / | awk 'NR==2 {print $2}'),"uptime":$(awk '{print int($1)}' /proc/uptime)}
EOF
}

get_metrics() {
  local cpu=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)
  local mem_total=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
  local mem_avail=$(awk '/MemAvailable/ {print $2}' /proc/meminfo)
  local mem_used=$((mem_total - mem_avail))
  local mem_percent=$(awk "BEGIN {printf \"%.2f\", ($mem_used/$mem_total)*100}")
  local disk_total=$(df / | awk 'NR==2 {print $2}')
  local disk_used=$(df / | awk 'NR==2 {print $3}')
  local disk_percent=$(df / | awk 'NR==2 {print $5}' | tr -d '%')
  local net_in=$(cat /sys/class/net/eth0/statistics/rx_bytes 2>/dev/null || echo 0)
  local net_out=$(cat /sys/class/net/eth0/statistics/tx_bytes 2>/dev/null || echo 0)
  local load=$(cat /proc/loadavg | awk '{print $1,$2,$3}')
  local tcp=$(ss -tan | grep -c ESTAB)
  local udp=$(ss -uan | wc -l)
  local procs=$(ps aux | wc -l)

  cat <<EOF
{"cpu":$cpu,"memory":$mem_percent,"memory_used":$mem_used,"disk":$disk_percent,"disk_used":$disk_used,"network_in":$net_in,"network_out":$net_out,"load_1":$(echo $load | awk '{print $1}'),"load_5":$(echo $load | awk '{print $2}'),"load_15":$(echo $load | awk '{print $3}'),"tcp_count":$tcp,"udp_count":$udp,"process_count":$procs}
EOF
}

get_containers() {
  if ! command -v docker &>/dev/null; then
    echo '[]'
    return
  fi
  docker ps -a --format '{"id":"{{.ID}}","name":"{{.Names}}","image":"{{.Image}}","status":"{{.Status}}","created":{{.CreatedAt}}}' 2>/dev/null | jq -s '.' || echo '[]'
}

get_processes() {
  ps aux --sort=-%cpu | head -20 | awk 'NR>1 {printf "{\"pid\":%s,\"name\":\"%s\",\"cpu\":%s,\"memory\":%s},", $2, $11, $3, $4}' | sed 's/,$//' | awk '{print "["$0"]"}'
}

get_network() {
  ss -tunap 2>/dev/null | awk 'NR>1 && $1!="Netid" {printf "{\"protocol\":\"%s\",\"local_addr\":\"%s\",\"remote_addr\":\"%s\",\"state\":\"%s\",\"pid\":0,\"program\":\"\"},", tolower($1), $5, $6, $2}' | sed 's/,$//' | awk '{print "["$0"]"}'
}

get_disks() {
  df -T | awk 'NR>1 && $1!="tmpfs" {printf "{\"device\":\"%s\",\"mount_point\":\"%s\",\"fs_type\":\"%s\",\"total\":%s,\"used\":%s,\"available\":%s,\"use_percent\":%s},", $1, $7, $2, $3, $4, $5, substr($6,1,length($6)-1)}' | sed 's/,$//' | awk '{print "["$0"]"}'
}

get_services() {
  if ! command -v systemctl &>/dev/null; then
    echo '[]'
    return
  fi
  systemctl list-units --type=service --all --no-pager --no-legend | awk '{printf "{\"name\":\"%s\",\"status\":\"%s\",\"enabled\":1},", $1, $3}' | sed 's/,$//' | awk '{print "["$0"]"}'
}

handle_request() {
  local method=$1
  local path=$2
  local auth=$3
  local body=$4

  if [ "$auth" != "Bearer $TOKEN" ]; then
    echo "HTTP/1.1 401 Unauthorized"
    echo "Content-Type: application/json"
    echo ""
    echo '{"error":"Unauthorized"}'
    return
  fi

  case "$method:$path" in
    # 查询接口
    GET:/info)
      echo "HTTP/1.1 200 OK"
      echo "Content-Type: application/json"
      echo ""
      get_system_info
      ;;
    GET:/metrics)
      echo "HTTP/1.1 200 OK"
      echo "Content-Type: application/json"
      echo ""
      get_metrics
      ;;
    GET:/containers)
      echo "HTTP/1.1 200 OK"
      echo "Content-Type: application/json"
      echo ""
      get_containers
      ;;
    GET:/processes)
      echo "HTTP/1.1 200 OK"
      echo "Content-Type: application/json"
      echo ""
      get_processes
      ;;
    GET:/network)
      echo "HTTP/1.1 200 OK"
      echo "Content-Type: application/json"
      echo ""
      get_network
      ;;
    GET:/disks)
      echo "HTTP/1.1 200 OK"
      echo "Content-Type: application/json"
      echo ""
      get_disks
      ;;
    GET:/services)
      echo "HTTP/1.1 200 OK"
      echo "Content-Type: application/json"
      echo ""
      get_services
      ;;

    # 系统操作
    POST:/reboot)
      echo "HTTP/1.1 200 OK"
      echo "Content-Type: application/json"
      echo ""
      echo '{"success":true,"message":"Rebooting..."}'
      nohup bash -c "sleep 2 && reboot" &>/dev/null &
      ;;
    POST:/shutdown)
      echo "HTTP/1.1 200 OK"
      echo "Content-Type: application/json"
      echo ""
      echo '{"success":true,"message":"Shutting down..."}'
      nohup bash -c "sleep 2 && shutdown -h now" &>/dev/null &
      ;;

    # 容器操作
    POST:/container/start/*)
      local cid=$(echo "$path" | sed 's|/container/start/||')
      docker start "$cid" &>/dev/null
      echo "HTTP/1.1 200 OK"
      echo "Content-Type: application/json"
      echo ""
      echo '{"success":true}'
      ;;
    POST:/container/stop/*)
      local cid=$(echo "$path" | sed 's|/container/stop/||')
      docker stop "$cid" &>/dev/null
      echo "HTTP/1.1 200 OK"
      echo "Content-Type: application/json"
      echo ""
      echo '{"success":true}'
      ;;
    POST:/container/restart/*)
      local cid=$(echo "$path" | sed 's|/container/restart/||')
      docker restart "$cid" &>/dev/null
      echo "HTTP/1.1 200 OK"
      echo "Content-Type: application/json"
      echo ""
      echo '{"success":true}'
      ;;
    POST:/container/remove/*)
      local cid=$(echo "$path" | sed 's|/container/remove/||')
      docker rm -f "$cid" &>/dev/null
      echo "HTTP/1.1 200 OK"
      echo "Content-Type: application/json"
      echo ""
      echo '{"success":true}'
      ;;

    # 服务操作
    POST:/service/start/*)
      local svc=$(echo "$path" | sed 's|/service/start/||')
      systemctl start "$svc" &>/dev/null
      echo "HTTP/1.1 200 OK"
      echo "Content-Type: application/json"
      echo ""
      echo '{"success":true}'
      ;;
    POST:/service/stop/*)
      local svc=$(echo "$path" | sed 's|/service/stop/||')
      systemctl stop "$svc" &>/dev/null
      echo "HTTP/1.1 200 OK"
      echo "Content-Type: application/json"
      echo ""
      echo '{"success":true}'
      ;;
    POST:/service/restart/*)
      local svc=$(echo "$path" | sed 's|/service/restart/||')
      systemctl restart "$svc" &>/dev/null
      echo "HTTP/1.1 200 OK"
      echo "Content-Type: application/json"
      echo ""
      echo '{"success":true}'
      ;;

    # 进程操作
    POST:/process/kill/*)
      local pid=$(echo "$path" | sed 's|/process/kill/||')
      kill -9 "$pid" &>/dev/null
      echo "HTTP/1.1 200 OK"
      echo "Content-Type: application/json"
      echo ""
      echo '{"success":true}'
      ;;

    # 文件操作
    GET:/files/list/*)
      local dir=$(echo "$path" | sed 's|/files/list||' | sed 's|^$|/|')
      echo "HTTP/1.1 200 OK"
      echo "Content-Type: application/json"
      echo ""
      ls -lAh "$dir" 2>/dev/null | awk 'NR>1 {printf "{\"name\":\"%s\",\"size\":\"%s\",\"date\":\"%s %s %s\",\"perm\":\"%s\",\"type\":\"%s\"},", $9, $5, $6, $7, $8, $1, substr($1,1,1)}' | sed 's/,$//' | awk '{print "["$0"]"}'
      ;;
    GET:/files/read/*)
      local file=$(echo "$path" | sed 's|/files/read||')
      echo "HTTP/1.1 200 OK"
      echo "Content-Type: application/json"
      echo ""
      if [ -f "$file" ]; then
        local content=$(cat "$file" 2>/dev/null | base64 -w 0)
        echo "{\"success\":true,\"content\":\"$content\"}"
      else
        echo '{"success":false,"error":"File not found"}'
      fi
      ;;
    POST:/files/write/*)
      local file=$(echo "$path" | sed 's|/files/write||')
      read content_length
      read content
      echo "$content" | base64 -d > "$file" 2>/dev/null
      echo "HTTP/1.1 200 OK"
      echo "Content-Type: application/json"
      echo ""
      echo '{"success":true}'
      ;;
    POST:/files/delete/*)
      local target=$(echo "$path" | sed 's|/files/delete||')
      rm -rf "$target" &>/dev/null
      echo "HTTP/1.1 200 OK"
      echo "Content-Type: application/json"
      echo ""
      echo '{"success":true}'
      ;;
    POST:/files/mkdir/*)
      local dir=$(echo "$path" | sed 's|/files/mkdir||')
      mkdir -p "$dir" &>/dev/null
      echo "HTTP/1.1 200 OK"
      echo "Content-Type: application/json"
      echo ""
      echo '{"success":true}'
      ;;

    # 命令执行
    POST:/exec)
      read content_length
      read cmd_line
      local cmd=$(echo "$cmd_line" | grep -oP '(?<="cmd":")[^"]*')
      local output=$(eval "$cmd" 2>&1 | base64 -w 0)
      echo "HTTP/1.1 200 OK"
      echo "Content-Type: application/json"
      echo ""
      echo "{\"success\":true,\"output\":\"$output\"}"
      ;;

    # 日志查看
    GET:/logs/*)
      local logfile=$(echo "$path" | sed 's|/logs||')
      echo "HTTP/1.1 200 OK"
      echo "Content-Type: application/json"
      echo ""
      if [ -f "$logfile" ]; then
        local content=$(tail -n 100 "$logfile" 2>/dev/null | base64 -w 0)
        echo "{\"success\":true,\"content\":\"$content\"}"
      else
        echo '{"success":false,"error":"Log file not found"}'
      fi
      ;;
    GET:/logs/service/*)
      local svc=$(echo "$path" | sed 's|/logs/service/||')
      echo "HTTP/1.1 200 OK"
      echo "Content-Type: application/json"
      echo ""
      local content=$(journalctl -u "$svc" -n 100 --no-pager 2>/dev/null | base64 -w 0)
      echo "{\"success\":true,\"content\":\"$content\"}"
      ;;

    # Docker高级操作
    GET:/container/logs/*)
      local cid=$(echo "$path" | sed 's|/container/logs/||')
      echo "HTTP/1.1 200 OK"
      echo "Content-Type: application/json"
      echo ""
      local logs=$(docker logs --tail 100 "$cid" 2>&1 | base64 -w 0)
      echo "{\"success\":true,\"logs\":\"$logs\"}"
      ;;
    POST:/container/exec/*)
      local cid=$(echo "$path" | sed 's|/container/exec/||')
      read content_length
      read cmd_line
      local cmd=$(echo "$cmd_line" | grep -oP '(?<="cmd":")[^"]*')
      local output=$(docker exec "$cid" sh -c "$cmd" 2>&1 | base64 -w 0)
      echo "HTTP/1.1 200 OK"
      echo "Content-Type: application/json"
      echo ""
      echo "{\"success\":true,\"output\":\"$output\"}"
      ;;

    *)
      echo "HTTP/1.1 404 Not Found"
      echo "Content-Type: application/json"
      echo ""
      echo '{"error":"Not Found"}'
      ;;
  esac
}

echo "🚀 昱君探针 API服务启动在端口 $PORT"

while true; do
  nc -l -p $PORT -q 1 | {
    read method path proto
    auth=""
    while read line; do
      line=$(echo "$line" | tr -d '\r')
      [ -z "$line" ] && break
      if echo "$line" | grep -q "^Authorization:"; then
        auth=$(echo "$line" | cut -d' ' -f2-)
      fi
    done
    handle_request "$method" "$path" "$auth"
  }
done
SCRIPT_EOF

chmod +x /usr/local/bin/yj.sh

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
  netstat -tlnp | grep yj || ss -tlnp | grep yj
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
    systemctl stop yj 2>/dev/null
    systemctl disable yj 2>/dev/null

    echo "正在释放端口..."
    # 获取服务使用的端口
    PORT=$(grep "Environment=\"PORT=" /etc/systemd/system/yj.service 2>/dev/null | grep -oP 'PORT=\K[0-9]+' || echo "37218")
    
    # 杀死占用端口的进程
    if command -v lsof &>/dev/null; then
      OLD_PID=$(lsof -ti:$PORT 2>/dev/null)
      if [ -n "$OLD_PID" ]; then
        echo "终止占用端口 $PORT 的进程 $OLD_PID..."
        kill -9 $OLD_PID 2>/dev/null
      fi
    elif command -v ss &>/dev/null; then
      OLD_PID=$(ss -tlnp | grep ":$PORT " | grep -oP 'pid=\K[0-9]+' | head -1)
      if [ -n "$OLD_PID" ]; then
        echo "终止占用端口 $PORT 的进程 $OLD_PID..."
        kill -9 $OLD_PID 2>/dev/null
      fi
    fi

    echo "正在删除文件..."
    rm -f /etc/systemd/system/yj.service
    rm -f /usr/local/bin/yj.sh
    rm -f /usr/local/bin/yj

    systemctl daemon-reload

    echo "✅ 昱君探针已卸载，端口已释放"
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
ExecStart=/usr/local/bin/yj.sh
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

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
echo "  yj          - 打开管理面板"
echo "  systemctl status yj  - 查看服务状态"
echo "  journalctl -u yj -f  - 查看实时日志"
echo "=========================================="
