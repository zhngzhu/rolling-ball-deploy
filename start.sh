#!/bin/bash
# 滚动小球游戏服务器 - 一键启动脚本（后台运行）
# 用法： bash start.sh
# 停止： bash stop.sh   或   pkill -f "python3 server.py"

# 切换到本脚本所在目录（保证相对路径正确）
cd "$(dirname "$0")"

# ===== 环境变量（可按需修改）=====
export PORT=8080            # 游戏对外端口（云安全组需放行此端口）
export ADMIN_PASS=pc767d54  # 管理后台密码（admin.html 登录用，账号固定为 user）
export ADMIN_REMOTE=1       # 1=允许从公网访问后台（仍需上面密码，安全）；改 0 则仅本机可进
export TRUST_XFF=1          # 1=信任反向代理/X-Forwarded-For，拿到真实玩家 IP（用了 nginx/负载均衡必开）
# export DATA_DIR=/data     # 可选：若挂载了云盘卷（如 /data），取消注释，存档写入该卷

# 后台启动，日志写入 server.log
nohup python3 server.py > server.log 2>&1 &
echo "已启动，进程 PID=$!"
echo "查看日志： tail -f server.log"
echo "游戏地址： http://<服务器公网IP>:${PORT}/"
echo "管理后台： http://<服务器公网IP>:${PORT}/admin.html  （账号 user / 密码 ${ADMIN_PASS}）"
