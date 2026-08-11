#!/bin/bash
# 停止滚动小球游戏服务器
pkill -f "python3 server.py" && echo "已停止" || echo "没有运行中的进程"
