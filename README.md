# fastj

# 功能

0. PID is pid of fastj
1. kill -SIGUSR1        PID         # 打印hash表
2. kill -SIGUSR2        PID         # 重新加载 url.ini

# 举例

连续执行中间要sleep 1
kill -SIGUSR2        PID; sleep 1; kill -SIGUSR1        PID


