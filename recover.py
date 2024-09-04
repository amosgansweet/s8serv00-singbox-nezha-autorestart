import os
import json
import subprocess
import requests
import time

def send_telegram_message(token, chat_id, message):
    telegram_url = f"https://api.telegram.org/bot{token}/sendMessage"
    telegram_payload = {
        "chat_id": chat_id,
        "text": message,
        "reply_markup": {
            "inline_keyboard": [[{"text": "问题反馈❓", "url": "https://t.me/amosgantian"}]]
        }
    }

    response = requests.post(telegram_url, json=telegram_payload)
    print(f"Telegram 请求状态码：{response.status_code}")
    print(f"Telegram 请求返回内容：{response.text}")

    if response.status_code != 200:
        print("发送 Telegram 消息失败")
    else:
        print("发送 Telegram 消息成功")

# 从环境变量中获取密钥
accounts_json = os.getenv('ACCOUNTS_JSON')
telegram_token = os.getenv('TELEGRAM_TOKEN')
telegram_chat_id = os.getenv('TELEGRAM_CHAT_ID')

# 打印环境变量的值进行检查
print(f"ACCOUNTS_JSON: {accounts_json}")
print(f"TELEGRAM_TOKEN: {telegram_token}")
print(f"TELEGRAM_CHAT_ID: {telegram_chat_id}")

# 检查环境变量是否存在
if not all([telegram_token, telegram_chat_id, accounts_json]):
    raise ValueError("Telegram token, chat ID, or accounts JSON is not set in environment variables.")

# 检查并解析 JSON 字符串
try:
    servers = json.loads(accounts_json)
except json.JSONDecodeError:
    error_message = "ACCOUNTS_JSON 参数格式错误"
    print(error_message)
    send_telegram_message(telegram_token, telegram_chat_id, error_message)
    exit(1)

# 初始化汇总消息
summary_message = "serv00-singbox-nezha 恢复操作结果：\n"

# 默认恢复命令
default_restore_command = [
    "ps aux | grep -v grep | grep run > /dev/null || nohup $HOME/sb/servesb.sh >/dev/null 2>&1 &",
    "ps aux | grep -v grep | grep nezha-agent > /dev/null || nohup $HOME/nezha-agent/nezha-agent.sh >/dev/null 2>&1 &"
]

# 遍历服务器列表并执行恢复操作
for server in servers:
    host = server['host']
    port = server['port']
    username = server['username']
    password = server['password']
    cron_commands = server.get('cron', default_restore_command)
    
    print(f"连接到 {host}...")

    # 如果 cron 命令是字符串，转换为列表
    if isinstance(cron_commands, str):
        cron_commands = [cron_commands]

    # 执行恢复命令（假设使用 SSH 连接和密码认证）
    for command in cron_commands:
        restore_command = f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no -p {port} {username}@{host} '{command}'"
        print(f"执行命令: {restore_command}")  # 添加日志
        try:
            result = subprocess.run(restore_command, shell=True, capture_output=True, text=True, timeout=90)
            if result.returncode == 0:
                # 检查是否有后台进程启动
                time.sleep(20)  # 等待后台进程启动
                verify_command = f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no -p {port} {username}@{host} 'ps aux | grep -v grep | grep {command.split()[0]}'"
                verify_result = subprocess.run(verify_command, shell=True, capture_output=True, text=True)
                if verify_result.returncode == 0:
                    summary_message += f"\n成功恢复 {host} 上的singbox and nezha服务：\n{verify_result.stdout}"
                else:
                    summary_message += f"\n后台进程可能未启动 {host} 上的singbox and nezha服务。"
            else:
                summary_message += f"\n未能恢复 {host} 上的服务：\n{result.stderr}"
        except subprocess.TimeoutExpired as e:
            print(f"命令执行超时: {restore_command}")  # 处理超时
            summary_message += f"\n命令执行超时 {host} 上的singbox and nezha服务。"
        except Exception as e:
            error_message = str(e)
            print(f"未知错误: {error_message}")  # 捕获其他异常
            summary_message += f"\n未能恢复 {host} 上的singbox and nezha服务：\n{error_message}"

# 发送汇总消息到 Telegram
send_telegram_message(telegram_token, telegram_chat_id, summary_message)
