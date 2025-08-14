import tkinter as tk
from tkinter import messagebox, scrolledtext, simpledialog
import platform
import psutil
import socket
import time
import datetime
import os
import sys
import subprocess
import hashlib
import webbrowser
import shutil
import tarfile
import paramiko
import threading
import re
import uuid
import json
import zipfile
import getpass
import logging
import random
import string
import base64
from io import BytesIO
from pathlib import Path

# 初始化日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class SystemUtilityApp:
    def __init__(self, root):
        self.root = root
        self.root.title("系统实用工具")
        self.root.geometry("800x600")

        # 创建菜单栏
        self.menu_bar = tk.Menu(self.root)
        self.root.config(menu=self.menu_bar)

        # 系统菜单
        self.system_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.menu_bar.add_cascade(label="系统", menu=self.system_menu)
        self.system_menu.add_command(label="显示系统信息", command=self.display_system_info)
        self.system_menu.add_command(label="检查CPU使用率", command=self.check_cpu_usage)
        self.system_menu.add_command(label="检查内存使用情况", command=self.check_memory_usage)
        self.system_menu.add_command(label="检查磁盘使用情况", command=self.check_disk_usage)
        self.system_menu.add_command(label="检查网络信息", command=self.check_network_info)
        self.system_menu.add_command(label="列出运行中的进程", command=self.list_processes)
        self.system_menu.add_command(label="终止进程", command=self.kill_process)
        self.system_menu.add_command(label="检查电池状态", command=self.check_battery_status)
        self.system_menu.add_command(label="检查系统运行时间", command=self.check_uptime)
        self.system_menu.add_command(label="显示Python环境信息", command=self.display_python_info)
        self.system_menu.add_command(label="列出环境变量", command=self.list_env_variables)

        # 网络菜单
        self.network_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.menu_bar.add_cascade(label="网络", menu=self.network_menu)
        self.network_menu.add_command(label="Ping主机", command=self.ping_host)
        self.network_menu.add_command(label="Traceroute主机", command=self.traceroute_host)
        self.network_menu.add_command(label="NSLookup主机", command=self.nslookup_host)
        self.network_menu.add_command(label="端口扫描", command=self.port_scan)
        self.network_menu.add_command(label="检查网速（模拟）", command=self.check_internet_speed)
        self.network_menu.add_command(label="监控网络流量", command=self.monitor_network_traffic)

        # 文件菜单
        self.file_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.menu_bar.add_cascade(label="文件", menu=self.file_menu)
        self.file_menu.add_command(label="搜索文件", command=self.search_files)
        self.file_menu.add_command(label="压缩文件", command=self.compress_files)
        self.file_menu.add_command(label="解压文件", command=self.extract_files)
        self.file_menu.add_command(label="清理临时文件", command=self.clean_temp_files)
        self.file_menu.add_command(label="计算文件哈希", command=self.calculate_file_hash)
        self.file_menu.add_command(label="加密文件", command=self.encrypt_file)
        self.file_menu.add_command(label="解密文件", command=self.decrypt_file)

        # 任务菜单
        self.task_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.menu_bar.add_cascade(label="任务", menu=self.task_menu)
        self.task_menu.add_command(label="列出任务", command=self.list_tasks)
        self.task_menu.add_command(label="添加任务", command=self.add_task)

        # 工具菜单
        self.tools_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.menu_bar.add_cascade(label="工具", menu=self.tools_menu)
        self.tools_menu.add_command(label="监控系统", command=self.monitor_system)
        self.tools_menu.add_command(label="SSH连接", command=self.ssh_connect)
        self.tools_menu.add_command(label="编辑环境变量", command=self.edit_env_var)
        self.tools_menu.add_command(label="打开URL", command=self.open_url)
        self.tools_menu.add_command(label="CPU基准测试", command=self.cpu_benchmark)
        self.tools_menu.add_command(label="磁盘碎片整理（仅Windows）", command=self.defragment_disk)
        self.tools_menu.add_command(label="扫描病毒（模拟）", command=self.scan_viruses)
        self.tools_menu.add_command(label="运行脚本", command=self.run_script)
        self.tools_menu.add_command(label="备份到云端（模拟）", command=self.backup_to_cloud)
        self.tools_menu.add_command(label="显示硬件信息", command=self.display_hardware_info)
        self.tools_menu.add_command(label="列出已安装软件", command=self.list_installed_software)
        self.tools_menu.add_command(label="更改主题", command=self.change_theme)
        self.tools_menu.add_command(label="创建备份", command=self.create_backup)
        self.tools_menu.add_command(label="恢复备份", command=self.restore_backup)
        self.tools_menu.add_command(label="运行诊断", command=self.run_diagnostics)
        self.tools_menu.add_command(label="FTP连接", command=self.ftp_connect)
        self.tools_menu.add_command(label="生成随机密码", command=self.generate_password)
        self.tools_menu.add_command(label="查看系统日志", command=self.system_logs)
        self.tools_menu.add_command(label="检查磁盘健康", command=self.disk_health_check)
        self.tools_menu.add_command(label="更新系统（模拟）", command=self.update_system)
        self.tools_menu.add_command(label="查看防火墙状态", command=self.firewall_status)
        self.tools_menu.add_command(label="远程桌面（模拟）", command=self.remote_desktop)
        self.tools_menu.add_command(label="发送邮件（模拟）", command=self.email_sender)
        self.tools_menu.add_command(label="文本转语音（模拟）", command=self.text_to_speech)
        self.tools_menu.add_command(label="生成QR码（模拟）", command=self.qr_code_generator)
        self.tools_menu.add_command(label="剪贴板管理（模拟）", command=self.clipboard_manager)
        self.tools_menu.add_command(label="获取天气（模拟）", command=self.weather_fetch)
        self.tools_menu.add_command(label="货币转换（模拟）", command=self.currency_converter)
        self.tools_menu.add_command(label="录音（模拟）", command=self.voice_recorder)
        self.tools_menu.add_command(label="录屏（模拟）", command=self.screen_recorder)

        # 输出文本框
        self.output_text = scrolledtext.ScrolledText(self.root, wrap=tk.WORD)
        self.output_text.pack(fill=tk.BOTH, expand=True)

    def run(self):
        self.root.mainloop()

    # 功能实现
    def display_system_info(self):
        uname = platform.uname()
        info = (
            f"System: {uname.system}\n"
            f"Node Name: {uname.node}\n"
            f"Release: {uname.release}\n"
            f"Version: {uname.version}\n"
            f"Machine: {uname.machine}\n"
            f"Processor: {uname.processor}\n"
        )
        self.show_output(info)

    def check_cpu_usage(self):
        cpu_usage = psutil.cpu_percent(interval=1)
        per_core = psutil.cpu_percent(interval=1, percpu=True)
        output = f"CPU Usage: {cpu_usage}%\n"
        for i, usage in enumerate(per_core):
            output += f"Core {i}: {usage}%\n"
        self.show_output(output)

    def check_memory_usage(self):
        memory = psutil.virtual_memory()
        output = (
            f"Total Memory: {memory.total / (1024**3):.2f} GB\n"
            f"Available Memory: {memory.available / (1024**3):.2f} GB\n"
            f"Used Memory: {memory.used / (1024**3):.2f} GB\n"
            f"Memory Usage: {memory.percent}%\n"
        )
        self.show_output(output)

    def check_disk_usage(self):
        partition = simpledialog.askstring("Input", "Enter the partition path (e.g., '/' or 'C:\\'):", parent=self.root)
        if partition:
            try:
                usage = psutil.disk_usage(partition)
                output = (
                    f"Total Disk Space: {usage.total / (1024**3):.2f} GB\n"
                    f"Used Disk Space: {usage.used / (1024**3):.2f} GB\n"
                    f"Free Disk Space: {usage.free / (1024**3):.2f} GB\n"
                    f"Disk Usage: {usage.percent}%\n"
                )
                self.show_output(output)
            except Exception as e:
                self.show_output(f"Error: {e}")

    def check_network_info(self):
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
        output = f"Hostname: {hostname}\nIP Address: {ip_address}\n\nNetwork Interfaces:\n"
        for interface, addrs in psutil.net_if_addrs().items():
            output += f"Interface: {interface}\n"
            for addr in addrs:
                output += f"  {addr.family.name}: {addr.address}\n"
        self.show_output(output)

    def list_processes(self):
        output = "PID\tName\tUsername\n"
        for proc in psutil.process_iter(['pid', 'name', 'username']):
            try:
                output += f"{proc.info['pid']}\t{proc.info['name']}\t{proc.info['username']}\n"
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        self.show_output(output)

    def kill_process(self):
        pid = simpledialog.askstring("Input", "Enter the PID of the process to kill:", parent=self.root)
        if pid:
            try:
                pid = int(pid)
                process = psutil.Process(pid)
                process.terminate()
                self.show_output(f"Process {pid} terminated.")
            except Exception as e:
                self.show_output(f"Error: {e}")

    def check_battery_status(self):
        if hasattr(psutil, 'sensors_battery'):
            battery = psutil.sensors_battery()
            if battery:
                output = (
                    f"Battery Percentage: {battery.percent}%\n"
                    f"Power Plugged: {'Yes' if battery.power_plugged else 'No'}\n"
                )
                self.show_output(output)
            else:
                self.show_output("No battery found.")
        else:
            self.show_output("Battery status not available.")

    def check_uptime(self):
        boot_time = psutil.boot_time()
        uptime_seconds = time.time() - boot_time
        uptime_string = str(datetime.timedelta(seconds=int(uptime_seconds)))
        self.show_output(f"System Uptime: {uptime_string}")

    def display_python_info(self):
        output = (
            f"Python Version: {sys.version}\n"
            f"Python Executable: {sys.executable}\n"
        )
        self.show_output(output)

    def list_env_variables(self):
        output = ""
        for key, value in os.environ.items():
            output += f"{key}: {value}\n"
        self.show_output(output)

    def ping_host(self):
        host = simpledialog.askstring("Input", "Enter the host to ping:", parent=self.root)
        if host:
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            command = ['ping', param, '4', host]
            try:
                output = subprocess.check_output(command).decode()
                self.show_output(output)
            except subprocess.CalledProcessError as e:
                self.show_output(f"Ping failed: {e}")

    def traceroute_host(self):
        host = simpledialog.askstring("Input", "Enter the host for traceroute:", parent=self.root)
        if host:
            command = ['tracert' if platform.system().lower() == 'windows' else 'traceroute', host]
            try:
                output = subprocess.check_output(command).decode()
                self.show_output(output)
            except subprocess.CalledProcessError as e:
                self.show_output(f"Traceroute failed: {e}")

    def nslookup_host(self):
        host = simpledialog.askstring("Input", "Enter the host for NSLookup:", parent=self.root)
        if host:
            command = ['nslookup', host]
            try:
                output = subprocess.check_output(command).decode()
                self.show_output(output)
            except subprocess.CalledProcessError as e:
                self.show_output(f"NSLookup failed: {e}")

    def port_scan(self):
        host = simpledialog.askstring("Input", "Enter the host to scan:", parent=self.root)
        if host:
            self.show_output(f"Scanning {host} for open ports...")
            threading.Thread(target=self._port_scan_thread, args=(host,)).start()

    def _port_scan_thread(self, host):
        ports = range(1, 1025)
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((host, port))
            if result == 0:
                self.show_output(f"Port {port} is open")
            sock.close()

    def search_files(self):
        path = simpledialog.askstring("Input", "Enter the directory to search in:", parent=self.root)
        pattern = simpledialog.askstring("Input", "Enter the file pattern (e.g., *.txt):", parent=self.root)
        if path and pattern:
            output = ""
            for root, _, files in os.walk(path):
                for file in files:
                    if re.match(pattern.replace('*', '.*'), file):
                        output += os.path.join(root, file) + "\n"
            self.show_output(output)

    def compress_files(self):
        src = simpledialog.askstring("Input", "Enter the source directory to compress:", parent=self.root)
        dest = simpledialog.askstring("Input", "Enter the destination archive name (e.g., archive.tar.gz or archive.zip):", parent=self.root)
        if src and dest:
            if dest.endswith('.zip'):
                with zipfile.ZipFile(dest, 'w', zipfile.ZIP_DEFLATED) as zipf:
                    for root, _, files in os.walk(src):
                        for file in files:
                            zipf.write(os.path.join(root, file), os.path.relpath(os.path.join(root, file), src))
            else:
                with tarfile.open(dest, "w:gz") as tar:
                    tar.add(src, arcname=os.path.basename(src))
            self.show_output(f"Compressed {src} to {dest}")

    def extract_files(self):
        archive = simpledialog.askstring("Input", "Enter the archive file to extract:", parent=self.root)
        dest = simpledialog.askstring("Input", "Enter the destination directory:", parent=self.root)
        if archive and dest:
            if archive.endswith('.zip'):
                with zipfile.ZipFile(archive, 'r') as zipf:
                    zipf.extractall(dest)
            else:
                with tarfile.open(archive, "r:gz") as tar:
                    tar.extractall(dest)
            self.show_output(f"Extracted {archive} to {dest}")

    def monitor_system(self):
        self.show_output("Monitoring system... Press Ctrl+C to stop.")
        threading.Thread(target=self._monitor_system_thread).start()

    def _monitor_system_thread(self):
        try:
            while True:
                cpu = psutil.cpu_percent()
                mem = psutil.virtual_memory().percent
                disk = psutil.disk_usage('/').percent
                self.show_output(f"CPU: {cpu}% | Memory: {mem}% | Disk: {disk}%")
                time.sleep(1)
        except KeyboardInterrupt:
            self.show_output("Monitoring stopped.")

    def ssh_connect(self):
        host = simpledialog.askstring("Input", "Enter SSH host:", parent=self.root)
        user = simpledialog.askstring("Input", "Enter SSH username:", parent=self.root)
        passwd = simpledialog.askstring("Input", "Enter SSH password:", parent=self.root, show='*')
        if host and user and passwd:
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(host, username=user, password=passwd)
                self.show_output(f"Connected to {host}")
                while True:
                    cmd = simpledialog.askstring("Input", "Enter command (or 'exit'):", parent=self.root)
                    if cmd.lower() == 'exit':
                        break
                    stdin, stdout, stderr = client.exec_command(cmd)
                    output = stdout.read().decode() + stderr.read().decode()
                    self.show_output(output)
                client.close()
            except Exception as e:
                self.show_output(f"SSH failed: {e}")

    def list_tasks(self):
        command = ['schtasks', '/query'] if platform.system().lower() == 'windows' else ['crontab', '-l']
        try:
            output = subprocess.check_output(command).decode()
            self.show_output(output)
        except subprocess.CalledProcessError as e:
            self.show_output(f"Failed to list tasks: {e}")

    def add_task(self):
        if platform.system().lower() == 'windows':
            task_name = simpledialog.askstring("Input", "Enter task name:", parent=self.root)
            command = simpledialog.askstring("Input", "Enter command to run:", parent=self.root)
            time_str = simpledialog.askstring("Input", "Enter time (HH:MM):", parent=self.root)
            subprocess.run(['schtasks', '/create', '/tn', task_name, '/tr', command, '/sc', 'daily', '/st', time_str])
        else:
            command = simpledialog.askstring("Input", "Enter cron command (e.g., '* * * * * echo test'):", parent=self.root)
            with open('temp_cron', 'w') as f:
                f.write(f"{command}\n")
            subprocess.run(['crontab', 'temp_cron'])
            os.remove('temp_cron')
        self.show_output("Task added.")

    def edit_env_var(self):
        key = simpledialog.askstring("Input", "Enter environment variable name:", parent=self.root)
        value = simpledialog.askstring("Input", "Enter new value (blank to delete):", parent=self.root)
        if value:
            os.environ[key] = value
        else:
            os.environ.pop(key, None)
        self.show_output(f"Environment variable {key} updated.")

    def clean_temp_files(self):
        temp_dir = os.path.join(os.environ.get('TEMP', '/tmp'))
        for root, dirs, files in os.walk(temp_dir, topdown=False):
            for file in files:
                try:
                    os.remove(os.path.join(root, file))
                except Exception:
                    pass
            for dir in dirs:
                try:
                    shutil.rmtree(os.path.join(root, dir))
                except Exception:
                    pass
        self.show_output("Temporary files cleaned.")

    def calculate_file_hash(self):
        file_path = simpledialog.askstring("Input", "Enter file path:", parent=self.root)
        if file_path and os.path.isfile(file_path):
            hashes = {'MD5': hashlib.md5(), 'SHA256': hashlib.sha256(), 'SHA512': hashlib.sha512()}
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    for hasher in hashes.values():
                        hasher.update(chunk)
            output = ""
            for name, hasher in hashes.items():
                output += f"{name}: {hasher.hexdigest()}\n"
            self.show_output(output)
        else:
            self.show_output("File not found.")

    def open_url(self):
        url = simpledialog.askstring("Input", "Enter URL to open:", parent=self.root)
        if url:
            webbrowser.open(url)
            self.show_output(f"Opened {url}")

    def cpu_benchmark(self):
        start = time.time()
        for _ in range(1000000):
            _ = 2 ** 20
        elapsed = time.time() - start
        self.show_output(f"CPU Benchmark: {elapsed:.2f} seconds")

    def defragment_disk(self):
        if platform.system().lower() == 'windows':
            subprocess.run(['defrag', 'C:', '/O'])
            self.show_output("Disk defragmentation completed.")
        else:
            self.show_output("Not supported on this platform.")

    def scan_viruses(self):
        self.show_output("Simulating virus scan...")
        time.sleep(2)
        self.show_output("No viruses found (simulation).")

    def run_script(self):
        script_path = simpledialog.askstring("Input", "Enter path to Python script:", parent=self.root)
        if script_path:
            try:
                subprocess.run([sys.executable, script_path], check=True)
                self.show_output("Script executed.")
            except Exception as e:
                self.show_output(f"Failed: {e}")

    def backup_to_cloud(self):
        folder = simpledialog.askstring("Input", "Enter folder to backup:", parent=self.root)
        if folder:
            self.show_output(f"Simulating cloud backup for {folder}...")
            time.sleep(2)
            self.show_output("Backup completed (simulation).")

    def display_hardware_info(self):
        if platform.system().lower() == 'windows':
            cpu = subprocess.check_output(['wmic', 'cpu', 'get', 'name']).decode().strip()
            mem = subprocess.check_output(['wmic', 'memorychip', 'get', 'capacity']).decode().strip()
            output = f"CPU: {cpu}\nMemory: {mem}\n"
            self.show_output(output)
        else:
            self.show_output("Limited hardware info on this platform.")

    def list_installed_software(self):
        if platform.system().lower() == 'windows':
            output = subprocess.check_output(['wmic', 'product', 'get', 'name']).decode()
            self.show_output(output)
        else:
            self.show_output("Not fully supported on this platform.")

    def change_theme(self):
        theme = simpledialog.askstring("Input", "Enter theme (light/dark):", parent=self.root)
        if theme:
            self.show_output(f"{theme.capitalize()} theme applied (simulation).")

    def create_backup(self):
        dest = simpledialog.askstring("Input", "Enter backup destination directory:", parent=self.root)
        if dest:
            backup_file = os.path.join(dest, f"backup_{uuid.uuid4().hex}.tar.gz")
            with tarfile.open(backup_file, "w:gz") as tar:
                tar.add(os.path.expanduser('~'), arcname='home')
            self.show_output(f"Backup created: {backup_file}")

    def restore_backup(self):
        backup_file = simpledialog.askstring("Input", "Enter backup file to restore:", parent=self.root)
        if backup_file:
            with tarfile.open(backup_file, "r:gz") as tar:
                tar.extractall(path=os.path.expanduser('~'))
            self.show_output(f"Backup restored from: {backup_file}")

    def run_diagnostics(self):
        if platform.system().lower() == 'windows':
            subprocess.run(['sfc', '/scannow'])
        else:
            subprocess.run(['fsck', '-n', '/'])
        self.show_output("Diagnostics completed.")

    # 新增功能
    def ftp_connect(self):
        host = simpledialog.askstring("Input", "Enter FTP host:", parent=self.root)
        user = simpledialog.askstring("Input", "Enter FTP username:", parent=self.root)
        passwd = simpledialog.askstring("Input", "Enter FTP password:", parent=self.root, show='*')
        if host and user and passwd:
            try:
                from ftplib import FTP
                ftp = FTP(host)
                ftp.login(user, passwd)
                self.show_output(f"Connected to FTP {host}")
                while True:
                    cmd = simpledialog.askstring("Input", "Enter FTP command (ls/get/put/exit):", parent=self.root)
                    if cmd.lower() == 'exit':
                        break
                    elif cmd.lower() == 'ls':
                        ftp.dir()
                    elif cmd.lower().startswith('get '):
                        file = cmd.split()[1]
                        with open(file, 'wb') as f:
                            ftp.retrbinary(f"RETR {file}", f.write)
                        self.show_output(f"Downloaded {file}")
                    elif cmd.lower().startswith('put '):
                        file = cmd.split()[1]
                        with open(file, 'rb') as f:
                            ftp.storbinary(f"STOR {file}", f)
                        self.show_output(f"Uploaded {file}")
                ftp.quit()
            except Exception as e:
                self.show_output(f"FTP failed: {e}")

    def encrypt_file(self):
        file_path = simpledialog.askstring("Input", "Enter file to encrypt:", parent=self.root)
        if file_path:
            key = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
            try:
                with open(file_path, 'rb') as f:
                    data = f.read()
                encrypted = base64.b64encode(data + key.encode())
                with open(file_path + '.enc', 'wb') as f:
                    f.write(encrypted)
                self.show_output(f"File encrypted as {file_path}.enc with key: {key}")
            except Exception as e:
                self.show_output(f"Encryption failed: {e}")

    def decrypt_file(self):
        file_path = simpledialog.askstring("Input", "Enter encrypted file:", parent=self.root)
        key = simpledialog.askstring("Input", "Enter decryption key:", parent=self.root)
        if file_path and key:
            try:
                with open(file_path, 'rb') as f:
                    encrypted = f.read()
                decrypted = base64.b64decode(encrypted).decode()
                if decrypted.endswith(key):
                    original = decrypted[:-len(key)]
                    with open(file_path.replace('.enc', '_decrypted'), 'w') as f:
                        f.write(original)
                    self.show_output(f"File decrypted as {file_path.replace('.enc', '_decrypted')}")
                else:
                    self.show_output("Invalid key.")
            except Exception as e:
                self.show_output(f"Decryption failed: {e}")

    def check_internet_speed(self):
        self.show_output("Simulating internet speed test...")
        time.sleep(2)
        download = random.uniform(10, 100)
        upload = random.uniform(5, 50)
        output = (
            f"Download Speed: {download:.2f} Mbps\n"
            f"Upload Speed: {upload:.2f} Mbps\n"
        )
        self.show_output(output)

    def generate_password(self):
        length = simpledialog.askinteger("Input", "Enter password length:", parent=self.root)
        if length:
            chars = string.ascii_letters + string.digits + string.punctuation
            password = ''.join(random.choice(chars) for _ in range(length))
            self.show_output(f"Generated Password: {password}")

    def system_logs(self):
        if platform.system().lower() == 'windows':
            output = subprocess.check_output(['wevtutil', 'qe', 'System', '/f:text']).decode()
        else:
            with open('/var/log/syslog', 'r') as f:
                output = f.read()
        self.show_output(output[:1000])  # 显示前1000字符

    def monitor_network_traffic(self):
        self.show_output("Monitoring network traffic... Press Ctrl+C to stop.")
        threading.Thread(target=self._monitor_network_traffic_thread).start()

    def _monitor_network_traffic_thread(self):
        try:
            while True:
                net = psutil.net_io_counters()
                output = f"Bytes Sent: {net.bytes_sent} | Bytes Received: {net.bytes_recv}\n"
                self.show_output(output)
                time.sleep(1)
        except KeyboardInterrupt:
            self.show_output("Monitoring stopped.")

    def disk_health_check(self):
        if platform.system().lower() == 'windows':
            output = subprocess.check_output(['wmic', 'diskdrive', 'get', 'status']).decode()
            self.show_output(output)
        else:
            self.show_output("Simulating disk health check...")
            time.sleep(1)
            self.show_output("Disk health: OK (simulation)")

    def update_system(self):
        if platform.system().lower() == 'windows':
            self.show_output("Run 'wuauclt.exe /detectnow' manually for updates.")
        else:
            subprocess.run(['apt', 'update'])
            subprocess.run(['apt', 'upgrade', '-y'])
        self.show_output("System update simulation completed.")

    def firewall_status(self):
        if platform.system().lower() == 'windows':
            output = subprocess.check_output(['netsh', 'advfirewall', 'show', 'allprofiles']).decode()
        else:
            output = subprocess.check_output(['ufw', 'status']).decode()
        self.show_output(output)

    def remote_desktop(self):
        host = simpledialog.askstring("Input", "Enter remote desktop host:", parent=self.root)
        user = simpledialog.askstring("Input", "Enter username:", parent=self.root)
        passwd = simpledialog.askstring("Input", "Enter password:", parent=self.root, show='*')
        if host and user and passwd:
            self.show_output(f"Simulating remote desktop connection to {host} as {user}...")
            time.sleep(2)
            self.show_output("Connection established (simulation).")

    def email_sender(self):
        recipient = simpledialog.askstring("Input", "Enter recipient email:", parent=self.root)
        subject = simpledialog.askstring("Input", "Enter subject:", parent=self.root)
        body = simpledialog.askstring("Input", "Enter body:", parent=self.root)
        if recipient and subject and body:
            self.show_output(f"Email to {recipient} with subject '{subject}' sent (simulation).")

    def text_to_speech(self):
        text = simpledialog.askstring("Input", "Enter text to convert to speech:", parent=self.root)
        if text:
            self.show_output(f"Simulating text-to-speech for: {text}")
            time.sleep(1)
            self.show_output("Speech generated (simulation).")

    def qr_code_generator(self):
        data = simpledialog.askstring("Input", "Enter data for QR code:", parent=self.root)
        if data:
            self.show_output(f"Simulating QR code generation for: {data}")
            time.sleep(1)
            self.show_output("QR code generated (simulation).")

    def clipboard_manager(self):
        action = simpledialog.askstring("Input", "Enter action (copy/paste):", parent=self.root)
        if action.lower() == 'copy':
            text = simpledialog.askstring("Input", "Enter text to copy:", parent=self.root)
            if text:
                self.show_output(f"Copied to clipboard (simulation): {text}")
        elif action.lower() == 'paste':
            self.show_output("Pasted from clipboard (simulation): [Sample Text]")

    def weather_fetch(self):
        city = simpledialog.askstring("Input", "Enter city name:", parent=self.root)
        if city:
            self.show_output(f"Fetching weather for {city} (simulation)...")
            time.sleep(1)
            temp = random.uniform(-10, 40)
            self.show_output(f"Temperature: {temp:.1f}°C, Condition: Sunny (simulation)")

    def currency_converter(self):
        amount = simpledialog.askfloat("Input", "Enter amount:", parent=self.root)
        from_curr = simpledialog.askstring("Input", "From currency (e.g., USD):", parent=self.root).upper()
        to_curr = simpledialog.askstring("Input", "To currency (e.g., EUR):", parent=self.root).upper()
        if amount and from_curr and to_curr:
            self.show_output(f"Converting {amount} {from_curr} to {to_curr} (simulation)...")
            rate = random.uniform(0.5, 1.5)
            self.show_output(f"Result: {amount * rate:.2f} {to_curr} (simulation)")

    def voice_recorder(self):
        self.show_output("Recording voice (simulation)... Press Ctrl+C to stop.")
        time.sleep(5)
        self.show_output("Recording saved (simulation).")

    def screen_recorder(self):
        self.show_output("Recording screen (simulation)... Press Ctrl+C to stop.")
        time.sleep(5)
        self.show_output("Screen recording saved (simulation).")

    def show_output(self, text):
        self.output_text.insert(tk.END, text + "\n")
        self.output_text.see(tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = SystemUtilityApp(root)
    app.run()
