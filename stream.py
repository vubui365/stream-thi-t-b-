from flask import Flask, render_template, jsonify, request, Response
import subprocess
import threading
import time
import os
from pysnmp.hlapi import * # type: ignore
import pymsteams # type: ignore
from datetime import datetime, timedelta
import csv
from io import StringIO
import json
import re
import concurrent.futures

app = Flask(__name__)

# Đường dẫn file danh sách thiết bị
FILE_PATH = r"D:\danhsach.txt"

# Webhook URL cho Microsoft Teams
TEAMS_WEBHOOK_URL = "https://riekerworld.webhook.office.com/webhookb2/f5b03295-141d-4b4d-a771-be86875ad09a@d05c6e7a-e5d1-4af0-a643-f829e6e08d31/IncomingWebhook/d6a8fd7946b743a6b5c27f5a46a5c19d/c09c20f3-d95c-479b-8554-e2914cce2924/V2P0qYVz3A5_XBSdH0NZBMdt2BhBUTmMCCaH03fxp_rRk1"

def send_teams_alert(device_name, ip, status):
    try:
        my_teams_message = pymsteams.connectorcard(TEAMS_WEBHOOK_URL)
        
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        if status == "Offline":
            my_teams_message.title("⚠️ CẢNH BÁO: THIẾT BỊ OFFLINE")
            my_teams_message.color("e74c3c")
            my_teams_message.text(f"""
**THIẾT BỊ:** {device_name}
**ĐỊA CHỈ IP:** {ip}
**TRẠNG THÁI:** ❌ OFFLINE
**THỜI ĐIỂM:** {current_time}

⚠️ Thiết bị đã mất kết nối. Vui lòng kiểm tra ngay!
""")
        elif status == "Online":
            my_teams_message.title("✅ THÔNG BÁO: THIẾT BỊ ĐÃ PHỤC HỒI")
            my_teams_message.color("27ae60")
            my_teams_message.text(f"""
**THIẾT BỊ:** {device_name}
**ĐỊA CHỈ IP:** {ip}
**TRẠNG THÁI:** ✅ ONLINE
**THỜI ĐIỂM:** {current_time}

🎉 Thiết bị đã kết nối lại thành công!
""")
        
        my_teams_message.send()
        print(f"✅ Đã gửi cảnh báo Teams: {device_name} ({ip}) - {status}")
        return True
        
    except Exception as e:
        print(f"❌ Lỗi gửi cảnh báo Teams: {e}")
        return False

# Hàm kiểm tra trạng thái bằng ping với độ trễ
def check_status_ping(ip):
    try:
        # Thực hiện ping và đo thời gian
        start_time = time.time()
        output = subprocess.check_output(["ping", "-n", "2", "-w", "1000", ip], universal_newlines=True)
        end_time = time.time()
        
        if "Reply from" in output:
            # Parse thời gian từ output
            time_matches = re.findall(r"time[=<](\d+)ms", output)
            if time_matches:
                latency = int(time_matches[-1])
            else:
                # Tính thời gian trung bình
                latency = int((end_time - start_time) * 1000 / 2)
            
            return "Online", latency
        return "Offline", None
    except subprocess.CalledProcessError:
        return "Offline", None
    except Exception as e:
        print(f"Lỗi ping {ip}: {e}")
        return "Offline", None

# Hàm kiểm tra trạng thái chính
def check_status(ip):
    try:
        errorIndication, errorStatus, errorIndex, varBinds = next(
            getCmd(SnmpEngine(),
                CommunityData('public', mpModel=0),
                UdpTransportTarget((ip, 161), timeout=1, retries=0),
                ContextData(),
                ObjectType(ObjectIdentity('1.3.6.1.2.1.1.3.0'))
            )
        )
        if errorIndication or errorStatus:
            status, latency = check_status_ping(ip)
            return status, latency
        else:
            # SNMP thành công, thử ping để lấy độ trễ
            status, latency = check_status_ping(ip)
            if status == "Online":
                return "Online", latency
            return "Online", None
    except Exception as e:
        return check_status_ping(ip)

# Lớp giám sát
class DeviceMonitor:
    def __init__(self):
        self.devices = self.load_devices()
        self.running = True
        self.update_thread = threading.Thread(target=self.update_status_loop)
        self.update_thread.daemon = True
        self.update_thread.start()
        print(f"Đã khởi tạo DeviceMonitor với {len(self.devices)} thiết bị")

    def load_devices(self):
        devices = []
        if os.path.exists(FILE_PATH):
            with open(FILE_PATH, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        parts = line.split(",")
                        if len(parts) == 2:
                            name = parts[0].strip()
                            ip = parts[1].strip()
                            
                            # Kiểm tra trạng thái ban đầu
                            initial_status, initial_latency = check_status(ip)
                            current_time = datetime.now()
                            
                            # Khởi tạo thiết bị
                            device_data = {
                                "STT": len(devices) + 1,
                                "Tên": name,
                                "IP": ip,
                                "Trạng Thái": initial_status,
                                "Cập nhật lúc": current_time.strftime("%Y-%m-%d %H:%M:%S"),
                                "Thời gian Trạng thái": current_time.strftime("%Y-%m-%d %H:%M:%S"),
                                "previous_status": initial_status,
                                "status_change_time": current_time,
                                "last_alert_sent": None,
                                "Latency": initial_latency,
                                "LatencyHistory": [],
                                "last_update_timestamp": time.time(),
                                "Bắt Đầu Offline": "--",
                                "Offline Duration": "--",
                                "offline_since": None
                            }
                            
                            # Nếu offline ngay từ đầu, set thời gian bắt đầu
                            if initial_status == "Offline":
                                device_data["offline_since"] = current_time
                                device_data["Bắt Đầu Offline"] = current_time.strftime("%Y-%m-%d %H:%M:%S")
                                device_data["Offline Duration"] = "0s"
                            
                            # Thêm lịch sử độ trễ nếu có
                            if initial_latency:
                                device_data["LatencyHistory"].append({
                                    "timestamp": time.time(),
                                    "latency": initial_latency
                                })
                            
                            devices.append(device_data)
                
                print(f"Đã tải {len(devices)} thiết bị từ file")
        else:
            print(f"File {FILE_PATH} không tồn tại!")
        
        return devices

    def reload_devices(self):
        """Tải lại danh sách thiết bị từ file"""
        old_devices = {device["IP"]: device for device in self.devices}
        new_devices = []
        
        if os.path.exists(FILE_PATH):
            with open(FILE_PATH, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        parts = line.split(",")
                        if len(parts) == 2:
                            name = parts[0].strip()
                            ip = parts[1].strip()
                            
                            current_time = datetime.now()
                            
                            if ip in old_devices:
                                # Giữ lại thông tin từ thiết bị cũ
                                old_device = old_devices[ip]
                                
                                # Kiểm tra trạng thái hiện tại
                                current_status, current_latency = check_status(ip)
                                
                                device_data = {
                                    "STT": len(new_devices) + 1,
                                    "Tên": name,
                                    "IP": ip,
                                    "Trạng Thái": current_status,
                                    "Cập nhật lúc": current_time.strftime("%Y-%m-%d %H:%M:%S"),
                                    "Thời gian Trạng thái": old_device.get("Thời gian Trạng thái", "--"),
                                    "previous_status": old_device.get("previous_status"),
                                    "status_change_time": old_device.get("status_change_time"),
                                    "offline_since": old_device.get("offline_since"),
                                    "last_alert_sent": old_device.get("last_alert_sent"),
                                    "Latency": current_latency,
                                    "LatencyHistory": old_device.get("LatencyHistory", []),
                                    "last_update_timestamp": time.time(),
                                    "Bắt Đầu Offline": old_device.get("Bắt Đầu Offline", "--"),
                                    "Offline Duration": old_device.get("Offline Duration", "--")
                                }
                                
                                # Nếu đang offline, giữ lại thời gian bắt đầu offline
                                if current_status == "Offline" and not device_data["offline_since"]:
                                    device_data["offline_since"] = current_time
                                    device_data["Bắt Đầu Offline"] = current_time.strftime("%Y-%m-%d %H:%M:%S")
                                    device_data["Offline Duration"] = "0s"
                                
                                # Thêm độ trễ hiện tại vào lịch sử
                                if current_latency:
                                    device_data["LatencyHistory"].append({
                                        "timestamp": time.time(),
                                        "latency": current_latency
                                    })
                                    if len(device_data["LatencyHistory"]) > 20:
                                        device_data["LatencyHistory"] = device_data["LatencyHistory"][-20:]
                                
                            else:
                                # Thiết bị mới
                                current_status, current_latency = check_status(ip)
                                
                                device_data = {
                                    "STT": len(new_devices) + 1,
                                    "Tên": name,
                                    "IP": ip,
                                    "Trạng Thái": current_status,
                                    "Cập nhật lúc": current_time.strftime("%Y-%m-%d %H:%M:%S"),
                                    "Thời gian Trạng thái": current_time.strftime("%Y-%m-%d %H:%M:%S"),
                                    "previous_status": current_status,
                                    "status_change_time": current_time,
                                    "offline_since": None,
                                    "last_alert_sent": None,
                                    "Latency": current_latency,
                                    "LatencyHistory": [],
                                    "last_update_timestamp": time.time(),
                                    "Bắt Đầu Offline": "--",
                                    "Offline Duration": "--"
                                }
                                
                                # Nếu offline ngay từ đầu
                                if current_status == "Offline":
                                    device_data["offline_since"] = current_time
                                    device_data["Bắt Đầu Offline"] = current_time.strftime("%Y-%m-%d %H:%M:%S")
                                    device_data["Offline Duration"] = "0s"
                                
                                # Thêm lịch sử độ trễ
                                if current_latency:
                                    device_data["LatencyHistory"].append({
                                        "timestamp": time.time(),
                                        "latency": current_latency
                                    })
                            
                            new_devices.append(device_data)
            
            # Cập nhật lại STT
            for i, device in enumerate(new_devices):
                device["STT"] = i + 1
            
            old_count = len(self.devices)
            self.devices = new_devices
            new_count = len(self.devices)
            
            print(f"Đã reload thiết bị: {old_count} → {new_count}")
            
            return new_count
        else:
            print(f"File {FILE_PATH} không tồn tại!")
            return 0

    def update_status_loop(self):
        print("Bắt đầu vòng lặp cập nhật trạng thái...")
        while self.running:
            current_time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            current_timestamp = time.time()
            current_time = datetime.now()
            
            for device in self.devices:
                new_status, latency = check_status(device["IP"])
                old_status = device.get("previous_status")
                
                # DEBUG: In ra trạng thái nếu cần
                if new_status != old_status and old_status is not None:
                    print(f"🔄 {device['Tên']} ({device['IP']}): {old_status} → {new_status}")
                
                # Đảm bảo các trường tồn tại
                device.setdefault("Bắt Đầu Offline", "--")
                device.setdefault("Offline Duration", "--")
                
                # CẬP NHẬT BẮT BUỘC MỖI LẦN KIỂM TRA
                device["Cập nhật lúc"] = current_time_str
                device["last_update_timestamp"] = current_timestamp
                device["Trạng Thái"] = new_status  # LUÔN cập nhật trạng thái
                
                # Cập nhật độ trễ
                if latency is not None:
                    device["Latency"] = latency
                    device["LatencyHistory"].append({
                        "timestamp": current_timestamp,
                        "latency": latency
                    })
                    if len(device["LatencyHistory"]) > 20:
                        device["LatencyHistory"] = device["LatencyHistory"][-20:]
                
                # XỬ LÝ THAY ĐỔI TRẠNG THÁI
                if new_status != old_status:
                    device["Thời gian Trạng thái"] = current_time_str
                    device["status_change_time"] = current_time
                    
                    # ONLINE → OFFLINE
                    if new_status == "Offline" and old_status == "Online":
                        device["offline_since"] = current_time
                        device["Bắt Đầu Offline"] = current_time_str
                        device["Offline Duration"] = "0s"
                        
                        # Gửi cảnh báo
                        if device.get("last_alert_sent") != "offline":
                            try:
                                send_teams_alert(device["Tên"], device["IP"], "Offline")
                                device["last_alert_sent"] = "offline"
                                print(f"✅ Cảnh báo Teams: {device['Tên']} OFFLINE")
                            except Exception as e:
                                print(f"❌ Lỗi cảnh báo Offline: {e}")
                    
                    # OFFLINE → ONLINE
                    elif new_status == "Online" and old_status == "Offline":
                        # Reset thời gian offline
                        device["offline_since"] = None
                        device["Bắt Đầu Offline"] = "--"
                        device["Offline Duration"] = "--"
                        
                        # Gửi cảnh báo phục hồi
                        try:
                            send_teams_alert(device["Tên"], device["IP"], "Online")
                            device["last_alert_sent"] = "online"
                            print(f"✅ Cảnh báo Teams: {device['Tên']} ONLINE")
                        except Exception as e:
                            print(f"❌ Lỗi cảnh báo Online: {e}")
                    
                    # Cập nhật trạng thái trước đó
                    device["previous_status"] = new_status
                
                # Nếu không thay đổi nhưng vẫn offline, tính thời gian offline
                elif new_status == "Offline" and device.get("offline_since"):
                    offline_duration = current_time - device["offline_since"]
                    
                    # Tính toán thời gian offline
                    days = offline_duration.days
                    hours, remainder = divmod(offline_duration.seconds, 3600)
                    minutes, seconds = divmod(remainder, 60)
                    
                    if days > 0:
                        duration_str = f"{days}d {hours}h {minutes}m {seconds}s"
                    elif hours > 0:
                        duration_str = f"{hours}h {minutes}m {seconds}s"
                    elif minutes > 0:
                        duration_str = f"{minutes}m {seconds}s"
                    else:
                        duration_str = f"{seconds}s"
                    
                    device["Offline Duration"] = duration_str
                
                # Nếu không thay đổi và đang online, đảm bảo các trường offline được reset
                elif new_status == "Online":
                    device["Bắt Đầu Offline"] = "--"
                    device["Offline Duration"] = "--"
                    if "offline_since" in device:
                        device["offline_since"] = None
                
                # Cập nhật trạng thái trước đó nếu chưa có
                if device.get("previous_status") is None:
                    device["previous_status"] = new_status
            
            time.sleep(3)  # Giảm thời gian chờ xuống 3 giây

    def get_devices(self, search=None, status_filter=None, page=1, per_page=20):
        """Lấy danh sách thiết bị với tìm kiếm, lọc và phân trang"""
        filtered_devices = self.devices.copy()
        
        if search and search.strip():
            search_lower = search.lower().strip()
            filtered_devices = [
                d for d in filtered_devices 
                if search_lower in d["Tên"].lower() or search_lower in d["IP"].lower()
            ]
        
        if status_filter and status_filter != "all":
            filtered_devices = [
                d for d in filtered_devices 
                if d["Trạng Thái"] == status_filter
            ]
            
        total_devices = len(filtered_devices)
        
        start_index = (page - 1) * per_page
        end_index = start_index + per_page
        paginated_devices = filtered_devices[start_index:end_index]
        
        online_count = sum(1 for d in filtered_devices if d["Trạng Thái"] == "Online")
        offline_count = sum(1 for d in filtered_devices if d["Trạng Thái"] == "Offline")
        
        return {
            "devices": paginated_devices,
            "total": total_devices,
            "page": page,
            "per_page": per_page,
            "total_pages": max(1, (total_devices + per_page - 1) // per_page),
            "online_count": online_count,
            "offline_count": offline_count
        }

# Khởi tạo monitor
monitor = DeviceMonitor()
def check_status_parallel(ip):
    """Kiểm tra trạng thái với xử lý đa luồng"""
    return ip, check_status(ip)

def update_status_loop_optimized(self):
    """Phiên bản tối ưu với đa luồng"""
    print("Bắt đầu vòng lặp cập nhật trạng thái (tối ưu)...")
    
    while self.running:
        start_time = time.time()
        current_time = datetime.now()
        current_time_str = current_time.strftime("%Y-%m-%d %H:%M:%S")
        current_timestamp = time.time()
        
        # Sử dụng ThreadPoolExecutor để kiểm tra nhiều thiết bị cùng lúc
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            # Tạo tasks cho tất cả thiết bị
            future_to_ip = {executor.submit(check_status_parallel, device["IP"]): device["IP"] 
                        for device in self.devices}
            
            # Xử lý kết quả khi hoàn thành
            for future in concurrent.futures.as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    ip_result, (new_status, latency) = future.result()
                    
                    # Tìm thiết bị tương ứng
                    device = next((d for d in self.devices if d["IP"] == ip), None)
                    if not device:
                        continue
                    
                    old_status = device.get("previous_status")
                    
                    # Cập nhật thông tin cơ bản
                    device["Cập nhật lúc"] = current_time_str
                    device["last_update_timestamp"] = current_timestamp
                    device["Trạng Thái"] = new_status
                    
                    # Cập nhật độ trễ
                    if latency is not None:
                        device["Latency"] = latency
                        device["LatencyHistory"].append({
                            "timestamp": current_timestamp,
                            "latency": latency
                        })
                        if len(device["LatencyHistory"]) > 10:  # Giảm lịch sử để tiết kiệm bộ nhớ
                            device["LatencyHistory"] = device["LatencyHistory"][-10:]
                    
                    # Xử lý thay đổi trạng thái
                    if new_status != old_status and old_status is not None:
                        device["Thời gian Trạng thái"] = current_time_str
                        device["status_change_time"] = current_time
                        
                        # OFFLINE → ONLINE
                        if new_status == "Online" and old_status == "Offline":
                            device["offline_since"] = None
                            device["Bắt Đầu Offline"] = "--"
                            device["Offline Duration"] = "--"
                            
                            # Gửi cảnh báo
                            try:
                                send_teams_alert(device["Tên"], device["IP"], "Online")
                                device["last_alert_sent"] = "online"
                                print(f"✅ {device['Tên']} đã ONLINE")
                            except Exception as e:
                                print(f"❌ Lỗi cảnh báo Online: {e}")
                        
                        # ONLINE → OFFLINE
                        elif new_status == "Offline" and old_status == "Online":
                            device["offline_since"] = current_time
                            device["Bắt Đầu Offline"] = current_time_str
                            device["Offline Duration"] = "0s"
                            
                            # Gửi cảnh báo
                            if device.get("last_alert_sent") != "offline":
                                try:
                                    send_teams_alert(device["Tên"], device["IP"], "Offline")
                                    device["last_alert_sent"] = "offline"
                                    print(f"⚠️ {device['Tên']} đã OFFLINE")
                                except Exception as e:
                                    print(f"❌ Lỗi cảnh báo Offline: {e}")
                        
                        device["previous_status"] = new_status
                    
                    # Cập nhật thời gian offline nếu đang offline
                    elif new_status == "Offline" and device.get("offline_since"):
                        offline_duration = current_time - device["offline_since"]
                        days = offline_duration.days
                        hours, remainder = divmod(offline_duration.seconds, 3600)
                        minutes, seconds = divmod(remainder, 60)
                        
                        if days > 0:
                            duration_str = f"{days}d {hours}h {minutes}m {seconds}s"
                        elif hours > 0:
                            duration_str = f"{hours}h {minutes}m {seconds}s"
                        elif minutes > 0:
                            duration_str = f"{minutes}m {seconds}s"
                        else:
                            duration_str = f"{seconds}s"
                        
                        device["Offline Duration"] = duration_str
                    
                    # Cập nhật previous_status nếu chưa có
                    if device.get("previous_status") is None:
                        device["previous_status"] = new_status
                        
                except Exception as e:
                    print(f"Lỗi khi kiểm tra {ip}: {e}")
        
        # Tính thời gian thực thi
        execution_time = time.time() - start_time
        sleep_time = max(1, 3 - execution_time)  # Đảm bảo mỗi vòng lặp cách nhau 3 giây
        time.sleep(sleep_time)
# =============== FLASK ROUTES ===============

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/devices')
def api_get_devices():
    try:
        search = request.args.get('search', '')
        status_filter = request.args.get('status', 'all')
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        
        result = monitor.get_devices(
            search=search,
            status_filter=status_filter,
            page=page,
            per_page=per_page
        )
        
        return jsonify(result)
    except Exception as e:
        print(f"Lỗi trong /api/devices: {str(e)}")
        return jsonify({
            "error": str(e),
            "devices": [],
            "total": 0,
            "page": page,
            "per_page": per_page,
            "total_pages": 0,
            "online_count": 0,
            "offline_count": 0
        }), 500

@app.route('/api/reload', methods=['POST'])
def reload():
    try:
        new_count = monitor.reload_devices()
        return jsonify({
            "success": True,
            "message": f"Danh sách đã được tải lại thành công! Có {new_count} thiết bị.",
            "count": new_count,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
    except Exception as e:
        print(f"Lỗi khi reload: {str(e)}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@app.route('/api/export/csv')
def export_csv():
    """Xuất danh sách thiết bị ra CSV"""
    try:
        search = request.args.get('search', '')
        status_filter = request.args.get('status', 'all')
        
        result = monitor.get_devices(
            search=search,
            status_filter=status_filter,
            page=1,
            per_page=10000
        )
        
        output = StringIO()
        writer = csv.writer(output)
        
        output.write('\ufeff')
        writer.writerow(['STT', 'Tên', 'IP', 'Trạng Thái', 'Cập nhật lúc', 'Thời gian Trạng thái', 'Bắt Đầu Offline', 'Offline Duration'])
        
        for device in result['devices']:
            writer.writerow([
                device.get('STT', ''),
                device.get('Tên', ''),
                device.get('IP', ''),
                device.get('Trạng Thái', ''),
                device.get('Cập nhật lúc', ''),
                device.get('Thời gian Trạng thái', ''),
                device.get('Bắt Đầu Offline', ''),
                device.get('Offline Duration', '')
            ])
        
        output.seek(0)
        filename = f"devices_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        
        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={
                "Content-Disposition": f"attachment; filename={filename}",
                "Content-Type": "text/csv; charset=utf-8"
            }
        )
        
    except Exception as e:
        print(f"Lỗi khi export CSV: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/ping/<path:ip_path>')
def ping_single_ip(ip_path):
    try:
        if ':' in ip_path:
            ip = ip_path.split(':')[0]
        else:
            ip = ip_path
            
        status, latency = check_status_ping(ip)
        
        return jsonify({
            "ip": ip,
            "original_request": ip_path,
            "status": status,
            "latency": latency,
            "latency_text": f"{latency}ms" if latency else "N/A",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
    except Exception as e:
        return jsonify({
            "ip": ip_path,
            "status": "Error",
            "error": str(e),
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }), 500

@app.route('/api/device-details/<ip>')
def get_device_details(ip):
    """API lấy thông tin chi tiết của một thiết bị"""
    try:
        device = next((d for d in monitor.devices if d["IP"] == ip), None)
        if not device:
            return jsonify({"error": "Device not found"}), 404
        
        # Kiểm tra ping để có thông tin mới nhất
        status, latency = check_status_ping(ip)
        
        # Tính chất lượng kết nối
        quality = "unknown"
        if latency:
            if latency < 30:
                quality = "excellent"
            elif latency < 60:
                quality = "good"
            elif latency < 100:
                quality = "fair"
            elif latency < 200:
                quality = "poor"
            else:
                quality = "bad"
        
        return jsonify({
            "device": {
                "name": device["Tên"],
                "ip": device["IP"],
                "status": status,
                "latency": latency,
                "latency_history": [d["latency"] for d in device.get("LatencyHistory", [])[-10:]],
                "connection_quality": quality,
                "last_updated": device.get("Cập nhật lúc", "--"),
                "status_since": device.get("Thời gian Trạng thái", "--"),
                "offline_duration": device.get("Offline Duration", "--"),
                "offline_since": device.get("Bắt Đầu Offline", "--")
            }
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/stats')
def get_stats():
    """API lấy thống kê tổng quan"""
    try:
        devices = monitor.devices
        online_count = sum(1 for d in devices if d["Trạng Thái"] == "Online")
        offline_count = sum(1 for d in devices if d["Trạng Thái"] == "Offline")
        total = len(devices)
        
        # Tính phần trăm uptime
        uptime_percent = (online_count / total * 100) if total > 0 else 0
        
        return jsonify({
            "total_devices": total,
            "online_devices": online_count,
            "offline_devices": offline_count,
            "uptime_percent": round(uptime_percent, 1),
            "last_update": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000, use_reloader=False)