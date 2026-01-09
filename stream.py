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

app = Flask(__name__)

# Đường dẫn file danh sách thiết bị
FILE_PATH = r"D:\danhsach.txt"

# Webhook URL cho Microsoft Teams
TEAMS_WEBHOOK_URL = "hs://riekerworld.webhook.office.com/webhookb2/f5b03295-141d-4b4d-a771-be86875ad09a@d05c6e7a-e5d1-4af0-a643-f829e6e08d31/IncomingWebhook/d6a8fd7946b743a6b5c27f5a46a5c19d/c09c20f3-d95c-479b-8554-e2914cce2924/V2P0qYVz3A5_XBSdH0NZBMdt2BhBUTmMCCaH03fxp_rRk1"

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
                            devices.append({
                                "STT": len(devices) + 1,
                                "Tên": name,
                                "IP": ip,
                                "Trạng Thái": "Checking...",
                                "Cập nhật lúc": "--",
                                "Thời gian Trạng thái": "--",
                                "Bắt Đầu Offline": "--",  
                                "Offline Duration": "--",  
                                "previous_status": None,
                                "status_change_time": None,
                                "offline_since": None,
                                "last_alert_sent": None,
                                "Latency": None,
                                "LatencyHistory": [],
                                "last_update_timestamp": time.time()
                            })
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
                            
                            if ip in old_devices:
                                old_device = old_devices[ip]
                                device = {
                                    "STT": len(new_devices) + 1,
                                    "Tên": name,
                                    "IP": ip,
                                    "Trạng Thái": old_device["Trạng Thái"],
                                    "Cập nhật lúc": old_device["Cập nhật lúc"],
                                    "Thời gian Trạng thái": old_device["Thời gian Trạng thái"],
                                    "Bắt Đầu Offline": old_device.get("Bắt Đầu Offline", "--"),  
                                    "Offline Duration": old_device.get("Offline Duration", "--"),
                                    "previous_status": old_device["previous_status"],
                                    "status_change_time": old_device["status_change_time"],
                                    "offline_since": old_device["offline_since"],
                                    "last_alert_sent": old_device["last_alert_sent"],
                                    "Latency": old_device.get("Latency"),
                                    "LatencyHistory": old_device.get("LatencyHistory", []),
                                    "last_update_timestamp": old_device.get("last_update_timestamp", time.time())
                                }
                            else:
                                device = {
                                    "STT": len(new_devices) + 1,
                                    "Tên": name,
                                    "IP": ip,
                                    "Trạng Thái": "Checking...",
                                    "Cập nhật lúc": "--",
                                    "Thời gian Trạng thái": "--",
                                    "Bắt Đầu Offline": "--",  
                                    "Offline Duration": "--",
                                    "previous_status": None,
                                    "status_change_time": None,
                                    "offline_since": None,
                                    "last_alert_sent": None,
                                    "Latency": None,
                                    "LatencyHistory": [],
                                    "last_update_timestamp": time.time()
                                }
                            
                            new_devices.append(device)
            
            old_count = len(self.devices)
            self.devices = new_devices
            new_count = len(self.devices)
            
            for i, device in enumerate(self.devices):
                device["STT"] = i + 1
            
            print(f"Đã reload thiết bị: {old_count} -> {new_count}")
            
            removed_devices = set(old_devices.keys()) - {device["IP"] for device in self.devices}
            if removed_devices:
                print(f"Thiết bị đã bị xóa: {removed_devices}")
            
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
                old_status = device["previous_status"]
                
                # Đảm bảo các trường tồn tại
                if "Bắt Đầu Offline" not in device:
                    device["Bắt Đầu Offline"] = "--"
                if "Offline Duration" not in device:
                    device["Offline Duration"] = "--"
                
                # Xử lý khi trạng thái thay đổi
                if new_status != old_status and old_status is not None:
                    device["Thời gian Trạng thái"] = current_time_str
                    device["status_change_time"] = current_time
                    
                    if new_status == "Offline":
                        device["offline_since"] = current_time
                        device["Bắt Đầu Offline"] = current_time_str
                        # Gửi cảnh báo nếu chưa gửi Offline
                        if device.get("last_alert_sent") != "offline":
                            try:
                                send_teams_alert(device["Tên"], device["IP"], "Offline")
                                device["last_alert_sent"] = "offline"
                                print(f"✅ Đã gửi cảnh báo Teams: {device['Tên']} OFFLINE")
                            except Exception as e:
                                print(f"❌ Lỗi gửi cảnh báo Offline: {e}")
                    
                    elif new_status == "Online" and old_status == "Offline":
                        device["offline_since"] = None
                        device["Bắt Đầu Offline"] = "--"
                        device["Offline Duration"] = "--"
                        # Gửi cảnh báo khi từ Offline -> Online
                        try:
                            send_teams_alert(device["Tên"], device["IP"], "Online")
                            device["last_alert_sent"] = "online"
                            print(f"✅ Đã gửi cảnh báo Teams: {device['Tên']} ONLINE")
                        except Exception as e:
                            print(f"❌ Lỗi gửi cảnh báo Online: {e}")
                
                # Nếu đây là lần đầu tiên (khởi tạo)
                if old_status is None:
                    device["previous_status"] = new_status
                    device["Thời gian Trạng thái"] = current_time_str
                    if new_status == "Offline":
                        device["offline_since"] = current_time
                        device["Bắt Đầu Offline"] = current_time_str
                
                # Cập nhật trạng thái
                device["previous_status"] = new_status
                device["Trạng Thái"] = new_status
                device["Cập nhật lúc"] = current_time_str
                device["last_update_timestamp"] = current_timestamp
                
                # Cập nhật độ trễ
                if latency is not None:
                    device["Latency"] = latency
                    device["LatencyHistory"].append({
                        "timestamp": current_timestamp,
                        "latency": latency
                    })
                    if len(device["LatencyHistory"]) > 20:
                        device["LatencyHistory"] = device["LatencyHistory"][-20:]
                
                # Tính thời gian offline cho thiết bị offline
                if new_status == "Offline":
                    if device["offline_since"]:
                        offline_duration = current_time - device["offline_since"]
                        total_seconds = int(offline_duration.total_seconds())
                        
                        days = total_seconds // 86400
                        hours = (total_seconds % 86400) // 3600
                        minutes = (total_seconds % 3600) // 60
                        seconds = total_seconds % 60
                        
                        if days > 0:
                            duration_str = f"{days}d {hours}h {minutes}m"
                        elif hours > 0:
                            duration_str = f"{hours}h {minutes}m {seconds}s"
                        elif minutes > 0:
                            duration_str = f"{minutes}m {seconds}s"
                        else:
                            duration_str = f"{seconds}s"
                        
                        device["Offline Duration"] = duration_str
                        
                        # Chỉ cập nhật Bắt Đầu Offline nếu chưa có
                        if device["Bắt Đầu Offline"] == "--":
                            device["Bắt Đầu Offline"] = device["offline_since"].strftime("%Y-%m-%d %H:%M:%S")
                    else:
                        # Nếu offline nhưng chưa có thời gian bắt đầu
                        device["offline_since"] = current_time
                        device["Bắt Đầu Offline"] = current_time_str
                        device["Offline Duration"] = "0s"
                else:
                    # Nếu online, reset thời gian offline
                    if "offline_since" in device:
                        device["offline_since"] = None
                    device["Bắt Đầu Offline"] = "--"
                    device["Offline Duration"] = "--"
                
                # Tính thời gian trạng thái hiện tại (nếu không phải "--")
                if device["Thời gian Trạng thái"] != "--":
                    try:
                        # Parse thời gian từ string
                        status_change_str = device["Thời gian Trạng thái"]
                        status_change_time = datetime.strptime(status_change_str, "%Y-%m-%d %H:%M:%S")
                        status_duration = current_time - status_change_time
                        total_seconds = int(status_duration.total_seconds())
                        
                        if total_seconds < 60:
                            status_duration_str = f"{total_seconds} giây"
                        elif total_seconds < 3600:
                            status_duration_str = f"{total_seconds // 60} phút"
                        elif total_seconds < 86400:
                            status_duration_str = f"{total_seconds // 3600} giờ"
                        else:
                            status_duration_str = f"{total_seconds // 86400} ngày"
                        
                        # Lưu giá trị tính toán
                        device["_computed_status_duration"] = status_duration_str
                    except Exception as e:
                        print(f"Lỗi tính thời gian trạng thái: {e}")
                        device["_computed_status_duration"] = "--"
            
            time.sleep(5)

    def get_devices(self, search=None, status_filter=None, page=1, per_page=20):
        """Lấy danh sách thiết bị với tìm kiếm, lọc và phân trang"""
        filtered_devices = self.devices.copy()
        
        current_time = datetime.now()
        
        # Tính toán thời gian realtime cho mỗi thiết bị
        for device in filtered_devices:
            # Tính thời gian trạng thái hiện tại
            if device.get("Thời gian Trạng thái") and device["Thời gian Trạng thái"] != "--":
                try:
                    # Nếu là thời điểm, tính khoảng thời gian
                    if ":" in device["Thời gian Trạng thái"] and "-" in device["Thời gian Trạng thái"]:
                        status_change_time = datetime.strptime(device["Thời gian Trạng thái"], "%Y-%m-%d %H:%M:%S")
                        duration = current_time - status_change_time
                        total_seconds = int(duration.total_seconds())
                        
                        if total_seconds < 60:
                            status_duration_str = f"{total_seconds} giây"
                        elif total_seconds < 3600:
                            status_duration_str = f"{total_seconds // 60} phút"
                        elif total_seconds < 86400:
                            status_duration_str = f"{total_seconds // 3600} giờ"
                        else:
                            status_duration_str = f"{total_seconds // 86400} ngày"
                        
                        # Tạo trường mới cho frontend
                        device["_display_status_duration"] = status_duration_str
                    else:
                        # Nếu đã là chuỗi thời gian, giữ nguyên
                        device["_display_status_duration"] = device["Thời gian Trạng thái"]
                except Exception as e:
                    device["_display_status_duration"] = "--"
            else:
                device["_display_status_duration"] = "--"
            
            # Tính thời gian offline nếu đang offline
            if device["Trạng Thái"] == "Offline":
                if device.get("offline_since"):
                    try:
                        offline_duration = current_time - device["offline_since"]
                        total_seconds = int(offline_duration.total_seconds())
                        
                        days = total_seconds // 86400
                        hours = (total_seconds % 86400) // 3600
                        minutes = (total_seconds % 3600) // 60
                        seconds = total_seconds % 60
                        
                        if days > 0:
                            device["_display_offline_duration"] = f"{days}d {hours}h {minutes}m"
                        elif hours > 0:
                            device["_display_offline_duration"] = f"{hours}h {minutes}m {seconds}s"
                        elif minutes > 0:
                            device["_display_offline_duration"] = f"{minutes}m {seconds}s"
                        else:
                            device["_display_offline_duration"] = f"{seconds}s"
                        
                        # Cập nhật thời gian bắt đầu offline
                        device["_display_offline_start"] = device["offline_since"].strftime("%Y-%m-%d %H:%M:%S")
                    except Exception as e:
                        device["_display_offline_duration"] = device.get("Offline Duration", "--")
                        device["_display_offline_start"] = device.get("Bắt Đầu Offline", "--")
                else:
                    device["_display_offline_duration"] = device.get("Offline Duration", "--")
                    device["_display_offline_start"] = device.get("Bắt Đầu Offline", "--")
            else:
                device["_display_offline_duration"] = "--"
                device["_display_offline_start"] = "--"
        
        # Áp dụng tìm kiếm
        if search and search.strip():
            search_lower = search.lower().strip()
            filtered_devices = [
                d for d in filtered_devices 
                if search_lower in d["Tên"].lower() or search_lower in d["IP"].lower()
            ]
        
        # Áp dụng lọc trạng thái
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

    def format_time_duration(self, seconds):
        """Format số giây thành chuỗi thời gian dễ đọc"""
        if seconds < 60:
            return f"{seconds} giây"
        elif seconds < 3600:
            return f"{seconds // 60} phút"
        elif seconds < 86400:
            return f"{seconds // 3600} giờ"
        else:
            days = seconds // 86400
            hours = (seconds % 86400) // 3600
            return f"{days} ngày {hours} giờ"
# Khởi tạo monitor
monitor = DeviceMonitor()

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
    app.run(debug=True, host='0.0.0.0', port=5500, use_reloader=False)