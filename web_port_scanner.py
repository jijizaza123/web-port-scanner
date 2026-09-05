# web_port_scanner.py - 端口扫描器Web界面

import socket
import struct
import os
import csv
import time
import ipaddress
import threading
import json
import uuid
from datetime import datetime
from typing import List, Tuple, Dict, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum

try:
    from flask import Flask, request, jsonify, render_template_string, send_file
except ImportError:
    print("请先安装Flask: pip install flask")
    exit(1)


class PortStatus(Enum):
    OPEN = "开放"
    CLOSED = "关闭"
    FILTERED = "已过滤"
    UNKNOWN = "未知"


class ScanType(Enum):
    TCP_CONNECT = "tcp_connect"
    TCP_SYN = "tcp_syn"
    UDP = "udp"
    BANNER = "banner"
    FULL = "full"

    def get_description(self):
        descriptions = {
            ScanType.TCP_CONNECT: "TCP全连接扫描",
            ScanType.TCP_SYN: "TCP-SYN半开扫描",
            ScanType.UDP: "UDP扫描",
            ScanType.BANNER: "Banner抓取",
            ScanType.FULL: "综合扫描"
        }
        return descriptions.get(self, str(self))


@dataclass
class PortResult:
    port: int
    status: PortStatus
    service: str
    scan_type: str = ""
    response_time_ms: float = 0.0
    banner: str = ""
    is_high_risk: bool = False
    risk_level: str = ""

    def to_dict(self) -> Dict:
        return {
            "port": self.port,
            "status": self.status.value,
            "service": self.service,
            "scan_type": self.scan_type,
            "response_time_ms": round(self.response_time_ms, 2),
            "banner": self.banner,
            "is_high_risk": self.is_high_risk,
            "risk_level": self.risk_level
        }


@dataclass
class ScanConfig:
    target_ip: str
    port_range: Tuple[int, int]
    scan_type: ScanType = ScanType.TCP_CONNECT
    timeout: float = 2.0
    thread_count: int = 50


@dataclass
class ScanResult:
    scan_id: str
    target_ip: str
    port_range: Tuple[int, int]
    scan_type: str
    start_time: float
    end_time: float = 0
    total_ports: int = 0
    scanned_ports: int = 0
    open_ports: int = 0
    closed_ports: int = 0
    filtered_ports: int = 0
    status: str = "running"
    port_results: List[PortResult] = field(default_factory=list)

    @property
    def duration_ms(self) -> float:
        return (self.end_time - self.start_time) * 1000

    def to_dict(self) -> Dict:
        return {
            "scan_id": self.scan_id,
            "target_ip": self.target_ip,
            "port_range": list(self.port_range),
            "scan_type": self.scan_type,
            "start_time": datetime.fromtimestamp(self.start_time).isoformat(),
            "end_time": datetime.fromtimestamp(self.end_time).isoformat() if self.end_time else None,
            "duration_ms": round(self.duration_ms, 2),
            "total_ports": self.total_ports,
            "scanned_ports": self.scanned_ports,
            "open_ports": self.open_ports,
            "closed_ports": self.closed_ports,
            "filtered_ports": self.filtered_ports,
            "status": self.status,
            "progress": round((self.scanned_ports / self.total_ports) * 100, 1) if self.total_ports > 0 else 0
        }


class CommonServices:
    SERVICES = {
        21: ("FTP", False),
        22: ("SSH", False),
        23: ("Telnet", True),
        25: ("SMTP", False),
        53: ("DNS", False),
        80: ("HTTP", False),
        110: ("POP3", False),
        135: ("RPC", True),
        139: ("NetBIOS", True),
        143: ("IMAP", False),
        443: ("HTTPS", False),
        445: ("SMB", True),
        465: ("SMTPS", False),
        587: ("SMTP-TLS", False),
        993: ("IMAPS", False),
        995: ("POP3S", False),
        1433: ("MSSQL", True),
        1521: ("Oracle", True),
        3306: ("MySQL", True),
        3389: ("RDP", True),
        5432: ("PostgreSQL", True),
        5900: ("VNC", True),
        6379: ("Redis", True),
        8080: ("HTTP-Proxy", False),
        8443: ("HTTPS-Alt", False),
        27017: ("MongoDB", True),
    }

    HIGH_RISK_PORTS = {23, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 27017}

    @classmethod
    def get_service(cls, port: int) -> str:
        return cls.SERVICES.get(port, ("Unknown", False))[0]

    @classmethod
    def is_high_risk(cls, port: int) -> bool:
        return port in cls.HIGH_RISK_PORTS


class ComplianceValidator:
    ALLOWED_NETWORKS = [
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("10.0.0.0/8"),
    ]

    @classmethod
    def validate_target(cls, ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
            for network in cls.ALLOWED_NETWORKS:
                if ip in network:
                    return True
            return False
        except ValueError:
            return False

    @classmethod
    def validate_port_range(cls, port_range: Tuple[int, int]) -> bool:
        start, end = port_range
        return 1 <= start <= 65535 and 1 <= end <= 65535 and start <= end


class WebPortScanner:
    def __init__(self, config: ScanConfig, progress_callback: Callable = None):
        self.config = config
        self.progress_callback = progress_callback
        self._lock = threading.Lock()

    def _tcp_connect_scan(self, port: int) -> PortResult:
        service = CommonServices.get_service(port)
        is_high_risk = CommonServices.is_high_risk(port)
        start_time = time.time()

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.timeout)
            result_code = sock.connect_ex((self.config.target_ip, port))
            response_time_ms = (time.time() - start_time) * 1000
            sock.close()

            if result_code == 0:
                status = PortStatus.OPEN
            else:
                status = PortStatus.CLOSED
        except socket.timeout:
            status = PortStatus.FILTERED
            response_time_ms = (time.time() - start_time) * 1000
        except socket.error:
            status = PortStatus.CLOSED
            response_time_ms = (time.time() - start_time) * 1000
        except Exception:
            status = PortStatus.UNKNOWN
            response_time_ms = (time.time() - start_time) * 1000

        risk_level = "建议关闭" if (is_high_risk and status == PortStatus.OPEN) else ""

        return PortResult(
            port=port, status=status, service=service,
            scan_type="TCP全连接", response_time_ms=response_time_ms,
            is_high_risk=is_high_risk and status == PortStatus.OPEN,
            risk_level=risk_level
        )

    def _tcp_syn_scan(self, port: int) -> PortResult:
        service = CommonServices.get_service(port)
        is_high_risk = CommonServices.is_high_risk(port)
        start_time = time.time()

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, struct.pack('ll', int(self.config.timeout * 1000), 0))

            src_port = 1024 + (port % 64511)
            seq_num = os.urandom(4)

            ip_header = self._build_ip_header()
            tcp_header = self._build_tcp_header(port, src_port, seq_num, syn=True)

            packet = ip_header + tcp_header
            sock.sendto(packet, (self.config.target_ip, 0))

            try:
                response, _ = sock.recvfrom(4096)
                response_time_ms = (time.time() - start_time) * 1000

                if len(response) >= 40:
                    tcp_offset = (response[0] & 0x0F) * 4
                    tcp_flags = response[tcp_offset + 13]
                    if tcp_flags & 0x12:
                        status = PortStatus.OPEN
                    elif tcp_flags & 0x14:
                        status = PortStatus.CLOSED
                    else:
                        status = PortStatus.UNKNOWN
                else:
                    status = PortStatus.UNKNOWN
            except socket.timeout:
                status = PortStatus.FILTERED
                response_time_ms = (time.time() - start_time) * 1000

            sock.close()

        except PermissionError:
            return PortResult(
                port=port, status=PortStatus.UNKNOWN, service=service,
                scan_type="TCP-SYN", banner="需要管理员权限"
            )
        except Exception:
            status = PortStatus.UNKNOWN
            response_time_ms = (time.time() - start_time) * 1000

        risk_level = "建议关闭" if (is_high_risk and status == PortStatus.OPEN) else ""

        return PortResult(
            port=port, status=status, service=service,
            scan_type="TCP-SYN", response_time_ms=response_time_ms,
            is_high_risk=is_high_risk and status == PortStatus.OPEN,
            risk_level=risk_level
        )

    def _build_ip_header(self) -> bytes:
        version_ihl = 0x45
        tos = 0
        total_len = 40
        id = os.urandom(2)
        frag_off = 0x0000
        ttl = 64
        protocol = socket.IPPROTO_TCP
        checksum = 0
        src_ip = socket.inet_aton("127.0.0.1")
        dst_ip = socket.inet_aton(self.config.target_ip)

        return struct.pack(
            '!BBHHHBBH4s4s',
            version_ihl, tos, total_len,
            int.from_bytes(id, 'big'), frag_off, ttl, protocol,
            checksum, src_ip, dst_ip
        )

    def _build_tcp_header(self, dst_port: int, src_port: int, seq_num: bytes, syn=False) -> bytes:
        seq = int.from_bytes(seq_num, 'big')
        ack_seq = 0
        data_offset = 0x50
        flags = 0x02 if syn else 0x10
        window = 65535
        checksum = 0
        urg_ptr = 0

        return struct.pack(
            '!HHLLBBHHH',
            src_port, dst_port, seq, ack_seq,
            data_offset, flags, window, checksum, urg_ptr
        )

    def _udp_scan(self, port: int) -> PortResult:
        service = CommonServices.get_service(port)
        is_high_risk = CommonServices.is_high_risk(port)
        start_time = time.time()

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.config.timeout)
            sock.sendto(b'', (self.config.target_ip, port))

            try:
                data, _ = sock.recvfrom(1024)
                response_time_ms = (time.time() - start_time) * 1000
                status = PortStatus.OPEN
            except socket.timeout:
                status = PortStatus.FILTERED
                response_time_ms = (time.time() - start_time) * 1000

            sock.close()
        except socket.error:
            status = PortStatus.CLOSED
            response_time_ms = (time.time() - start_time) * 1000
        except Exception:
            status = PortStatus.UNKNOWN
            response_time_ms = (time.time() - start_time) * 1000

        risk_level = "建议关闭" if (is_high_risk and status == PortStatus.OPEN) else ""

        return PortResult(
            port=port, status=status, service=service,
            scan_type="UDP", response_time_ms=response_time_ms,
            is_high_risk=is_high_risk and status == PortStatus.OPEN,
            risk_level=risk_level
        )

    def _banner_grab_scan(self, port: int) -> PortResult:
        service = CommonServices.get_service(port)
        is_high_risk = CommonServices.is_high_risk(port)
        start_time = time.time()
        banner = ""

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.timeout)
            result_code = sock.connect_ex((self.config.target_ip, port))
            response_time_ms = (time.time() - start_time) * 1000

            if result_code == 0:
                status = PortStatus.OPEN
                try:
                    sock.send(b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                    banner_data = sock.recv(1024)
                    banner = banner_data.decode('utf-8', errors='ignore').strip()[:200]
                except Exception:
                    try:
                        banner_data = sock.recv(1024)
                        banner = banner_data.decode('utf-8', errors='ignore').strip()[:200]
                    except Exception:
                        banner = "无法获取Banner"
            else:
                status = PortStatus.CLOSED

            sock.close()
        except socket.timeout:
            status = PortStatus.FILTERED
            response_time_ms = (time.time() - start_time) * 1000
        except socket.error:
            status = PortStatus.CLOSED
            response_time_ms = (time.time() - start_time) * 1000
        except Exception:
            status = PortStatus.UNKNOWN
            response_time_ms = (time.time() - start_time) * 1000

        risk_level = "建议关闭" if (is_high_risk and status == PortStatus.OPEN) else ""

        return PortResult(
            port=port, status=status, service=service,
            scan_type="Banner", response_time_ms=response_time_ms,
            banner=banner, is_high_risk=is_high_risk and status == PortStatus.OPEN,
            risk_level=risk_level
        )

    def _scan_port(self, port: int) -> PortResult:
        scan_type = self.config.scan_type
        if scan_type == ScanType.TCP_CONNECT:
            return self._tcp_connect_scan(port)
        elif scan_type == ScanType.TCP_SYN:
            return self._tcp_syn_scan(port)
        elif scan_type == ScanType.UDP:
            return self._udp_scan(port)
        elif scan_type == ScanType.BANNER:
            return self._banner_grab_scan(port)
        elif scan_type == ScanType.FULL:
            tcp_result = self._tcp_connect_scan(port)
            if tcp_result.status == PortStatus.OPEN:
                banner_result = self._banner_grab_scan(port)
                banner_result.scan_type = "综合扫描"
                return banner_result
            tcp_result.scan_type = "综合扫描"
            return tcp_result
        else:
            return self._tcp_connect_scan(port)

    def scan(self) -> ScanResult:
        scan_id = str(uuid.uuid4())[:8]
        start_time = time.time()
        result = ScanResult(
            scan_id=scan_id,
            target_ip=self.config.target_ip,
            port_range=self.config.port_range,
            scan_type=self.config.scan_type.get_description(),
            start_time=start_time
        )

        ports = list(range(self.config.port_range[0], self.config.port_range[1] + 1))
        result.total_ports = len(ports)

        from concurrent.futures import ThreadPoolExecutor, as_completed

        with ThreadPoolExecutor(max_workers=self.config.thread_count) as executor:
            future_to_port = {executor.submit(self._scan_port, port): port for port in ports}

            for future in as_completed(future_to_port):
                port_result = future.result()

                with self._lock:
                    result.port_results.append(port_result)
                    if port_result.status == PortStatus.OPEN:
                        result.open_ports += 1
                    elif port_result.status == PortStatus.CLOSED:
                        result.closed_ports += 1
                    else:
                        result.filtered_ports += 1
                    result.scanned_ports += 1

                if self.progress_callback:
                    self.progress_callback(result)

        result.end_time = time.time()
        result.status = "completed"

        if self.progress_callback:
            self.progress_callback(result)

        return result


scans = {}


app = Flask(__name__)


@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)


@app.route('/api/scan', methods=['POST'])
def start_scan():
    data = request.get_json()
    target_ip = data.get('target_ip', '')
    port_range_str = data.get('port_range', '')
    scan_type_str = data.get('scan_type', 'tcp_connect')
    timeout = float(data.get('timeout', 2.0))
    thread_count = int(data.get('thread_count', 50))

    if not ComplianceValidator.validate_target(target_ip):
        return jsonify({
            "success": False,
            "error": f"目标IP {target_ip} 不合规！仅允许扫描: 127.0.0.1, 192.168.x.x, 10.x.x.x"
        }), 400

    if '-' in port_range_str:
        parts = port_range_str.split('-')
        port_range = (int(parts[0].strip()), int(parts[1].strip()))
    else:
        port = int(port_range_str)
        port_range = (port, port)

    if not ComplianceValidator.validate_port_range(port_range):
        return jsonify({
            "success": False,
            "error": f"端口范围 {port_range} 不合法！"
        }), 400

    scan_type_mapping = {
        "tcp_connect": ScanType.TCP_CONNECT,
        "tcp_syn": ScanType.TCP_SYN,
        "udp": ScanType.UDP,
        "banner": ScanType.BANNER,
        "full": ScanType.FULL
    }
    scan_type = scan_type_mapping.get(scan_type_str, ScanType.TCP_CONNECT)

    config = ScanConfig(
        target_ip=target_ip,
        port_range=port_range,
        scan_type=scan_type,
        timeout=timeout,
        thread_count=thread_count
    )

    scan_id = str(uuid.uuid4())[:8]

    initial_result = ScanResult(
        scan_id=scan_id,
        target_ip=target_ip,
        port_range=port_range,
        scan_type=scan_type.get_description(),
        start_time=time.time(),
        status="running",
        total_ports=port_range[1] - port_range[0] + 1
    )
    scans[scan_id] = initial_result

    def progress_callback(result):
        scans[scan_id] = result

    scanner = WebPortScanner(config, progress_callback)

    def run_scan():
        try:
            final_result = scanner.scan()
            scans[scan_id] = final_result
        except Exception as e:
            print(f"Scan error: {e}")
            error_result = ScanResult(
                scan_id=scan_id,
                target_ip=target_ip,
                port_range=port_range,
                scan_type=scan_type.get_description(),
                start_time=time.time(),
                end_time=time.time(),
                status="error",
                total_ports=port_range[1] - port_range[0] + 1
            )
            scans[scan_id] = error_result

    thread = threading.Thread(target=run_scan)
    thread.daemon = True
    thread.start()

    return jsonify({
        "success": True,
        "scan_id": scan_id,
        "message": "扫描已启动"
    })


@app.route('/api/scan/<scan_id>/status')
def get_scan_status(scan_id):
    result = scans.get(scan_id)
    if not result:
        return jsonify({"error": "扫描不存在"}), 404

    return jsonify({
        "success": True,
        "scan": result.to_dict(),
        "open_ports": [p.to_dict() for p in result.port_results if p.status == PortStatus.OPEN]
    })


@app.route('/api/scan/<scan_id>/results')
def get_scan_results(scan_id):
    result = scans.get(scan_id)
    if not result:
        return jsonify({"error": "扫描不存在"}), 404

    return jsonify({
        "success": True,
        "scan": result.to_dict(),
        "results": [p.to_dict() for p in result.port_results]
    })


@app.route('/api/scan/<scan_id>/export/txt')
def export_txt(scan_id):
    result = scans.get(scan_id)
    if not result or result.status != "completed":
        return jsonify({"error": "扫描未完成"}), 400

    import io
    output = io.StringIO()
    output.write("=" * 70 + "\n")
    output.write("端口扫描报告\n")
    output.write("=" * 70 + "\n\n")
    output.write(f"目标IP: {result.target_ip}\n")
    output.write(f"端口范围: {result.port_range[0]}-{result.port_range[1]}\n")
    output.write(f"扫描类型: {result.scan_type}\n")
    output.write(f"扫描耗时: {result.duration_ms:.2f} 毫秒\n")
    output.write(f"总端口数: {result.total_ports}\n")
    output.write(f"开放端口: {result.open_ports}\n")
    output.write(f"关闭端口: {result.closed_ports}\n")
    output.write(f"过滤端口: {result.filtered_ports}\n")
    output.write("\n" + "-" * 70 + "\n")
    output.write(f"{'端口':<10}{'状态':<12}{'服务':<15}{'响应时间':<12}{'高危':<8}\n")
    output.write("-" * 70 + "\n")

    open_results = sorted([r for r in result.port_results if r.status == PortStatus.OPEN], key=lambda x: x.port)
    for port_result in open_results:
        risk_tag = "[HIGH]" if port_result.is_high_risk else ""
        output.write(f"{port_result.port:<10}{port_result.status.value:<12}{port_result.service:<15}{port_result.response_time_ms:.2f}ms    {risk_tag}\n")

    output.write("-" * 70 + "\n")
    output.write(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    data = output.getvalue().encode('utf-8')
    from flask import Response
    return Response(
        data,
        mimetype='text/plain; charset=utf-8',
        headers={
            'Content-Disposition': f'attachment; filename="scan_result_{scan_id}.txt"',
            'Content-Length': len(data)
        }
    )


@app.route('/api/scan/<scan_id>/export/csv')
def export_csv(scan_id):
    result = scans.get(scan_id)
    if not result or result.status != "completed":
        return jsonify({"error": "扫描未完成"}), 400

    import io
    output = io.StringIO()
    output.write('\ufeff')
    writer = csv.writer(output)
    writer.writerow(["端口", "状态", "服务", "响应时间(ms)", "Banner", "高危端口", "风险等级"])

    open_results = sorted([r for r in result.port_results if r.status == PortStatus.OPEN], key=lambda x: x.port)
    for port_result in open_results:
        writer.writerow([
            port_result.port,
            port_result.status.value,
            port_result.service,
            round(port_result.response_time_ms, 2),
            port_result.banner,
            "是" if port_result.is_high_risk else "否",
            port_result.risk_level
        ])

    data = output.getvalue().encode('utf-8')
    from flask import Response
    return Response(
        data,
        mimetype='text/csv; charset=utf-8',
        headers={
            'Content-Disposition': f'attachment; filename="scan_result_{scan_id}.csv"',
            'Content-Length': len(data)
        }
    )


HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>端口扫描器</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); min-height: 100vh; color: #fff; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .header { text-align: center; margin-bottom: 30px; padding: 20px; background: rgba(255,255,255,0.05); border-radius: 15px; }
        .header h1 { font-size: 2.5em; margin-bottom: 10px; background: linear-gradient(90deg, #00d2ff, #3a7bd5); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .header p { color: #aaa; }
        
        .scan-form { background: rgba(255,255,255,0.05); border-radius: 15px; padding: 30px; margin-bottom: 30px; }
        .form-row { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 20px; }
        .form-group { }
        .form-group label { display: block; margin-bottom: 8px; color: #aaa; font-size: 0.9em; }
        .form-group input, .form-group select { width: 100%; padding: 12px 15px; border: 1px solid rgba(255,255,255,0.1); border-radius: 8px; background: rgba(255,255,255,0.05); color: #fff; font-size: 1em; }
        .form-group input:focus, .form-group select:focus { outline: none; border-color: #00d2ff; }
        
        .btn { padding: 12px 30px; border: none; border-radius: 8px; font-size: 1em; cursor: pointer; transition: all 0.3s; }
        .btn-primary { background: linear-gradient(90deg, #00d2ff, #3a7bd5); color: #fff; }
        .btn-primary:hover { transform: translateY(-2px); box-shadow: 0 5px 20px rgba(0,210,255,0.3); }
        .btn-primary:disabled { opacity: 0.5; cursor: not-allowed; }
        .btn-secondary { background: rgba(255,255,255,0.1); color: #fff; margin-left: 10px; }
        .btn-secondary:hover { background: rgba(255,255,255,0.15); }
        
        .progress-section { display: none; margin-bottom: 30px; }
        .progress-box { background: rgba(255,255,255,0.05); border-radius: 15px; padding: 20px; }
        .progress-bar { height: 20px; background: rgba(255,255,255,0.1); border-radius: 10px; overflow: hidden; margin-bottom: 10px; }
        .progress-fill { height: 100%; background: linear-gradient(90deg, #00d2ff, #3a7bd5); transition: width 0.3s; width: 0%; }
        .progress-info { display: flex; justify-content: space-between; color: #aaa; font-size: 0.9em; }
        
        .results-section { display: none; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-bottom: 20px; }
        .stat-card { background: rgba(255,255,255,0.05); border-radius: 10px; padding: 20px; text-align: center; }
        .stat-card .number { font-size: 2em; font-weight: bold; }
        .stat-card.open .number { color: #00ff88; }
        .stat-card.closed .number { color: #ff6b6b; }
        .stat-card.filtered .number { color: #ffd93d; }
        .stat-card.total .number { color: #00d2ff; }
        .stat-card .label { color: #aaa; font-size: 0.9em; margin-top: 5px; }
        
        .results-table { width: 100%; border-collapse: collapse; background: rgba(255,255,255,0.05); border-radius: 15px; overflow: hidden; }
        .results-table th, .results-table td { padding: 12px 15px; text-align: left; border-bottom: 1px solid rgba(255,255,255,0.05); }
        .results-table th { background: rgba(255,255,255,0.1); color: #aaa; font-weight: 500; }
        .results-table tr:hover { background: rgba(255,255,255,0.05); }
        .status-open { color: #00ff88; font-weight: bold; }
        .status-closed { color: #ff6b6b; }
        .status-filtered { color: #ffd93d; }
        .high-risk { color: #ff6b6b; font-weight: bold; }
        
        .banner-cell { max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .banner-cell:hover { overflow: visible; white-space: normal; }
        
        .export-buttons { margin-top: 20px; display: flex; gap: 10px; }
        
        .error-message { background: rgba(255,107,107,0.2); border: 1px solid rgba(255,107,107,0.5); border-radius: 8px; padding: 15px; margin-bottom: 20px; color: #ff6b6b; display: none; }
        .success-message { background: rgba(0,255,136,0.2); border: 1px solid rgba(0,255,136,0.5); border-radius: 8px; padding: 15px; margin-bottom: 20px; color: #00ff88; display: none; }
        
        .preset-tags { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 10px; }
        .preset-tag { padding: 5px 12px; background: rgba(255,255,255,0.1); border-radius: 20px; font-size: 0.8em; cursor: pointer; transition: all 0.2s; }
        .preset-tag:hover { background: rgba(0,210,255,0.3); }
        
        @media (max-width: 768px) {
            .form-row { grid-template-columns: 1fr; }
            .results-table { font-size: 0.8em; }
            .results-table th, .results-table td { padding: 8px 10px; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 端口扫描器</h1>
            <p>合规型多线程端口扫描器 - 仅限本机及内网地址扫描</p>
        </div>

        <div class="error-message" id="errorMessage"></div>
        <div class="success-message" id="successMessage"></div>

        <div class="scan-form">
            <h2>扫描配置</h2>
            <div class="form-row">
                <div class="form-group">
                    <label for="targetIp">目标IP地址</label>
                    <input type="text" id="targetIp" placeholder="例如: 127.0.0.1" value="127.0.0.1">
                </div>
                <div class="form-group">
                    <label for="portRange">端口范围</label>
                    <input type="text" id="portRange" placeholder="例如: 1-1024" value="1-100">
                    <div class="preset-tags">
                        <span class="preset-tag" onclick="setPortRange('1-1024')">快速扫描</span>
                        <span class="preset-tag" onclick="setPortRange('1-65535')">全端口</span>
                        <span class="preset-tag" onclick="setPortRange('80,443,8080')">Web常用</span>
                        <span class="preset-tag" onclick="setPortRange('21,22,23,3306,3389')">高危端口</span>
                    </div>
                </div>
            </div>
            <div class="form-row">
                <div class="form-group">
                    <label for="scanType">扫描类型</label>
                    <select id="scanType">
                        <option value="tcp_connect">TCP全连接扫描</option>
                        <option value="tcp_syn">TCP-SYN半开扫描</option>
                        <option value="udp">UDP扫描</option>
                        <option value="banner">Banner抓取</option>
                        <option value="full">综合扫描</option>
                    </select>
                </div>
                <div class="form-group">
                    <label for="timeout">超时时间(秒)</label>
                    <input type="number" id="timeout" min="1" max="30" value="2">
                </div>
                <div class="form-group">
                    <label for="threadCount">线程数</label>
                    <input type="number" id="threadCount" min="1" max="200" value="50">
                </div>
            </div>
            <button class="btn btn-primary" id="startBtn" onclick="startScan()">开始扫描</button>
            <button class="btn btn-secondary" onclick="clearResults()">清除结果</button>
        </div>

        <div class="progress-section" id="progressSection">
            <div class="progress-box">
                <h3>扫描进度</h3>
                <div class="progress-bar">
                    <div class="progress-fill" id="progressFill"></div>
                </div>
                <div class="progress-info">
                    <span>扫描ID: <span id="scanId"></span></span>
                    <span id="progressText">0%</span>
                    <span>开放: <span id="openCount">0</span></span>
                </div>
            </div>
        </div>

        <div class="results-section" id="resultsSection">
            <h2>扫描结果</h2>
            <div class="stats-grid">
                <div class="stat-card total">
                    <div class="number" id="totalPorts">0</div>
                    <div class="label">总端口数</div>
                </div>
                <div class="stat-card open">
                    <div class="number" id="openPorts">0</div>
                    <div class="label">开放端口</div>
                </div>
                <div class="stat-card closed">
                    <div class="number" id="closedPorts">0</div>
                    <div class="label">关闭端口</div>
                </div>
                <div class="stat-card filtered">
                    <div class="number" id="filteredPorts">0</div>
                    <div class="label">过滤端口</div>
                </div>
            </div>

            <table class="results-table">
                <thead>
                    <tr>
                        <th>端口</th>
                        <th>状态</th>
                        <th>服务</th>
                        <th>响应时间</th>
                        <th>Banner</th>
                        <th>高危端口</th>
                    </tr>
                </thead>
                <tbody id="resultsBody">
                </tbody>
            </table>

            <div class="export-buttons">
                <button class="btn btn-secondary" id="exportTxtBtn" onclick="exportResults('txt')">导出TXT</button>
                <button class="btn btn-secondary" id="exportCsvBtn" onclick="exportResults('csv')">导出CSV</button>
            </div>
        </div>
    </div>

    <script>
        let currentScanId = null;
        let pollInterval = null;

        function setPortRange(range) {
            document.getElementById('portRange').value = range;
        }

        function showError(msg) {
            document.getElementById('errorMessage').textContent = msg;
            document.getElementById('errorMessage').style.display = 'block';
            document.getElementById('successMessage').style.display = 'none';
        }

        function showSuccess(msg) {
            document.getElementById('successMessage').textContent = msg;
            document.getElementById('successMessage').style.display = 'block';
            document.getElementById('errorMessage').style.display = 'none';
        }

        function hideMessages() {
            document.getElementById('errorMessage').style.display = 'none';
            document.getElementById('successMessage').style.display = 'none';
        }

        async function startScan() {
            const targetIp = document.getElementById('targetIp').value.trim();
            const portRange = document.getElementById('portRange').value.trim();
            const scanType = document.getElementById('scanType').value;
            const timeout = parseFloat(document.getElementById('timeout').value);
            const threadCount = parseInt(document.getElementById('threadCount').value);

            if (!targetIp) {
                showError('请输入目标IP地址');
                return;
            }

            hideMessages();
            document.getElementById('startBtn').disabled = true;
            document.getElementById('progressSection').style.display = 'block';
            document.getElementById('resultsSection').style.display = 'none';

            try {
                const response = await fetch('/api/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        target_ip: targetIp,
                        port_range: portRange,
                        scan_type: scanType,
                        timeout: timeout,
                        thread_count: threadCount
                    })
                });

                const data = await response.json();

                if (data.success) {
                    currentScanId = data.scan_id;
                    document.getElementById('scanId').textContent = currentScanId;
                    showSuccess(`扫描已启动 (ID: ${currentScanId})`);
                    pollProgress();
                } else {
                    showError(data.error);
                    document.getElementById('startBtn').disabled = false;
                    document.getElementById('progressSection').style.display = 'none';
                }
            } catch (error) {
                showError('请求失败: ' + error.message);
                document.getElementById('startBtn').disabled = false;
                document.getElementById('progressSection').style.display = 'none';
            }
        }

        function pollProgress() {
            if (pollInterval) clearInterval(pollInterval);

            pollInterval = setInterval(async () => {
                try {
                    const response = await fetch(`/api/scan/${currentScanId}/status`);
                    const data = await response.json();

                    if (data.success) {
                        const scan = data.scan;

                        document.getElementById('progressFill').style.width = scan.progress + '%';
                        document.getElementById('progressText').textContent = scan.progress + '%';
                        document.getElementById('openCount').textContent = scan.open_ports;

                        if (scan.status === 'completed') {
                            clearInterval(pollInterval);
                            document.getElementById('startBtn').disabled = false;
                            displayResults(data);
                        }
                    } else {
                        clearInterval(pollInterval);
                        document.getElementById('startBtn').disabled = false;
                        showError('扫描状态获取失败');
                    }
                } catch (error) {
                    console.error('Poll error:', error);
                }
            }, 500);
        }

        async function displayResults(data) {
            document.getElementById('progressSection').style.display = 'none';
            document.getElementById('resultsSection').style.display = 'block';

            const scan = data.scan;
            document.getElementById('totalPorts').textContent = scan.total_ports;
            document.getElementById('openPorts').textContent = scan.open_ports;
            document.getElementById('closedPorts').textContent = scan.closed_ports;
            document.getElementById('filteredPorts').textContent = scan.filtered_ports;

            const resultsBody = document.getElementById('resultsBody');
            resultsBody.innerHTML = '';

            const openPorts = data.open_ports || [];

            if (openPorts.length === 0) {
                resultsBody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:#aaa;">没有发现开放端口</td></tr>';
                return;
            }

            openPorts.forEach(port => {
                const statusClass = port.status === '开放' ? 'status-open' : 
                                   port.status === '关闭' ? 'status-closed' : 'status-filtered';
                const riskClass = port.is_high_risk ? 'high-risk' : '';
                const riskText = port.is_high_risk ? '⚠️ 是' : '否';

                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${port.port}</td>
                    <td><span class="${statusClass}">${port.status}</span></td>
                    <td>${port.service}</td>
                    <td>${port.response_time_ms}ms</td>
                    <td class="banner-cell" title="${port.banner || ''}">${port.banner || '-'}</td>
                    <td><span class="${riskClass}">${riskText}</span></td>
                `;
                resultsBody.appendChild(row);
            });
        }

        function clearResults() {
            if (pollInterval) clearInterval(pollInterval);
            currentScanId = null;
            document.getElementById('startBtn').disabled = false;
            document.getElementById('progressSection').style.display = 'none';
            document.getElementById('resultsSection').style.display = 'none';
            hideMessages();
        }

        async function exportResults(format) {
            if (!currentScanId) {
                showError('没有可导出的扫描结果');
                return;
            }
            
            try {
                const response = await fetch(`/api/scan/${currentScanId}/export/${format}`);
                
                if (!response.ok) {
                    const errorData = await response.json();
                    showError(errorData.error || '导出失败');
                    return;
                }
                
                const blob = await response.blob();
                const contentDisposition = response.headers.get('Content-Disposition');
                let filename = `scan_result_${currentScanId}.${format}`;
                
                if (contentDisposition) {
                    const match = contentDisposition.match(/filename="(.+)"/);
                    if (match) {
                        filename = match[1];
                    }
                }
                
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = filename;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                window.URL.revokeObjectURL(url);
                
                showSuccess(`文件 ${filename} 已开始下载`);
            } catch (error) {
                console.error('Export error:', error);
                showError('导出失败: ' + error.message);
            }
        }
    </script>
</body>
</html>
"""


if __name__ == "__main__":
    print("=" * 60)
    print("  Web Port Scanner")
    print("=" * 60)
    print("启动Flask服务...")
    print("访问地址: http://localhost:5000")
    print("按 Ctrl+C 停止服务")
    print("=" * 60)
    app.run(host='0.0.0.0', port=5000, debug=False)
