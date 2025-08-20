import subprocess
import json
import time
import requests
import os
import re 
from urllib.parse import urlparse 
from pathlib import Path
from zapv2 import ZAPv2

def wait_for_zap_start(zap, max_wait=60):
    """Chờ ZAP khởi động hoàn toàn"""
    print(">>> Đang chờ ZAP khởi động...")
    start_time = time.time()
    while time.time() - start_time < max_wait:
        try:
            zap.core.version
            print("✅ ZAP đã sẵn sàng!")
            return True
        except:
            print("   Đang chờ ZAP khởi động...")
            time.sleep(2)
    return False

def run_zap_proxy():
    """Chạy ZAP Proxy để khởi tạo server."""
    print(">>> Bắt đầu chạy ZAP Proxy...")
    project_root = Path(__file__).resolve().parent.parent
    config_path = project_root / "config.json"
    
    with open(config_path, 'r') as f:
        config = json.load(f)
    api_key = config['zap']['api_key']
    zap_bat_path = str(Path(config['zap']['dir']) / config['zap']['bat'])
    firefox_bin = config['zap']['firefox_binary']
    gecko_path = config['zap']['geckodriver_path']

    #Câu lệnh khởi tạo ZAP Proxy
    command = [
        zap_bat_path,
        '-daemon',
        '-config', f'api.key={api_key}',
        '-config', f'selenium.firefoxBinary={firefox_bin}',
        '-config', f'selenium.firefoxDriverPath={gecko_path}',
        '-config', 'ajaxSpider.browserId=firefox',
        '-config', 'spider.maxDuration=10',  # Giới hạn thời gian spider
        '-config', 'ajaxSpider.maxDuration=10',  # Giới hạn thời gian ajax spider
    ]

    try:
        print(f"   [Lệnh] {' '.join(command)}")
        process = subprocess.Popen(command, cwd=config['zap']['dir'], text=True)
        print(f"✅ Khởi tạo ZAP thành công. ZAP Proxy đang chạy.")
        
        zap = ZAPv2(apikey=api_key)
        if wait_for_zap_start(zap):
            return True
        else:
            print("❌ ZAP không khởi động trong thời gian cho phép")
            return False
            
    except FileNotFoundError as e:
        print(f"❌ LỖI: {e}")
        print(f"❌ LỖI: Không tìm thấy ZAP tại đường dẫn '{config['zap']['dir']}'. Vui lòng kiểm tra file config.json.")
        return False
    except subprocess.CalledProcessError as e:
        print(f"❌ LỖI: ZAP gặp sự cố khi đang chạy.")
        print(f"   [STDERR]: {e.stderr}")
        return False


def run_zap_scan(target_url: str):
    """Chạy ZAP_API với URL mục tiêu được cung cấp."""
    print(">>> Bắt đầu quét với ZAP...")

    project_root = Path(__file__).resolve().parent.parent
    config_path = project_root / "config.json"
    with open(config_path, 'r') as f:
        config = json.load(f)
    report_file = (project_root / config['zap']['report_file']).resolve()
    report_file.parent.mkdir(parents=True, exist_ok=True)
    api_key = config['zap']['api_key']

    zap = ZAPv2(apikey=api_key)
    
    try:
        version = zap.core.version
        print(f"✅ Kết nối ZAP thành công. Version: {version}")
    except Exception as e:
        print(f"❌ Không thể kết nối ZAP API: {e}")
        return False

    print(f'>>> Truy cập target: {target_url}')
    try:
        zap.urlopen(target_url)
        time.sleep(3)
    except Exception as e:
        print(f"❌ Không thể truy cập URL: {e}")
        return False

    print(f'>>> Bắt đầu Spider scan: {target_url}')
    try:
        scanid = zap.spider.scan(target_url)
        time.sleep(2)
        
        while int(zap.spider.status(scanid)) < 100:
            progress = zap.spider.status(scanid)
            print(f'   Spider progress: {progress}%')
            time.sleep(5)
        print('✅ Spider completed')
        
        # Hiển thị số URLs được tìm thấy
        urls_found = zap.core.urls()
        print(f"   Tìm thấy {len(urls_found)} URLs (tổng)")
        
    except Exception as e:
        print(f"❌ Spider scan failed: {e}")
        return False

    print('>>> Bắt đầu Ajax Spider...')
    try:
        zap.ajaxSpider.scan(target_url)
        timeout = time.time() + 60*2 
        
        while True:
            st = zap.ajaxSpider.status() 
            if st == 'stopped':
                break
            if time.time() > timeout:
                print("⚠️ Ajax Spider timeout")
                zap.ajaxSpider.stop()
                break
            print(f'   Ajax Spider status: {st}')
            time.sleep(5)
        print('✅ Ajax Spider completed')
        
    except Exception as e:
        print(f"❌ Ajax Spider failed: {e}")

    print('>>> Chờ Passive scan hoàn thành...')
    try:
        while int(zap.pscan.records_to_scan) > 0:
            remaining = zap.pscan.records_to_scan
            print(f'   Passive scan remaining: {remaining}')
            time.sleep(3)
        print('✅ Passive scan completed')
    except Exception as e:
        print(f"❌ Passive scan check failed: {e}")


    print('>>> Bắt đầu Active scan (iterate targets cùng thư mục với target_url)...')
    try:
        parsed = urlparse(target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        if '/' in parsed.path:
            dir_prefix = parsed.path.rsplit('/', 1)[0] + '/'
        else:
            dir_prefix = '/'
        start_prefix = base + dir_prefix

        urls_spider = set()
        try:
            urls_spider = set(zap.spider.results(scanid))
        except Exception:
            pass
        urls_all = set(zap.core.urls())
        candidates = urls_spider | urls_all

        targets = [u for u in candidates if u.startswith(base) and u.startswith(start_prefix)]

        print(f"   Tổng URL đã biết: {len(candidates)} | Mục tiêu cùng thư mục: {len(targets)}")
        for u in targets[:10]:
            print(f"      - {u}")

        policy_name = 'ComprehensiveScan'
        existing_policies = [p['name'] for p in zap.ascan.policies()]
        if policy_name in existing_policies:
            zap.ascan.remove_scan_policy(policy_name)
        
        zap.ascan.add_scan_policy(policy_name)
        zap.ascan.disable_all_scanners(scanpolicyname=policy_name)
        
        important_scanners = [
            '40012',  # Cross Site Scripting (Reflected)
            '40014',  # Cross Site Scripting (Persistent)
            '40016',  # Cross Site Scripting (Persistent) - Prime
            '40017',  # Cross Site Scripting (Persistent) - Spider
            '40018',  # Cross Site Scripting (Persistent) - OData
        ]
        for scanner_id in important_scanners:
            try:
                zap.ascan.enable_scanners(scanner_id, scanpolicyname=policy_name)
            except:
                print(f"   Không thể enable scanner {scanner_id}")
        
        scanners = zap.ascan.scanners(scanpolicyname=policy_name)
        for scanner in scanners:
            if scanner['enabled'] == 'true':
                zap.ascan.set_scanner_alert_threshold(scanner['id'], 'MEDIUM', scanpolicyname=policy_name)
                zap.ascan.set_scanner_attack_strength(scanner['id'], 'MEDIUM', scanpolicyname=policy_name)
        print(f"✅ Đã cấu hình policy với {len([s for s in scanners if s['enabled'] == 'true'])} scanners")

        for idx, url in enumerate(targets, 1):
            print(f"   ▶️ Scan {idx}/{len(targets)}: {url}")
            scan_id = zap.ascan.scan(url, recurse=False, scanpolicyname=policy_name) 
            time.sleep(2)
            while int(zap.ascan.status(scan_id)) < 100:
                progress = zap.ascan.status(scan_id)
                try:
                    scans_info = zap.ascan.scans() 
                    curr = next((s for s in scans_info if s.get('id') == str(scan_id)), None)
                    messages_sent = (curr or {}).get('messagesSent', 'N/A')
                    state = (curr or {}).get('state', 'N/A')
                    print(f'      progress: {progress}% | messages: {messages_sent} | state: {state}')
                except Exception:
                    print(f'      progress: {progress}%')
                time.sleep(5)
            print("      ✅ done")

        print('✅ Active scan (iterate) completed')
        
    except Exception as e:
        print(f"❌ Active scan failed: {e}")
        return False

    try:
        alerts = zap.core.alerts()
        print(f"🔍 Tìm thấy {len(alerts)} alerts")
        risk_counts = {}
        for alert in alerts:
            risk = alert.get('risk', 'Unknown')
            risk_counts[risk] = risk_counts.get(risk, 0) + 1
        
        for risk, count in risk_counts.items():
            print(f"   {risk}: {count} alerts")
            
    except Exception as e:
        print(f"⚠️ Không thể lấy alerts: {e}")

    print(">>> Tạo báo cáo...")
    ZAP_HOST = 'http://localhost:8080'
    ZAP_Internal_DIR = str(report_file.parent)
    REPORT_FILENAME = os.path.basename(report_file)

    generate_url = f'{ZAP_HOST}/JSON/reports/action/generate/'
    params = {
        'apikey': api_key,
        'template': 'sarif-json',
        'title': 'ZAP Report SARIF',
        'reportDir': ZAP_Internal_DIR,
        'reportFileName': REPORT_FILENAME
    }

    try:
        res_response = requests.get(generate_url, params=params)
        if res_response.status_code == 200:
            print(f'✅ Báo cáo được tạo thành công: {report_file}')
        else:
            print(f'❌ Không thể tạo báo cáo: {res_response.status_code} - {res_response.text}')
            return False
    except Exception as e:
        print(f'❌ LỖI: Không thể tạo báo cáo. {e}')
        return False

    print(">>> Tắt ZAP...")
    try:
        zap.core.shutdown(apikey=api_key)
        print("✅ ZAP đã được tắt")
    except:
        print("ℹ️ ZAP có thể đã được tắt")
        
    return True
