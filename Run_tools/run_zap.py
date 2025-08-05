import subprocess
import json
import time
import requests
import os
from pathlib import Path
from zapv2 import ZAPv2

def run_zap_proxy():
    """Chạy ZAP Proxy để khởi tạo server."""
    print(">>> Bắt đầu chạy ZAP Proxy...")
    # Đọc cấu hình từ file config.json
    project_root = Path(__file__).resolve().parent.parent
    config_path = project_root / "config.json"
    
    with open(config_path, 'r') as f:
        config = json.load(f)
    api_key = config['zap']['api_key']
    zap_bat_path = str(Path(config['zap']['dir']) / config['zap']['bat'])

    #Câu lệnh khởi tạo ZAP Proxy
    command = [
        zap_bat_path,
        '-daemon',
        '-config', f'api.key={api_key}'
    ]
    # khởi tạo ZAP Proxy
    try:
        print(f"   [Lệnh] {' '.join(command)}")
        process = subprocess.Popen(command, cwd=config['zap']['dir'], text=True)
        print(f"✅ Khởi tạo ZAP thành công. ZAP Proxy đang chạy.")
        return process
    except FileNotFoundError as e:
        print(f"❌ LỖI: {e}")
        print(f"❌ LỖI: Không tìm thấy ZAP tại đường dẫn 'config['zap']['dir']'. Vui lòng kiểm tra file config.json.")
        return False
    except subprocess.CalledProcessError as e:
        print(f"❌ LỖI: ZAP gặp sự cố khi đang chạy.")
        print(f"   [STDERR]: {e.stderr}")
        return False


def run_zap_scan(target_url: str):
    """Chạy ZAP_API với URL mục tiêu được cung cấp."""
    print(">>> Bắt đầu quét với ZAP...")

    # Đọc cấu hình từ file config.json
    project_root = Path(__file__).resolve().parent.parent
    config_path = project_root / "config.json"
    with open(config_path, 'r') as f:
        config = json.load(f)
    report_file = (project_root / config['zap']['report_file']).resolve()
    report_file.parent.mkdir(parents=True, exist_ok=True)
    api_key = config['zap']['api_key']

    # Khởi tạo ZAP API client and connect url
    zap = ZAPv2(apikey=api_key)
    # Đặt URL mục tiêu
    print('Accessing target {}'.format(target_url))
    zap.urlopen(target_url)
    # Give the sites tree a chance to get updated
    time.sleep(2)

    # Spider and Ajax Spider
    print('Spidering target {}'.format(target_url))
    scanid = zap.spider.scan(target_url)
    time.sleep(2)
    while int(zap.spider.status(scanid)) < 100:
        print('Spider progress %: {}'.format(zap.spider.status(scanid)))
        time.sleep(5)
    print('Ajax Spider start')
    scanID = zap.ajaxSpider.scan(target_url)

    timeout = time.time() + 60*1   # 1 minutes from now
    # Loop until the ajax spider has finished or the timeout has exceeded
    while zap.ajaxSpider.status == 'running':
        if time.time() > timeout:
            break
        print('Ajax Spider status' + zap.ajaxSpider.status)
        time.sleep(2)

    print('Spider and Ajax Spider completed')

    # Scan active and passive
    while int(zap.pscan.records_to_scan) > 0:
        print('Passive scan progress %: {}'.format(zap.pscan.records_to_scan))
        time.sleep(2)
    print('Active scan start')

    #create new policy
    policy_name = 'XSS Policy'
    zap.ascan.add_scan_policy(policy_name)
    zap.ascan.enable_scanners('40012', scanpolicyname=policy_name)
    zap.ascan.enable_scanners('40014', scanpolicyname=policy_name) 
    zap.ascan.enable_scanners('40016', scanpolicyname=policy_name)
    #run
    scanid = zap.ascan.scan(target_url, scanpolicyname='XSS Policy')
    time.sleep(2)
    while int(zap.ascan.status(scanid)) < 100:
        print('Active scan progress %: {}'.format(zap.ascan.status(scanid)))
        time.sleep(5)
    print('Active scan completed')

    # Lưu báo cáo
    print("🧩 Cài đặt add-on SARIF (nếu chưa có) ...")
    zap.autoupdate.install_addon("sarif-json", apikey=api_key)
    time.sleep(10)  # Đợi để add-on được load

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
            print(f'✅ Report created successfully: {res_response.text}')
        else:
            print(f'❌ Failed to create report: {res_response.status_code}')
            return False
    except Exception as e:
        print(f'❌ LỖI: Không thể tạo báo cáo. {e}')
        return False

    print("🛑 Tắt ZAP...")
    zap.core.shutdown(apikey=api_key)
    return True
