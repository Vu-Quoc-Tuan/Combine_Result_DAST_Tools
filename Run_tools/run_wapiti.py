import subprocess
import json
from pathlib import Path

def run_wapiti_scan(target_url: str):
    """Chạy Wapiti với URL mục tiêu được cung cấp."""
    print(">>> Bắt đầu quét với Wapiti...")
    
    project_root = Path(__file__).resolve().parent.parent
    config_path = project_root / "config.json"
    # Đọc cấu hình từ file config.json
    with open(config_path, 'r') as f:
        config = json.load(f)
    
    wapiti_path = config['wapiti']['path']
    report_file = (project_root / config['wapiti']['report_file']).resolve()
    report_file.parent.mkdir(parents=True, exist_ok=True)
    
    command = [
        wapiti_path,
        '-u', target_url,
        '-m', 'xss',
        '--scope', 'domain',
        '--flush-session',
        '--max-links-per-page', '500',
        '--max-parameters', '100',
        '--headless', 'hidden',
        '--color',
        '-v', '2',
        '--tasks', '15',
        '--verify-ssl', '0',
        '--max-scan-time', '28800',
        '-dr', '2',
        '-f', 'json',
        '-o', str(report_file)
    ]
    
    try:
        print(f"   [Lệnh] {' '.join(command)}")
        subprocess.run(command, check=True, capture_output=True, text=True)
        print(f"✅ Quét Wapiti hoàn tất. Báo cáo đã được lưu tại: {str(report_file)}")
        return True
    except FileNotFoundError:
        print(f"❌ LỖI: Không tìm thấy Wapiti. Hãy chắc chắn rằng Wapiti đã được cài đặt và có trong PATH hệ thống.")
        return False
    except subprocess.CalledProcessError as e:
        print(f"❌ LỖI: Wapiti gặp sự cố khi đang chạy.")
        print(f"   [STDERR]: {e.stderr}")
        return False