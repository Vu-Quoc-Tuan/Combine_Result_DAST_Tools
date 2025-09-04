import subprocess
import json
from pathlib import Path
import requests


def _login_get_token(base_url: str, email: str, password: str, timeout: int = 10) -> str:
    """
    Đăng nhập Juice Shop qua API /rest/user/login và trả về JWT token (string).
    Ném Exception nếu không lấy được token.
    """
    login_url = f"{base_url.rstrip('/')}/rest/user/login"
    headers = {"Content-Type": "application/json"}
    payload = {"email": email, "password": password}

    resp = requests.post(login_url, json=payload, headers=headers, timeout=timeout)
    resp.raise_for_status()
    data = resp.json()

    # Tùy phiên bản, token nằm ở authentication.token hoặc token
    token = (
        (data.get("authentication") or {}).get("token")
        or data.get("token")
    )
    if not token:
        raise RuntimeError(f"Không tìm thấy token trong phản hồi: {data}")
    return token


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






    base_url = config['juice']['base_url']
    email = config['juice']['email']
    password = config['juice']['password']


    # 1) Đăng nhập lấy JWT
    print(">>> Đăng nhập Juice Shop để lấy JWT...")
    try:
        token = _login_get_token(base_url, email, password)
        print("✅ Lấy token thành công.")
    except Exception as e:
        print(f"❌ LỖI đăng nhập / lấy token: {e}")
        return False
    
    command = [
        wapiti_path,
        '-u', target_url,               # VD: "http://localhost:3000"
        '-m', 'all',
        '--scope', 'domain',
        '--flush-session',              # nếu muốn quét lại từ đầu, cân nhắc thêm '--flush-attacks'
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
        '-o', str(report_file),
        '--cookie-value', f"token={token}",  # <<< quan trọng: truyền JWT
    ]


    
    # command = [
    #     wapiti_path,
    #     '-u', target_url,
    #     '-m', 'all',
    #     '--scope', 'domain',
    #     '--flush-session',
    #     '--max-links-per-page', '500',
    #     '--max-parameters', '100',
    #     '--headless', 'hidden',
    #     '--color',
    #     '-v', '2',
    #     '--tasks', '15',
    #     '--verify-ssl', '0',
    #     '--max-scan-time', '28800',
    #     '-dr', '2',
    #     '-f', 'json',
    #     '-o', str(report_file)
    # ]
    
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