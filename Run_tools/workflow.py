from Run_tools.run_zap import run_zap_scan,run_zap_proxy
from Run_tools.run_wapiti import run_wapiti_scan
import time

def start_scans(target_url: str):
    """
    Chạy các công cụ quét bảo mật Zap và Wapiti với URL mục tiêu được cung cấp.
    Note: ZAP và Wapiti sẽ được chạy tuần tự.
    """
    print("--- BẮT ĐẦU QUY TRÌNH QUÉT BẢO MẬT ---")
    print(f"Mục tiêu: {target_url}")

    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        print("❌ LỖI: URL mục tiêu phải bắt đầu bằng 'http://' hoặc 'https://'.")
        return
        
    process = run_zap_proxy()
    time.sleep(15)  # Đợi một chút để ZAP Proxy khởi động hoàn toàn
    zap_success = run_zap_scan(target_url)
    wapiti_success = run_wapiti_scan(target_url)
    
    if wapiti_success and zap_success:
        print("\n--- HOÀN TẤT QUY TRÌNH QUÉT ---")
    else:
        if not zap_success :
            print("❌ Quét ZAP không thành công. Vui lòng kiểm tra lỗi.")
        else:
            print("❌ Quét Wapiti không thành công. Vui lòng kiểm tra lỗi.")
        
        return