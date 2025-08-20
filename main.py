from Run_tools.workflow import start_scans
from Merge_reports.merge import start_merge
import argparse
import time

def main_workflow():
    """
    Quy trình chính của workflow quét bảo mật tự động Zap, Wapiti và merge report.
    """
    # Thiết lập trình phân tích đối số dòng lệnh
    parser = argparse.ArgumentParser(description="Workflow Quét Bảo mật Tự động.")
    parser.add_argument(
        'mode', 
        type=int, 
        choices=[1], 
        help="Chế độ chạy normal."
    )
    parser.add_argument(
        'target_url', 
        type=str, 
        help="URL của ứng dụng web cần quét."
    )
    
    # Đọc các đối số input từ dòng lệnh
    args = parser.parse_args()

    print("==========================================")
    print("==   BẮT ĐẦU WORKFLOW BẢO MẬT TỰ ĐỘNG   ==")
    print("==========================================")
    
    # Kiểm tra chế độ chạy
    if args.mode == 1:
        # Giai đoạn 1: Chạy các công cụ quét với URL từ người dùng
        # start_scans(args.target_url)
        
        print("\nChờ 5 giây trước khi chuyển sang giai đoạn hợp nhất...\n")
        time.sleep(5)
        
        # Giai đoạn 2: Hợp nhất báo cáo
        start_merge()
    
    print("\n==========================================")
    print("==      WORKFLOW ĐÃ HOÀN TẤT          ==")
    print("==========================================")

if __name__ == "__main__":
    main_workflow()