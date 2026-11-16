#!/usr/bin/env python3
"""Train a baseline Isolation Forest from authorized Suricata EVE flow logs."""
import argparse
from ai_model import train


def main():
    parser = argparse.ArgumentParser(description="Huấn luyện baseline AI từ EVE flow events")
    parser.add_argument("--eve", required=True, help="Đường dẫn eve.json đã ghi các flow event")
    parser.add_argument("--model", default="models/suricata_iforest.joblib")
    parser.add_argument("--contamination", type=float, default=0.02,
                        help="Tỷ lệ bất thường dự kiến trong dữ liệu huấn luyện (mặc định 0.02)")
    args = parser.parse_args()
    if not 0 < args.contamination <= 0.5:
        parser.error("--contamination phải lớn hơn 0 và không quá 0.5")
    try:
        count, path = train(args.eve, args.model, args.contamination)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(f"Đã huấn luyện từ {count} flow event. Mô hình: {path}")
    print("Hãy rà soát các cảnh báo AI trước khi kết luận đây là xâm nhập.")


if __name__ == "__main__":
    main()
