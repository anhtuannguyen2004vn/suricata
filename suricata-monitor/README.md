# Suricata IDS + AI: giám sát và cảnh báo

Bộ phần mềm phòng thủ này kết hợp hai lớp:

1. **Suricata IDS** đối chiếu lưu lượng với luật và ghi cảnh báo `alert` vào EVE JSON.
2. **AI Isolation Forest** học baseline từ các sự kiện `flow` bình thường, sau đó đánh dấu luồng lệch đáng kể khỏi baseline.
3. **Dashboard** lưu sự kiện vào SQLite, hiển thị cảnh báo Suricata và dấu hiệu bất thường AI.

AI chỉ đánh dấu hành vi khác thường để người vận hành kiểm tra. Một luồng bất thường không tự động đồng nghĩa với một cuộc tấn công. Suricata phát ra EVE JSON gồm các loại sự kiện như alert và flow; cần bật cả hai loại này để có chữ ký IDS lẫn dữ liệu cho AI.

## Kiến trúc

`Lưu lượng trong lab → Suricata → eve.json (alert + flow) → Python monitor → SQLite + Dashboard`

## 1. Bật EVE alert và flow trên Ubuntu

Mở cấu hình Suricata (thường là `/etc/suricata/suricata.yaml`) và kiểm tra phần `outputs` / `eve-log`. Bên trong `types`, bảo đảm có ít nhất:

```yaml
types:
  - alert
  - flow
```

Giữ nguyên các tùy chọn EVE khác đang có. Kiểm tra cấu hình rồi khởi động lại dịch vụ:

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml
sudo systemctl restart suricata
sudo systemctl status suricata --no-pager
```

Kiểm tra log:

```bash
sudo ls -l /var/log/suricata/eve.json
sudo tail -n 5 /var/log/suricata/eve.json
sudo grep -m 3 '"event_type":"flow"' /var/log/suricata/eve.json
```

Nếu `eve.json` không nằm ở đường dẫn này, lấy đường dẫn thực tế để dùng ở các bước sau. Nếu không có sự kiện `flow`, hãy xác nhận EVE có `flow` trong `types`, interface giám sát có lưu lượng lab, rồi tạo một ít lưu lượng hợp lệ trong mạng lab để Suricata ghi nhận.

## 2. Cài và huấn luyện AI baseline

Giữ một khoảng dữ liệu đại diện cho hoạt động bình thường của lab để AI học baseline. Tối thiểu cần 100 flow event; nên thu thập nhiều hơn và qua các trạng thái sử dụng bình thường khác nhau. Không huấn luyện bằng giai đoạn đang có sự cố hoặc hoạt động bất thường đã biết.

```bash
cd suricata-monitor
sudo apt update
sudo apt install -y python3-venv python3-pip
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
python train_ai.py --eve /var/log/suricata/eve.json --model models/suricata_iforest.joblib
```

Nếu tài khoản hiện tại không đọc được log Suricata, cấp quyền đọc tối thiểu theo chính sách máy của bạn hoặc dùng đúng tài khoản dịch vụ đã được cấp quyền. Kiểm tra quyền trước bằng `ls -l /var/log/suricata/eve.json`; tránh mở quyền đọc cho tất cả người dùng.

Huấn luyện thành công sẽ tạo `models/suricata_iforest.joblib`. Tham số `--contamination 0.02` là tỷ lệ bất thường dự kiến trong baseline; có thể chỉnh, nhưng thay đổi tham số sẽ đổi ngưỡng AI đánh dấu.

## 3. Chạy dashboard

Giữ môi trường ảo đã kích hoạt:

```bash
python app.py \
  --eve /var/log/suricata/eve.json \
  --db ./data/alerts.sqlite3 \
  --model ./models/suricata_iforest.joblib \
  --bind 127.0.0.1 \
  --port 8080
```

Mở `http://127.0.0.1:8080` trên Ubuntu. Dashboard tự cập nhật mỗi 5 giây. Trên giao diện:

- Cảnh báo `Suricata` đến từ chữ ký IDS.
- Cảnh báo `AI` là flow bị mô hình đánh dấu bất thường.
- Điểm Isolation Forest càng thấp/âm thì flow càng lệch khỏi baseline mà mô hình đã học; đây không phải xác suất tấn công.
- Bấm **Mở rộng** ở từng dòng để mở cửa sổ phân tích riêng; cửa sổ không tự đóng khi dashboard cập nhật. Đóng bằng nút `×` (hoặc phím `Esc`). Nội dung gồm diễn giải cảnh báo, thời gian GMT+7, IP/cổng hai chiều, giao thức, số byte/gói, thời lượng flow và gợi ý rà soát.

Mặc định dashboard chỉ mở trên loopback của Ubuntu. Nếu cần mở từ máy khác trong mạng lab, cấu hình firewall giới hạn đúng IP máy quản trị và dùng `--bind 0.0.0.0`; không công khai dashboard ra Internet.

## 4. Huấn luyện lại sau khi baseline thay đổi

Nếu thay đổi đáng kể máy chủ, dịch vụ hoặc kiểu lưu lượng bình thường, hãy thu thập baseline mới rồi chạy lại lệnh `train_ai.py`. Dừng app trước khi thay file model để tránh đọc file trong lúc đang ghi. Lưu lại phiên bản cũ nếu cần đối chiếu kết quả.

## API

- `GET /api/stats`: số cảnh báo, số dấu hiệu AI, trạng thái mô hình.
- `GET /api/alerts?limit=100`: danh sách mới nhất.
- `GET /api/alerts?q=192.168.56.10&severity=2`: tìm theo chữ ký/IP/danh mục và lọc severity.

## Docker Compose

Thư mục project đã có `Dockerfile` và `docker-compose.yml`. Compose mount log Suricata ở chế độ chỉ đọc, mount model đã huấn luyện tại `./models/suricata_iforest.joblib`, và lưu SQLite trong volume riêng. Các phiên bản Python/AI trong image được khóa theo môi trường đã tạo model để tránh sai khác phiên bản khi nạp model.

Trước khi chạy, bảo đảm model đã có trong `./models`. Nếu dashboard Python đang chạy ở port 8080, quay lại terminal của dashboard và nhấn `Ctrl+C`. Sau đó, trong thư mục `suricata-monitor`:

```bash
sudo docker compose up --build -d
sudo docker compose ps
```

Lần đầu build cần mạng để tải image và các package, có thể mất vài phút. Mở `http://127.0.0.1:8080` trên Ubuntu. Xem log bằng `sudo docker compose logs -f monitor`; dừng container bằng `sudo docker compose down`. Không thêm `-v` nếu muốn giữ dữ liệu SQLite. Mặc định port chỉ được bind vào `127.0.0.1:8080` trên host.

## Giới hạn và an toàn vận hành

- Đây là mô hình đồ án/lab. AI không thay thế luật Suricata, phân tích của người vận hành hay hệ thống phản ứng sự cố.
- Baseline thiếu đại diện có thể tạo nhiều cảnh báo sai hoặc bỏ qua hoạt động lạ. Cần xem lại từng dấu hiệu và tinh chỉnh sau khi đánh giá dữ liệu.
- Mô hình chỉ sử dụng số byte/gói hai chiều, thời lượng, cổng, giao thức và app-protocol từ flow event; chưa phân loại chính xác từng kiểu tấn công.
- Cảnh báo AI không tự chặn IP hay thay đổi firewall.
- Chưa có tài khoản đăng nhập, HTTPS, phân quyền, chính sách lưu trữ log, hoặc tích hợp email/Telegram. Chỉ chạy trong lab hoặc sau lớp bảo vệ phù hợp.
- Chỉ giám sát hệ thống và mạng mà bạn được phép quản trị.
