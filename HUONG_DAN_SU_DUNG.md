# Hướng dẫn cài đặt và sử dụng Suricata IDS + AI

Tài liệu hướng dẫn chạy dashboard giám sát trên Ubuntu, đọc sự kiện EVE JSON của Suricata và truy cập giao diện từ máy Windows trong cùng mạng.

## 1. Mô hình hoạt động

- Suricata theo dõi lưu lượng mạng và ghi sự kiện vào `eve.json`.
- Ứng dụng trong Docker đọc log EVE, lưu cảnh báo và hiển thị trên dashboard.
- Isolation Forest phân tích các sự kiện `flow` để gắn cờ những luồng khác với dữ liệu huấn luyện.
- Máy Windows dùng trình duyệt để truy cập dashboard chạy trên Ubuntu.

> Cảnh báo do AI đánh dấu là dấu hiệu cần xem xét, không tự khẳng định có xâm nhập. Hãy đối chiếu chữ ký Suricata và hoạt động thực tế trước khi kết luận.

## 2. Yêu cầu

Trên máy Ubuntu chạy hệ thống:

- Docker Engine và Docker Compose plugin.
- Suricata đã cài đặt và đang giám sát đúng card mạng.
- EVE JSON được bật, có ghi loại sự kiện `alert` và `flow`.
- Mã nguồn dự án, file model `models/suricata_iforest.joblib` và cấu hình Compose.

Đường dẫn log mặc định của hướng dẫn này là `/var/log/suricata/eve.json`. Nếu máy đang dùng đường dẫn khác, sửa đường dẫn mount trong `docker-compose.yml` cho đúng.

## 3. Lấy mã nguồn trên máy Ubuntu

Trên GitHub, mở repo, bấm **Code** → **HTTPS** và sao chép địa chỉ clone. Trên Ubuntu chạy:

```bash
git clone <URL-HTTPS-cua-repo>
cd <ten-thu-muc-repo>
```

Ví dụ cấu trúc thư mục cần có:

```text
app.py
ai_model.py
train_ai.py
Dockerfile
docker-compose.yml
requirements.txt
templates/index.html
models/suricata_iforest.joblib
```

Nếu file model chưa có, huấn luyện từ log EVE trên máy Ubuntu:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
sudo .venv/bin/python train_ai.py \
  --eve /var/log/suricata/eve.json \
  --model models/suricata_iforest.joblib
```

Nên huấn luyện trên dữ liệu flow bình thường của chính mạng lab. Đảm bảo thư mục `models/` tồn tại trước khi chạy lệnh.

## 4. Kiểm tra Suricata và đường dẫn log

Kiểm tra Suricata đang chạy:

```bash
sudo systemctl status suricata --no-pager
```

Kiểm tra log EVE có dữ liệu:

```bash
sudo ls -lh /var/log/suricata/eve.json
sudo tail -n 3 /var/log/suricata/eve.json
```

Kiểm tra Compose đang mount đúng file log và model:

```bash
grep -nE 'eve.json|models|ports' docker-compose.yml
```

Nếu đường dẫn trên máy khác với cấu hình Compose, sửa phần `volumes` theo đường dẫn thực tế. EVE JSON cần có sự kiện `alert` và `flow` để dashboard hiển thị cảnh báo Suricata và kết quả phân tích AI.

## 5. Khởi chạy dashboard

Đứng trong thư mục dự án, chạy:

```bash
sudo docker compose up -d --build
```

Kiểm tra trạng thái container:

```bash
sudo docker compose ps
```

Xem log nếu container chưa chạy:

```bash
sudo docker compose logs -f
```

Mở trình duyệt ngay trên Ubuntu tại:

```text
http://localhost:8080
```

Dashboard tự tải lại dữ liệu định kỳ. Có thể tìm theo chữ ký hoặc IP, lọc mức độ, bấm **Mở rộng** để xem thời gian, cổng/IP nguồn và đích cùng thông tin flow. Dùng nút **×** hoặc phím `Esc` để đóng phần phân tích.

## 6. Mở dashboard từ Windows

Ubuntu và Windows cần kết nối được với nhau qua mạng. Trên Ubuntu lấy địa chỉ IP:

```bash
hostname -I
```

Trong `docker-compose.yml`, phần công bố cổng cần cho phép truy cập từ mạng. Nếu đang là:

```yaml
127.0.0.1:8080:8080
```

đổi thành:

```yaml
8080:8080
```

Lưu file và chạy lại:

```bash
sudo docker compose up -d
```

Trên Windows, mở trình duyệt và truy cập `http://<IP-Ubuntu>:8080`, ví dụ `http://192.168.22.100:8080`. Nếu vẫn không truy cập được, kiểm tra hai máy có cùng mạng, IP Ubuntu chính xác, firewall và trạng thái container.

Với mô hình này, dashboard và Suricata vẫn chạy trên Ubuntu; Windows chỉ mở giao diện. Nếu chuyển dashboard sang một máy khác, máy đó phải được cấu hình để đọc được file EVE JSON và model tương ứng.

## 7. Kiểm tra hoạt động

1. Mở dashboard và ghi lại tổng cảnh báo ban đầu.
2. Tìm một IP đang có trong bảng, sau đó thử lọc mức độ `High`.
3. Bấm **Mở rộng**, kiểm tra thời gian, IP/cổng nguồn-đích và giao thức; chờ hơn 5 giây để xác nhận bảng vẫn mở, rồi đóng bằng `×`.
4. Tạo lưu lượng hoặc sự kiện thử trong mạng lab được phép giám sát.
5. Trên Ubuntu kiểm tra log mới bằng `sudo tail -f /var/log/suricata/eve.json`; đối chiếu thời gian và chữ ký với dòng xuất hiện trên dashboard.

Làm mới trang không tự tạo cảnh báo. Suricata chỉ ghi cảnh báo khi một luật khớp với lưu lượng mà cảm biến quan sát được; AI cũng chỉ đánh dấu flow nếu mô hình đánh giá nó khác thường.

## 8. Dừng, chạy lại và cập nhật

Dừng container nhưng giữ lại dữ liệu trong volume:

```bash
sudo docker compose down
```

Chạy lại:

```bash
sudo docker compose up -d
```

Sau khi sửa mã nguồn và tải phiên bản mới nhất từ GitHub:

```bash
git pull
sudo docker compose up -d --build
```

Không thêm `-v` vào lệnh `docker compose down` nếu muốn giữ cơ sở dữ liệu cảnh báo trong Docker volume.

## 9. Xử lý lỗi thường gặp

- **Trang không mở:** chạy `sudo docker compose ps`, xem `sudo docker compose logs -f`, kiểm tra cổng `8080` và IP Ubuntu.
- **Trang mở nhưng không có cảnh báo mới:** kiểm tra Suricata có chạy, `eve.json` có cập nhật, và Compose có mount đúng file đó không.
- **AI báo không hoạt động:** kiểm tra file `models/suricata_iforest.joblib` tồn tại và đường dẫn model trong cấu hình ứng dụng/Compose trùng nhau.
- **Bảng không hiện cảnh báo thử:** xác nhận sự kiện có trong EVE trước; dashboard chỉ hiển thị sự kiện mà ứng dụng đọc và lưu thành công.
- **Không thấy flow mới ngay:** một số flow được ghi khi kết nối kết thúc hoặc hết thời gian chờ.

## 10. Dữ liệu không nên đưa lên repo công khai

Không commit log `eve.json` thật, cơ sở dữ liệu cảnh báo, file `.env`, mật khẩu, hoặc dữ liệu mạng có thông tin riêng tư. Nếu cần ví dụ trong repo, chỉ dùng file `sample/eve.json` đã tạo dữ liệu giả và đã loại bỏ thông tin nhạy cảm.
