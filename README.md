# 🛡️ TERMINAL ACCESS & BIOMETRIC INTELLIGENCE SYSTEM

[![Gemini AI](https://img.shields.io/badge/AI-Gemini%20Pro-blueviolet?style=for-the-badge&logo=google-gemini)](https://deepmind.google/technetwork/gemini/)
[![FaceID](https://img.shields.io/badge/Biometric-FaceID-green?style=for-the-badge&logo=biometric)](https://github.com/justadudewhohacks/face-api.js)
[![Status](https://img.shields.io/badge/Status-Operational-brightgreen?style=for-the-badge)](https://github.com/)

Hệ thống quản trị nội bộ tối mật với giao diện **Cyberpunk Terminal**. Tích hợp xác thực sinh trắc học khuôn mặt (FaceID) và trợ lý ảo Gemini AI để phân tích dữ liệu log thời gian thực từ MongoDB.

---

## 📸 Trải nghiệm Giao diện (UI/UX)

- **Hacker Aesthetic:** Hiệu ứng Matrix Rain, Scanline CRT, và Terminal text chạy thời gian thực.
- **Interactive Mascots:** Linh vật (Ong & Bướm) phản hồi trạng thái hệ thống:
  - 🐝 **Bee:** Xuất hiện khi hệ thống đang xử lý tác vụ nặng hoặc quét dữ liệu.
  - 🦋 **Butterfly:** Biểu tượng của trạng thái hệ thống ổn định và an toàn.
- **Responsive Design:** Tối ưu hóa trải nghiệm trên các màn hình độ phân giải cao với font chữ mono-space.

---

## 🚀 Tính năng cốt lõi

### 1. Hệ thống FaceID 3D Scanning

Sử dụng thư viện `face-api.js` trên nền tảng `TensorFlow.js` để triển khai bảo mật sinh trắc học:

- **Enrollment Mode:** Quy trình đăng ký nghiêm ngặt, yêu cầu người dùng xoay mặt các góc để thu thập 40 mẫu nhận diện (descriptors).
- **Biometric Security:** Tính toán khoảng cách Euclid (Euclidean distance) giữa khuôn mặt hiện tại và dữ liệu gốc. Ngưỡng chấp nhận (Threshold) được thiết lập ở mức `< 0.4` để đảm bảo độ chính xác tuyệt đối.
- **Security Lock:** Tự động khóa các tính năng nhạy cảm nếu không phát hiện khuôn mặt Admin.

### 2. Quản lý Log & MongoDB Data

- **Dynamic Explorer:** Tự động truy vấn và hiển thị danh sách tất cả các Collections có trong Database.
- **Pagination Engine:** Hệ thống phân trang thông minh với tham số `Limit` và `Skip`, giúp duyệt hàng triệu bản ghi log mà không gây treo trình duyệt.
- **Data Manipulation:**
  - Xem dữ liệu dưới định dạng JSON Beautify.
  - Sao chép nhanh dữ liệu (Copy to Clipboard).
  - Xóa bản ghi trực tiếp từ giao diện Terminal.

### 3. Phân tích AI (Gemini Integration)

- **Contextual Analysis:** Gửi dữ liệu log trực tiếp sang Gemini AI để nhận diện các mẫu truy cập bất thường (Security Analysis).
- **Structured Reports:** AI trả về kết quả được định dạng sẵn (Markdown) với các mục: Tóm tắt, Cảnh báo rủi ro, và Đề xuất xử lý.

---

## 🛠️ Kiến trúc Công nghệ (Stack)

| Lớp (Layer)           | Công nghệ sử dụng                                      |
| :-------------------- | :----------------------------------------------------- |
| **Frontend**          | HTML5, CSS3 (Custom Properties), JavaScript ES6+       |
| **Bảo mật**           | `face-api.js` (SSDLite MobileNet V1, Face Landmark 68) |
| **Trí tuệ nhân tạo**  | Google Gemini Pro API                                  |
| **Backend (Yêu cầu)** | Node.js, Express.js                                    |
| **Cơ sở dữ liệu**     | MongoDB (Native Driver)                                |
| **Icons & Fonts**     | FontAwesome 6, Google Fonts (VT323, Share Tech Mono)   |

---

## 📂 Cấu trúc dự án

```text
├── index.html          # Cổng vào hệ thống (Landing Page)
├── access.html         # Bảng điều khiển quản trị (Main Dashboard)
├── faceid.html         # Giao diện quét khuôn mặt bảo mật
├── css/
│   ├── style.css       # Hiệu ứng Terminal & Matrix
│   └── faceid.css      # Hiệu ứng Laser Scan & Camera Overlay
├── js/
│   ├── access.js       # Logic xử lý API MongoDB & Gemini AI
│   └── faceid.js       # Logic xử lý AI nhận diện khuôn mặt
└── models/             # Chứa các file trọng số (weights) của face-api.js
```
