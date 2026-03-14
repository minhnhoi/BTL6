# Preserve + Harden patch

Bản này giữ lại giao diện và phần lớn flow cũ, nhưng vá các điểm nguy hiểm:

- Bỏ cơ chế admin hardcode ở frontend, chuyển sang session cookie HttpOnly trên backend.
- Access Manager và Admin mode dùng session backend, không còn phụ thuộc localStorage/token plain text.
- FaceID login chuyển sang verify descriptor ở server, không public descriptor của Admin cho client khi chưa xác thực.
- Thiết lập FaceID mới yêu cầu xác thực admin password trước.
- Xóa FaceID yêu cầu xác thực khuôn mặt thành công ngay trước khi xóa.
- Chặn upload các MIME nguy hiểm như HTML, JS, SVG.
- Chặn upload URL tới localhost/private IP để giảm SSRF.
- Static files chỉ serve từ thư mục public, không phơi server.js/package.json.
- Thêm same-origin checks cho các route nhạy cảm và rate limit cho admin login / face verify.
- Sửa lỗi integrity do Cloudinary config toàn cục bằng cách serial hóa các thao tác theo account.
- Giữ route cũ `/get-count` và `/save-count` để code cũ không lỗi console.

## Chạy

1. `npm install`
2. Tạo `.env` từ `.env.example`
3. Tạo hash admin:
   `npm run hash:admin -- "mat-khau-cua-ban"`
4. Dán hash vào `ADMIN_PASSWORD_HASH`
5. `npm start`

## Lưu ý

- Nếu bạn có các asset như `intro.mp4`, `logo (1).png` thì đặt trong `public/`.

### chạy lệnh up git

@"
node_modules/
.env
.env.\*
_.log
npm-debug.log_
.DS_Store
Thumbs.db
.vscode/
.idea/
"@ | Set-Content .gitignore

git config --global user.name "minhnhoi"
git config --global user.email "minhnhoi2804@gmail.com"

git init
git branch -M main

git remote remove origin 2>$null
git remote add origin https://github.com/TEN-TAI-KHOAN/TEN-REPO.git <!--https://github.com/minhnhoi/project.git -->

git add .
git status
git commit -m "first commit"
git push -u origin main
