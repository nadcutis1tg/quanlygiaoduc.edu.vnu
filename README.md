# EduManager Pro - Hệ Thống Quản Trị Giáo Dục Toàn Diện

## Tổng Quan
EduManager Pro là hệ thống quản lý giáo dục thông minh tích hợp AI, hỗ trợ quản lý toàn diện các hoạt động của trường đại học/trung tâm đào tạo.

## Công Nghệ Sử Dụng
- **Backend**: Node.js + Express.js
- **Frontend**: React.js + TypeScript
- **Database**: PostgreSQL + Redis
- **AI/ML**: Python (FastAPI) + TensorFlow
- **Authentication**: OAuth 2.0 (Google, Apple)
- **Real-time**: Socket.io
- **File Storage**: AWS S3 / Local Storage

## Cấu Trúc Dự Án
```
edumanager-pro/
├── backend/              # Node.js API Server
├── frontend/             # React Application
├── ai-service/           # Python AI/ML Service
├── database/             # Database schemas & migrations
└── docs/                 # Documentation
```

## Các Module Chính

### 1. Quản Lý Học Viên
- Hồ sơ học viên chi tiết
- Đăng ký khóa học
- Theo dõi học tập
- AI dự đoán nguy cơ bỏ học
- Phân tích hành vi học tập

### 2. Quản Lý Giáo Viên
- Thông tin giáo viên (trình độ, kinh nghiệm)
- Quản lý lương, chấm công
- Đánh giá giờ dạy
- Quản lý nghỉ phép
- Phân công giảng dạy

### 3. Thời Khóa Biểu Thông Minh
- Xếp lịch tự động bằng AI
- Quản lý thay thế giáo viên
- View theo giáo viên/phòng học
- Xuất TKB đa định dạng
- Upload file Excel tự động phân tích

### 4. Quản Lý Tài Chính
- Thu học phí đa kênh
- Quản lý học bổng
- Báo cáo tài chính
- Dự báo doanh thu AI

### 5. Quản Lý Nghiên Cứu Khoa Học
- Quản lý đề tài
- Theo dõi công bố
- Quản lý phòng thí nghiệm
- Sở hữu trí tuệ

### 6. Lớp Học Online
- Tích hợp Zoom/Google Meet/MS Teams
- Quản lý lớp hybrid
- Ghi hình tự động

### 7. Báo Cáo & Phân Tích AI
- Dashboard thông minh
- Báo cáo tự động
- Phân tích dự đoán
- Benchmarking

### 8. Hệ Thống Thông Báo
- Đa kênh (Email, SMS, Push, In-app)
- Thông báo thông minh
- Real-time updates

### 9. Cổng Phụ Huynh
- Theo dõi con em
- Thanh toán trực tuyến
- Nhận thông báo

### 10. Bảo Mật & Phân Quyền
- OAuth 2.0 (Google, Apple)
- JWT Authentication
- Role-based Access Control

## Cài Đặt

### Yêu Cầu Hệ Thống
- Node.js >= 18.x
- Python >= 3.9
- PostgreSQL >= 14
- Redis >= 6.x

### Cài Đặt Backend
```bash
cd backend
npm install
cp .env.example .env
npm run migrate
npm run dev
```

### Cài Đặt Frontend
```bash
cd frontend
npm install
npm start
```

### Cài Đặt AI Service
```bash
cd ai-service
pip install -r requirements.txt
python main.py
```

## API Documentation
Xem tài liệu API tại: http://localhost:3000/api-docs

## License
MIT License
