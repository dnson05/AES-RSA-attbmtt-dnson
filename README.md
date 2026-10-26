# BÁO CÁO BÀI TẬP
## Môn: An toàn và bảo mật thông tin
### Đề tài: Mã hoá AES, mã hoá RSA, hàm băm SHA-256 và chữ ký số

---

## THÔNG TIN SINH VIÊN

| Mục | Nội dung |
|---|---|
| Họ và tên | `Đàm Ngọc Sơn` |
| Mã sinh viên | `K235480106061` |
| Lớp | `K59.KTP.K01` |
| Khoa | `Điện tử` |
| Trường | `Trường đại học kỹ thuật công nghiệp Thái Nguyên` |


---

## MỤC LỤC
1. [Môi trường thực hiện](#1-môi-trường-thực-hiện)
2. [Bài 1: Mã hoá AES](#bài-1-mã-hoá-aes-đối-xứng)
3. [Bài 2: Mã hoá RSA, SHA-256 và chữ ký số](#bài-2-mã-hoá-rsa-sha-256-và-chữ-ký-số)
4. [Tổng kết](#tổng-kết)

---

## 1. Môi trường thực hiện

| Mục | Thông tin |
|---|---|
| Hệ điều hành | `<vd: Windows 11>` |
| CPU | `<vd: Intel Core i5-xxxx, có AES-NI>` |
| RAM | `<vd: 16 GB>` |
| Ổ đĩa | `<vd: SSD NVMe / HDD>` |
| Công cụ | .NET 8 SDK, ngôn ngữ C#, ứng dụng Console |
| Thư viện | `System.Security.Cryptography` (có sẵn trong .NET) |

Cấu trúc mã nguồn:
```
Bai1_AES/   (Bai1_AES.csproj, Program.cs)
Bai2_RSA/   (Bai2_RSA.csproj, Program.cs)
```
Chạy: `dotnet run -c Release` trong từng thư mục.

---

# BÀI 1: MÃ HOÁ AES (đối xứng)

## 1.1. Yêu cầu
Xây dựng ứng dụng (console) thực hiện: sinh khoá AES, lưu khoá ra file, import khoá từ file, mã hoá một đoạn văn bản và hiển thị kết quả, mã hoá một file rồi lưu ra file. Thử nghiệm với file dung lượng lớn (hàng GB), tính thời gian mã hoá và giải mã, so sánh theo byte giữa file nguồn và file giải mã, từ đó rút ra kết luận.

## 1.2. Cơ sở lý thuyết
AES là mật mã khối đối xứng: **mã hoá và giải mã dùng chung một khoá**. Khối dữ liệu 128 bit (16 byte), khoá 128, 192 hoặc 256 bit. Chương trình dùng **AES-256 chế độ CBC, padding PKCS7**. Mỗi lần mã hoá sinh một **IV ngẫu nhiên** 16 byte (IV không bí mật nên được lưu ở đầu file mã hoá).

## 1.3. Thiết kế chương trình
| Chức năng | Cách thực hiện |
|---|---|
| Sinh khoá | `RandomNumberGenerator.GetBytes(32)` |
| Lưu khoá | Ghi chuỗi base64 của khoá ra file `aes.key` |
| Import khoá | Đọc file, giải base64, kiểm tra độ dài 16/24/32 byte |
| Mã hoá văn bản | Kết quả in ra màn hình dạng base64 của `IV ‖ ciphertext` |
| Mã hoá, giải mã file | Dùng `CryptoStream`, đọc ghi từng khối 1 MB nên không tốn RAM với file GB. Cấu trúc file mã hoá: `[16 byte IV][ciphertext]` |
| So sánh byte | Đọc song song hai file theo từng khối 1 MB, so sánh từng byte |
| Đo thời gian | `Stopwatch` |

## 1.4. Kết quả thực hiện

### a) Sinh khoá AES và lưu khoá ra file

<img width="1917" height="1017" alt="image" src="https://github.com/user-attachments/assets/5c4ebc5c-df95-42c5-bc20-177e6d009062" />
<img width="1917" height="1018" alt="image" src="https://github.com/user-attachments/assets/f26ceab3-9a02-4809-8752-54d7d1bf3071" />


Nội dung file `aes.key` (mở bằng Notepad):

<img width="1423" height="732" alt="image" src="https://github.com/user-attachments/assets/5138448c-ebce-41c6-a858-7f61344fb986" />


### b) Import khoá từ file

<img width="1917" height="1020" alt="image" src="https://github.com/user-attachments/assets/6631936e-10ad-4a72-8637-b4f77d7d2eb8" />


### c) Mã hoá đoạn văn bản

<img width="1121" height="697" alt="image" src="https://github.com/user-attachments/assets/9d6d7ded-3bb7-4c91-8409-692fc4b72710" />


### d) Mã hoá file

<img width="1212" height="787" alt="image" src="https://github.com/user-attachments/assets/15b86bfd-18ca-4be9-a244-0be7873ff99b" />
<img width="1202" height="857" alt="image" src="https://github.com/user-attachments/assets/3d09b204-caa3-4d70-8adf-c35639c3d2d4" />


### e) Thử nghiệm với file dung lượng lớn
Tạo file test bằng menu 8, sau đó chạy menu 7 để mã hoá, giải mã, đo thời gian và so sánh byte.

**File ~100 MB:**

<img width="1917" height="1020" alt="image" src="https://github.com/user-attachments/assets/dfce3a59-f5c1-4cd4-98ef-355f5fa6a728" />



**File ~1 GB:**

<img width="1917" height="1018" alt="image" src="https://github.com/user-attachments/assets/b459fb80-807b-46d2-9a6a-f38b01ab9234" />



## 1.5. Nhận xét và kết luận
1. **Tính đúng đắn**: kết quả so sánh byte cho thấy file giải mã giống file nguồn hoàn toàn, nên quá trình mã hoá và giải mã không làm mất hay sai lệch dữ liệu, kể cả với file hàng GB.
2. **Quan hệ thời gian và dung lượng**: thời gian xử lý tăng xấp xỉ **tuyến tính** theo dung lượng file (tốc độ MB/s gần như không đổi). AES xử lý từng khối 16 byte nên độ phức tạp O(n).
3. **Tốc độ**: tốc độ đạt `<...>` MB/s. Nếu CPU có AES-NI thì tốc độ cao và thường bị giới hạn bởi tốc độ đọc ghi ổ đĩa chứ không phải do thuật toán.
4. **Mã hoá và giải mã**: thời gian hai chiều xấp xỉ nhau (`<...>` s so với `<...>` s).
5. **Kích thước file mã hoá**: lớn hơn file gốc chỉ khoảng 17 đến 32 byte (padding + 16 byte IV), nên chi phí lưu trữ không đáng kể.
6. **Đánh giá chung**: AES đủ nhanh và phù hợp để mã hoá dữ liệu lớn. Hạn chế là vấn đề **trao đổi khoá**: hai bên phải chia sẻ khoá bí mật an toàn. Vấn đề này được giải quyết bằng mã hoá bất đối xứng (RSA) ở Bài 2.

---

# BÀI 2: MÃ HOÁ RSA, SHA-256 VÀ CHỮ KÝ SỐ

## 2.1. Yêu cầu
Xây dựng ứng dụng .NET thực hiện: sinh cặp khoá RSA, xuất ra file PEM, xem cấu trúc PEM và ý nghĩa các byte, import PEM để lấy n, e (public) và n, e, d... (private), mã hoá dữ liệu không quá 190 byte và lưu base64, giải mã và so sánh với nguồn, đánh giá tốc độ khoá công khai và khoá bí mật, sinh chuỗi băm SHA-256 và đánh giá sự thay đổi khi đầu vào đổi rất ít, cuối cùng là chữ ký số và đề xuất phương pháp để cùng dữ liệu, cùng người ký nhưng mỗi lần ký cho chữ ký khác nhau.

## 2.2. Cơ sở lý thuyết
RSA là mã hoá **bất đối xứng**: mã hoá bằng một khoá và giải mã bằng khoá còn lại.
- Chọn hai số nguyên tố lớn p, q. Tính n = p·q.
- Chọn e (thường là 65537), tính d = e⁻¹ mod φ(n).
- Khoá công khai (n, e). Khoá bí mật (n, d) cùng p, q, dp, dq, qinv (phục vụ tăng tốc bằng CRT).
- Mã hoá: c = m^e mod n. Giải mã: m = c^d mod n.

Padding sử dụng: **OAEP với SHA-256**. Với khoá 2048 bit (k = 256 byte), dữ liệu tối đa là k − 2·32 − 2 = **190 byte**. Khoá AES-256 (32 byte) nằm trong giới hạn nên thường được bọc bằng RSA.

## 2.3. Kết quả thực hiện

### a) Sinh cặp khoá và xuất file PEM (yêu cầu 1, 2)

<img width="1480" height="760" alt="image" src="https://github.com/user-attachments/assets/4428b5c8-b0a7-4a33-88c7-df6d942e062f" />


> puclic.pem
<img width="1432" height="730" alt="image" src="https://github.com/user-attachments/assets/5dd6db77-8574-4f6e-9ba3-96f74c6934c9" />

> private.pem
<img width="1427" height="742" alt="image" src="https://github.com/user-attachments/assets/12a9b546-b2bb-4b7a-8b65-ccbb0fd693b4" />


### b) Xem file PEM và ý nghĩa các byte (yêu cầu 3)
**Public key:**

<img width="1917" height="1018" alt="image" src="https://github.com/user-attachments/assets/3095a94d-3466-49bd-8e3a-bed82dc83165" />


**Private key:**
<img width="1917" height="1017" alt="image" src="https://github.com/user-attachments/assets/70364883-e5cc-4c93-9c1a-f59fbeaff52c" />


**Giải thích cấu trúc.** PEM gồm dòng `-----BEGIN ...-----`, phần **Base64 của DER**, và dòng `-----END ...-----`. DER là mã hoá nhị phân theo ASN.1 với từng phần tử dạng **TLV** (Tag – Length – Value):

| Tag (hex) | Ý nghĩa |
|---|---|
| `30` | SEQUENCE: gói các phần tử con |
| `02` | INTEGER: số nguyên lớn (big-endian) |
| `03` | BIT STRING: byte đầu là số bit đệm; trong public key chứa `SEQUENCE{n, e}` |
| `04` | OCTET STRING: trong PKCS#8 chứa `RSAPrivateKey` |
| `05` | NULL |
| `06` | OBJECT IDENTIFIER: `2A 86 48 86 F7 0D 01 01 01` = 1.2.840.113549.1.1.1 (rsaEncryption) |

- **Length**: dưới 128 thì 1 byte; từ 128 trở lên thì `81 xx` hoặc `82 xx xx`.
- Byte `00` đứng đầu INTEGER được thêm để số luôn dương khi bit cao của byte kế tiếp bằng 1.
- `02 03 01 00 01` là INTEGER dài 3 byte, giá trị 0x010001 = **65537** (chính là e).
- **Public key (SPKI)**: `SEQ{ SEQ{OID rsaEncryption, NULL}, BITSTRING{ SEQ{ INTEGER n, INTEGER e } } }`.
- **Private key (PKCS#8)**: `SEQ{ INTEGER 0, SEQ{OID, NULL}, OCTETSTRING{ SEQ{ 0, n, e, d, p, q, dp, dq, qinv } } }`.

### c) Import PEM, lấy các tham số (yêu cầu 4)

**Public key (n, e):**

<img width="1917" height="905" alt="image" src="https://github.com/user-attachments/assets/9db808de-1e2e-4bc5-8d46-641026a3ca34" />


**Private key (n, e, d, p, q, ...):**

<img width="1917" height="1018" alt="image" src="https://github.com/user-attachments/assets/8a83a172-a9c7-4e20-8668-26574d9c0044" />

### d) Mã hoá dữ liệu bằng public key (yêu cầu 5)
Dữ liệu là mảng byte không quá 190 byte (thử với chuỗi ngẫu nhiên 32 byte, tương đương một khoá AES-256). Kết quả mã hoá lưu base64 trong `cipher.b64`.

<img width="953" height="376" alt="image" src="https://github.com/user-attachments/assets/378139f2-c0cb-4192-93db-d098c0587f4f" />

<img width="1906" height="687" alt="image" src="https://github.com/user-attachments/assets/d95e1a34-b2da-4f00-a7ff-da5285e7d683" />


### e) Giải mã và so sánh với dữ liệu nguồn (yêu cầu 6)


<img width="1170" height="657" alt="image" src="https://github.com/user-attachments/assets/4821b450-dc04-4ab7-9005-2c0ce2ae7773" />


### f) Đánh giá tốc độ: khoá công khai và khoá bí mật (yêu cầu 7)


<img width="1790" height="818" alt="image" src="https://github.com/user-attachments/assets/ae837b81-a006-4a15-ba7d-ad6e72c1a32f" />


**Nhận xét** (đối chiếu với số liệu thực tế):
- Dùng khoá công khai (e = 65537 chỉ 17 bit, chỉ có 2 bit 1) thì lũy thừa modular chỉ cần ~17 phép bình phương và 1 phép nhân nên **rất nhanh**.
- Dùng khoá bí mật (d xấp xỉ 2048 bit) cần ~2048 phép bình phương và ~1024 phép nhân trên số 2048 bit nên **chậm hơn hàng chục lần**, dù đã có CRT hỗ trợ.
- Tăng độ dài khoá thì thời gian dùng khoá bí mật tăng nhanh (xấp xỉ bậc 3 theo độ dài khoá).
- Hệ quả: RSA **không phù hợp mã hoá dữ liệu lớn**, thường chỉ dùng mã hoá khoá AES hoặc ký số. Việc xác minh chữ ký (dùng public key) nhanh hơn việc ký (dùng private key).

### g) Hàm băm SHA-256 và hiệu ứng thác lũ (yêu cầu 8)

<img width="1497" height="748" alt="image" src="https://github.com/user-attachments/assets/7a523981-2c31-461d-94b6-f92eca535ba1" />




**Nhận xét:** SHA-256 luôn cho đầu ra 256 bit (64 ký tự hex) bất kể độ dài đầu vào. Chỉ thay đổi **1 bit** đầu vào thì trung bình khoảng **128/256 bit (≈50%)** của kết quả băm thay đổi và kết quả không còn giống bản cũ. Đó là **hiệu ứng thác lũ (avalanche effect)**: không thể suy ra đầu vào từ kết quả băm hay đoán mối liên hệ giữa hai giá trị băm, và mọi sửa đổi dù rất nhỏ đều bị phát hiện.

### h) Chữ ký số (yêu cầu 9)
Chữ ký số = dùng **khoá bí mật RSA** để ký lên **giá trị băm SHA-256** của dữ liệu. Bên nhận dùng khoá công khai kiểm tra. Dữ liệu khác nhau thì giá trị băm khác nhau nên chữ ký khác nhau.

**Vấn đề cần giải quyết:** với PKCS#1 v1.5, cùng dữ liệu và cùng khoá bí mật luôn cho **cùng một chữ ký** (tất định). Đề mong muốn mỗi lần ký cho chữ ký **khác nhau** nhưng vẫn kiểm tra đúng.

<img width="1542" height="833" alt="image" src="https://github.com/user-attachments/assets/dc7b1f39-8219-40f7-b1be-3845ea7a550b" />

**Đề xuất 1 (chính): RSA-PSS (RSASSA-PSS, RFC 8017).**
1. Tính h = SHA-256(M).
2. Sinh **salt ngẫu nhiên** (độ dài thường bằng độ dài băm).
3. Tính H = SHA-256( 0x00×8 ‖ h ‖ salt ). Ghép `padding ‖ salt` rồi che bằng mặt nạ MGF1(H) để được chuỗi EM.
4. Chữ ký s = EM^d mod n.
5. Bên nhận tính EM = s^e mod n, gỡ mặt nạ để lấy lại salt, tính lại H rồi so sánh. Salt nằm sẵn trong chữ ký nên bên nhận không cần biết trước.

Vì salt đổi mỗi lần nên chữ ký đổi mỗi lần, nhưng mọi chữ ký đều hợp lệ. PSS còn là chuẩn được khuyến nghị cho RSA hiện nay, có chứng minh an toàn chặt chẽ hơn PKCS#1 v1.5. Trong .NET dùng `RSASignaturePadding.Pss`.

**Đề xuất 2 (bổ sung): thêm nonce và timestamp.** Ký `SHA-256(M ‖ nonce ‖ thời gian)` và gửi kèm `(M, nonce, thời gian, chữ ký)`. Mỗi lần nonce khác thì chữ ký khác, đồng thời chống tấn công phát lại (replay). Nhược điểm: phải thống nhất giao thức vì dữ liệu được ký không còn là M thuần.

**Kết luận phần này:** dùng **RSA-PSS**, và kết hợp nonce/timestamp khi cần chống phát lại.

---

# TỔNG KẾT

1. Đã xây dựng 2 ứng dụng console .NET hoàn thành đủ các yêu cầu của Bài 1 và Bài 2.
2. **AES** (đối xứng) nhanh, thời gian tăng tuyến tính theo dung lượng, phù hợp mã hoá dữ liệu lớn, nhưng gặp khó khăn khi phân phối khoá.
3. **RSA** (bất đối xứng) giải quyết bài toán trao đổi khoá và ký số, nhưng chậm (đặc biệt phép dùng khoá bí mật) và chỉ mã hoá được dữ liệu nhỏ (≤ 190 byte với RSA-2048 + OAEP-SHA256).
4. Thực tế hai loại được dùng kết hợp (**mã hoá lai**): dùng AES mã hoá dữ liệu, dùng RSA mã hoá khoá AES.
5. **SHA-256** có hiệu ứng thác lũ mạnh, là nền tảng để phát hiện dữ liệu bị sửa đổi và dùng cho chữ ký số.
6. **RSA-PSS** thoả yêu cầu: cùng dữ liệu, cùng khoá bí mật nhưng chữ ký khác nhau mỗi lần ký mà vẫn xác minh đúng.

## Tài liệu tham khảo
- RFC 8017: PKCS #1 v2.2, RSA Cryptography Specifications
- FIPS 197: Advanced Encryption Standard (AES)
- FIPS 180-4: Secure Hash Standard (SHA-256)
- Microsoft Docs: `System.Security.Cryptography` (Aes, RSA, SHA256)
