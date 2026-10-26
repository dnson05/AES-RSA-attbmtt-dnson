using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

// ===== BÀI 1: MÃ HOÁ AES (đối xứng) - Console =====
// AES-256-CBC, PKCS7. File mã hoá = [16 byte IV][ciphertext]. Xử lý theo stream nên chạy được file hàng GB.

Console.OutputEncoding = Encoding.UTF8;
Console.InputEncoding = Encoding.UTF8;
const int BufSize = 1 << 20; // 1 MB
byte[]? key = null;

while (true)
{
    Console.WriteLine("\n===== AES =====");
    Console.WriteLine($"Khoá hiện tại: {(key == null ? "(chưa có)" : $"{key.Length * 8} bit")}");
    Console.WriteLine("1. Sinh khoá AES");
    Console.WriteLine("2. Lưu khoá ra file");
    Console.WriteLine("3. Import khoá từ file");
    Console.WriteLine("4. Mã hoá / giải mã đoạn văn bản");
    Console.WriteLine("5. Mã hoá file");
    Console.WriteLine("6. Giải mã file");
    Console.WriteLine("7. THỬ NGHIỆM: mã hoá + giải mã + đo thời gian + so sánh byte");
    Console.WriteLine("8. Tạo file test dung lượng lớn");
    Console.WriteLine("0. Thoát");
    Console.Write("Chọn: ");
    try
    {
        switch (Console.ReadLine()?.Trim())
        {
            case "1":
                Console.Write("Độ dài khoá (128/192/256) [256]: ");
                var s = Console.ReadLine();
                int bits = int.TryParse(s, out var b) ? b : 256;
                key = RandomNumberGenerator.GetBytes(bits / 8);
                Console.WriteLine("Khoá (base64): " + Convert.ToBase64String(key));
                break;
            case "2":
                NeedKey();
                File.WriteAllText(Ask("Đường dẫn file lưu khoá [aes.key]: ", "aes.key"), Convert.ToBase64String(key!));
                Console.WriteLine("Đã lưu.");
                break;
            case "3":
                key = Convert.FromBase64String(File.ReadAllText(Ask("File khoá [aes.key]: ", "aes.key")).Trim());
                if (key.Length is not (16 or 24 or 32)) { key = null; throw new Exception("Khoá không hợp lệ."); }
                Console.WriteLine($"Đã import khoá {key.Length * 8} bit.");
                break;
            case "4":
                NeedKey();
                Console.Write("Nhập văn bản: ");
                string text = Console.ReadLine() ?? "";
                string cipher = EncryptText(text, key!);
                Console.WriteLine("Bản mã (base64): " + cipher);
                Console.WriteLine("Giải mã lại    : " + DecryptText(cipher, key!));
                break;
            case "5":
                NeedKey();
                {
                    string i = Ask("File nguồn: ");
                    string o = Ask("File đích [" + i + ".enc]: ", i + ".enc");
                    var sw = Stopwatch.StartNew();
                    EncryptFile(i, o, key!);
                    Console.WriteLine($"Xong trong {sw.Elapsed.TotalSeconds:F2}s");
                }
                break;
            case "6":
                NeedKey();
                {
                    string i = Ask("File mã hoá: ");
                    string o = Ask("File đích [" + i + ".dec]: ", i + ".dec");
                    var sw = Stopwatch.StartNew();
                    DecryptFile(i, o, key!);
                    Console.WriteLine($"Xong trong {sw.Elapsed.TotalSeconds:F2}s");
                }
                break;
            case "7":
                NeedKey();
                Experiment(Ask("File nguồn: "), key!);
                break;
            case "8":
                {
                    string p = Ask("Đường dẫn file test [test.bin]: ", "test.bin");
                    long mb = long.Parse(Ask("Dung lượng (MB) [1024]: ", "1024"));
                    MakeTestFile(p, mb);
                }
                break;
            case "0": return;
        }
    }
    catch (Exception ex) { Console.WriteLine("LỖI: " + ex.Message); }
}

string Ask(string prompt, string? def = null)
{
    Console.Write(prompt);
    var v = Console.ReadLine()?.Trim().Trim('"');
    return string.IsNullOrEmpty(v) ? (def ?? throw new Exception("Thiếu dữ liệu nhập.")) : v;
}

void NeedKey() { if (key == null) throw new Exception("Chưa có khoá (chọn 1 hoặc 3)."); }

static string EncryptText(string plain, byte[] key)
{
    using var aes = Aes.Create();
    aes.Key = key;
    aes.GenerateIV();
    byte[] ct = aes.EncryptCbc(Encoding.UTF8.GetBytes(plain), aes.IV);
    return Convert.ToBase64String(aes.IV.Concat(ct).ToArray());
}

static string DecryptText(string b64, byte[] key)
{
    byte[] all = Convert.FromBase64String(b64);
    using var aes = Aes.Create();
    aes.Key = key;
    byte[] pt = aes.DecryptCbc(all.AsSpan(16), all.AsSpan(0, 16));
    return Encoding.UTF8.GetString(pt);
}

static void EncryptFile(string inPath, string outPath, byte[] key)
{
    using var aes = Aes.Create();
    aes.Key = key;
    aes.GenerateIV();
    using var fin = new FileStream(inPath, FileMode.Open, FileAccess.Read, FileShare.Read, BufSize, FileOptions.SequentialScan);
    using var fout = new FileStream(outPath, FileMode.Create, FileAccess.Write, FileShare.None, BufSize);
    fout.Write(aes.IV);
    using var cs = new CryptoStream(fout, aes.CreateEncryptor(), CryptoStreamMode.Write);
    fin.CopyTo(cs, BufSize);
}

static void DecryptFile(string inPath, string outPath, byte[] key)
{
    using var fin = new FileStream(inPath, FileMode.Open, FileAccess.Read, FileShare.Read, BufSize, FileOptions.SequentialScan);
    byte[] iv = new byte[16];
    fin.ReadExactly(iv);
    using var aes = Aes.Create();
    aes.Key = key;
    aes.IV = iv;
    using var fout = new FileStream(outPath, FileMode.Create, FileAccess.Write, FileShare.None, BufSize);
    using var cs = new CryptoStream(fin, aes.CreateDecryptor(), CryptoStreamMode.Read);
    cs.CopyTo(fout, BufSize);
}

// So sánh 2 file theo từng byte (stream, không nạp cả file vào RAM). Trả về -1 nếu giống hệt, ngược lại là vị trí byte khác đầu tiên.
static long CompareFiles(string a, string b)
{
    using var fa = new FileStream(a, FileMode.Open, FileAccess.Read, FileShare.Read, BufSize, FileOptions.SequentialScan);
    using var fb = new FileStream(b, FileMode.Open, FileAccess.Read, FileShare.Read, BufSize, FileOptions.SequentialScan);
    if (fa.Length != fb.Length) return Math.Min(fa.Length, fb.Length);
    byte[] ba = new byte[BufSize], bb = new byte[BufSize];
    long pos = 0;
    while (true)
    {
        int na = fa.Read(ba, 0, BufSize);
        if (na == 0) return -1;
        fb.ReadExactly(bb, 0, na);
        var sa = ba.AsSpan(0, na);
        int mism = sa.CommonPrefixLength(bb.AsSpan(0, na));
        if (mism < na) return pos + mism;
        pos += na;
    }
}

static void Experiment(string src, byte[] key)
{
    string enc = src + ".enc", dec = src + ".dec";
    long size = new FileInfo(src).Length;
    double mb = size / 1024.0 / 1024.0;

    var sw = Stopwatch.StartNew();
    EncryptFile(src, enc, key);
    double tEnc = sw.Elapsed.TotalSeconds;

    sw.Restart();
    DecryptFile(enc, dec, key);
    double tDec = sw.Elapsed.TotalSeconds;

    sw.Restart();
    long diff = CompareFiles(src, dec);
    double tCmp = sw.Elapsed.TotalSeconds;

    Console.WriteLine("\n----- KẾT QUẢ THỬ NGHIỆM -----");
    Console.WriteLine($"Khoá AES            : {key.Length * 8} bit (CBC, PKCS7)");
    Console.WriteLine($"File nguồn          : {size:N0} byte ({mb:F1} MB)");
    Console.WriteLine($"File mã hoá         : {new FileInfo(enc).Length:N0} byte (= nguồn + padding + 16 byte IV)");
    Console.WriteLine($"Thời gian mã hoá    : {tEnc:F2} s  -> {mb / tEnc:F1} MB/s");
    Console.WriteLine($"Thời gian giải mã   : {tDec:F2} s  -> {mb / tDec:F1} MB/s");
    Console.WriteLine($"Thời gian so sánh   : {tCmp:F2} s");
    Console.WriteLine(diff < 0 ? "So sánh byte        : GIỐNG HỆT 100% (file giải mã == file nguồn)"
                               : $"So sánh byte        : KHÁC tại byte thứ {diff:N0}");
    Console.WriteLine($"AES phần cứng (AES-NI): {(System.Runtime.Intrinsics.X86.Aes.IsSupported || System.Runtime.Intrinsics.Arm.Aes.IsSupported ? "có" : "không")}");
    Console.WriteLine("(Ghi lại các số liệu này vào bảng báo cáo để rút kết luận.)");
}

static void MakeTestFile(string path, long mb)
{
    byte[] buf = new byte[BufSize];
    using var f = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None, BufSize);
    for (long i = 0; i < mb; i++)
    {
        RandomNumberGenerator.Fill(buf);
        f.Write(buf);
    }
    Console.WriteLine($"Đã tạo {path} ({mb} MB).");
}
