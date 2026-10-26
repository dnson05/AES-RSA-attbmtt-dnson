using System.Diagnostics;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

// ===== BÀI 2: RSA + SHA-256 + CHỮ KÝ SỐ =====
Console.OutputEncoding = Encoding.UTF8;
Console.InputEncoding = Encoding.UTF8;

var OAEP = RSAEncryptionPadding.OaepSHA256; // tối đa (k - 2*32 - 2) = 190 byte với RSA-2048
RSA? generated = null, rsaPub = null, rsaPriv = null;

while (true)
{
    Console.WriteLine("\n===== RSA =====");
    Console.WriteLine("1. Sinh cặp khoá");
    Console.WriteLine("2. Xuất cặp khoá ra file PEM");
    Console.WriteLine("3. Xem file PEM (giải phẫu từng byte DER/ASN.1)");
    Console.WriteLine("4. Nhập PEM -> hiển thị n, e (public) / n, e, d, p, q... (private)");
    Console.WriteLine("5. Tạo dữ liệu (<=190 byte) rồi MÃ HOÁ bằng public key -> base64 file");
    Console.WriteLine("6. GIẢI MÃ (pem private + file base64) và so sánh với nguồn");
    Console.WriteLine("7. Đo tốc độ: khoá công khai (e nhỏ) vs khoá bí mật (d lớn)");
    Console.WriteLine("8. SHA-256 và hiệu ứng thác lũ (avalanche)");
    Console.WriteLine("9. Chữ ký số: PKCS#1 v1.5 (tất định) vs RSA-PSS (ngẫu nhiên)");
    Console.WriteLine("0. Thoát");
    Console.Write("Chọn: ");
    try
    {
        switch (Console.ReadLine()?.Trim())
        {
            case "1":
                int bits = int.Parse(Ask("Độ dài khoá [2048]: ", "2048"));
                generated = RSA.Create(bits);
                Console.WriteLine($"Đã sinh cặp khoá RSA-{bits}.");
                break;

            case "2":
                if (generated == null) throw new Exception("Chưa sinh khoá (chọn 1).");
                File.WriteAllText("public.pem", generated.ExportSubjectPublicKeyInfoPem());
                File.WriteAllText("private.pem", generated.ExportPkcs8PrivateKeyPem());
                Console.WriteLine("Đã ghi public.pem (SPKI) và private.pem (PKCS#8).");
                break;

            case "3":
                ViewPem(Ask("File PEM [public.pem]: ", "public.pem"));
                break;

            case "4":
                {
                    string path = Ask("File PEM [public.pem]: ", "public.pem");
                    var r = RSA.Create();
                    r.ImportFromPem(File.ReadAllText(path));
                    bool isPriv = File.ReadAllText(path).Contains("PRIVATE KEY");
                    var p = r.ExportParameters(isPriv);
                    if (isPriv) rsaPriv = r; else rsaPub = r;
                    Console.WriteLine($"Loại khoá: {(isPriv ? "PRIVATE" : "PUBLIC")}");
                    PrintParam("n (modulus)", p.Modulus);
                    PrintParam("e (public exponent)", p.Exponent);
                    if (isPriv)
                    {
                        PrintParam("d (private exponent)", p.D);
                        PrintParam("p", p.P); PrintParam("q", p.Q);
                        PrintParam("dp = d mod (p-1)", p.DP); PrintParam("dq = d mod (q-1)", p.DQ);
                        PrintParam("qinv = q^-1 mod p", p.InverseQ);
                    }
                }
                break;

            case "5":
                {
                    if (rsaPub == null) throw new Exception("Chưa import public key (chọn 4).");
                    string dataPath = Ask("File dữ liệu nguồn (raw) [data.bin]: ", "data.bin");
                    if (!File.Exists(dataPath))
                    {
                        Console.Write("Chưa có file. Nhập chuỗi (Enter = sinh ngẫu nhiên 32 byte như khoá AES-256): ");
                        string t = Console.ReadLine() ?? "";
                        File.WriteAllBytes(dataPath, t.Length == 0 ? RandomNumberGenerator.GetBytes(32) : Encoding.UTF8.GetBytes(t));
                    }
                    byte[] data = File.ReadAllBytes(dataPath);
                    int max = rsaPub.KeySize / 8 - 2 * 32 - 2;
                    if (data.Length > max) throw new Exception($"Dữ liệu {data.Length} byte > giới hạn {max} byte.");
                    byte[] ct = rsaPub.Encrypt(data, OAEP);
                    string outPath = Ask("File kết quả [cipher.b64]: ", "cipher.b64");
                    File.WriteAllText(outPath, Convert.ToBase64String(ct));
                    Console.WriteLine($"Dữ liệu {data.Length} byte -> bản mã {ct.Length} byte. Đã lưu base64 vào {outPath}");
                }
                break;

            case "6":
                {
                    string pem = Ask("File PEM private [private.pem]: ", "private.pem");
                    var r = RSA.Create();
                    r.ImportFromPem(File.ReadAllText(pem));
                    byte[] ct = Convert.FromBase64String(File.ReadAllText(Ask("File bản mã base64 [cipher.b64]: ", "cipher.b64")).Trim());
                    byte[] pt = r.Decrypt(ct, OAEP);
                    byte[] src = File.ReadAllBytes(Ask("File dữ liệu nguồn để so sánh [data.bin]: ", "data.bin"));
                    Console.WriteLine($"Giải mã được {pt.Length} byte (base64): {Convert.ToBase64String(pt)}");
                    Console.WriteLine(pt.AsSpan().SequenceEqual(src) ? "=> KHỚP 100% với dữ liệu nguồn." : "=> KHÔNG KHỚP!");
                }
                break;

            case "7": Benchmark(); break;
            case "8": HashDemo(); break;

            case "9":
                {
                    if (generated == null && rsaPriv == null) throw new Exception("Cần có private key (chọn 1 hoặc 4).");
                    SignDemo(rsaPriv ?? generated!);
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

static void PrintParam(string name, byte[]? v)
{
    if (v == null) return;
    var bi = new BigInteger(v, isUnsigned: true, isBigEndian: true);
    string hex = Convert.ToHexString(v);
    Console.WriteLine($"\n{name}: {v.Length} byte, {bi.GetBitLength()} bit");
    Console.WriteLine("  hex: " + (hex.Length > 120 ? hex[..120] + "..." : hex));
    if (v.Length <= 8) Console.WriteLine("  dec: " + bi);
}

// ---------- 3. Xem PEM: PEM = Base64(DER) kẹp giữa dòng BEGIN/END; DER = chuỗi TLV (Tag-Length-Value) ----------
static void ViewPem(string path)
{
    string text = File.ReadAllText(path);
    var lines = text.Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(l => l.Trim()).ToList();
    string header = lines.First(l => l.StartsWith("-----BEGIN"));
    string b64 = string.Concat(lines.Where(l => !l.StartsWith("-----")));
    byte[] der = Convert.FromBase64String(b64);
    Console.WriteLine($"Header : {header}  (cho biết loại: PUBLIC KEY = SPKI, RSA PUBLIC KEY = PKCS#1, PRIVATE KEY = PKCS#8, RSA PRIVATE KEY = PKCS#1)");
    Console.WriteLine($"Base64 : {b64.Length} ký tự -> DER {der.Length} byte (mỗi 4 ký tự base64 = 3 byte)");
    Console.WriteLine("DER hex (32 byte/dòng):");
    for (int i = 0; i < der.Length; i += 32)
        Console.WriteLine($"  {i:X4}: {Convert.ToHexString(der.AsSpan(i, Math.Min(32, der.Length - i)))}");
    Console.WriteLine("\nCấu trúc ASN.1 (Tag | Length | Value):");
    DumpDer(der, 0, der.Length, 0);
}

static void DumpDer(byte[] d, int start, int end, int depth)
{
    int p = start;
    string ind = new string(' ', depth * 2 + 2);
    while (p < end)
    {
        int off = p;
        byte tag = d[p++];
        int len = d[p++], lenBytes = 1;
        if ((len & 0x80) != 0) { int n = len & 0x7F; len = 0; for (int i = 0; i < n; i++) len = (len << 8) | d[p++]; lenBytes = 1 + n; }
        string name = tag switch
        {
            0x30 => "SEQUENCE", 0x02 => "INTEGER", 0x03 => "BIT STRING", 0x04 => "OCTET STRING",
            0x05 => "NULL", 0x06 => "OBJECT IDENTIFIER", _ => "tag?"
        };
        Console.Write($"{ind}[{off:X4}] {tag:X2} {name}, len-field {lenBytes}B, length={len}");
        switch (tag)
        {
            case 0x30:
                Console.WriteLine(); DumpDer(d, p, p + len, depth + 1); break;
            case 0x03:
                Console.WriteLine($"  (byte đầu = số bit đệm {d[p]}, phần sau là DER lồng nhau)");
                DumpDer(d, p + 1, p + len, depth + 1); break;
            case 0x04:
                if (len > 0 && d[p] == 0x30) { Console.WriteLine("  (chứa DER RSAPrivateKey lồng nhau)"); DumpDer(d, p, p + len, depth + 1); }
                else Console.WriteLine(); break;
            case 0x06:
                Console.WriteLine("  = " + Oid(d, p, len)); break;
            case 0x02:
                {
                    string hex = Convert.ToHexString(d, p, len);
                    string note = len <= 4 ? "  = " + new BigInteger(d.AsSpan(p, len), true, true) : "";
                    if (d[p] == 0 && len > 1) note += "  (byte 00 đứng đầu để số dương, vì bit cao của byte kế = 1)";
                    Console.WriteLine($"  {(hex.Length > 40 ? hex[..40] + "..." : hex)}{note}");
                }
                break;
            default: Console.WriteLine(); break;
        }
        p += (tag is 0x30 or 0x03 or 0x04) ? len : len;
    }
}

static string Oid(byte[] d, int p, int len)
{
    var parts = new List<string> { (d[p] / 40).ToString(), (d[p] % 40).ToString() };
    long v = 0;
    for (int i = 1; i < len; i++) { v = (v << 7) | (uint)(d[p + i] & 0x7F); if ((d[p + i] & 0x80) == 0) { parts.Add(v.ToString()); v = 0; } }
    string s = string.Join(".", parts);
    return s == "1.2.840.113549.1.1.1" ? s + " (rsaEncryption)" : s;
}

// ---------- 7. Tốc độ ----------
static void Benchmark()
{
    var oaep = RSAEncryptionPadding.OaepSHA256;
    Console.WriteLine("\n(A) Qua API RSA (OAEP-SHA256, dữ liệu 32 byte):");
    Console.WriteLine("  Khoá    | Mã hoá (public, e=65537) | Giải mã (private, d~n, có CRT) | Giải mã/Mã hoá");
    foreach (int bits in new[] { 1024, 2048, 3072, 4096 })
    {
        using var r = RSA.Create(bits);
        byte[] data = RandomNumberGenerator.GetBytes(32);
        byte[] ct = r.Encrypt(data, oaep);
        r.Decrypt(ct, oaep); // warm-up
        int nE = 500, nD = 50;
        var sw = Stopwatch.StartNew();
        for (int i = 0; i < nE; i++) r.Encrypt(data, oaep);
        double e = sw.Elapsed.TotalMilliseconds / nE;
        sw.Restart();
        for (int i = 0; i < nD; i++) r.Decrypt(ct, oaep);
        double d = sw.Elapsed.TotalMilliseconds / nD;
        Console.WriteLine($"  {bits,5}   | {e,10:F3} ms/op          | {d,10:F3} ms/op                | x{d / e:F0}");
    }

    Console.WriteLine("\n(B) Phép toán thuần m^x mod n (BigInteger.ModPow, KHÔNG dùng CRT) - RSA-2048:");
    using var k = RSA.Create(2048);
    var p = k.ExportParameters(true);
    BigInteger n = new(p.Modulus, true, true), e2 = new(p.Exponent, true, true), d2 = new(p.D, true, true);
    BigInteger m = new BigInteger(RandomNumberGenerator.GetBytes(200), true, true);
    int N = 200;
    var s2 = Stopwatch.StartNew();
    BigInteger c = default;
    for (int i = 0; i < N; i++) c = BigInteger.ModPow(m, e2, n);
    double te = s2.Elapsed.TotalMilliseconds / N;
    s2.Restart();
    BigInteger back = default;
    for (int i = 0; i < 20; i++) back = BigInteger.ModPow(c, d2, n);
    double td = s2.Elapsed.TotalMilliseconds / 20;
    Console.WriteLine($"  e = {e2} ({e2.GetBitLength()} bit): {te:F4} ms/op");
    Console.WriteLine($"  d = {d2.GetBitLength()} bit            : {td:F4} ms/op   (chậm hơn ~{td / te:F0} lần)");
    Console.WriteLine($"  Kiểm tra m^e^d mod n == m: {back == m}");
    Console.WriteLine("  => Chi phí ModPow tỉ lệ số bit của số mũ (square-and-multiply): e=17 bit ~ 17 bình phương + 2 phép nhân; d~2048 bit ~ 2048 bình phương + ~1024 phép nhân.");
}

// ---------- 8. SHA-256 ----------
static int BitDiff(byte[] a, byte[] b) { int c = 0; for (int i = 0; i < a.Length; i++) c += BitOperations.PopCount((uint)(a[i] ^ b[i])); return c; }

static void HashDemo()
{
    Console.Write("Nhập chuỗi 1 (Enter = 'Hello world'): ");
    string s1 = Console.ReadLine() is { Length: > 0 } x ? x : "Hello world";
    Console.Write("Nhập chuỗi 2 (Enter = đổi 1 bit của chuỗi 1): ");
    string? s2 = Console.ReadLine();
    byte[] b1 = Encoding.UTF8.GetBytes(s1);
    byte[] b2;
    if (string.IsNullOrEmpty(s2)) { b2 = (byte[])b1.Clone(); b2[^1] ^= 0x01; }
    else b2 = Encoding.UTF8.GetBytes(s2);
    byte[] h1 = SHA256.HashData(b1), h2 = SHA256.HashData(b2);
    Console.WriteLine($"Input 1: {Convert.ToHexString(b1)}\nSHA256 : {Convert.ToHexString(h1)}");
    Console.WriteLine($"Input 2: {Convert.ToHexString(b2)}\nSHA256 : {Convert.ToHexString(h2)}");
    int dIn = BitDiff(b1.Length == b2.Length ? b1 : new byte[1], b1.Length == b2.Length ? b2 : new byte[1]);
    Console.WriteLine($"Bit khác ở đầu vào: {(b1.Length == b2.Length ? dIn.ToString() : "(độ dài khác nhau)")}; bit khác ở kết quả băm: {BitDiff(h1, h2)}/256 = {BitDiff(h1, h2) / 2.56:F1}%");

    // Thống kê: lật từng 1 bit đầu vào, đo số bit băm thay đổi
    byte[] msg = RandomNumberGenerator.GetBytes(64);
    byte[] baseHash = SHA256.HashData(msg);
    var diffs = new List<int>();
    for (int i = 0; i < msg.Length * 8; i++)
    {
        var m2 = (byte[])msg.Clone(); m2[i / 8] ^= (byte)(1 << (i % 8));
        diffs.Add(BitDiff(baseHash, SHA256.HashData(m2)));
    }
    Console.WriteLine($"\nThống kê 512 lần lật 1 bit của thông điệp 64 byte ngẫu nhiên: TB {diffs.Average():F1}/256 bit đổi, min {diffs.Min()}, max {diffs.Max()} (lý tưởng = 128).");
}

// ---------- 9. Chữ ký số ----------
static void SignDemo(RSA rsa)
{
    Console.Write("Nhập dữ liệu cần ký: ");
    byte[] data = Encoding.UTF8.GetBytes(Console.ReadLine() ?? "");
    var H = HashAlgorithmName.SHA256;

    byte[] p1 = rsa.SignData(data, H, RSASignaturePadding.Pkcs1), p2 = rsa.SignData(data, H, RSASignaturePadding.Pkcs1);
    byte[] s1 = rsa.SignData(data, H, RSASignaturePadding.Pss), s2 = rsa.SignData(data, H, RSASignaturePadding.Pss);

    Console.WriteLine("\n--- PKCS#1 v1.5 (tất định) ---");
    Console.WriteLine("Lần 1: " + Convert.ToBase64String(p1)[..48] + "...");
    Console.WriteLine("Lần 2: " + Convert.ToBase64String(p2)[..48] + "...");
    Console.WriteLine("Giống nhau: " + p1.AsSpan().SequenceEqual(p2));

    Console.WriteLine("\n--- RSA-PSS (thêm salt ngẫu nhiên) ---");
    Console.WriteLine("Lần 1: " + Convert.ToBase64String(s1)[..48] + "...");
    Console.WriteLine("Lần 2: " + Convert.ToBase64String(s2)[..48] + "...");
    Console.WriteLine("Giống nhau: " + s1.AsSpan().SequenceEqual(s2));
    Console.WriteLine($"Verify lần 1: {rsa.VerifyData(data, s1, H, RSASignaturePadding.Pss)}, lần 2: {rsa.VerifyData(data, s2, H, RSASignaturePadding.Pss)}");

    byte[] tampered = (byte[])data.Clone();
    if (tampered.Length > 0) tampered[0] ^= 1;
    Console.WriteLine($"Verify sau khi sửa 1 bit dữ liệu: {rsa.VerifyData(tampered, s1, H, RSASignaturePadding.Pss)}");
}
