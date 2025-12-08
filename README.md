 X-Override Scanner
Advanced URL Override & Admin Bypass Detector

X-Override Scanner, web uygulamalarında yanlış yapılandırılmış URL override header’ları kullanılarak oluşan kritik erişim kontrol zafiyetlerini tespit eden gelişmiş bir güvenlik aracıdır.

Araç şu override headerlarını destekler:

X-Original-URL

X-Rewrite-URL

X-Original-URI

X-Forwarded-Host

X-Forwarded-Proto

X-Forwarded-For

X-HTTP-Method-Override

Bu zafiyetler genellikle şu güvenlik açıklarına yol açar:

Admin panel bypass

403 bypass

Broken Access Control

Front-end vs Back-end URL mismatch

Unprotected admin functionality

🚀 Özellikler
✔ URL Override Detection

Sunucunun hangi override header’larını desteklediğini otomatik olarak analiz eder.

✔ SecLists Destekli Admin Path Brute-Force

/usr/share/seclists/Discovery/Web-Content/ içindeki admin/directory listeleri otomatik taranır.

✔ GET & POST Analizi

Her iki yöntem üzerinde override testleri yapılır.

✔ PortSwigger Auto-Login (Opsiyonel)

--auto-login ile wiener/peter kullanıcı bilgisi ve CSRF token otomasyonuyla lab girişleri yapılır.

✔ PortSwigger Auto-Exploit

--auto-exploit aktif olduğunda araç bypass başarılıysa şu isteği göndererek labı otomatik çözer:

/admin/delete?username=carlos

✔ Redirect Chain Analizi

--follow ile 301/302 zinciri takip edilir ve farklılıklar raporlanır.

✔ JSON / CSV Çıktı

Pentest raporlaması ve SIEM entegrasyonları için idealdir.

✔ Proxy Destekli

Burp Suite üzerinden çalıştırmak için:

export HTTPS_PROXY=http://127.0.0.1:8080

📦 Kurulum
Gereksinimler
pip install aiohttp certifi


Python 3.9+ kullanmanız tavsiye edilir.

🔧 Kullanım
Basit tarama
python3 x_override_full_exploit.py -u https://example.com

Derin tarama + SecLists brute-force
python3 x_override_full_exploit.py -u https://target.com --deep

Redirect zincirlerini takip et
python3 x_override_full_exploit.py -u https://target.com --follow

PortSwigger otomatik login + otomatik exploit
python3 x_override_full_exploit.py -u https://example.web-security-academy.net \
--auto-login --auto-exploit --deep --follow

Sonuçları JSON/CSV olarak kaydet
python3 x_override_full_exploit.py -u https://target.com \
--output findings.json --csv findings.csv

Cookie ekleyerek çalıştır
python3 x_override_full_exploit.py -u https://target.com --cookie "session=abc123;"

POST isteği ile çalıştır
python3 x_override_full_exploit.py -u https://target.com/login \
--post-data "username=test&password=1234&csrf=XYZ"

📂 Örnek Çıktı
[X-Original-URL] GET → /admin => 200 | len=1234
[HIGH] status changed 403 → 200
- admin keywords found in response
- redirect chain differs

⚠️ Yasal Uyarı

Bu araç yalnızca:

kendi sistemlerinizde

izinli güvenlik testlerinde

PortSwigger lablarında

kullanılmak için tasarlanmıştır.

İzinsiz tarama yasadışıdır ve hukuki sonuçlar doğurabilir.

Geliştirici (Songül Kızılay) kötüye kullanımdan sorumlu değildir.

🤝 Katkıda Bulunma

Pull request’ler açıktır.
Yeni override headerları veya exploit modülleri eklemek isteyen herkes katkıda bulunabilir.

⭐ Destek

Eğer araç işinize yaradıysa ⭐ vermeyi unutmayın!
Blog yazısı, PoC videosu veya eğitim içeriklerinde paylaşabilirsiniz.

👩‍💻 Geliştiren

Songül Kızılay
Siber Güvenlik • Pentest • Red Team
PortSwigger + Web Security araştırmacısı
