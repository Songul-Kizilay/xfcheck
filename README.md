# 🔥 X-Override Scanner — Advanced URL Override & Admin Bypass Detector

X-Override Scanner, modern web uygulamalarında görülen **URL override / header-based access control bypass** zafiyetlerini tespit etmek için geliştirilmiş gelişmiş bir güvenlik aracıdır.

Bu araç özellikle şu zafiyetleri tespit eder:

- `X-Original-URL`
- `X-Rewrite-URL`
- `X-Original-URI`
- `X-Forwarded-For`
- `X-Forwarded-Host`
- `X-HTTP-Method-Override`

ve benzeri HTTP header'larının **sunucu tarafından yanlış yorumlanması** sonucu oluşan:

🔹 **Broken Access Control**  
🔹 **Admin panel bypass**  
🔹 **Front-end → Back-end URL inconsistency**  
🔹 **403 bypass**  
🔹 **Unprotected admin functionality**

gibi kritik güvenlik açıklarını otomatik olarak tespit eder.

---

## 🚀 Özellikler

### ✔ URL Override Detection
Uygulamanın hangi override header’larını desteklediğini otomatik olarak belirler.

### ✔ SecLists destekli admin path brute-force (Optimize)
`/usr/share/seclists/Discovery/Web-Content/` dizinindeki wordlistlerde:

- admin  
- panel  
- dashboard  
- root  
- manage  
- private  
- console  
- login  

gibi **anahtar kelime filtrelemesi** yaparak gereksiz girişleri eler ve sadece gerçek admin path'lerini test eder.

### ✔ GET & POST Bağımsız Analiz
Hem GET hem POST isteklerinde override denemesi yapılır.

### ✔ Otomatik PortSwigger Login (Opsiyonel)
`--auto-login` seçeneği ile PortSwigger labları için otomatik giriş yapılır:

- username: **wiener**
- password: **peter**
- CSRF token otomatik çekilir.

### ✔ Otomatik Exploit Modu (Opsiyonel)
`--auto-exploit` aktif olduğunda araç, override bypass tespitinde otomatik:

/admin/delete?username=carlos

shell
Kodu kopyala

gibi istekleri göndererek **PortSwigger lablarını otomatik çözer**.

### ✔ Redirect Chain Analizi
`--follow` ile 301/302 zincirleri takip edilir ve karşılaştırılır.

### ✔ JSON / CSV Çıktı
Raporlama ve SIEM entegrasyonu için uygundur.

### ✔ Proxy Destekli
Burp Suite üzerinden çalıştırmak için:

export HTTPS_PROXY=http://127.0.0.1:8080

yaml
Kodu kopyala

---

## 📦 Kurulum

### Gerekli Paketler

pip install aiohttp certifi

yaml
Kodu kopyala

Aracı çalıştırmadan önce Python 3.9+ kullanmanız önerilir.

---

## 🔧 Kullanım

### Basit tarama

python3 x_override_full_exploit.py -u https://example.com

shell
Kodu kopyala

### Derin tarama + SecLists brute-force

python3 x_override_full_exploit.py -u https://target.com --deep

shell
Kodu kopyala

### Redirect zincirlerini takip et

python3 x_override_full_exploit.py -u https://target.com --follow

graphql
Kodu kopyala

### PortSwigger otomatik login + auto exploit

python3 x_override_full_exploit.py -u https://example.web-security-academy.net
--auto-login --auto-exploit --deep --follow

shell
Kodu kopyala

### Sonuçları kayıt et

python3 x_override_full_exploit.py -u https://target.com
--output findings.json --csv findings.csv

shell
Kodu kopyala

### Cookie ile çalıştırmak

python3 x_override_full_exploit.py -u https://target.com --cookie "session=abc123;"

shell
Kodu kopyala

### POST desteği

python3 x_override_full_exploit.py -u https://target.com/login
--post-data "username=test&password=1234&csrf=XYZ"

yaml
Kodu kopyala

---

## 📂 Örnek Çıktı

[X-Original-URL] GET → /admin => 200 | len=1234
[HIGH] status changed 403 → 200
- admin keywords found in response
- redirect chain differs

yaml
Kodu kopyala

---

## ⚠️ Yasal Uyarı

Bu araç yalnızca:

- kendi sistemlerinizde  
- izinli güvenlik testlerinde  
- PortSwigger lablarında  

kullanılmak üzere tasarlanmıştır.

İzinsiz tarama yapmak **yasadışıdır** ve ciddi hukuki sonuçlar doğurabilir.

Geliştirici (sen ve repo sahibi) yapılan kötüye kullanımdan **sorumlu değildir**.

---

## 🤝 Katkıda Bulunma

Pull request'ler açıktır.  
Yeni override header'ları veya yeni exploit modülleri eklemek istiyorsanız PR gönderebilirsiniz.

---

## ⭐ Destek

Eğer araç işinize yaradıysa lütfen ⭐ vererek destek olun!  
Dilerseniz:

- Blog yazısı  
- PoC videosu  
- Eğitim serisi  

kısaca paylaşabilirsiniz.

---

## 👩‍💻 Geliştiren

**Songül Kızılay**

Siber güvenlik / Pentest / Red Team odaklı güvenlik araştırmacısı.  
PortSwigger + Web Security + Blue/Red Team konularında aktif üretici.

