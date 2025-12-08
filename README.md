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

