# xfcheck — X‑Forwarded Header Checker

Kendi çalışmalarımda sürekli ihtiyaç duyduğum bir şeydi:  
Bir hedef URL **X‑Forwarded‑For** ve **X‑Forwarded‑Host** header’larını gerçekten işliyor mu, bunu hızlıca test etmek.

Bazı uygulamalar bu header’lara göre:
- IP doğrulaması yapıyor,
- admin panel erişimini kontrol ediyor,
- password‑reset linki oluştururken Host yapısını kullanıyor,
- backend tarafında farklı davranışa geçiyor.

Ben de oturdum, bunun hızlıca tespitini yapan küçük bir Python aracı yazdım.

---

## 🎯 Ne İşe Yarar?

`xfcheck` bir URL’ye **GET** ve **POST** isteği atarak şunları kontrol eder:

- X‑Forwarded‑For isteği response’u değiştiriyor mu?
- X‑Forwarded‑Host isteği response’u değiştiriyor mu?
- Header değeri response body içinde yansıyor mu?
- Status code farkı var mı?

Eğer backend bu header’ları işliyorsa **DESTEKLİYOR** olarak işaretler.

Bu, özellikle şu zafiyetlerde işe yarar:

- Access control bypass  
- IP‑based authentication bypass  
- Password reset poisoning  
- Cache poisoning  
- Host header saldırıları  
- SSRF varyasyonları  

---

## 🚀 Kurulum

git clone https://github.com/Songul-Kizilay/xfcheck-.git
cd xfcheck
chmod +x xfcheck.py


Gerekli kütüphane yoksa otomatik yüklenir.

---

## 🧪 Kullanım



./xfcheck.py -u https://hedefsite.com/


Örnek çıktı:



[X-Forwarded-For Test]
GET : DESTEKLİYOR
POST: DESTEKLİYOR

[X-Forwarded-Host Test]
GET : Desteklemiyor
POST: Desteklemiyor


---

## 🧠 Mantık Nasıl Çalışıyor?

xfcheck şu karşılaştırmayı yapar:

1. Normal GET isteği → status + body
2. X‑Forwarded header’lı GET isteği → status + body
3. Fark varsa = destekliyor

Aynısı POST için de yapılır.

---

## 🐍 Kodun İçinde Otomatik `requests` Yükleyici Var

Eğer sistemde `requests` yoksa:



pip install requests


komutunu arka planda otomatik çalıştırır.

---

## 💡 Not

Bu araç bir **zafiyet tespit aracı değildir**.  
Sadece uygulamanın ilgili header’ları **işleyip işlemediğini** gösterir.

Geri kalan değerlendirme pentest aşamasına kalır 🙂

---

## ✨ Yapan

**Songül Kızılay**  
Security Researcher / Pentester
