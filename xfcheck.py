#!/usr/bin/env python3

# =========================
#  Otomatik requests yükleyici
# =========================
try:
    import requests
except ImportError:
    import os
    print("[!] requests kütüphanesi yüklü değil. Kuruluyor...")
    os.system("pip install requests || pip3 install requests")
    import requests

import argparse
import random
import time

BANNER = """
                    ฅ^>⩊<^ ฅ
  X‑Forwarded Checker by Songül
"""

# =========================
#   Timeout + Retry fonksiyonu
# =========================
def safe_request(method, url, headers=None):
    for attempt in range(2):  # maksimum 2 deneme
        try:
            return requests.request(method, url, headers=headers, timeout=20)
        except requests.exceptions.Timeout:
            if attempt == 0:
                print(" ↻ Timeout oldu, yeniden deneniyor...")
                time.sleep(1)
            else:
                print(" [!] Site çok yavaş yanıt veriyor (timeout).")
                return None
        except Exception as e:
            print(f"[!] Hata: {e}")
            return None
    return None


def check_header_effect(url, method, header_key, header_value):

    normal = safe_request(method, url)
    if normal is None:
        return False

    modified = safe_request(method, url, {header_key: header_value})
    if modified is None:
        return False

    # Status değişti mi?
    if modified.status_code != normal.status_code:
        return True

    # Body içinde reflection var mı?
    if header_value in modified.text:
        return True

    return False


def test_url(url):
    print(f"\n=== Test Edilen URL: {url} ===")

    # RANDOM sayı (X-Forwarded-For için)
    random_for_value = str(random.randint(100000, 999999))

    print("\n[X-Forwarded-For Test]")
    for_method_get = check_header_effect(url, "GET", "X-Forwarded-For", random_for_value)
    for_method_post = check_header_effect(url, "POST", "X-Forwarded-For", random_for_value)

    print(" GET : ", "DESTEKLİYOR" if for_method_get else "Desteklemiyor")
    print(" POST: ", "DESTEKLİYOR" if for_method_post else "Desteklemiyor")

    print("\n[X-Forwarded-Host Test]")
    host_method_get = check_header_effect(url, "GET", "X-Forwarded-Host", "evil.com")
    host_method_post = check_header_effect(url, "POST", "X-Forwarded-Host", "evil.com")

    print(" GET : ", "DESTEKLİYOR" if host_method_get else "Desteklemiyor")
    print(" POST: ", "DESTEKLİYOR" if host_method_post else "Desteklemiyor")


if __name__ == "__main__":
    print(BANNER)

    parser = argparse.ArgumentParser(description="xfcheck - X‑Forwarded Checker")
    parser.add_argument("-u", "--url", required=True, help="Hedef URL")
    args = parser.parse_args()

    test_url(args.url)
