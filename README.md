# AES + SHA256 Şifreleme ve Çözme Uygulaması (GUI)

Bu Python projesi, kullanıcıdan alınan **metni veya dosya içeriğini** AES algoritmasıyla şifreleyen ve çözebilen, ayrıca SHA-256 özetini hesaplayabilen basit ve kullanışlı bir grafik arayüz (GUI) uygulamasıdır.

---

## Özellikler

- Girdi olarak **elle yazılan metin** veya **.txt dosya** içeriği kullanılabilir.
- **AES (CBC Mode)** ile şifreleme ve şifre çözme işlemi yapılabilir.
- **SHA-256** özet algoritması ile hem metin hem de dosya özeti çıkarılabilir.
- Sonuçlar istenirse dosyaya kaydedilebilir.
- Kolay ve kullanıcı dostu arayüz (Tkinter ile)

---

## Kullanılan Teknolojiler

- Python 3.x
- Tkinter (grafik arayüz için, Python'la birlikte gelir)
- [PyCryptodome](https://pypi.org/project/pycryptodome/) (AES işlemleri için)
- Hashlib (SHA256 için - standart kütüphane)

---

## Kurulum

### 1. Gerekli Kütüphaneyi Yükleyin
```
pip install pycryptodome
```

### 2. Uygulamayı Çalıştırın
```
python crypto_GUI.py
```

> `crypto_GUI.py` dosyası, uygulama kodunun bulunduğu Python dosyasıdır.

---

## Ekran Görüntüleri

Aşağıdaki ekran görüntüleri, uygulamanın şifreleme ve çözme sırasında nasıl göründüğünü göstermektedir:

### Şifreleme Ekranı
"AES_GUI\şifreleme.png"

### Şifre Çözme Ekranı

"AES_GUI\şifre çözme.png"
---

## Örnek Kullanım

1. Uygulama açıldığında metin kutusuna bir metin yazın **veya** bir `.txt` dosyası yükleyin.
2. Alt kısma bir şifre (anahtar) girin.
3. "Şifrele" tuşuna basarak AES şifrelenmiş sonucu alın.
4. Aynı metni çözmek için şifreli veriyi giriş kutusuna yapıştırın ve "Çöz" tuşuna basın.
5. SHA256 özeti için "SHA256" butonlarını kullanabilirsiniz.
6. Sonucu kaydetmek isterseniz "Sonucu Kaydet" butonunu kullanabilirsiniz.

---

## Geliştirici

Bu proje, İbrahim KARAKUZU tarafından Bilgi Güvenliği ve Kriptografi Dersi Final Ödevi kapsamında geliştirilmiştir.
