# Phishing E-posta Tespit / Analiz Aracı (savunma)

Bir e-postayı (`.eml` dosyası, ham metin veya stdin) alıp **phishing göstergelerini**
statik olarak analiz eden, **açıklanabilir bir risk skoru** veren komut satırı aracı.
Kara kutu değil: her puan tetiklenen bir kurala bağlıdır ve kanıtıyla listelenir.

> Bu bir **savunma** aracıdır. Hiçbir e-posta göndermez, hiçbir hesaba erişmez,
> hiçbir eki veya bağlantıyı **çalıştırmaz/açmaz**. Sadece verilen e-postayı okur.

## Kurulum

```bash
# Çekirdek analiz sadece Python standart kütüphanesini kullanır (kurulum gerekmez).
# Opsiyonel iyileştirmeler:
pip install -r requirements.txt
```

- `rich` → renkli tablo çıktısı (yoksa düz metin)
- `tldextract` → doğru registrable-domain (yoksa naif son-iki-etiket)
- `dnspython` / `python-whois` / `requests` → yalnızca `--online` modunda

Python 3.11+ (3.14'te test edildi).

## Kullanım

```bash
# Tek dosya
python -m detector.cli analyze tests/samples/phish.eml

# JSON çıktı (otomasyon için)
python -m detector.cli analyze tests/samples/phish.eml --json

# stdin'den ham e-posta
cat mail.eml | python -m detector.cli analyze -

# Bir klasördeki tüm .eml dosyaları (CSV özet)
python -m detector.cli batch tests/samples

# Ağ sorgularını aç (SPF/DMARC DNS, WHOIS, itibar API — opt-in)
python -m detector.cli analyze mail.eml --online
```

## Verdict (risk seviyesi) — kimlik doğrulamaya duyarlı

Puanlama artık **düz toplam değil**. Yanlış pozitifleri (meşru pazarlama
maillerinin yüksek puan alması) engellemek için iki ilke:

**1. Sert / yumuşak ayrımı.** Göstergeler ikiye ayrılır:
- **Sert** — gerçek saldırı izi: auth başarısızlığı, kimlik sahteciliği
  (`display_name_spoof`, `lookalike_domain`, `confusable_brand`…), kimlik hasadı
  formu, çalıştırılabilir/makrolu ek, `anchor_href_mismatch`. **Her zaman tam ağırlık.**
- **Yumuşak** — meşru gönderende de sık görülen bağlam gürültüsü: aciliyet dili,
  genel hitap, kısaltıcı, takip-redirect'i, ESP alt alan adları.

**2. Güven çarpanı.** Gönderen doğrulanmışsa (DMARC pass = From domaini gerçek)
yumuşak sinyaller ×0.3'e iner; kısmi (SPF/DKIM pass) ×0.6; başarısız/yok ×1.0.
Sert sinyaller etkilenmez.

**3. Kanıt desteği.** Verdict **sert-sinyal toplamına** bakar. Sadece yumuşak
sinyal varsa (sert = 0) sonuç **daima low** — kaç tane olursa olsun.

| Sert toplam | Verdict  |
|-------------|----------|
| 0 (yalnız yumuşak) | low |
| 10–21       | medium   |
| 22–44       | high     |
| 45+         | critical |

**First-party bastırma:** link gönderenin kendi domainine aitse (kendi tıklama
tracker'ı) `anchor_href_mismatch`, `open_redirect`, `random_host` ateşlenmez.

**Allowlist:** `data/trusted_domains.txt`'e yazılan domainler, mail
**doğrulanmış (DMARC pass)** ise ve sert saldırı izi yoksa **low**'a sabitlenir.

## Kontrol edilen göstergeler

**Başlık / kimlik doğrulama** — `spf_fail`/`spf_softfail`, `dkim_fail`, `dmarc_fail`,
`from_replyto_mismatch`, `from_returnpath_mismatch`, `display_name_spoof`,
(online) `no_spf_record`.

**URL / bağlantı** — `anchor_href_mismatch`, `ip_url`, `punycode_domain`,
`homograph_domain`, `at_in_url`, `url_shortener`, `suspicious_tld`,
`excessive_subdomains`, `lookalike_domain`.

**İçerik** — `urgency_language`, `credential_request`, `brand_impersonation`,
`generic_greeting`.

**Ek** — `dangerous_attachment`, `double_extension`, `macro_document`,
`archive_attachment`, `mime_extension_mismatch`.

**İtibar (online, opt-in)** — `vt_flagged` (VirusTotal, `VT_API_KEY` gerekir).

**HTML adli (Tier 2)** — `form_external_action`, `html_password_input`,
`meta_refresh_redirect`, `hidden_iframe`, `base_tag_href`, `obfuscated_script`,
`hidden_text`.

**Ek derin statik (Tier 2)** — `html_smuggling`, `macro_detected`,
`macro_autoexec` (oletools), `pdf_active_content`, `pdf_launch_action`.

**QR / quishing (Tier 2)** — `qr_code_url`, `qr_suspicious_url`
(OpenCV veya pyzbar backend'i kuruluysa).

**URL derin (Tier 2)** — `open_redirect`, `combosquat_domain`,
`brand_in_subdomain`, `confusable_brand` (IDN homoglyph), `random_host` (DGA).

## Özelleştirme

Sözlükler `data/` altında düz metin — kod değiştirmeden genişlet:

- `data/brands.txt` — `marka,domain1;domain2` (taklit tespiti)
- `data/suspicious_tlds.txt` — satır başına bir TLD
- `data/urgency_keywords.txt` — satır başına bir anahtar kelime/ifade (TR + EN)

## Gizlilik ve güvenlik

- **Offline-first:** çekirdek analiz ağ kullanmaz. `--online` olmadan hiçbir
  DNS/WHOIS/API çağrısı yapılmaz.
- **İtibar sorgusu** (`--online` + `VT_API_KEY`) yalnızca **domain adlarını**
  VirusTotal'a gönderir; e-posta içeriği gönderilmez.
- Ekler/bağlantılar **hiçbir zaman açılmaz veya çalıştırılmaz** — sadece meta veri
  ve metin incelenir.
- Analiz edilen e-posta yerelde kalır.

## Testler

```bash
python -m pytest -q
```

## Mimari

```
detector/
  cli.py          # komut satırı (analyze / batch)
  analyzer.py     # orkestratör: parse -> tüm kontroller -> skor
  parser.py       # .eml / ham metin -> normalize ParsedEmail
  checks/         # headers, urls, content, attachments
  scoring.py      # ağırlıklı, açıklanabilir skor -> verdict
  report.py       # rich tablo / düz metin / JSON çıktı
  reputation.py   # opsiyonel VirusTotal (online)
data/             # brands / suspicious_tlds / urgency sözlükleri
tests/            # pytest + örnek .eml dosyaları
```

## Yol haritası (opsiyonel)

- Web UI (FastAPI): e-posta yapıştır/yükle → görsel rapor
- Ek itibar kaynakları (PhishTank, Google Safe Browsing)
- Redirect zinciri takibi (opt-in, sandboxed)

## Masaüstü GUI (opsiyonel)

Komut satırı yerine tıkla-kullan arayüz (CustomTkinter, koyu tema):

```bash
pip install customtkinter
python run_gui.py
```

- **Dosya Seç (.eml)** ile e-posta yükle veya ham metni kutuya **yapıştır**.
- Sonuç: renkli **verdict rozeti** (low→critical) + SPF/DKIM/DMARC + severity renkli
  **gösterge kartları** (kanıt + açıklama).
- **Online** anahtarı DNS/WHOIS/itibar sorgularını açar; analiz arka planda çalışır,
  pencere donmaz.
- **JSON Kaydet** ile raporu dosyaya yaz.

Motor (`detector/`) GUI'den bağımsızdır; CLI ve GUI aynı `analyzer` API'sini kullanır.

### Gelişmiş kimlik doğrulama (Tier 1, `--online`)

Başlığı okumak yerine **doğrular**:
- **DKIM** imzasını kriptografik olarak doğrular (başlık yalan söylese de yakalar)
- **SPF**'i gönderen IP'ye karşı canlı değerlendirir
- **DMARC** politikasını çeker; politika `reject/quarantine` iken auth başarısızsa güçlü spoofing sinyali
- **Received/IP adli** (offline): özel-IP köken, eksik Received zinciri

Gerektirir: `pip install dkimpy pyspf dnspython`

### Saldırı vektörleri (Tier 2)

Statik derin analiz — dosya/bağlantı **hiçbir zaman açılmaz/çalıştırılmaz**, sadece
içeriği ayrıştırılır:

- **HTML adli** — gövdedeki oturum formunun harici sunucuya POST etmesi,
  parola alanı, `meta`-refresh yönlendirme, `<base>` hilesi, gizli iframe,
  gizlenmiş metin (spam filtresi kandırma), şifrelenmiş inline JavaScript.
- **Ek derin statik** — HTML smuggling (base64 + Blob otomatik indirme),
  Office makrosu (OLE/`vbaProject.bin`; `oletools` varsa auto-exec anahtar
  kelimeleri), PDF aktif içeriği (`/JS` `/OpenAction` `/AA` `/EmbeddedFile`)
  ve `/Launch`.
- **QR / quishing** — resim eklerindeki ve gövdedeki `data:` görüntülerdeki QR
  kodları çözer, içindeki URL'yi denetler. Backend opsiyonel: `opencv-python`
  (önerilir, Windows'ta ek DLL istemez) veya `pyzbar`; kurulu değilse sessizce atlanır.
- **URL derin** — açık yönlendirme parametreleri, combosquatting
  (`paypal-secure.com`), subdomain'e gömülü marka (`paypal.login.evil.com`),
  IDN/Unicode homoglyph (`pаypаl.com` → `paypal.com`), yüksek-entropili DGA host.

Opsiyonel bağımlılıklar: `pip install oletools opencv-python-headless numpy`
(hiçbiri şart değil — HTML/PDF/URL kontrolleri saf standart kütüphaneyle çalışır).

Deneme örneği: `python -m detector.cli analyze tests/samples/phish_tier2.eml`
→ 23 gösterge, **critical 100**.
