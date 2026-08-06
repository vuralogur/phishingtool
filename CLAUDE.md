# CLAUDE.md — phishingtool

Bu dosya, Claude Code'un bu projede çalışırken bağlam olarak okuduğu nottur.
Amaç: ne yapıldığını, sınırları ve mimariyi tek bakışta netleştirmek.

## Proje nedir

**Savunma amaçlı phishing e-posta tespit/analiz aracı.** Bir `.eml` dosyasını
veya ham e-posta metnini **statik** analiz eder, ağırlıklı ve açıklanabilir bir
risk skoru üretir (`low` / `medium` / `high` / `critical`). Türkçe arayüz/çıktı.

- CLI: `detector/` paketi
- Masaüstü GUI: `gui/` (CustomTkinter, motoru aynen kullanır)

## KESİN ETİK SINIR (değişmez)

- Bu bir **saldırı / kimlik-hasadı (credential harvesting) aracı DEĞİLDİR** ve
  öyle bir şeye dönüştürülmeyecek.
- **Statik analiz** — link/ek **asla açılmaz, çalıştırılmaz, çözülmez**. Sadece
  içerik ayrıştırılır.
- **Ağ işlemleri opt-in** — DNS/WHOIS/itibar/canlı SPF-DKIM-DMARC yalnızca
  `--online` ile. Varsayılan tamamen çevrimdışı.
- Analiz edilen e-posta **yerelde kalır**. İtibar sorguları yalnızca **domain**
  gönderir, e-posta içeriğini asla göndermez.

## Çalıştırma

```bash
# tek dosya
python -m detector.cli analyze mail.eml
python -m detector.cli analyze mail.eml --online --json
# klasör
python -m detector.cli batch klasor/
# GUI
python run_gui.py
# testler
python -m pytest -q      # 19 test
```

## Mimari

`analyzer.analyze()` akışı: **parse → tüm check'ler → score → report**.

- `detector/parser.py` — `.eml`/metin → `ParsedEmail` (headers, from/reply/return,
  bodies, `links`, `attachments` [her ekin `payload` bytes'ı derin analiz için saklanır]).
- `detector/analyzer.py` — orkestrasyon. `build_context()` veri dosyalarını yükler.
  Analiz başında **güven bağlamı** hesaplar (`auth_level`, `from_rdom`) ve hem
  check'lere (ctx içinde) hem `score()`'a geçirir.
- `detector/checks/*.py` — her modül `run(email, online=False, ctx=None) -> list[Indicator]`.
- `detector/indicators.py` — `Indicator(id, category, severity, weight, evidence, explanation)`.
- `detector/scoring.py` — güven-farkındalıklı skor + verdict.
- `detector/report.py` — rich tablo (yoksa düz metin), `to_json`.

### Check modülleri

| Modül | Ne bakar | Not |
|-------|----------|-----|
| `checks/headers.py` | SPF/DKIM/DMARC özeti, from↔reply/return-path uyuşmazlığı, `display_name_spoof` | online: `no_spf_record` |
| `checks/auth_verify.py` | **Tier 1** kripto: DKIM imza doğrulama, canlı SPF, DMARC politikası, Received/IP adli | online-gated (Received adli offline) |
| `checks/urls.py` | `anchor_href_mismatch` (first-party farkında), `ip_url`, punycode/homograph, shortener, suspicious_tld, `lookalike_domain` | |
| `checks/url_deep.py` | **Tier 2**: `open_redirect`, `combosquat_domain`, `brand_in_subdomain`, `confusable_brand` (IDN), `random_host` (DGA) | first-party farkında |
| `checks/content.py` | `urgency_language`, `credential_request`, `generic_greeting`, `brand_impersonation` | brand_imp **kimlik-temelli** (aşağıda) |
| `checks/html_forensics.py` | **Tier 2**: harici form POST, parola alanı, meta-refresh, `<base>`, gizli iframe, gizli metin, obfuscated JS | stdlib |
| `checks/attachments.py` | `double_extension`, `dangerous_attachment`, `macro_document`, arşiv, MIME uyuşmazlığı | ada göre |
| `checks/attachment_deep.py` | **Tier 2**: `html_smuggling`, `macro_detected/autoexec`, `pdf_active_content`, `pdf_launch_action` | içeriğe göre; oletools opsiyonel |
| `checks/qr.py` | **Tier 2** quishing: resim/`data:` içindeki QR çözüp URL denetler | opencv veya pyzbar opsiyonel; yoksa sessiz atlar |
| `reputation.py` | `vt_flagged` (VirusTotal) | online + `VT_API_KEY` |

## Skorlama modeli (yanlış-pozitif önleme)

Düz toplam DEĞİL. `detector/scoring.py`:

1. **Sert / yumuşak ayrımı** — `SOFT_IDS` yumuşak (bağlam gürültüsü: aciliyet,
   hitap, shortener, tracker-redirect, ESP alt alanları). Listede olmayan her id
   **sert** kabul edilir (yeni gösterge güvenli tarafta = sert).
2. **Güven çarpanı** (`_SOFT_MULT`) — `auth_level`: DMARC pass → yumuşak ×0.3,
   kısmi ×0.6, fail/none ×1.0. **Sert sinyaller hiç etkilenmez.**
3. **Kanıt desteği** — verdict **sert-toplama** dayanır: `<10 low · 10–21 medium ·
   22–44 high · 45+ critical`. Yalnız yumuşak sinyal (sert=0) → **daima low**.
4. **First-party bastırma** — link gönderenin domainine aitse (kendi tracker'ı)
   `anchor_href_mismatch`/`open_redirect`/`random_host` ateşlenmez.
5. **Allowlist** — `data/trusted_domains.txt`: DMARC-pass + listedeki domain, sert
   iz yoksa **low**'a sabitlenir.

`brand_impersonation` **kimlik-temelli**: marka adı yalnızca **From display-name
veya From adresinde** geçip domain markanın resmi domaini değilse ateşler
(kelime-sınırlı). Gövdede marka *anmak* tetiklemez — meşru mail sürekli marka anar.

## Veri dosyaları (`data/`, kullanıcı düzenleyebilir)

- `brands.txt` — `marka,domain1;domain2`
- `suspicious_tlds.txt`, `urgency_keywords.txt` (TR+EN)
- `trusted_domains.txt` — güvenilen gönderen allowlist'i

## Tier durumu

- **Tier 1** (kripto auth) — **DONE**
- **Tier 2** (saldırı vektörleri: html_forensics, attachment_deep, qr, url_deep) — **DONE**
- **Tier 3** (ML sınıflandırıcı + precision/recall benchmark + Ollama yerel LLM) — PENDING
- **Tier 4** (threat intel API + YAML config + pyproject/CI + GUI önizleme + PDF rapor) — PENDING

Örnek: `python -m detector.cli analyze tests/samples/phish_tier2.eml` → critical 100.

## Ortam notları (bu makineye özel)

- Bağımlılıkların hepsi **opsiyonel**; çekirdek saf stdlib. Eksikse zarifçe düşer
  (tldextract, rich, dkimpy, pyspf, dnspython, oletools, opencv, customtkinter).
- **GateGuard hook**: her dosyanın oturumdaki ilk Write/Edit'i "[Fact-Forcing
  Gate]" ile reddedilir; importer/API/şema + kullanıcı talebini yazıp aynı
  düzenlemeyi tekrarla → geçer.
- **Bash heredoc `\\` → `\`** çökertir (raw-string regex bozulur). Backslash-yoğun
  içerik için `Edit` aracını kullan; heredoc gerekiyorsa `chr(92)` ile düzelt.
- Windows konsolu cp1254; CLI çıktısı için stdout UTF-8'e `reconfigure` edilir.
