# CLAUDE.md — phishingtool

Bu dosya, Claude Code'un bu projede çalışırken bağlam olarak okuduğu nottur.
Amaç: ne yapıldığını, sınırları ve mimariyi tek bakışta netleştirmek.

## Proje nedir

**Savunma amaçlı phishing e-posta tespit/analiz aracı.** Bir `.eml`/`.msg`
dosyasını veya ham e-posta metnini **statik** analiz eder, ağırlıklı ve açıklanabilir bir
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
# kurulum (opsiyonel; `phishingtool` konsol komutunu verir)
pip install -e ".[dev]"          # extras: cli / online / deep / gui / dev
# tek dosya  (`phishingtool analyze ...` ile birebir aynı; .msg de olur)
python -m detector.cli analyze mail.eml
python -m detector.cli analyze mail.msg
python -m detector.cli analyze mail.eml --online --json
# IOC listesi (blocklist/SIEM): metin defanged, --json/CSV ham
python -m detector.cli analyze mail.eml --iocs
# Received hop tablosu (yolculuk sırası, gecikme, ters ad, TLS) — DNS yok
python -m detector.cli analyze mail.eml --hops
# tek dosyalık HTML rapor (gömülü CSS, JS/dış kaynak yok, mail içeriği tıklanamaz)
python -m detector.cli analyze mail.eml --iocs --html rapor.html
# skorlama ayarları (ağırlık/eşik/yumuşak küme) — her komutta geçerli, opt-in
python -m detector.cli analyze mail.eml --config config.toml
# klasör (CSV'nin son kolonu `error`; hata varsa exit 1, --verbose traceback verir)
python -m detector.cli batch klasor/ [--iocs] [--verbose]
# etiketli korpusa karşı ölçüm (precision/recall/F1 + hata listesi)
python -m detector.cli bench corpus/ [--threshold high] [--json]
# GUI
python run_gui.py
# testler
python -m pytest -q      # 162 test (CI: 3.11–3.14 Linux + 3.12 Windows)
```

## Mimari

`analyzer.analyze()` akışı: **parse → tüm check'ler → score → report**.

- `detector/parser.py` — `.eml`/`.msg`/metin → `ParsedEmail` (headers, from/reply/return,
  bodies, `links`, `attachments` [her ekin `payload` bytes'ı derin analiz için saklanır],
  `source_format` `eml|msg`, `header_source` `rfc822|mapi`). `parse_bytes()` OLE2
  imzasını görünce `.msg` dalına girer — `MAIL_GLOBS` klasör taramalarının tek kaynağı.
- `detector/msg.py` — Outlook `.msg` okuyucu, **saf stdlib** (bağımlılık yok):
  MS-CFB kapsayıcı (FAT/mini-FAT/directory) + MAPI özellikleri → `EmailMessage`.
  `is_msg()`, `to_message() -> (msg, header_source)`, `MsgError`. Transport
  header'lar (`007D`) varsa gerçek Received/auth kullanılır; yoksa başlıklar MAPI
  alanlarından kurulur (`5D02`/`0042` From, `39FE`+`0C15` alıcılar, `0039` FILETIME
  tarih) ve `header_source="mapi"` döner. Ekler baytı baytına korunur; gömülü
  mesajlar (stream değil storage) atlanır. Hiçbir şey çalıştırılmaz/çözülmez.
- `detector/analyzer.py` — orkestrasyon. `build_context(data_dir, config)` veri
  dosyalarını + skorlama politikasını yükler (`ctx["config"]`). Analiz başında
  **güven bağlamı** hesaplar (`auth_level`, `from_rdom`) ve hem check'lere
  (ctx içinde) hem `score()`'a geçirir.
- `detector/config.py` — opsiyonel TOML override'ı, saf stdlib (`tomllib`).
  `Config` (`weights`/`thresholds`/`soft_mult`/`soft_ids`/`source`/`changed`),
  `resolve(path)` (`--config` > `PHISHINGTOOL_CONFIG` > `DEFAULTS`), `load`,
  `from_dict`, `ConfigError`, `KNOWN_IDS` (= `mitre.TECHNIQUES | NO_TECHNIQUE`;
  gösterge id'lerinin tek kayıt defteri). Üç kural: **opt-in** (cwd'deki
  `config.toml` otomatik bulunmaz), **sesli hata** (bilinmeyen bölüm/anahtar/id,
  sırası bozuk eşik, aralık dışı çarpan = `ConfigError` → CLI exit 2), **görünür**
  (yüklenen ayar rapora ve `breakdown.config`'e yazılır). BOM'lu dosya
  (`utf-8-sig`) kabul edilir — Notepad/PowerShell öyle yazıyor.
- `detector/checks/*.py` — her modül `run(email, online=False, ctx=None) -> list[Indicator]`.
- `detector/indicators.py` — `Indicator(id, category, severity, weight, evidence,
  explanation, technique="", technique_name="")`. `__post_init__` boş `technique`'i
  `mitre.lookup(id)` ile doldurur → **her yol** (CLI/GUI/bench/doğrudan check)
  etiketi otomatik alır, atlanacak ayrı adım yok.
- `detector/mitre.py` — gösterge id → MITRE ATT&CK tekniği. `TECHNIQUES` (eşleme),
  `NAMES` (teknik adları), `NO_TECHNIQUE` (bilerek eşlenmeyenler: `vt_flagged`,
  `no_spf_record`, `no_dmarc_record`, `no_received_headers`, `private_origin_ip`),
  `lookup(id)`, `summary(indicators)`, `url(tid)`. Gösterge başına **tek** teknik.
  Saf tablo — ağ yok, bağımlılık yok. `tests/test_mitre.py` içindeki **drift testi**
  kaynağı tarar: eşlemesiz yeni `Indicator(...)` = kırmızı test.
- `detector/scoring.py` — güven-farkındalıklı skor + verdict. `Result.breakdown`
  (`Breakdown`): sert/yumuşak alt toplam, uygulanan çarpan, sayımlar, `trusted`,
  `capped`, verdict'i belirleyen kural anahtarı `reason` (`hard_critical|
  hard_high|hard_medium|soft_pileup|allowlist|weak_hard_evidence|no_hard_evidence`)
  ve `config_source`/`config_changed`. Modül sabitleri (`SOFT_IDS`, `SOFT_MULT`,
  `THRESHOLDS`) **varsayılan**; `score(..., config=)` verilirse hepsi o nesneden
  okunur ve `weights` `dataclasses.replace` ile uygulanır (çağıranın gösterge
  nesneleri değiştirilmez). `config` modülünü import etmez — nesne duck-typed.
- `detector/bench.py` — etiketli korpus → `Case`/`Metrics`/`BenchResult`;
  precision/recall/F1/FP-oranı, eşik taraması (`medium|high|critical`), FP/FN
  listesi (her biri sert gösterge id'leriyle). Etiket kaynağı: `labels.csv`
  (`file,label`) **veya** `phish/` + `ham/` alt klasörleri.
- `detector/iocs.py` — `collect(email) -> IOCSet` (urls/domains/ips/emails/
  attachments+sha256) + `defang()`. HTML'de **yalnız attribute içindeki** URL'ler
  sayılır (anchor *metni* IOC değil — meşru markayı engellememek için); Received
  köken IP'sinde özel/ayrılmış aralıklar elenir. Metin defanged, JSON/CSV ham.
- `detector/received.py` — `Received` yığını → **yolculuk sırasına** dizilmiş hop
  listesi. `parse(email) -> list[Hop]` (`index` 1 = mailin girdiği yer),
  `summary(hops)` (hop sayısı, köken IP, süre, uyarılar), `Hop.to_dict()`.
  Hop alanları: duyurulan ad (HELO iddiası), alıcının yazdığı **ters ad**, IP,
  hedef, protokol/`tls`, `time`, önceki hoptan `delay`, `flags`, `raw`.
  Uyarılar: `rdns_mismatch`, `private_ip`, `no_tls` (yalnız public IP'li gerçek
  internet hopunda), `big_delay` (>300 sn), `clock_skew`, `unparsed` (okunamayan
  satır düşürülmez, ham hâliyle taşınır). **DNS yok** — ters ad zaten başlıkta
  yazılıdır; **skoru etkilemez**, ATT&CK etiketi gibi saf metadata.
- `detector/report.py` — rich tablo (yoksa düz metin), `to_json(result, source, iocs, hops)`,
  `iocs_lines`/`print_iocs`;
  `breakdown_lines()` skor kırılımının iki Türkçe satırı (CLI + GUI ortak kullanır;
  ayar dosyası varsa **üçüncü** satır: yol + değişen bölümler);
  `technique_lines()` ATT&CK bloğu (CLI) / `technique_summary_line()` tek satır (GUI);
  `received_lines()` hop bloğu + `_received_rich()` rich tablosu /
  `received_summary_line()` tek satır (GUI); `HOP_TRUST_NOTE` + `hop_flag_text()`
  HTML ile ortak. `hops=None` "sorulmadı", `[]` "soruldu, zincir yok" demek;
  `print_bench` / `bench_to_json` benchmark çıktısı.
- `detector/html_report.py` — `to_html(result, source, iocs, email, when)`: tek
  dosyalık HTML (gömülü CSS). **JS yok, dış kaynak yok**; mail kaynaklı her değer
  `html.escape`'ten geçer ve **asla `href` olmaz** — sayfadaki tek bağlantı
  `attack.mitre.org`. IOC bloğu terminaldeki gibi defanged (`report.iocs_lines`
  ortak kullanılır); `--hops` verilmişse Received tablosu da bu sayfada, host/IP
  değerleri kaçışlanmış metin olarak. CLI: `analyze --html DOSYA`; bilgi satırı stderr'e gider ki
  `--json` ile stdout geçerli JSON kalsın, yazma hatasında exit 2.
- `detector/cli.py` — `batch` hata sebebini **yutmaz**: satır `error` kolonuna +
  stderr'e yazılır, `--verbose` traceback ekler, en az bir hata varsa exit 1.

### Check modülleri

| Modül | Ne bakar | Not |
|-------|----------|-----|
| `checks/headers.py` | SPF/DKIM/DMARC özeti, from↔reply/return-path uyuşmazlığı, `display_name_spoof`, `msg_no_transport_headers` | online: `no_spf_record` |
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
2. **Güven çarpanı** (`SOFT_MULT`) — `auth_level`: DMARC pass → yumuşak ×0.3,
   kısmi ×0.6, fail/none ×1.0. **Sert sinyaller hiç etkilenmez.**
3. **Kanıt desteği** — verdict **sert-toplama** dayanır: `<10 low · 10–21 medium ·
   22–44 high · 45+ critical`. Yalnız yumuşak sinyal (sert=0) → **daima low**.
4. **First-party bastırma** — link gönderenin domainine aitse (kendi tracker'ı)
   `anchor_href_mismatch`/`open_redirect`/`random_host` ateşlenmez.
5. **Allowlist** — `detector/data/trusted_domains.txt`: DMARC-pass + listedeki
   domain, sert iz yoksa **low**'a sabitlenir.

**ATT&CK etiketi skoru etkilemez** — saf metadata. Her gösterge `technique`/
`technique_name` taşır; `Result.to_dict()` üst seviyede gruplanmış `techniques`
listesi (`id`, `name`, `url`, tetikleyen `indicators`) verir.

Bu hesap gizli değil: her rapor (düz metin, rich, GUI, `--json`) iki satır olarak
gösterir — `Skor kırılımı: sert 34 (3 gösterge) + yumuşak 18×0.3=5.4 (4 gösterge)
= 39/100` ve `Verdict nedeni: sert toplam ≥ 22 → high · auth=pass`.

Bu beş maddenin **sayıları** `--config` ile değiştirilebilir (`[weights]`,
`[thresholds]`, `[soft_multiplier]`, `[soft_ids]`); **mantığı** değişmez —
sert/yumuşak ayrımı, kanıt desteği ve first-party bastırma kod tarafında kalır.
Ayar verilmezse çıktı birebir eskisi gibidir; verilirse rapor üçüncü satırda
hangi dosyanın hangi bölümü değiştirdiğini yazar (bkz. `detector/config.py`).

`brand_impersonation` **kimlik-temelli**: marka adı yalnızca **From display-name
veya From adresinde** geçip domain markanın resmi domaini değilse ateşler
(kelime-sınırlı). Gövdede marka *anmak* tetiklemez — meşru mail sürekli marka anar.

## Veri dosyaları (`detector/data/`, kullanıcı düzenleyebilir)

Sözlükler **paket içinde** (wheel'e girer, `phishingtool` her dizinden bulur).
Çözümleme sırası `analyzer.resolve_data_dir()`: `--data-dir` argümanı >
`PHISHINGTOOL_DATA` ortam değişkeni > paket içi varsayılan. Eksik dosya = boş küme.

- `brands.txt` — `marka,domain1;domain2`
- `suspicious_tlds.txt`, `urgency_keywords.txt` (TR+EN)
- `trusted_domains.txt` — güvenilen gönderen allowlist'i

**Skorlama ayarı ayrı** (`--config config.toml`, `PHISHINGTOOL_CONFIG`): sözlük
değil politika. Şablon repo kökünde `config.example.toml`; şema ve kurallar
`detector/config.py` docstring'inde. Gerçek `config.toml` git'te takip edilmez.

`corpus/` — `bench` korpusu (yerel). Gerçek mailler git'te **yok**: `.gitignore`
`corpus/**/*.eml`, `corpus/**/*.msg`, `corpus/labels.csv` hariç tutar; sadece
`corpus/README.md` + `labels.example.csv` takip edilir.

## Tier durumu

- **Tier 1** (kripto auth) — **DONE**
- **Tier 2** (saldırı vektörleri: html_forensics, attachment_deep, qr, url_deep) — **DONE**
- **Tier 3** — precision/recall **benchmark harness DONE** (`detector/bench.py`,
  `bench` komutu). ML sınıflandırıcı + Ollama yerel LLM hâlâ PENDING; ölçüm artık
  var, bir sonraki değişiklik F1 ile doğrulanabilir.
- **Tier 4** — **pyproject + `phishingtool` konsol komutu + GitHub Actions CI DONE**
  (`pyproject.toml`, `.github/workflows/ci.yml`; sözlükler pakete taşındı,
  `--data-dir`/`PHISHINGTOOL_DATA` override'ı eklendi; **TOML config DONE**,
  aşağıya bak). Threat intel API, GUI önizleme, PDF rapor hâlâ PENDING.
- **MITRE ATT&CK etiketi** (`detector/mitre.py`) — **DONE**; `batch` hata
  raporlaması (`error` kolonu + `--verbose` + exit 1) — **DONE**.
- **`.msg` (Outlook) desteği** — **DONE** (`detector/msg.py`, bağımlılıksız).
  Başlıksız `.msg`'de `msg_no_transport_headers` bilgi göstergesi çıkar (ağırlık 0,
  `SOFT_IDS` + `NO_TECHNIQUE`); `auth_verify` o durumda `no_received_headers`
  üretmez — eksiklik dosyanın, mailin değil.
- **HTML rapor** (`--html`) — **DONE** (`detector/html_report.py`; analyze
  komutunda, tek dosya, JS/dış kaynak yok, mail içeriği tıklanamaz).
  (`batch --html` henüz yok — istenirse tek sayfalık özet olarak eklenebilir.)
- **Received hop tablosu** (`--hops`) — **DONE** (`detector/received.py`; CLI
  düz metin + rich, `--json` `received` anahtarı, HTML bölümü, GUI özet satırı).
  Opt-in bayrak: verilmezse çıktı eskisiyle birebir aynı. Skorlama dokunulmadı.
- **`config.toml` (ağırlık/eşik override)** — **DONE** (`detector/config.py`,
  `tomllib`, bağımlılıksız). Her komutta `--config DOSYA` +
  `PHISHINGTOOL_CONFIG`; `[weights]`/`[thresholds]`/`[soft_multiplier]`/
  `[soft_ids]`. Opt-in (cwd otomatik taranmaz), sesli hata (exit 2), rapor +
  `breakdown.config` içinde görünür. Şablon: `config.example.toml`.
  **Roadmap'in 9 maddesi bitti** — kalan iş: ML sınıflandırıcı (Tier 3),
  threat intel API, GUI önizleme, PDF rapor, `batch --html`.

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
