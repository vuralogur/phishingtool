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
- **Statik analiz** — link **asla ziyaret edilmez**; ek **asla çalıştırılmaz,
  bir uygulamayla açılmaz/render edilmez, diske çıkarılmaz**. Yalnız içerik
  ayrıştırılır. Kapsayıcıların **yapısı** okunabilir (kullanıcı onayı:
  2026-11-15), tamamı `detector/documents.py` içinde, bellekte ve boyut
  sınırıyla: ZIP **dizini** (dosya adları + şifreli bayrağı; üye çıkarılmaz),
  OOXML'in yalnız `*.rels` dosyaları, PDF'in yalnız `/ObjStm` akışları. Bunun
  ötesi (üye çıkarma, makro/betik çalıştırma, sayfa render) sınırın dışındadır.
- **Ağ işlemleri opt-in** — DNS/RDAP (domain yaşı)/itibar/canlı SPF-DKIM-DMARC
  yalnızca `--online` ile. Varsayılan tamamen çevrimdışı. Tek başka ağ kodu
  `phishingtool feeds update`: kullanıcı açıkça yazınca herkese açık tehdit
  listelerini **indirir**, karşıya mailden hiçbir şey göndermez. Analiz
  sırasında liste **asla indirilmez**; eşleştirme diskteki dosyaya karşı yereldir
  (`detector/feeds.py` — `update()` ağ, `load()`/`lookup()` yerel, ikisi ayrı).
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
# tehdit listeleri: indir (ağ; mail verisi gitmez) / eldekini göster
python -m detector.cli feeds update [--source usom] [--days 30]
python -m detector.cli feeds status [--json]
# indirilen listeler her analizde yerelde okunur; --feeds-dir / --no-feeds
python -m detector.cli analyze mail.eml --no-feeds
# GUI
python run_gui.py
# testler (ağa çıkmaz: conftest HTTP yardımcılarını kapatır)
python -m pytest -q      # 888 test (CI: 3.11–3.14 Linux + 3.12 Windows)
```

## Mimari

`analyzer.analyze()` akışı: **parse → tüm check'ler → score → report**.

- `detector/parser.py` — `.eml`/`.msg`/metin → `ParsedEmail` (headers, from/reply/return,
  bodies, `links`, `attachments` [her ekin `payload` bytes'ı derin analiz için saklanır],
  `source_format` `eml|msg`, `header_source` `rfc822|mapi`). `parse_bytes()` OLE2
  imzasını görünce `.msg` dalına girer — `MAIL_GLOBS` klasör taramalarının tek kaynağı.
  **Tüm** `text/plain` / `text/html` parçaları birleştirilir (`_bodies`): istemci
  sonuncuyu gösterir, yalnız ilkini okumak kaçış yoluydu. `links` tarayıcının
  izlediği her yazımı kapsar: `normalize_href()` (`//host`, baştaki boşluk,
  `https:\\host` → `scheme://host`), `<area href>`, `<form action>`,
  `formaction`, kapatılmamış `<a>`, `javascript:` içindeki URL, ve şemasız metin
  adresleri (`_text_urls`: `www.` veya yol + gerçek public suffix şart). HTML'de
  yalnız anchor **dışı** görünür metin taranır — anchor metni hedef değildir.
  `attachments`: dosya adı ya da `attachment` disposition'ı olan parçalar **ve**
  `_carries_a_file()` — adsız `image/*`/`application/*`/`audio/*`/`video/*`
  parçaları (yalnız Content-ID'li gömülü resim, "noname" ikili; adı `(unnamed)`),
  imza parçaları (`_SIGNATURE_TYPES`) hariç. Multipart olmayan mailin kendisi de
  dosya olabilir. `Attachment.clean_name` = OS'un göreceği ad (sondaki nokta/
  boşluk ve görünmez karakterler atılır); `ext` ondan türetilir.
  `links` ek **içindeki** linkleri de taşır (`_attachment_links`): HTML/SVG ek
  (`_extract_links`), PDF `/URI`, OOXML `hyperlink` ilişkisi. `Link.source` =
  ek adı ("" = gövde); `util.link_origin()` kanıt satırına "Ek 'x.pdf'
  icindeki link - " önekini koyar. Gövdede zaten olan adres tekrar eklenmez.
  URL kontrolleri ve IOC listesi bunları kendiliğinden görür.
- `detector/documents.py` — kapsayıcı **yapısı** (etik sınırdaki istisnanın
  tek yeri). `zip_members()` (merkezi dizin → `Member(name, encrypted, size)`,
  `None` = okunamadı), `is_office_package()` (OOXML/ODF), `ooxml_external()`
  (`(kind, target)`; yalnız `TargetMode="External"`), `pdf_object_streams()`
  (yalnız `/Type /ObjStm` + `/FlateDecode`), `pdf_urls()`, `markup_text()`.
  Her okuma `MAX_*` sabitleriyle sınırlı (bomba = sınırlı bellek, sonra durur);
  okunamayan dosya = "bulgu yok", exception yok. `lru_cache`'li: parser ve
  check aynı eki iki kez açmaz.
- `detector/filetype.py` — `sniff(data) -> kind` (`exe|ole|zip|image|archive|
  rtf|pdf|html|svg|""`) + `LABELS`. Yalnız ilk baytların imza karşılaştırması;
  açma/çözme yok. Tanınmayan = `""` = "bulgu yok" (tahmin etmez; "MZ" tek
  başına PE değildir, `e_lfanew`→`PE\0\0` ya da DOS stub metni aranır).
- `detector/msg.py` — Outlook `.msg` okuyucu, **saf stdlib** (bağımlılık yok):
  MS-CFB kapsayıcı (FAT/mini-FAT/directory) + MAPI özellikleri → `EmailMessage`.
  `is_msg()`, `to_message() -> (msg, header_source)`, `MsgError`. Transport
  header'lar (`007D`) varsa gerçek Received/auth kullanılır; yoksa başlıklar MAPI
  alanlarından kurulur (`5D02`/`0042` From, `39FE`+`0C15` alıcılar, `0039` FILETIME
  tarih) ve `header_source="mapi"` döner. Ekler baytı baytına korunur; gömülü
  mesajlar (stream değil storage) atlanır. Hiçbir şey çalıştırılmaz/çözülmez.
- `detector/analyzer.py` — orkestrasyon. `build_context(data_dir, config,
  feeds_dir=None)` veri dosyalarını + skorlama politikasını (`ctx["config"]`) +
  indirilmiş tehdit listelerini (`ctx["feeds"]`; `feeds_dir=False` = liste
  kullanma) yükler. Analiz başında
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
  hard_high|hard_medium|soft_pileup|soft_stack|allowlist|weak_hard_evidence|no_hard_evidence`)
  ve `config_source`/`config_changed`. Modül sabitleri (`SOFT_IDS`, `SOFT_MULT`,
  `THRESHOLDS`) **varsayılan**; `score(..., config=)` verilirse hepsi o nesneden
  okunur ve `weights` `dataclasses.replace` ile uygulanır (çağıranın gösterge
  nesneleri değiştirilmez). `config` modülünü import etmez — nesne duck-typed.
- `detector/bench.py` — etiketli korpus → `Case`/`Metrics`/`BenchResult`;
  precision/recall/F1/FP-oranı, eşik taraması (`medium|high|critical`), FP/FN
  listesi (her biri sert gösterge id'leriyle). `BenchResult.indicator_stats()`
  = **gösterge kırılımı**: id başına kaç phish / kaç ham mailde ateşlendi (mail
  başına bir kez; `Case.all_ids`, `soft_ids` koşunun kullandığı küme), en çok
  ham vuran üstte; düz metin raporda tablo, `--json`'da `indicators`. Etiket kaynağı: `labels.csv`
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
  `_context(args)` üç analiz komutunun ortak `build_context` çağrısı
  (`--data-dir`, `--config`, `--feeds-dir`/`--no-feeds`). `feeds update|status`
  (`cmd_feeds`): kaynak başına `OK|ATLANDI|HATA` satırı; bir kaynak `failed`
  ise **ya da** adıyla istenen kaynak atlandıysa exit 1, `--days < 1` exit 2.
- `detector/feeds.py` — tehdit listeleri, saf stdlib (`urllib`). **İki yarı
  birbirine değmez**: `update(sources, feeds_dir, days, now)` tek ağ kodu
  (yalnız `feeds update` çağırır) → `list[UpdateResult(source, status
  ok|skipped|failed, entries, message)]`; `load(feeds_dir) -> FeedSet` yalnız
  diski okur (klasör yok = boş/falsy küme). `SOURCES` = `openphish`
  (`openphish.com/feed.txt`, satır başına URL), `usom`
  (`siberguvenlik.gov.tr/api/address/index?per-page=5000&date_gte=…&page=N`,
  sayfa 1'den başlar, JSON `models[].url`; yalnız son `days` gün, tavan
  `USOM_MAX_PAGES`), `urlhaus` (`urlhaus-api.abuse.ch/v2/files/exports/<KEY>/
  recent.csv`; `URLHAUS_AUTH_KEY` yoksa `skipped`, anahtar hata metninde `***`).
  Eski adresler öldü: `urlhaus.abuse.ch/downloads/*` 410, `usom.gov.tr/
  url-list.txt` HTML döndürür — bu yüzden `parse_url_lines` "satırların çoğu URL
  mü" diye bakar ve **başarısız/boş indirme diskteki listeyi ezmez** (`.tmp` +
  `os.replace`). `url_key()` = karşılaştırma biçimi (`host` ya da
  `host/yol?sorgu`; şema, `www.`, sondaki `/`, fragment, port atılır; IP düz
  yazılır; yol büyük/küçük harfi korunur; `mailto:` vb. = ""). `FeedSet.lookup
  (url) -> Hit(kind, source, entry)`: `url` (tam adres) > `host` > `domain`
  (kayıtlı domain listede) > `path` (aynı host'ta **başka** adres listede);
  `lookup_host()` gönderen domaini için (yalnız host/domain). Klasör:
  `--feeds-dir` > `PHISHINGTOOL_FEEDS` > `default_dir()` (kullanıcı önbelleği).
  Klasördeki her `*.txt` okunur (elle yazılmış `kurum.txt` dahil; BOM/CRLF olur);
  `FeedInfo` (`source`, `entries`, `fetched`, `age_days()`, `stale()` >
  `STALE_DAYS` = 7, `error`).
- `detector/rdap.py` — domain kayıt tarihi, saf stdlib, **yalnız `--online`**.
  `age_days(domain)` / `registration_date()` / `parse_registration(payload)`
  (`events[].eventAction == "registration"`). `rdap.org/domain/<domain>`
  (IANA bootstrap yönlendiricisi); yalnız düz domain gider (`_ascii_domain`
  yol/sorgu/boşluk içereni göndermez). Her hata/404/RDAP'sız TLD (`.tr` dahil)
  = `None` = bulgu yok. Süreç içi `_cache` (başarısızlık da hatırlanır).

### Check modülleri

| Modül | Ne bakar | Not |
|-------|----------|-----|
| `checks/headers.py` | SPF/DKIM/DMARC özeti (**güven sınırı**, aşağıda), from↔reply/return-path uyuşmazlığı, `display_name_spoof`, `msg_no_transport_headers`, `auth_results_conflict`, `auth_claim_unverifiable`, `alignment()` → `auth_pass_unaligned`, `brand_domain_spoof` / `brand_domain_unverified`, `multiple_from_headers` (sert 14; iki From + **farklı** adres) | online: `no_spf_record` |
| `checks/auth_verify.py` | **Tier 1** kripto: DKIM imza doğrulama, canlı SPF, DMARC politikası, Received/IP adli | online-gated (Received adli offline) |
| `checks/urls.py` | `anchor_href_mismatch` (first-party farkında), `ip_url`, punycode/homograph, shortener, suspicious_tld, `lookalike_domain`, `free_hosting_url` (yumuşak 8; host `free_hosting.txt` soneklerinden birinin **alt alanı**, first-party hariç) | `ip_url` gizli yazımları da tanır (`util.canonical_ip`: ondalık/hex/sekizlik/IPv6) |
| `checks/url_deep.py` | **Tier 2**: `open_redirect`, `combosquat_domain`, `brand_in_subdomain`, `confusable_brand` (IDN), `random_host` (DGA), `brand_in_path` (yumuşak 10; marka domaini başka host'un **yolunda**, sorgu dizgisi `open_redirect`'e kalır) | first-party farkında |
| `checks/content.py` | `urgency_language`, `credential_request`, `generic_greeting`, `brand_impersonation` | brand_imp **kimlik-temelli** (aşağıda). Kelimeler ham HTML **+** `util.visible_text()` üzerinde aranır (`pass<span></span>word`, sıfır-genişlik bölme) |
| `checks/social.py` | **Yüksüz** sosyal mühendislik: `callback_phishing` (sert 14), `bec_request` (sert 14), `bank_change_request` (sert 12; auth pass → 6), `vip_impersonation` (sert 18), `fake_reply_subject` (yumuşak 6) | her bulgu **birleşim** (aşağıda); desenler `ascii_fold` edilmiş görünen metne yazılı |
| `checks/html_forensics.py` | **Tier 2**: harici form POST (`formaction` dahil), parola alanı, meta-refresh, `<base>`, gizli iframe, gizli metin, obfuscated JS, `active_content_link` (`javascript:`/`vbscript:`/`data:` href; `void(0)` ve `data:image` hariç) | stdlib |
| `checks/attachments.py` | `double_extension`, `dangerous_attachment`, `macro_document`, arşiv, MIME uyuşmazlığı, `disguised_executable` (sert: içerik exe, ad değil), `content_extension_mismatch` (yumuşak, `CONTENT_EXPECT`) | ad + MIME + içerik imzası (`filetype.sniff`); bayt/MIME aynı eki yalanlıyorsa **tek** bulgu |
| `checks/attachment_deep.py` | **Tier 2**: `html_smuggling`, `macro_detected/autoexec`, `pdf_active_content`, `pdf_launch_action`, HTML/SVG ek = sayfa (`_page`): `html_attachment_form` (sert 16) **ya da** `html_attachment_script` (sert 14); ZIP dizini: `archive_dangerous_member` (sert 18; `DANGEROUS` − sayfa uzantıları + disk imajları), `archive_encrypted` (yumuşak 8, taşıyıcı); OOXML: `remote_template` (sert 18; `attachedTemplate`/`oleObject`/`frame`/`subDocument` + **uzak** hedef — Word'ün yerel `file:///C:/…` şablon kaydı değil); PDF adları `/ObjStm` içinde de aranır | içeriğe göre; oletools opsiyonel. Sayfa okuması `html_forensics.scan()` ile; dosya başına **tek** bulgu (form kazanır) — meşru "güvenli mesaj" HTML ekleri critical'a çıkmasın |
| `checks/qr.py` | **Tier 2** quishing: resim/`data:` içindeki QR çözüp URL denetler | opencv veya pyzbar opsiyonel; yoksa sessiz atlar |
| `checks/threat_intel.py` | **Yerel:** `threat_feed_hit` (sert 25; link tam adres/host/kayıtlı domain ya da From/Reply-To domaini listede), `threat_feed_neighbor` (yumuşak 10; aynı host'ta başka adres listede). **Online:** `newly_registered_domain` (RDAP, < `NEW_DOMAIN_DAYS` = 30 gün; sert 12, auth pass → 6; mail başına en çok `MAX_AGE_LOOKUPS` = 5 sorgu, gönderen önce) | liste yoksa (`ctx["feeds"]` boş) hiçbir şey üretmez. `_excused()`: host düzeyi eşleşme marka/allowlist/`own_domains` domaininde, kısaltıcıda ve barındırma servisinin **kendisinde** (`pages.dev`) sayılmaz; **tam adres** eşleşmesi her yerde sayılır, `x.pages.dev` tek kiracıdır ve sayılır. Yaş sorgusu marka/allowlist/freemail/kısaltıcı/barındırma/IP için yapılmaz. İki feed id'si `NO_TECHNIQUE` (`vt_flagged` gibi) |
| `reputation.py` | `vt_flagged` (VirusTotal) | online + `VT_API_KEY` |

## Skorlama modeli (yanlış-pozitif önleme)

Düz toplam DEĞİL. `detector/scoring.py`:

1. **Sert / yumuşak ayrımı** — `SOFT_IDS` yumuşak (bağlam gürültüsü: aciliyet,
   hitap, shortener, tracker-redirect, ESP alt alanları). Listede olmayan her id
   **sert** kabul edilir (yeni gösterge güvenli tarafta = sert).
2. **Güven çarpanı** (`SOFT_MULT`) — `auth_level`: DMARC pass → yumuşak ×0.3,
   kısmi ×0.6, fail/none ×1.0. **Sert sinyaller hiç etkilenmez.**
3. **Kanıt desteği** — verdict **sert-toplama** dayanır: `<10 low · 10–21 medium ·
   22–44 high · 45+ critical`. Yalnız yumuşak sinyal (sert=0) → **low**; tek
   istisna madde 8.
4. **First-party bastırma** — link gönderenin domainine aitse (kendi tracker'ı)
   `anchor_href_mismatch`/`open_redirect`/`random_host` ateşlenmez.
5. **Allowlist** — `detector/data/trusted_domains.txt`: DMARC-pass + listedeki
   domain, sert iz yoksa **low**'a sabitlenir.
6. **Auth ailesi tavanı** — `scoring.AUTH_FAIL_IDS` (spf/dkim/dmarc fail + canlı
   karşılıkları) tek kök nedendir; sert toplama en fazla `THRESHOLDS["auth_cap"]`
   = 20 ekler. Tek başına `medium`, `high` için bağımsız kanıt gerekir.
   `Breakdown.auth_raw`/`auth_trimmed` + kırılım satırında `auth ailesi 42→20`.
7. **Doğrulanmış gönderende zayıflayan iki sert gösterge** (check içinde, ctx
   `auth_level == "pass"`): `credential_request` 12→6, `from_replyto_mismatch`
   10→5 (Reply-To `headers.FREEMAIL` içindeyse indirim yok). Sert kalırlar,
   başka kanıtla toplanırlar; tek başlarına `medium` edemezler. `[weights]`
   override'ı bu indirimi ezer.
8. **Taşıyıcı sinyal yığını** (`reason = soft_stack`) — yumuşak sinyalin tek
   başına `medium` edebildiği tek yol, daha yukarı asla. `scoring.STACK_IDS`
   (kısaltıcı, şüpheli TLD, punycode, `@`, tld-swap, ücretsiz barındırma,
   yolda marka domaini, makrolu belge, MIME/içerik uyuşmazlığı, şifreli arşiv,
   QR, meta-refresh, `<base>`, gizli iframe, obfuscated JS):
   `auth_level != "pass"` + en az `soft_stack_min` = 2 **farklı** id + çarpanlı
   toplam ≥ `soft_stack` = 15. Ton (aciliyet/hitap, `fake_reply_subject`), tracker gürültüsü
   (`open_redirect`/`random_host`/`excessive_subdomains`), `hidden_text`,
   düz arşiv ve **tüm auth-kategorisi notlar bilerek dışarıda**: A-R'siz meşru ESP
   bülteni bunlardan phishing kadar puan toplar, puan eşiği ayıramaz.
   Merdivende `soft_pileup`'tan sonra gelir, "sert == 0" şartı yok (zayıf sert
   iz + yığın, yığından düşük çıkmasın); config ile sert'e taşınan id tam
   ağırlıkla yine sayılır. `soft_stack_min = 0` kuralı kapatır.
   `Breakdown.stack`/`stack_ids` yalnız kural karar verdiğinde dolu; rapor
   satırı sayılan id'leri yazar. `tests/test_soft_stack.py` iki taraftan sınar.

**Yanlış-pozitif dersleri** (`tests/test_false_positives.py` iki taraftan sınar):
`combosquat_domain` = marka + `lure_words.txt` kelimeleri (etiketin markadan
kalan her parçası sözlükten kurulabilmeli; "marka + herhangi ek" `googleapis`/
`amazonaws`/`pineapple`'ı vuruyordu). `credential_request` yalın `iban` ve
`müşteri numara` aramaz, yalnız isteme biçimini (`...numaranızı`,
`IBAN bilgilerinizi`). PDF adları `_pdf_name()` ile **tam** eşleşir (`/AA` ≠
`/AAAAAA+Font`); `/OpenAction`/`/AA` tek başına bulgu değil; betiksiz
`/EmbeddedFile` = yumuşak `pdf_embedded_file`. `macro_detected` OLE imzasıyla
değil `_VBA_PROJECT` deposuyla ateşlenir (oletools okuyabildiyse onun sözü
geçer). `mime_extension_mismatch` takma adları ve `application/octet-stream`'i
uyuşmazlık saymaz.

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

**Güven sınırı (auth)**: `headers.summary()` SPF/DKIM/DMARC'ı **yalnızca en
üstteki** `Authentication-Results`'tan okur; başlıklar yukarı eklendiği için
alttakiler gönderenin kendi yazdığı satır olabilir. Üst satırın söylemediği
mekanizma `none` kalır — alttan doldurulmaz. `Received-SPF` ayrı alandan
(`ParsedEmail.spf_received`) kendi dilbilgisiyle okunur. Alt satır daha iyi
sonuç iddia ederse `auth_results_conflict` (yumuşak, ATT&CK'siz) raporlanır.
Hiç `Received` yokken "pass" iddiası = `auth_claim_unverifiable` **ve**
`analyzer.analyze()` `auth_level`'ı `none`'a düşürür (indirim yok).
**Hizalama** (`headers.alignment(email) -> (state, foreign)`): en üst A-R'deki
`header.d`/`header.i`/`smtp.mailfrom`/`header.from` From'un kayıtlı domainiyle
karşılaştırılır. `aligned | unaligned | unknown | nopass | none`. `unaligned`
(tüm pass'lar başka domain için) → `auth_pass_unaligned` (yumuşak, ATT&CK'siz)
**ve** `analyzer.analyze()` `auth_level`'ı `none`'a düşürür. Özelliksiz yalın
`spf=pass` = `unknown`, seviye korunur. `dmarc=pass header.from=baska.com` da
`unaligned`'dır (iki-From hilesi).
**Kimlik kontrolleri** (`tests/test_identity.py`): From `brands.txt`'deki gerçek
bir domainde + A-R var ama hizalı pass yok (veya Received'sız pass iddiası) →
`brand_domain_spoof` (sert 18); hiç A-R yok → `brand_domain_unverified`
(yumuşak). `headers.FREEMAIL` ve `.msg`/mapi hariç. `urls.py` ve `url_deep.py`
domain kontrollerini link döngüsünden sonra **From + Reply-To domainine** de
uygular (`domain_checks` / `brand_checks`, aynı `add()` → tek bulgu).
`tld_swap_domain` (`urls._tld_swap`) yumuşak: aynı ad, farklı uzantı; 2 harfli
ülke uzantısı şüpheli listede değilse ve ad < 4 harfse atlanır.
`brand_impersonation` kimliği `util.skeleton()` ile de karşılaştırır (NFKC +
görünmez karakter silme + `util.CONFUSABLES` Kiril/Yunan eşlemesi).
`util.ascii_fold()` marka/anahtar kelime karşılaştırmalarını ASCII'ye katlar
(`str.lower()` "I"→"ı" yapamaz; "VAKIFBANK" aksi hâlde hiç eşleşmiyordu).
`util.looks_like_domain()` "Ltd.Sti" gibi domain olmayan token'ları eler,
`util.lookalike_distance()` düzenleme mesafesi toleransını marka adının
uzunluğuna göre ölçekler (`fb.com`'a 2 mesafe = internetin yarısı).

`brand_impersonation` **kimlik-temelli**: marka adı yalnızca **From display-name
veya From adresinde** geçip domain markanın resmi domaini değilse ateşler
(kelime-sınırlı). Gövdede marka *anmak* tetiklemez — meşru mail sürekli marka anar.

**Yüksüz sosyal mühendislik** (`checks/social.py`, `tests/test_social.py` iki
taraftan sınar): link/ek/sahte başlık taşımayan mailler. Kelime tek başına
kanıt değil → her bulgu **birleşim**: ifade + talebin biçimi + göndereni kimin
doğruladığı. Okunan metin = konu + düz gövde + `util.visible_text(html)`.
- `callback_phishing`: `_AMOUNT` + `_CHARGE` + `_DISPUTE` + telefon (`_phones`:
  10–13 hane ya da 444'lü 7 hane; ayraçsız rakam dizisi ve tarih elenir) +
  numaranın çevresinde (−160/+80 karakter) `_CALL` + (From `headers.FREEMAIL`
  **ya da** metin bir markayı anıyor ve From o markanın domaini değil; marka
  koşulu `auth_level == "pass"` iken sayılmaz).
- `bec_request`: `_MONEY` + `_PRETEXT` + görünen metin ≤ `_BEC_MAX_CHARS` (1500)
  + (From freemail **ya da** Reply-To başka kayıtlı domain).
- `bank_change_request`: `_BANK_CHANGE` ("değişti/güncellendi" şart; yalın
  "yeni" + sipariş cümlesi değil). Auth pass → 6, değilse 12.
- `vip_impersonation`: From görünen adının `util.skeleton()` token'ları
  `vip_names.txt`'deki bir adın **tüm** token'larını içeriyor (≥ 2 kelime) ve
  From kayıtlı domaini `own_domains.txt`'de değil.
- `fake_reply_subject`: konu `re|ynt|yanit|cevap|aw|sv:` + `In-Reply-To` ve
  `References` yok; `.msg`/mapi hariç.

**Kurum koruması**: `build_context` `own_domains.txt`'deki her domaini
`brands` sözlüğüne ekler (anahtar = ilk etiket) → lookalike/combosquat/tld-swap
ve `brand_domain_spoof` kendiliğinden kurum domainini de korur. ctx anahtarları:
`own_domains` (set), `vip_names` (sıralı liste), `free_hosting` (set). İki
kurum dosyası **boş gelir**; boşken çıktı birebir eskisi gibidir.

## Veri dosyaları (`detector/data/`, kullanıcı düzenleyebilir)

Sözlükler **paket içinde** (wheel'e girer, `phishingtool` her dizinden bulur).
Çözümleme sırası `analyzer.resolve_data_dir()`: `--data-dir` argümanı >
`PHISHINGTOOL_DATA` ortam değişkeni > paket içi varsayılan. Eksik dosya = boş küme.

- `brands.txt` — `marka,domain1;domain2`
- `suspicious_tlds.txt`, `urgency_keywords.txt` (TR+EN)
- `trusted_domains.txt` — güvenilen gönderen allowlist'i
- `lure_words.txt` — combosquat tuzak kelimeleri (ctx `lure_words`); özel
  `--data-dir`'de yoksa `build_context` paket içi listeye düşer
- `free_hosting.txt` — ücretsiz barındırma/tünel/dinamik DNS sonekleri (ctx
  `free_hosting`); `lure_words` gibi paket içi listeye düşer
- `own_domains.txt` — kurumun kendi domainleri (boş gelir; doldurulunca marka
  gibi korunur) · `vip_names.txt` — satır başına AD SOYAD (boş gelir)

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
  var, bir sonraki değişiklik F1 ile doğrulanabilir. `bench` gösterge bazlı
  kırılım da verir (hangi sinyal ham'de ateşleniyor).
- **Yüksüz sosyal mühendislik + kurum koruması** — **DONE** (`checks/social.py`,
  `own_domains.txt`/`vip_names.txt`/`free_hosting.txt`; çevrimdışı).
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
  GUI önizleme, PDF rapor, `batch --html`.
- **Tehdit listeleri + domain yaşı** — **DONE** (`detector/feeds.py`,
  `detector/rdap.py`, `checks/threat_intel.py`; `feeds update|status`,
  `--feeds-dir`/`--no-feeds`). URLhaus anahtarsız **canlı denenmedi** (yalnız
  belgelenen `recent.csv` adresi + sahte yanıtla test). PhishTank / Google Safe
  Browsing yok.

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
- **Testler ağa çıkmaz ve bu makinenin listelerini görmez**: `tests/conftest.py`
  import anında `PHISHINGTOOL_FEEDS`'i var olmayan bir klasöre sabitler (modül
  düzeyindeki `CTX = build_context()` fixture'dan önce çalışır) ve autouse
  fixture `feeds._http_get` / `rdap._http_get`'i "çağrılırsa hata" ile değiştirir.
  `online=True` ile `analyzer.analyze` çağıran test canlı DNS de açar
  (`auth_verify`) — `tests/test_threat_intel.py`'deki `ages` fixture'ı gibi
  üç `auth_verify._*` fonksiyonunu kapat. Test domainlerinde `.example` kullanma:
  tldextract'te kayıtlı domain `example` çıkar, domain mantığı hiç çalışmaz.
- **Bu makinede tldextract kurulu, CI çekirdek işinde değil.** Yalnız yedek
  yolda (`util.registered_domain` son-iki-etiket) yaşayan hata yerelde hiç
  görünmez: `garantibbva.com.tr` → `com.tr` üç push boyunca CI'ı kırmızı tuttu.
  Yedek yol artık iki parçalı ülke soneklerini biliyor
  (`util._FALLBACK_SECOND_LEVEL` + `_TR`); `tests/test_domain_fallback.py`
  tldextract'i kendisi kapatıp sınar. Domain mantığına dokunan değişiklikten
  sonra opsiyonel paketsiz koşuyu da dene (`sys.modules["tldextract"] = None`
  yapıp `pytest.main()` çağıran tek satırlık betik yeter) ve push'tan sonra
  `gh run list --limit 1` ile CI'a bak.
