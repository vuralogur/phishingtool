# Phishing E-posta Tespit / Analiz Aracı (savunma)

[![CI](https://github.com/vuralogur/phishingtool/actions/workflows/ci.yml/badge.svg)](https://github.com/vuralogur/phishingtool/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Bir e-postayı (`.eml` / `.msg` dosyası, ham metin veya stdin) alıp **phishing göstergelerini**
statik olarak analiz eden, **açıklanabilir bir risk skoru** veren komut satırı aracı.
Kara kutu değil: her puan tetiklenen bir kurala bağlıdır ve kanıtıyla listelenir.

> Bu bir **savunma** aracıdır. Hiçbir e-posta göndermez, hiçbir hesaba erişmez,
> hiçbir eki veya bağlantıyı **çalıştırmaz/açmaz**. Sadece verilen e-postayı okur.

## Kurulum

```bash
# Paket olarak kur -> her dizinden çalışan `phishingtool` komutu
pip install -e .

# İhtiyacına göre opsiyonel gruplar (hiçbiri şart değil):
pip install -e ".[cli]"     # rich tablo + tldextract
pip install -e ".[online]"  # --online: canlı SPF/DKIM/DMARC, WHOIS, itibar
pip install -e ".[deep]"    # Tier 2: oletools makro, OpenCV QR
pip install -e ".[gui]"     # masaüstü arayüz
pip install -e ".[dev]"     # pytest
```

Kurulum bile şart değil: çekirdek analiz **saf standart kütüphane**, depoyu
klonlayıp `python -m detector.cli ...` diye çalıştırabilirsin.

- `rich` → renkli tablo çıktısı (yoksa düz metin)
- `tldextract` → doğru registrable-domain (yoksa naif son-iki-etiket)
- `dnspython` / `python-whois` / `requests` → yalnızca `--online` modunda

Python 3.11+ (CI: 3.11 / 3.12 / 3.13 / 3.14, Linux + Windows).

## Kullanım

Kurulduysa `phishingtool ...`, kurulmadıysa `python -m detector.cli ...` — ikisi
aynı komut:

```bash
# Tek dosya
phishingtool analyze tests/samples/phish.eml
python -m detector.cli analyze tests/samples/phish.eml

# JSON çıktı (otomasyon için)
python -m detector.cli analyze tests/samples/phish.eml --json

# stdin'den ham e-posta
cat mail.eml | python -m detector.cli analyze -

# IOC listesi de ver (URL / domain / IP / e-posta / ek SHA256)
python -m detector.cli analyze mail.eml --iocs

# Mailin geçtiği sunucuları hop hop göster (Received zinciri, ağ kullanmaz)
python -m detector.cli analyze mail.eml --hops

# Outlook'tan sürüklenen .msg de aynı komut (ek bağımlılık yok)
python -m detector.cli analyze mail.msg

# Paylaşılabilir tek dosyalık HTML rapor (gömülü CSS; JS/dış kaynak yok)
python -m detector.cli analyze mail.eml --iocs --html rapor.html

# Bir klasördeki tüm .eml/.msg dosyaları (CSV özet)
python -m detector.cli batch tests/samples
python -m detector.cli batch klasor/ --verbose   # bozuk dosyalar için traceback

# Etiketli korpusa karşı doğruluk ölçümü (precision / recall / F1)
python -m detector.cli bench corpus/

# Ağ sorgularını aç (SPF/DMARC DNS, WHOIS, itibar API — opt-in)
python -m detector.cli analyze mail.eml --online

# Kendi ağırlık/eşiklerinle skorla (her komutta geçerli)
python -m detector.cli analyze mail.eml --config config.toml
```

`batch` CSV'sinin **son kolonu her zaman `error`**: bir dosya analiz edilemediyse
sebebi (`ValueError: ...`) orada yazar, aynı satır `stderr`'e de düşer ve komut
**exit 1** döner. Bozuk örnek sessizce taramadan düşmez — sebepsiz bir "error"
satırı, kimsenin göremediği bir yanlış negatiftir. `--verbose` tam traceback ekler.

## Masaüstü GUI (opsiyonel)

Komut satırı sevmiyorsan tıkla-kullan arayüz (CustomTkinter, koyu tema):

```bash
pip install customtkinter
python run_gui.py
```

- **Dosya Seç (.eml/.msg)** ile e-posta yükle veya ham metni kutuya **yapıştır**.
- Sonuç: renkli **verdict rozeti** (low→critical) + SPF/DKIM/DMARC + **skor kırılımı**
  (sert/yumuşak toplam, çarpan, verdict nedeni) + tek satırlık **Received özeti**
  (hop sayısı, köken IP, uyarılar) + severity renkli **gösterge kartları**
  (kanıt + açıklama).
- **Online** anahtarı DNS/WHOIS/itibar sorgularını açar; analiz arka planda çalışır,
  pencere donmaz.
- **JSON Kaydet** ile raporu dosyaya yaz (Received zinciri de içinde).

Motor (`detector/`) GUI'den bağımsızdır; CLI ve GUI aynı `analyzer` API'sini kullanır.

## IOC export — `--iocs`

Bir maili "kötü" diye işaretlemek işin yarısı; diğer yarısı **aynı saldırıyı bir
daha içeri almamak**. `--iocs` maildeki gözlemlenebilirleri blocklist / SIEM /
VirusTotal beslemesi olarak çıkarır:

```bash
python -m detector.cli analyze mail.eml --iocs           # rapor + IOC bloğu
python -m detector.cli analyze mail.eml --iocs --json    # ham değerler, otomasyon
python -m detector.cli batch klasor/ --iocs              # CSV'ye 4 kolon ekler
```

Çıkarılanlar:

- **URL** — anchor `href`'leri + form `action`, `img src`, `meta` refresh ve
  yönlendirme parametresi hedefleri
- **Domain** — hem tam host hem **kayıtlı domain** (`login.evil.tk` → `evil.tk`);
  biri altyapıyı, diğeri saldırganın aldığı domainin tamamını engeller
- **IP** — URL'deki IP-literal host + Received zincirindeki köken IP
  (özel/ayrılmış aralıklar atılır — blocklist'te işe yaramaz)
- **E-posta** — From / Reply-To / Return-Path
- **Ek** — dosya adı, MIME tipi, boyut, **SHA256** (VT'ye sorgu için hazır)

```
IOC listesi (defanged — tıklanamaz; ham değerler için --json):
  URL (2):
    hxxp://198[.]51[.]100[.]7/login
    hxxp://secure-verify[.]tk/paypal
  Ek (1):
    fatura.pdf.exe  ·  32 B  ·  application/octet-stream
      sha256=34b9348ecccb09747637e5bdaa744e48362a9e684b260766e49868f2e50cecab
```

İki kural:

- **Metin çıktısı defanged** (`hxxp://`, `[.]`, `[at]`) — bileti/mesajı okuyan
  kimse yanlışlıkla tıklamasın. **JSON ve CSV ham** değer taşır; tüketicisi makine.
- **Anchor metni IOC değildir.** `<a href="http://kotu.tk">https://www.paypal.com</a>`
  bağlantısında `paypal.com` **listeye girmez** — o, göze gösterilen isimdir;
  engellemek kurbanın kendi bankasını engellemek olurdu.

Hiçbir şey çözümlenmez, indirilmez, çalıştırılmaz — sadece ayrıştırılmış metin.

## Received hop tablosu — `--hops`

Bir mailin nereden geldiği tek satırda yazmaz: `Received` başlıkları mailin
geçtiği her sunucuyu yığın halinde taşır. `--hops` bu yığını **yolculuk sırasına**
çevirir (en eski hop = mailin internete girdiği yer) ve her hop için ne
duyurulduğunu, alıcı sunucunun ne gördüğünü yan yana koyar:

```bash
python -m detector.cli analyze mail.eml --hops           # rapor + hop tablosu
python -m detector.cli analyze mail.eml --hops --json    # yapısal, otomasyon
python -m detector.cli analyze mail.eml --hops --html rapor.html
```

```
Received zinciri — 2 hop (en eski önce):
  1. 2026-08-14 09:59:58 +0300
     kimden: mail.evil.tk  ·  ters ad: host9.bad.net  ·  45.146.164.110
     kime  : mx.example.com  ·  ESMTP
     ! duyurulan ad, alıcı sunucunun yazdığı ters ad ile uyuşmuyor
     ! şifresiz teslim (TLS yok)
  2. 2026-08-14 10:00:12 +0300  (+14 sn)
     kimden: mx.example.com  ·  ters ad: mx.example.com  ·  93.184.216.34
     kime  : imap.example.com  ·  ESMTPS (TLS)
  Not: yalnızca güvendiğiniz ilk sunucunun üstündeki hoplar güvenilirdir — alt
  hoplar gönderen tarafından uydurulmuş olabilir.
```

Hop başına çıkarılanlar: zaman damgası ve bir öncekine göre **gecikme**, duyurulan
ad (HELO iddiası), alıcının yazdığı **ters ad**, IP, hedef sunucu, protokol/TLS.
Uyarılar: `rdns_mismatch`, `private_ip`, `no_tls`, `big_delay`, `clock_skew`,
`unparsed` (okunamayan satır yine de gösterilir — sessizce düşmez).

Üç sınır:

- **DNS yok.** Karşılaştırılan ters ad, alıcı MTA'nın zaten başlığa yazdığı addır;
  bu tablo hiçbir şeyi çözümlemez, `--online` bile gerektirmez.
- **Skoru değiştirmez.** ATT&CK etiketi gibi saf metadata: verdict'i açıklar,
  belirlemez.
- **Kanıt, ispat değil.** Güven sınırının altındaki hoplar gönderen tarafından
  yazılmış olabilir; tablo bunu her seferinde söyler.

## MITRE ATT&CK etiketi

Her gösterge, tespit ettiği davranışın **ATT&CK teknik kimliğiyle** birlikte
raporlanır. `anchor_href_mismatch` bu araca özel bir slug; `T1566.002` ise SOC'un
kapsama haritasında, playbook'unda ve SIEM kuralında zaten kullandığı ortak dil —
rapor böylece doğrudan pivotlanabilir hale gelir.

```
23 gösterge:
  [HIGH    ] +20 anchor_href_mismatch (url)  ·  T1566.002
  ...

MITRE ATT&CK teknikleri (7):
  T1036.007  Masquerading: Double File Extension  —  double_extension
  T1566      Phishing  —  generic_greeting, urgency_language
  T1566.001  Phishing: Spearphishing Attachment  —  dangerous_attachment
  T1566.002  Phishing: Spearphishing Link  —  anchor_href_mismatch, ip_url
  T1583.001  Acquire Infrastructure: Domains  —  suspicious_tld
  T1598      Phishing for Information  —  credential_request
  T1656      Impersonation  —  brand_impersonation, dmarc_fail, spf_fail
```

`--json` çıktısında iki yerde görünür: her göstergede `technique` +
`technique_name`, ayrıca üst seviyede gruplanmış `techniques` listesi.

```json
"techniques": [
  {"id": "T1566.002", "name": "Phishing: Spearphishing Link",
   "url": "https://attack.mitre.org/techniques/T1566/002/",
   "indicators": ["anchor_href_mismatch", "ip_url"]}
]
```

Eşleme (`detector/mitre.py`) bilinçli olarak muhafazakâr:

- **Gösterge başına tek teknik** — en yakın eşleşme, "olabilecek her teknik"
  değil. Her phishing maili tepede zaten T1566'dır; bunu 50 göstergeye birden
  basmak hiçbir bilgi taşımaz.
- **Her şey eşlenmez.** `vt_flagged` üçüncü taraf verdict'i, `no_spf_record`
  taklit edilen domainin kendi hijyeni — ikisi de saldırganın *yaptığı* bir şey
  değil, o yüzden `NO_TECHNIQUE` kümesinde durur. "Bilerek eşlenmedi" ile
  "unutuldu" ayrımını bir **drift testi** korur: kaynakta eşlemesiz yeni bir
  gösterge belirirse test kırmızı yanar.

Etiketleme `Indicator.__post_init__` içinde yapılır; CLI, GUI, `bench` ve doğrudan
check çağrısı dahil her yol etiketi otomatik alır — atlanabilecek ayrı bir adım yok.
Skoru ve verdict'i **etkilemez**, saf metadata'dır.

## Doğruluk ölçümü — `bench`

Skorlama ayarı yaptığında "daha iyi mi oldu?" sorusunun tek dürüst cevabı sayıdır.
`bench` komutu etiketli bir korpusu baştan sona analiz edip **precision / recall /
F1** üretir ve **hangi dosyada yanıldığını** listeler.

```bash
python -m detector.cli bench corpus/                      # varsayılan eşik: medium
python -m detector.cli bench corpus/ --threshold high     # daha katı sayım
python -m detector.cli bench corpus/ --labels etiket.csv --json
```

Etiketler iki biçimden biriyle verilir:

```
corpus/labels.csv          corpus/
file,label                   phish/kotu1.eml
mail1.eml,phish              phish/kotu2.eml
mail2.eml,ham                ham/iyi1.eml
```

(`phish` yerine `phishing/spam/malicious/1`, `ham` yerine `benign/legit/clean/0`
de yazılabilir. Başlık satırı ve `#` yorumları atlanır.)

Çıktı:

```
Karisiklik matrisi (medium):
                 tahmin: phish   tahmin: ham
  gercek phish   TP=2           FN=0
  gercek ham     FP=0           TN=1

  precision 100.0%   recall 100.0%   F1 100.0%   FP orani 0.0%

Esik taramasi:
  esik       precision  recall     F1         FP
  medium     100.0%     100.0%     100.0%     0
  high       100.0%     100.0%     100.0%     0
  critical   100.0%     100.0%     100.0%     0
```

Ardından **gösterge kırılımı** gelir — her göstergenin kaç phishing ve kaç meşru
mailde ateşlendiği (mail başına bir kez sayılır, en çok meşru mail vuran üstte):

```
Gosterge kirilimi (kac mailde ateslendi; en cok ham vuran ustte):
  gosterge                      tur      phish          ham
  anchor_href_mismatch          sert     2 (100.0%)     0 (0.0%)
  credential_request            sert     2 (100.0%)     0 (0.0%)
  urgency_language              yumusak  2 (100.0%)     0 (0.0%)
  combosquat_domain             sert     1 (50.0%)      0 (0.0%)
  ...
```

Dört şey kazandırır:

- **Eşik taraması** — aynı koşuyu `medium/high/critical` için puanlar; eşiği
  tahminle değil ölçümle seçersin.
- **Gösterge kırılımı** — verdict metrikleri modelin *bir yerde* yanıldığını
  söyler, bu tablo *hangi sinyale* bakılacağını. Meşru mailde phishing kadar sık
  ateşlenen gösterge hiçbir ağırlıkta bilgi taşımaz; ham oranı yüksek **sert**
  gösterge yanlış pozitifin ilk aranacağı yerdir. `--json` çıktısında
  `indicators` listesi (`id`, `kind`, `phish`, `ham`, `phish_rate`, `ham_rate`).
- **Hata listesi** — her yanlış pozitif/negatif için dosya adı, verdict, skor ve
  **tetikleyen sert göstergeler**; düzeltilecek kuralı doğrudan gösterir.
- **Regresyon koruması** — ağırlık değiştirdikten sonra tekrar çalıştır; F1
  düştüyse değişiklik kötüdür.

`--online` burada da opt-in. Eksik dosyalar, etiketsiz `.eml`'ler ve
ayrıştırılamayan örnekler ayrı ayrı raporlanır (sessizce yutulmaz).
Ek bağımlılık gerekmez — ölçüm de rapor da saf standart kütüphane.

> Korpusundaki gerçek e-postaları **repo'ya commit'leme** — `.gitignore` zaten
> `corpus/**/*.eml` ve `corpus/labels.csv`'yi hariç tutar.

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
sinyal varsa (sert = 0) sonuç **low** kalır — tek istisna aşağıdaki taşıyıcı
sinyal yığınıdır (madde 6).

| Sert toplam | Verdict  |
|-------------|----------|
| 0 (yalnız yumuşak) | low (taşıyıcı yığını varsa medium) |
| 10–21       | medium   |
| 22–44       | high     |
| 45+         | critical |

**4. Tek kök neden, tek sayım.** SPF + DKIM + DMARC başarısızlığı üç ayrı kanıt
değil, tek bir olgudur ("gönderen From domaini adına doğrulanamadı") — DMARC
zaten diğer ikisinin özetidir, `--online` de aynı üçünü yeniden ölçer. Bu aile
sert toplama en fazla **20 puan** ekler (`[thresholds] auth_cap`): tek başına
`medium` eder, `high` için bağımsız bir kanıt daha gerekir. İçeriği temiz bir
liste/yönlendirme maili artık yalnız bu yüzden `high` olmaz. Tavan uygulandığında
kırılım satırı bunu yazar: `sert 20 (3 gösterge; auth ailesi 42→20)`.

**5. Doğrulanmış gönderende bağlama duyarlı iki gösterge.** `credential_request`
ve `from_replyto_mismatch` sert kalır ama gönderen DMARC pass ise tek başına
verdict taşıyamayacak ağırlığa iner (12→6, 10→5): şifre sıfırlama / tek
kullanımlık kod mailleri phishing ile aynı kelimeleri kullanır, destek
sistemleri de Reply-To'yu başka domaine yazar. Reply-To ücretsiz posta kutusuna
(gmail vb.) gidiyorsa indirim yoktur. Başka sert kanıtla birlikte yine toplanır.

**6. Taşıyıcı sinyal yığını.** Yumuşak sinyallerin tek başına `medium`
edebildiği tek yol. Yumuşak kümenin çoğu toplu postanın doğal gürültüsüdür:
aciliyet dili, genel hitap, tıklama tracker'ı, ESP alt alan adı, gizli ön
başlık. Kimlik doğrulama satırı olmadan kaydedilmiş meşru bir bülten bunlardan
sahte bir mail kadar puan toplar; bu yüzden toplam puan ikisini ayıramaz.
Aşağıdaki **taşıyıcı** sinyaller farklıdır — mailin nereye götürdüğünü ya da ne
taşıdığını anlatır ve sıradan posta altyapısı bunları üretmez:

`url_shortener`, `suspicious_tld`, `punycode_domain`, `at_in_url`,
`tld_swap_domain`, `free_hosting_url`, `brand_in_path`, `macro_document`,
`mime_extension_mismatch`, `content_extension_mismatch`, `archive_encrypted`,
`qr_code_url`,
`meta_refresh_redirect`, `base_tag_href`, `hidden_iframe`, `obfuscated_script`

Kural: gönderen **DMARC pass değilse** ve en az **2 farklı** taşıyıcı sinyal
toplam **15 puan** ediyorsa verdict `medium` olur (daha yukarı asla). Tek sinyal
yetmez: bültendeki bir `t.co` linki ya da şirket içi tek bir `.docm` `low`
kalır. Puan güven çarpanıyla ölçeklenir, yani kısmi doğrulanmış gönderende
(×0.6) daha uzun bir yığın gerekir. Rapor hangi sinyalleri saydığını yazar:

```
Verdict nedeni: sert kanıt yetersiz, ama taşıyıcı sinyaller üst üste (url_shortener, suspicious_tld = 16 puan) → medium
```

Eşikler `[thresholds] soft_stack_min` / `soft_stack` ile değişir;
`soft_stack_min = 0` kuralı kapatır. Kural **DMARC pass eden** saldırgan
domainini yakalamaz (SPF/DKIM/DMARC kurmak saldırgan için de kolaydır) — o
durumda yumuşak sinyaller eskisi gibi `low` kalır.

**Skor kırılımı raporda.** Puan düz toplam olmadığı için her rapor "bu sayı
nereden geldi, verdict'i ne belirledi" sorusunu iki satırda kapatır — düz
metinde, rich tablosunda, GUI'de ve `--json` çıktısında:

```
Skor kırılımı: sert 34 (3 gösterge) + yumuşak 18×0.3=5.4 (4 gösterge)  =  39/100
Verdict nedeni: sert toplam ≥ 22 → high  ·  auth=pass (yumuşak çarpan ×0.3)
```

`--json` çıktısında aynı veri `breakdown` nesnesidir: `hard`, `soft_raw`, `soft`,
`multiplier`, `auth_level`, `hard_count`, `soft_count`, `trusted`, `capped`
(puan 100'de kırpıldı mı), `reason` (verdict'i belirleyen kural anahtarı),
`auth_raw` / `auth_trimmed` (auth ailesi tavana takıldıysa ham toplam ve kırpılan
puan, aksi hâlde 0), `stack` / `stack_ids` (verdict'i taşıyıcı yığını belirlediyse
sayılan puan ve göstergeler, aksi hâlde 0 ve `[]`), `config` (ayar dosyası kullanıldıysa yolu + değişen bölümler, yoksa `null`).

**First-party bastırma:** link gönderenin kendi domainine aitse (kendi tıklama
tracker'ı) `anchor_href_mismatch`, `open_redirect`, `random_host` ateşlenmez.

**Allowlist:** `detector/data/trusted_domains.txt`'e yazılan domainler, mail
**doğrulanmış (DMARC pass)** ise ve sert saldırı izi yoksa **low**'a sabitlenir.

## Kontrol edilen göstergeler

**Başlık / kimlik doğrulama** — `spf_fail`/`spf_softfail`, `dkim_fail`, `dmarc_fail`,
`from_replyto_mismatch`, `from_returnpath_mismatch`, `display_name_spoof`,
`auth_claim_unverifiable`, `auth_results_conflict`, `auth_pass_unaligned`,
`brand_domain_spoof`, `brand_domain_unverified`, `multiple_from_headers`,
(online) `no_spf_record`.

**Birden fazla From:** RFC 5322 tek bir `From` başlığına izin verir. İki tane
ve **farklı adresli** ise doğrulamayı yapan sunucu birini, postayı gösteren
istemci diğerini okuyabilir — `multiple_from_headers` (sert). Aynı adresin iki
kez yazılması bulgu değildir; analiz ilk başlığa göre yapılır.

**Güven sınırı:** SPF/DKIM/DMARC sonucu **yalnızca en üstteki**
`Authentication-Results` başlığından okunur — başlıklar yukarı eklendiği için
alttakiler mail size ulaşmadan önce yazılmıştır, gönderenin kendi eklediği satır
da dahil. Alt satır daha iyi bir sonuç iddia ederse `auth_results_conflict` ile
raporlanır ama skora girmez (yönlendirilmiş mailde normaldir). Hiç `Received`
başlığı yokken gelen "pass" iddiası ise `auth_claim_unverifiable` üretir ve
**yumuşak sinyal indirimi verilmez**: o satırı damgalayan bir sunucu yok.
`Received-SPF` kendi dilbilgisiyle (`Pass (...)`) okunur.

**Hizalama:** `spf=pass` zarf domaininin, `dkim=pass` imzalayan domainin
doğrulandığını söyler — From adresinin değil. Herkes kendi domaini için ikisini
de geçirip From'a istediğini yazabilir. Bu yüzden en üst satırdaki `header.d`,
`smtp.mailfrom` ve `header.from` From domainiyle (kayıtlı domain düzeyinde)
karşılaştırılır. Tüm "pass"lar başka domain içinse `auth_pass_unaligned`
raporlanır ve **güven indirimi verilmez**. Hangi domain için olduğunu söylemeyen
yalın `spf=pass` şüpheden yararlanır.

**Marka domaini taklidi:** From adresi `brands.txt`'deki bir markanın **gerçek**
domainindeyse (`service@paypal.com`) ve alıcı sunucu o domain adına hizalı bir
pass yazmamışsa `brand_domain_spoof` (sert) üretilir — From satırını herkes
istediği gibi yazabilir. Dosyada hiç `Authentication-Results` yoksa yalnız
`brand_domain_unverified` notu çıkar (yumuşak; `--online` ile kesinleştirin).
Ücretsiz posta domainleri (gmail.com vb.) bu kontrolün dışındadır.

**URL / bağlantı** — `anchor_href_mismatch`, `ip_url`, `punycode_domain`,
`homograph_domain`, `at_in_url`, `url_shortener`, `suspicious_tld`,
`excessive_subdomains`, `lookalike_domain`, `tld_swap_domain` (yumuşak),
`free_hosting_url` (yumuşak).

`free_hosting_url`: link, herkesin dakikalar içinde ve kimlik göstermeden sayfa
açabildiği bir barındırma / tünel / dinamik DNS servisinin **alt alanında**
(`x.pages.dev`, `abc.ngrok-free.app`). Meşru küçük projeler de kullanır, bu
yüzden yumuşak ve taşıyıcı sinyaldir; gönderenin kendi domaini aynı adresse
ateşlenmez. Liste `free_hosting.txt` içinde.

Domain kontrolleri (lookalike, combosquat, subdomain'e gömülü marka, homoglyph,
şüpheli TLD) yalnız linklere değil **gönderenin kendi domainine** (From ve
Reply-To) de uygulanır: `noreply@paypa1.com` hiçbir link içermese de yakalanır.
Aynı domain hem gönderen hem link ise tek bulgu sayılır. `tld_swap_domain` aynı
adın başka uzantısını işaretler (`akbank.net`); ülke uzantıları (`amazon.co.uk`)
ve 4 harften kısa adlar hariçtir. Markanın kendi yan domaini de olabileceği için
yumuşaktır — sizin için kesinse `[soft_ids] remove = ["tld_swap_domain"]`.

Link, tarayıcının izlediği **her yazımla** toplanır — yalnız `<a href="http…">`
değil: `//host/yol`, başında boşluk olan href, `https:\\host`, `<area href>`,
`<form action>`, `<button formaction>`, `javascript:` içine gömülü URL ve metne
şemasız yazılmış adresler (`www.x.com`, `x.com/giris`). Çok parçalı mailde
**tüm** `text/html` ve `text/plain` parçaları okunur (istemci sonuncuyu gösterir;
yalnız ilkine bakmak, zararsız bir ilk parçanın arkasına saklanmaya izin verirdi).
`ip_url` IP'nin gizlenmiş yazımlarını da tanır: ondalık (`http://3232235777/`),
hex (`0xC0A80101`), sekizlik ve IPv6 — kanıt satırı gerçek adresi gösterir.

**İçerik** — `urgency_language`, `credential_request`, `brand_impersonation`,
`generic_greeting`. `brand_impersonation` görünen adı **gözün okuduğu hâliyle**
de karşılaştırır: Kiril/Yunan benzer harfler ("PаyPal"), sıfır-genişlik
karakterler ve tam-genişlik/matematiksel harfler Latin'e katlanır
(`util.skeleton`); böyle yazılmış ad kanıt satırında ayrıca belirtilir.

Anahtar kelimeler ham HTML'de **ve okuyucunun gördüğü metinde** aranır
(`util.visible_text`): `pass<span></span>word` ya da araya sıfır-genişlik
karakter konmuş `numa&#8203;ranızı` ham işaretlemede hiçbir kelime içermez, ekranda
ise düz okunur — tam da bu yüzden öyle yazılır.

**Sosyal mühendislik** (`checks/social.py`) — link de ek de taşımayan mailler.
"Yük" aranacak bir telefon numarası ya da uyulacak bir talimattır; diğer bütün
kontroller bir *şey* aradığı için bunlar bulgusuz geçiyordu. Kelime tek başına
kanıt değildir (dürüst fatura da telefon numarası yazar, dürüst müdür de ödeme
ister); her bulgu bir **birleşimdir**: ifade + talebin biçimi + göndereni kimin
doğruladığı.

- `callback_phishing` (sert) — geri-arama dolandırıcılığı: tutar + ücret/yenileme
  bildirimi + "iptal/iade için" + **yanında "arayın" yazan** bir telefon
  numarası; gönderen ücretsiz posta adresi ya da mail bir markayı anıp o markanın
  domaininden gelmiyor. Gönderen DMARC pass ise marka koşulu sayılmaz.
- `bec_request` (sert) — yönetici/iş ortağı taklidi (BEC): ödeme talebi
  ("havale", "wire transfer", "hediye kartı") + bahane ("toplantıdayım",
  "arayamam", "aramızda kalsın") + **kısa** not (≤ 1500 karakter) + gönderen
  ücretsiz posta adresi ya da Reply-To başka domain.
- `bank_change_request` (sert) — "banka/hesap bilgilerimiz değişti" bildirimi:
  fatura gerçektir, hesap numarası değildir. Doğrulanmamış gönderende 12,
  DMARC pass gönderende 6 puan (tek başına verdict taşıyamaz).
- `vip_impersonation` (sert) — görünen ad `vip_names.txt`'deki bir yöneticinin
  adı, adres `own_domains.txt`'deki kurum domainlerinin **dışında**
  ("Ahmet Yılmaz <ahmet.yilmaz.ofis@gmail.com>"). İki dosya da boş gelir;
  doldurulmadıkça kontrol hiçbir şey üretmez.
- `fake_reply_subject` (yumuşak) — konu `RE:` / `YNT:` ile başlıyor ama
  `In-Reply-To` / `References` yok: mail hiçbir mesaja yanıt değil. Bazı
  istemciler bu başlıkları siler; tek başına kanıt değildir.

**Kurum koruması:** `own_domains.txt`'e yazdığınız domainler bir marka gibi
korunur — benzeri gönderen/link domaini `lookalike_domain` / `combosquat_domain`
/ `tld_swap_domain`, kendi domaininizden geliyor görünen doğrulanmamış mail
`brand_domain_spoof` üretir. Dosya boşken hiçbir şey değişmez.

**Ek** — `dangerous_attachment`, `double_extension`, `macro_document`,
`archive_attachment`, `mime_extension_mismatch`, `disguised_executable`,
`content_extension_mismatch` (yumuşak).

- **İçerik imzası.** Dosya adını da MIME tipini de gönderen yazar; ilk baytları
  yazamaz. `disguised_executable` (sert): içerik PE/ELF/Mach-O/LNK ama ad
  çalıştırılabilir uzantı taşımıyor (`fatura.pdf`, adsız parça). 
  `content_extension_mismatch`: `.pdf` adlı HTML, `.jpg` adlı SVG, `.docx` adlı
  PDF gibi. Yalnız bayt karşılaştırması; hiçbir şey açılmaz. Tanınmayan içerik
  bulgu değildir; `.jpg` adlı PNG ve parola korumalı (OLE) `.docx` de değildir.
- **Uzantılar.** Tehlikeli liste posta sağlayıcılarının hiç teslim etmediği
  türlerle genişledi (`.one`, `.xll`, `.chm`, `.url`, `.iqy`, `.dll`, `.msix`,
  `.library-ms`…); arşivlere disk imajları (`.vhd`, `.vhdx`, `.cab`…), makro
  belgelerine `.xlsb`/`.ppam` vb. eklendi.
- **Dosya adı yazımı.** Uzantı, işletim sisteminin göreceği ada göre okunur:
  `fatura.exe.`, `fatura.exe ` ve içine sıfır-genişlik karakter konmuş adlar
  `.exe` sayılır.
- **Adı konmamış dosyalar.** Yalnız `Content-ID` ile gömülü resimler (QR'ın
  saklandığı yer), adsız `application/*` parçaları ve gövdesinin tamamı tek
  dosya olan mailler artık ek listesinde ve tüm ek kontrollerinden geçer.

**İtibar (online, opt-in)** — `vt_flagged` (VirusTotal, `VT_API_KEY` gerekir).

Her gösterge ayrıca bir **MITRE ATT&CK tekniğiyle** etiketlidir (`detector/mitre.py`).

**HTML adli (Tier 2)** — `form_external_action`, `html_password_input`,
`meta_refresh_redirect`, `hidden_iframe`, `base_tag_href`, `obfuscated_script`,
`hidden_text`, `active_content_link` (`javascript:` / `vbscript:` / `data:` linki;
`javascript:void(0)` gibi boş yer tutucular ve `data:image/…` sayılmaz).

**Ek derin statik (Tier 2)** — `html_smuggling`, `macro_detected`,
`macro_autoexec` (oletools), `pdf_active_content`, `pdf_launch_action`,
`pdf_embedded_file` (yumuşak). `macro_detected` için OLE dosyası olmak yetmez,
içinde VBA projesi (`_VBA_PROJECT`) bulunmalı. PDF'te `/JS`/`/JavaScript`
bulgudur; `/OpenAction` ve `/AA` tek başına raporlanmaz (sayfa/zoom ayarı da
böyle yapılır), betiğin yanında kanıt satırına eklenir.

HTML ve SVG ekler gövde gibi okunur (ek, tarayıcıda yerel dosya olarak açılan
bir sayfadır): `html_attachment_form` (parola alanı ya da dışarı gönderen form)
ve `html_attachment_script` (betikle yönlendirme, meta-refresh, gizlenmiş betik,
SVG içinde betik/olay işleyici). Dosya başına **tek** bulgu çıkar; form varsa o
raporlanır. Betiksiz HTML rapor ve düz SVG çizim bulgu üretmez.

**Kapsayıcı yapısı** (`detector/documents.py`) — ekin içine bakmadan görülemeyen
üç şey; hiçbiri için dosya çıkarılmaz ya da çalıştırılmaz:

- **ZIP dizini.** `archive_dangerous_member` (sert): arşivin dosya listesinde
  çalıştırılabilir/betik dosya ya da disk imajı (`fatura.zip` içinde
  `fatura.pdf.exe`). `archive_encrypted` (yumuşak): parola korumalı arşiv —
  ZIP şifrelemesi dosya adlarını gizlemez, ikisi birlikte de çıkabilir.
  `.docx`/`.odt` gibi "içi ZIP olan" belgeler arşiv sayılmaz.
- **Uzak şablon.** `remote_template` (sert): belge açıldığı an uzak adresten
  şablon/nesne yükleyen OOXML (template injection). Word'ün hemen her belgeye
  yazdığı yerel şablon yolu (`file:///C:/…/Normal.dotm`) bulgu değildir.
- **PDF nesne akışları.** PDF 1.5'ten beri bağlantılar ve `/JavaScript` adları
  sıkıştırılmış `/ObjStm` akışlarında durabilir; mevcut PDF kontrolleri artık
  oraya da bakar.

**Ek içindeki linkler.** PDF `/URI` bağlantıları, `.docx` köprüleri ve HTML/SVG
ekteki `href`/`form action` adresleri gövdedeki linklerle aynı URL
kontrollerinden geçer ve IOC listesine girer. Bulgu satırı adresin nereden
geldiğini yazar: `Ek 'fatura.pdf' icindeki link - paypa1.com ~ paypal.com`.

**QR / quishing (Tier 2)** — `qr_code_url`, `qr_suspicious_url`
(OpenCV veya pyzbar backend'i kuruluysa).

**URL derin (Tier 2)** — `open_redirect`, `combosquat_domain`,
`brand_in_subdomain`, `confusable_brand` (IDN homoglyph), `random_host` (DGA),
`brand_in_path` (yumuşak). `brand_in_path`: marka domaini başkasının host'unun
**yoluna** yazılmış (`evil.example/paypal.com/login`) — göz adreste `paypal.com`'u
bulur ve okumayı bırakır. Arşiv/önbellek servisleri de böyle adres ürettiği için
yumuşak ve taşıyıcı sinyaldir; sorgu dizgisi `open_redirect`'e bırakılır.
`combosquat_domain` "marka + **tuzak kelime**" arar (`paypal-secure`,
`garantibbva-destek`, `akbankgiris`); markanın kendi altyapısı (`googleapis`,
`amazonaws`, `paypalobjects`) ve içinde marka geçen sıradan kelimeler
(`pineapple`) tetiklemez. Kelimeler `lure_words.txt` içinde.

## Özelleştirme

Sözlükler `detector/data/` altında düz metin — kod değiştirmeden genişlet:

- `detector/data/brands.txt` — `marka,domain1;domain2` (taklit tespiti)
- `detector/data/suspicious_tlds.txt` — satır başına bir TLD
- `detector/data/urgency_keywords.txt` — satır başına bir kelime/ifade (TR + EN)
- `detector/data/trusted_domains.txt` — güvenilen gönderen allowlist'i
- `detector/data/lure_words.txt` — combosquat tuzak kelimeleri (login, secure,
  destek, giris…); `--data-dir` klasöründe yoksa paket içindeki liste kullanılır
- `detector/data/free_hosting.txt` — ücretsiz barındırma / tünel / dinamik DNS
  sonekleri (`pages.dev`, `ngrok-free.app`…); `--data-dir` klasöründe yoksa
  paket içindeki liste kullanılır
- `detector/data/own_domains.txt` — **kurumunuzun kendi domainleri** (boş gelir);
  doldurulunca marka gibi korunur
- `detector/data/vip_names.txt` — adına sahte mail atılması en olası kişiler,
  satır başına bir AD SOYAD (boş gelir; tek kelimelik satırlar yok sayılır)

Karşılaştırmalar **ASCII'ye katlanır** (`util.ascii_fold`): `str.lower()` "I"
harfini "ı"ya çeviremediği için "VAKIFBANK" yazan bir mail "vakıfbank" satırıyla
asla eşleşmezdi. Artık sözlüğü hangi yazımla yazarsanız yazın iki yönde de
eşleşir; büyük harfli Türkçe konu satırları da anahtar kelimeleri yakalar.
Konuşulan ad ile domain etiketi farklıysa iki satır yazın (`yurtiçi kargo` ve
`yurticikargo`). Anahtar kelimeler **alt dizi** olarak arandığı için ayırt edici
olmalı: `acil` değil `acilen`.

Sözlükler **paketin içinde** taşınır; böylece `phishingtool` komutu hangi
dizinden çalıştırılırsa çalıştırılsın onları bulur. Kurulu dosyalara dokunmadan
kendi kopyanı kullanmak için:

```bash
phishingtool analyze mail.eml --data-dir ./kendi-sozluklerim
export PHISHINGTOOL_DATA=/opt/phishingtool-data   # kalıcı alternatif
```

Öncelik sırası: `--data-dir` > `PHISHINGTOOL_DATA` > paket içi varsayılan.
Eksik dosya hata değil — o sözlük boş kabul edilir.

### Skorlama ayarları — `--config config.toml`

Ağırlıklar, eşikler ve sert/yumuşak ayrımı da kod değiştirmeden ayarlanabilir.
Bir bankanın SOC'u ile küçük bir işletmenin tolere ettiği yanlış-pozitif oranı
aynı değil; bu politika fork yerine bir dosyada yaşasın diye:

```bash
cp config.example.toml config.toml
phishingtool analyze mail.eml --config config.toml
export PHISHINGTOOL_CONFIG=/etc/phishingtool/config.toml   # kalıcı alternatif
```

```toml
[weights]                        # gösterge id -> puan (0..100)
urgency_language = 3             # aciliyet tonuna daha az puan

[thresholds]                     # sert alt toplam eşikleri
high = 30                        # medium <= high <= critical şartı var

[soft_multiplier]                # auth seviyesine göre yumuşak ölçek (0..1)
pass = 0.2

[soft_ids]                       # sert/yumuşak ayrımını taşı
remove = ["macro_document"]      # makrolu belgeyi sert kanıt say
```

Üç kural:

- **Opt-in** — bayrak/ortam değişkeni yoksa hiçbir şey okunmaz. Çalışma dizinindeki
  `config.toml` **otomatik bulunmaz**; sessizce herkesin skorunu değiştirmesin diye.
- **Sesli hata** — bilinmeyen bölüm/anahtar, bilinmeyen gösterge id'si, sırası
  bozuk eşik veya aralık dışı çarpan **exit 2** ile durur. Sessizce yok sayılan
  bir yazım hatası, bir ayar dosyası için en kötü sonuçtur.
- **Görünür** — yüklenen ayar rapora yazılır (`Ayar dosyası: … · değişen: eşikler`,
  `--json` içinde `breakdown.config`). Kimsenin yeniden üretemediği bir skor kalmaz.

Geçerli gösterge id'lerinin tam listesi `detector/mitre.py` içindedir. Tüm
seçenekler ve açıklamaları: [`config.example.toml`](config.example.toml).
Öncelik sırası: `--config` > `PHISHINGTOOL_CONFIG` > dahili model.

## Gizlilik ve güvenlik

- **Offline-first:** çekirdek analiz ağ kullanmaz. `--online` olmadan hiçbir
  DNS/WHOIS/API çağrısı yapılmaz.
- **İtibar sorgusu** (`--online` + `VT_API_KEY`) yalnızca **domain adlarını**
  VirusTotal'a gönderir; e-posta içeriği gönderilmez.
- Bağlantılar **hiçbir zaman ziyaret edilmez**; ekler **hiçbir zaman
  çalıştırılmaz, bir uygulamayla açılmaz, diske çıkarılmaz**. Kapsayıcıların
  yalnız **yapısı** bellekte ve boyut sınırıyla okunur: ZIP'in dosya listesi
  (üyeler çıkarılmaz), `.docx`/`.xlsx`'in ilişki dosyaları (`*.rels`), PDF'in
  nesne akışları. Hepsi tek modülde: `detector/documents.py`.
- Analiz edilen e-posta yerelde kalır.

## Testler

```bash
python -m pytest -q      # 707 test
```

Her push ve PR'da GitHub Actions bunları çalıştırır: **opsiyonel bağımlılık
kurulmadan** Python 3.11/3.12/3.13/3.14 (Linux) + 3.12 (Windows) — yeşil kalması
çekirdeğin gerçekten saf stdlib olduğunun kanıtı — artı extras'lı ikinci bir tur
(`rich`, `tldextract`, `oletools`, OpenCV) ve `phishingtool` komutunun duman testi.

## Mimari

```
detector/
  cli.py          # komut satırı (analyze / batch / bench, --iocs, --hops, --config)
  config.py       # opsiyonel TOML: ağırlık/eşik/yumuşak küme override'ı
  iocs.py         # IOC çıkarımı: URL/domain/IP/e-posta/ek SHA256 (+ defang)
  received.py     # Received zinciri -> hop listesi (gecikme, ters ad, TLS) — DNS yok
  analyzer.py     # orkestratör: parse -> tüm kontroller -> skor
  parser.py       # .eml / .msg / ham metin -> normalize ParsedEmail
  msg.py          # Outlook .msg (OLE2/CFB + MAPI) okuyucu — saf stdlib
  checks/         # headers, urls, content, social, attachments, html_forensics…
  indicators.py   # Indicator (kanıt birimi) + otomatik ATT&CK etiketi
  mitre.py        # gösterge -> MITRE ATT&CK tekniği eşlemesi
  scoring.py      # ağırlıklı, açıklanabilir skor -> verdict + skor kırılımı
  bench.py        # etiketli korpus -> precision / recall / F1 / hata listesi
  report.py       # rich tablo / düz metin / JSON çıktı
  html_report.py  # tek dosyalık HTML rapor (gömülü CSS, JS yok)
  reputation.py   # opsiyonel VirusTotal (online)
  data/           # sözlükler (paketle birlikte kurulur)
gui/              # CustomTkinter masaüstü arayüz
corpus/           # (opsiyonel, yerel) bench korpusu — gerçek mailler commit'lenmez
tests/            # pytest + örnek .eml dosyaları
config.example.toml        # skorlama ayarları şablonu (--config, opt-in)
pyproject.toml             # paket metadata + `phishingtool` konsol komutu
.github/workflows/ci.yml   # pytest matrisi (Linux/Windows, 3.11–3.14)
```

## Yol haritası (opsiyonel)

- Web UI (FastAPI): e-posta yapıştır/yükle → görsel rapor
- Ek itibar kaynakları (PhishTank, Google Safe Browsing)
- Redirect zinciri takibi (opt-in, sandboxed)

## Gelişmiş özellikler

### HTML rapor (`--html`)

```bash
python -m detector.cli analyze mail.eml --iocs --html rapor.html
```

Tek dosya: CSS gömülü, **JavaScript yok, dış kaynak yok** — raporu açmak hiçbir
istek yapmaz. İçerik terminaldekinin aynısı: verdict rozeti, skor kırılımı,
e-posta kimliği (gönderen/konu/tarih), gösterge tablosu, ATT&CK bloğu, `--hops`
verildiyse Received hop tablosu ve `--iocs` verildiyse IOC listesi.

Güvenlik kuralı: **maile ait hiçbir değer tıklanabilir değildir.** Konu, kanıt
ve IOC'ler kaçışlanmış düz metindir (IOC'ler ayrıca defanged); sayfadaki tek
bağlantı `attack.mitre.org` teknik sayfalarıdır. Raporu açan analist, incelediği
kimlik-hasadı sayfasına bir tık uzakta olmamalı.

`--json` ile birlikte kullanılabilir: bilgi satırı stderr'e gider, stdout geçerli
JSON kalır.

### Outlook `.msg` desteği

`.eml` ile aynı: `analyze`, `batch`, `bench` ve GUI dosyayı imzasından tanır
(`analyze mail.msg`). Okuyucu **saf standart kütüphane** (`detector/msg.py`):
OLE2/CFB kapsayıcısı ayrıştırılır, MAPI özellikleri ve ek baytları çıkarılır —
`extract_msg` gibi bir bağımlılık **gerekmez**, hiçbir şey çalıştırılmaz.

Outlook maili iki türlü kaydeder; rapor hangisi olduğunu **söyler**:

| Dosyanın durumu | Sonuç |
|---|---|
| İnternet başlıkları var (`PR_TRANSPORT_MESSAGE_HEADERS`) | Received / Authentication-Results / DKIM-Signature gerçek — bütün kontroller tam güçte |
| Başlıklar yok | Başlıklar MAPI alanlarından kurulur (gönderen, "adına" gönderen, alıcılar, konu, tarih). Kimlik, URL, içerik ve ek kontrolleri normal çalışır. SPF/DKIM/DMARC ve Received zinciri **dosyada hiç bulunmaz** → `msg_no_transport_headers` bilgi göstergesi çıkar: **0 puan**, verdict'i etkilemez ve "başarısız doğrulama" sayılmaz. Kaynak sunucu analizi gerekiyorsa maili `.eml` olarak dışa aktarın. |

### Gelişmiş kimlik doğrulama (Tier 1, `--online`)

Başlığı okumak yerine **doğrular**:
- **DKIM** imzasını kriptografik olarak doğrular (başlık yalan söylese de yakalar)
- **SPF**'i gönderen IP'ye karşı canlı değerlendirir
- **DMARC** politikasını çeker; politika `reject/quarantine` iken auth başarısızsa güçlü spoofing sinyali
- **Received/IP adli** (offline): özel-IP köken, eksik Received zinciri

Gerektirir: `pip install dkimpy pyspf dnspython`

### Saldırı vektörleri (Tier 2)

Statik derin analiz — bağlantı **hiçbir zaman ziyaret edilmez**, dosya **hiçbir
zaman çalıştırılmaz ya da diske çıkarılmaz**; içerik ve kapsayıcı yapısı bellekte
ayrıştırılır:

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

## Lisans

[MIT](LICENSE) — kullan, değiştir, dağıt; telif ve lisans notunu koru.
Yazılım "olduğu gibi" sunulur, garanti verilmez.

## Yazar

**vuralogur** — <vuralogr@gmail.com>
GitHub: https://github.com/vuralogur/phishingtool
