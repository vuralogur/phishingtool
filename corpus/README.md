# Benchmark korpusu (yerel)

`python -m detector.cli bench corpus/` bu klasörü okur.

Gerçek e-postalar **repo'ya girmez** — `.gitignore` `corpus/**/*.eml`,
`corpus/**/*.msg` ve `corpus/labels.csv`'yi hariç tutar. Burada sadece düzeni
anlatan bu dosya ve `labels.example.csv` takip edilir.

## İki düzenden birini seç

**1) CSV etiketi** — dosyalar düz burada dursun:

```
corpus/
  labels.csv        # file,label
  mail1.eml
  mail2.eml
```

`labels.example.csv`'yi `labels.csv` olarak kopyalayıp doldur.

**2) Klasör etiketi** — CSV'siz:

```
corpus/
  phish/kotu1.eml
  ham/iyi1.eml
```

## Etiket yazımları

- phishing: `phish`, `phishing`, `spam`, `malicious`, `1`
- meşru: `ham`, `benign`, `legit`, `clean`, `0`

## İyi bir korpus

- **Meşru mail çoğunlukta olsun** (gerçek hayatta da öyle). Yanlış pozitif oranı
  ancak bol `ham` örneğiyle anlamlı ölçülür.
- Zor `ham` örnekleri koy: pazarlama bültenleri, şifre sıfırlama, fatura, kargo
  bildirimi — yani phishing'e *benzeyen* meşru mailler.
- Örnekleri **ham `.eml`** olarak kaydet (Outlook/Thunderbird "farklı kaydet"),
  ekran görüntüsü veya kopyalanmış metin değil; başlıklar olmadan SPF/DKIM/DMARC
  ölçülemez.
