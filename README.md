# 🛡️ Detection Engineering Asistanı

Doğal dil veya CTI raporu girişinden otomatik detection kuralı üreten yapay zeka sistemi.

## Ne Yapar?

Kullanıcı saldırı senaryosunu yazar, sistem otomatik olarak üretir:
- **MITRE ATT&CK** teknik eşleştirmesi
- **Sigma** kuralı (evrensel format)
- **KQL** (Microsoft Sentinel)
- **SPL** (Splunk)
- **Elastic DSL**
- **Chronicle YARA-L**

## Örnek Kullanım

```
Girdi: "PowerShell ile credential dumping tespit etmek istiyorum"

Çıktı:
  ✓ MITRE: T1003.001 - LSASS Memory
  ✓ Sigma kuralı üretildi
  ✓ KQL sorgusu üretildi
  ✓ SPL sorgusu üretildi
```

## Kurulum

### Gereksinimler
- Python 3.10+
- Ollama (local GPU kullanımı için)
- 8GB+ RAM (7B model için), 16GB+ RAM (14B model için)

### Hızlı Başlangıç

```bash
# 1. Repoyu klonla
git clone https://github.com/kullanici/detection-engineering-assistant
cd detection-engineering-assistant

# 2. Kurulum scriptini çalıştır
chmod +x setup.sh
./setup.sh

# 3. .env dosyasını düzenle
cp .env.example .env
nano .env

# 4. Çalıştır
python main.py
```

### Model Seçenekleri

| Seçenek | Gereksinim | Açıklama |
|---|---|---|
| `ollama` | 10GB+ RAM | Local, tamamen offline |
| `groq` | İnternet + API key | Ücretsiz bulut, hızlı |

```bash
# .env ayarları
LLM_PROVIDER=ollama   # veya groq
GROQ_API_KEY=         # sadece groq için
```

## Mimari

```
Kullanıcı Girdisi (doğal dil veya CTI raporu)
    ↓
Aşama 1: LLM → MITRE Tespiti (Qwen2.5 Coder 14B)
    ↓
Validasyon: MITRE API + ChromaDB Semantic Search
    ↓
Aşama 2: LLM → IR Üretimi (Llama 3.3 70B)
    ↓
IR → Sigma Kuralı (deterministik Python kodu)
    ↓
pySigma → KQL / SPL / Elastic / Chronicle
```

## Kullanılan Teknolojiler

- **Qwen2.5 Coder 14B** — MITRE tespiti ve JSON üretimi
- **Llama 3.3 70B** — CTI raporu analizi ve IR üretimi
- **ChromaDB** — MITRE teknik vektör veritabanı
- **pySigma** — Sigma → SIEM dönüşümü
- **Ollama** — Local model çalıştırma
- **Groq API** — Bulut fallback

## Bilinen Davranışlar

Faz 8'de gerçek LLM çağrılarıyla yapılan uçtan uca testler sırasında gözlemlenen,
bilinmesi gereken davranışlar (detaylar için [tests/README.md](tests/README.md)):

- **`THRESHOLD_ASK=0.65` CTI raporları için fazla katı olabilir.** Gerçek, anlatı
  tarzında yazılmış CTI raporu paragrafları, `all-MiniLM-L6-v2` embedding modeliyle
  MITRE teknik açıklamalarına karşı genellikle 0.60-0.70 aralığında benzerlik skoru
  alır — teknik gerçekten metinde anlatılsa bile. Varsayılan eşikle
  `examples/cti_report.txt` çalıştırıldığında 3 teknikten sadece 1'i (T1003.001)
  tespit edilir; diğer ikisi (RDP ile yanal hareket, zamanlanmış görev kalıcılığı)
  eşiğin hemen altında kalır. CTI raporu işlerken `.env` içinde `THRESHOLD_ASK`
  değerini 0.60 civarına düşürmeyi değerlendirin — LLM konsolidasyon adımı zaten
  anlamsal aramanın getirdiği alakasız adayları eleyecektir.
- **Belirsiz girdiler doğru şekilde `NeedsMoreDetailError` tetikler.** Örneğin
  "detect suspicious activity" gibi çok genel bir girdi verildiğinde, Stage 1
  modeli bunu kendisi fark edip `mitre_technique_id: "None"` döndürür; bu da
  `handle_validation()`'ın kullanıcıdan daha fazla ayrıntı istemesine yol açar —
  hatalı bir teknik uydurmak yerine.
- **Türkçe girdi doğru çalışır.** Stage 1 modeli Türkçe girdiyi doğru şekilde
  işleyip doğru İngilizce `technique_id`/`technique_name` alanlarını döndürebiliyor
  (örn. "PowerShell ile kimlik bilgisi çalma tespiti" → `T1003.001`). Tek istisna:
  girdi/reasoning metniyle İngilizce MITRE açıklamaları arasında yapılan (tanılama
  amaçlı) çapraz-dilli benzerlik karşılaştırmaları düşük skor verebilir — bu, gerçek
  doğruluğu etkilemez çünkü teknik ID zaten doğrudan eşleşiyor.
- **`STAGE1_MODEL_GROQ` artık `llama-3.1-8b-instant` olmalı, `qwen-2.5-coder-32b-instruct`
  değil.** Bu model Groq'un güncel kataloğunda mevcut değil (404 hatası verir).
  Groq'ta gerçekten bulunan Qwen modeli (`qwen/qwen3.6-27b`) ise yanıtına her zaman
  bir `<think>...</think>` bloğu ekleyen bir "thinking" modelidir ve bu, JSON
  ayrıştırmasını bozar. `.env.example` ve `.env` bu düzeltmeyi zaten içeriyor.

## Örnek Çıktı

`src/rules/sigma.py`'nin kendi test bloğundan (`python -m src.rules.sigma`), kanonik
PowerShell/LSASS örneği için üretilen Sigma kuralı:

```yaml
title: PowerShell Credential Dumping
description: Detects LSASS memory access via PowerShell
status: experimental
references:
- https://attack.mitre.org/techniques/T1003/001
tags:
- attack.credential_access
- attack.t1003001
logsource:
  product: windows
  category: process_creation
  service: sysmon
detection:
  selection:
    Image|endswith:
    - \powershell.exe
    - \pwsh.exe
    CommandLine|contains:
    - sekurlsa
    - lsass
    - mimikatz
  condition: selection
falsepositives:
- Legitimate system administration tools
level: high
```

Aynı IR, `convert_ir()` ile KQL, SPL, Elastic DSL ve Chronicle YARA-L formatlarına da
deterministik olarak (LLM çağrısı olmadan) dönüştürülür. Daha fazla örnek girdi için
[examples/](examples/) klasörüne bakın.

## Testleri Çalıştırma

Uçtan uca testler `tests/` klasöründedir ve **gerçek LLM çağrıları** yapar (Ollama
veya Groq) — mock kullanılmaz. Kurulum adımları, her testin ne yaptığı ve gerçek
çalıştırmalardan alınan çıktı örnekleri için [tests/README.md](tests/README.md)
dosyasına bakın. Kısaca:

```bash
./setup.sh                                  # .venv, bağımlılıklar, MITRE verisi, vektör DB
# .env içinde LLM_PROVIDER ve gerekli anahtarı/modelleri ayarlayın
.venv/bin/python3 tests/test_short_sentence_en.py
.venv/bin/python3 tests/test_short_sentence_tr.py
.venv/bin/python3 tests/test_cti_report.py
.venv/bin/python3 tests/test_invalid_mitre.py < /dev/null
.venv/bin/python3 tests/test_ambiguous_input.py < /dev/null
```

Bir LLM sağlayıcısı yapılandırılmamışsa veya erişilemiyorsa, her test `SKIPPED: ...`
yazdırıp 0 koduyla çıkar; gerçek bir assertion hatası her zaman iz (traceback) ile
başarısız olur.

## Katkıda Bulunma

PR ve issue'lar memnuniyetle karşılanır.

## Lisans

MIT
