# 🛡️ Detection Engineering Asistanı

Doğal dil veya CTI raporu girişinden otomatik detection kuralı üreten yapay zeka sistemi.

## Ne Yapar?

Kullanıcı saldırı senaryosunu yazar, sistem otomatik olarak üretir:
- **MITRE ATT&CK** teknik eşleştirmesi
- Parent MITRE teknik girildiğinde (örn. `T1059`) tüm alt teknikler otomatik tespit edilip her biri için ayrı kural üretilir
- **9 SIEM formatı** desteği: Sigma, KQL, SPL, Elastic, CrowdStrike LogScale, Chronicle YARA-L, SentinelOne, Carbon Black, Grafana Loki
- SHA-256 tabanlı önbellekleme: tekrarlayan sorgular <10ms'de yanıtlanır, gereksiz LLM çağrıları ve token maliyeti önlenir
- PDF rapor yükleme desteği (dashboard üzerinden, `pdfplumber` ile metin çıkarımı)

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

7 LLM sağlayıcısından biri seçilebilir — detaylar için aşağıdaki
[Desteklenen LLM Sağlayıcıları](#desteklenen-llm-sağlayıcıları) tablosuna bakın.

```bash
# .env ayarları (örnek: Ollama)
LLM_PROVIDER=ollama   # veya: groq, openai, anthropic, gemini, mistral, together
```

### Dashboard'u Başlatma

Komut satırı yerine tarayıcı üzerinden kullanmak için:

```bash
pip install -r dashboard/requirements.txt
uvicorn dashboard.app:app --reload --port 8000
# Tarayıcıda: http://localhost:8000
```

Dashboard aynı `.env` yapılandırmasını ve `src/` pipeline'ını kullanır; ayrıca
PDF rapor yükleme ve son 20 üretimi gösteren bir geçmiş paneli sunar. Detaylar
için [dashboard/README.md](dashboard/README.md).

## Desteklenen LLM Sağlayıcıları

| Sağlayıcı | Env Var | Stage 1 Modeli | Stage 2 Modeli |
|---|---|---|---|
| Ollama (local) | `LLM_PROVIDER=ollama` | `qwen2.5-coder:14b` | `llama3.3:70b` |
| Groq (ücretsiz) | `LLM_PROVIDER=groq` | `llama-3.1-8b-instant` | `llama-3.3-70b-versatile` |
| OpenAI | `LLM_PROVIDER=openai` | `gpt-4o-mini` | `gpt-4o` |
| Anthropic | `LLM_PROVIDER=anthropic` | `claude-haiku-4-5-20251001` | `claude-sonnet-4-6` |
| Google Gemini | `LLM_PROVIDER=gemini` | `gemini-2.0-flash` | `gemini-1.5-pro` |
| Mistral AI | `LLM_PROVIDER=mistral` | `mistral-small-latest` | `mistral-large-latest` |
| Together AI | `LLM_PROVIDER=together` | `Qwen/Qwen2.5-Coder-32B-Instruct` | `meta-llama/Llama-3.3-70B-Instruct-Turbo` |

Her sağlayıcı `BaseLLM`'i uygular ve model adları ilgili `STAGE1_MODEL_*` /
`STAGE2_MODEL_*` ortam değişkenleriyle (yukarıdaki varsayılanlarla)
yapılandırılır — bkz. `.env.example`. Bulut sağlayıcıların SDK'ları
(`openai`, `anthropic`, `google-generativeai`, `mistralai`, `together`)
opsiyoneldir; yalnızca kullandığınız sağlayıcının paketini kurmanız yeterlidir
(bkz. `requirements.txt`'teki not — `mistralai`'yi `chromadb` ile birlikte
kurmak bilinen bir `opentelemetry` sürüm çakışması yaratabilir).

> ⚠️ `claude-sonnet-4-6` bu proje tarafından gerçek bir API çağrısıyla
> doğrulanamadı (gerçek API çağrısı yapılmadan uygulandı). Stage 2 için
> "model bulunamadı" hatası alırsanız güncel model ID için
> [Anthropic model dokümantasyonuna](https://docs.claude.com/en/docs/about-claude/models)
> bakıp `.env` içindeki `STAGE2_MODEL_ANTHROPIC` değerini güncelleyin.

## Mimari

```
Kullanıcı Girdisi (doğal dil veya CTI raporu)
    ↓
Aşama 1: LLM → MITRE Tespiti (Stage 1 modeli — 7 sağlayıcıdan biri)
    ↓
Validasyon: MITRE JSON + ChromaDB Semantic Search
    ↓
Parent teknik ise → alt teknikler otomatik eklenir (get_subtechniques)
    ↓
Aşama 2: LLM → IR Üretimi (Stage 2 modeli — 7 sağlayıcıdan biri)
    ↓
IR → Sigma Kuralı (deterministik Python kodu)
    ↓
pySigma → KQL / SPL / Elastic / Chronicle / CrowdStrike / Loki / SentinelOne / Carbon Black
```

## Kullanılan Teknolojiler

- **7 LLM sağlayıcısı** — Ollama, Groq, OpenAI, Anthropic (Claude), Google Gemini,
  Mistral AI, Together AI (bkz. [Desteklenen LLM Sağlayıcıları](#desteklenen-llm-sağlayıcıları))
- **ChromaDB** — MITRE teknik vektör veritabanı (`all-MiniLM-L6-v2` embedding)
- **pySigma** — Sigma → SIEM dönüşümü; kullanılan backend'ler:
  `microsoft365defender` (KQL), `splunk`, `elasticsearch`, `secops` (Chronicle),
  `crowdstrike`, `loki`, `sentinelone`, `carbonblack`
- **FastAPI dashboard** (`dashboard/app.py` + `dashboard/static/index.html`) —
  web arayüzü, REST API, ve `pdfplumber` ile PDF rapor yükleme desteği
- **SHA-256 girdi önbellekleme** (`src/pipeline/cache.py`) — tekrarlayan
  sorguları `data/cache/` altında JSON dosyaları olarak önbelleğe alır

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
- **`THRESHOLD_ASK=0.65` (varsayılan) CTI raporlarında fazla katı kalabilir.**
  Yukarıdaki bulgu gereği bu proje `examples/cti_report.txt` ile test ederken
  eşiği ~0.60'a düşürmenin yeterli olduğunu doğruladı; bu depodaki `.env` şu an
  daha da düşük bir değerle (`0.35`) çalışıyor, bu da daha fazla aday tekniği
  eşiğin üzerine çıkarır (LLM konsolidasyon adımı yine de alakasız adayları eler).
  Kendi CTI raporlarınızda az teknik tespit ediliyorsa bu değeri düşürmeyi deneyin.
- **SentinelOne backend'i bazı kural tiplerini desteklemiyor.** Yüklü
  `pysigma-backend-sentinelone` paketi kaynak kodu incelendiğinde: sayısal alan
  eşitliği ifadeleri için açıkça `NotImplementedError` fırlatıyor, ve pipeline'ı
  yalnızca `product: windows/linux/macos` için alan eşlemesi tanımlıyor —
  bu projenin IR şemasının izin verdiği `cloud`/`network` platformları için
  SentinelOne çıktısı eksik/boş kalabilir.
- **`mistralai` paketi `chromadb` ile birlikte kurulunca `opentelemetry` sürüm
  çakışması yaratabilir** ve `import chromadb`'i bozabilir (MITRE katmanı
  çalışmaz hale gelir). `pip` bu kombinasyonu hata vermeden kurar, sorunu ancak
  chromadb'yi import etmeye çalışınca fark edersiniz. Çözüm ve detaylar için
  `requirements.txt`'teki yoruma bakın.
- **`google-generativeai` paketi (Gemini sağlayıcısı) upstream'de deprecated,**
  ama hâlâ çalışıyor. Google bu paketin artık güncelleme almayacağını ve
  `google.genai` paketine geçilmesini öneriyor; çalışma zamanında bir
  `FutureWarning` görürsünüz.

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
