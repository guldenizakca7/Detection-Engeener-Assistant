# Web Dashboard

Detection Engineering Assistant'ın FastAPI + düz HTML/CSS/JS ile yazılmış web
arayüzü. React, Node.js veya herhangi bir build aracı kullanılmaz — `dashboard/static/`
altındaki `index.html` doğrudan tarayıcıya sunulur.

## Başlatma

```bash
cd <proje kök dizini>
pip install -r dashboard/requirements.txt
uvicorn dashboard.app:app --reload --port 8000
```

Ardından tarayıcıda [http://localhost:8000](http://localhost:8000) adresini açın.

`.env` dosyanızın (proje kökünde) `LLM_PROVIDER` ve ilgili model/API key
değişkenleriyle yapılandırılmış olması gerekir — dashboard, mevcut `src/`
pipeline'ını olduğu gibi kullanır, kendi LLM mantığını içermez.

## Ne Yapar?

- **Kural yaz** paneli: Kısa cümle girip tek bir MITRE tekniği için Sigma +
  8 SIEM formatında kural üretir (`src.pipeline.detect_mitre_technique` →
  `src.mitre.handle_validation` → `src.pipeline.generate_ir` →
  `src.rules.convert_ir`).
- **Rapor yükle** paneli: CTI raporu yapıştırıp birden fazla teknik için aynı
  anda kural üretir (`src.pipeline.extract_techniques_from_report` +
  `extract_context_for_technique`, teknik başına).
- **Geçmiş**: Son 20 üretim `dashboard/history.json` dosyasına kaydedilir ve
  sağ üstteki "Geçmiş" butonuyla görüntülenebilir.

## API

- `POST /api/generate` — `{"input": "...", "mode": "sentence" | "cti"}`
- `GET /api/history` — son 20 üretim özeti
- `GET /health` — `{"status": "ok", "llm_provider": "..."}`

## Bilinen Sınırlama

`src.mitre.handle_validation()`, benzerlik skoru `THRESHOLD_ASK` ile
`THRESHOLD_AUTO` arasında kaldığında (belirsiz eşleşme) kullanıcıya en yakın 3
adayı gösterip terminalden seçim ister (`ask_user_confirmation()`,
`console.input()` ile). Bu davranış CLI (`main.py`) için tasarlanmıştır ve
dashboard'dan **değiştirilmemiştir** (`src/` dosyalarına dokunulmadı). Web
üzerinden böyle belirsiz bir girdi gönderilirse istek, sunucunun kendi
terminalinde girdi bekleyerek asılı kalabilir veya (stdin yönlendirilmişse)
`EOFError` ile `500` hatası döner — tarayıcıda bir seçim ekranı **görünmez**.
Bunu önlemek için net, spesifik girdiler kullanın (örn. "PowerShell credential
dumping" gibi) ya da sunucuyu `uvicorn dashboard.app:app --reload --port 8000 < /dev/null`
şeklinde başlatarak asılı kalmak yerine hızlıca `500` almayı tercih edin.
