# AKTOOL Core

نواة محلية لتنظيم معرفة ملفات ECU وبناء ملفات JSON. هذه النسخة تغطي المراحل 0 و1 و2 من وثيقة AKTOOL.

الهيكلة الكاملة (النواة، الذكاء الاصطناعي، السيرفر، البوت) في [docs/ARCHITECTURE_AR.md](docs/ARCHITECTURE_AR.md).

## ما يعمل الآن
- **JSON Schemas الأربعة** في `schemas/`: function_on_off، وfunction_map_table، وbosch_dtc، وnon_bosch_dtc، مع ترويسة مشتركة.
- **أمثلة** في `schemas/examples/`: 4 صحيحة و8 خاطئة، كل خاطئ يحمل رمز الخطأ المتوقع.
- **الفحص الحتمي**: Schema، والفحوص المنطقية (النطاق، الأطوال، أبعاد الخرائط، المحاور)، ومطابقة `original_bytes` مع ملف BIN الفعلي.
- **BIN Vault** غير قابل للتعديل: مسمّى بالـ SHA-256، كتابة ذرية، الملف الأصلي للقراءة فقط، ورفع نفس الملف مرتين لا يكرره.
- **قاعدة SQLite** (WAL، foreign keys) مع Alembic migrations تعمل تلقائياً عند التشغيل.
- **العلاقات** بين الملفات (Original/Modified/Variant...) مع منع الربط الذاتي والدوائر.
- **Audit log** لكل إنشاء وتعديل وربط.
- **JSON Factory**: سجلات بنسخ غير قابلة للتعديل (revision 1، 2، ...)، hash ثابت بعد التطبيع، تصدير بالتسمية القياسية للسجلات المعتمدة فقط بعد إعادة فحصها مقابل BIN، واستيراد مع معاينة يتعرف على السجل نفسه أو النسخة التالية أو التعارض.
- **وضعان**: `local` (على 127.0.0.1 بدون مفتاح) و`server` (يتطلب `X-API-Key`).

## التشغيل على Windows 11
```powershell
cd aktool
py -3.12 -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"
python -m pytest          # 59 اختباراً
python -m core            # http://127.0.0.1:8765/docs
```

وضع السيرفر:
```powershell
$env:AKTOOL_MODE="server"; $env:AKTOOL_API_KEY="ضع-مفتاحاً-طويلاً"; python -m core
```

متغيرات أخرى: `AKTOOL_DATA_DIR` (الافتراضي `data`)، `AKTOOL_PORT` (8765)، `AKTOOL_MAX_BIN_MB` (64).

## الـ API الحالي (`/docs` يعرضه تفاعلياً)
| Method | Endpoint | الغرض |
|---|---|---|
| GET | `/api/v1/health` | حالة النواة |
| POST | `/api/v1/firmware` | رفع BIN مع البيانات (multipart)، و`parent_firmware_id` لربط المعدّل بالأصل |
| GET | `/api/v1/firmware?q=` | بحث بالـ hash أو SW/CAL أو العائلة أو الاسم |
| GET / PATCH | `/api/v1/firmware/{id}` | التفاصيل والعلاقات، وتصحيح البيانات مع audit |
| POST | `/api/v1/firmware/{id}/relations` | ربط ملفين |
| GET | `/api/v1/firmware/{id}/bytes?offset=&length=` | قراءة مقطع (حتى 64 KB) |
| POST | `/api/v1/json/validate` | فحص سجل JSON، ومع `firmware_id` يُطابَق مع ملف BIN |
| GET / POST | `/api/v1/definitions` | بحث في السجلات، وإنشاء سجل جديد (revision 1) |
| GET | `/api/v1/definitions/{record_id}` | السجل وكل نسخه |
| POST | `/api/v1/definitions/{record_id}/revisions` | نسخة جديدة (يجب أن تكون التالية بالترتيب) |
| POST | `/api/v1/definitions/{record_id}/validate` | إعادة فحص نسخة مقابل Schema وBIN |
| POST | `/api/v1/exports/preview` و`/api/v1/exports` | معاينة ثم تصدير ملف JSON إلى `data/exports/` |
| POST | `/api/v1/json/import` | معاينة (`apply=false`) أو استيراد (`apply=true`) |

الأخطاء دائماً بالشكل `{"error": {"code", "message", "field", "details"}}` برموز ثابتة.

## ربط romHEX14 بالنواة
النواة تقدم نفس API السيرفر الذي يتصل به romHEX14 (`/v1/health` و`/v1/dtc/analyze` و`/v1/dtc/disable` و`/v1/features/detect` و`/v1/features/apply`)، فيعمل romHEX14 كما هو بدون تعديل:

1. شغّل النواة: `python -m core`.
2. في romHEX14 افتح Cloud Tools ثم Configure، وضع العنوان `http://127.0.0.1:8765`.
3. ضع أي قيمة في خانة Pro token (مثل `local`)، لأن romHEX14 لا يطلب الوظائف (features) بدونها.

القواعد:
- الإجابة فقط من السجلات `approved` أو `validated` المصنوعة لنفس الملف بالضبط (نفس SHA-256)، بعد إعادة فحص بايتاتها مقابل الملف المرسل. ملف غير معروف يعطي قائمة فارغة، لا تخميناً.
- آخر نسخة من السجل هي المعتمدة: إضافة نسخة `draft` أحدث تسحب السجل حتى تُعتمد.
- `disable` يكتب `proposed_bytes` من سجل DTC، و`apply` يكتب `on_bytes` أو `off_bytes` حسب `proposed_state` في سجل function_on_off. أي كود أو وظيفة بلا سجل معتمد يرفض الطلب كله (422).
- **الـ checksum**: افتراضياً (`AKTOOL_RX14_CHECKSUM=require`) لا يُعاد ملف معدّل إلا إذا وُجد مصحح checksum لعائلة الـ ECU في `core/checksum.py`، ولا يوجد أي مصحح حتى الآن. مع `AKTOOL_RX14_CHECKSUM=client` يُعاد الملف بدون تصحيح، ويجب تشغيل Correct Checksum في romHEX14 قبل الحفظ.
- كل ملف يُرسل يُحفظ في الـ Vault، والملف المعدّل يُحفظ كـ `modified` ومرتبط بالأصل (`modified_from`)، مع audit.
- في وضع السيرفر يوضع المفتاح في العنوان: `https://host/rx14/<API_KEY>`، لأن romHEX14 يرسل طلبات DTC بدون توكن.

## الملفات التجريبية
`fixtures/synthetic/synthetic_ecu.bin` ملف **اصطناعي** (ليس من ECU حقيقي)، يُعاد بناؤه مع الأمثلة بالأمر:
```
python -m fixtures.synthetic.build_fixtures
```
ملفات ECU الحقيقية للمجموعة الذهبية توضع في `fixtures/golden/` ولا تُرفع إلى مستودع عام.

## قواعد مهمة
- السجل `approved` أو `validated` لا يُحفظ إلا إذا كان ملف BIN الخاص به في الـ Vault وطابقت بايتاته.
- `draft` مسموح بدون BIN، لكنه لا يُصدَّر.
- التصدير لا يكتب فوق ملف مختلف بنفس الاسم.

## التالي
مراجعة: محرك التعرّف على الملفات المتشابهة (variant) حتى يجيب الـ API عن ملفات قريبة وليس المطابقة فقط، ومصححات checksum عبر plugins الخاصة بـ romHEX14.

المرحلة 3: قائمة المراجعة (Accept / Edit / Reject) والبحث النصي FTS5، ثم نقل `kp_parser` من ECU Expert JSON Builder كأول importer.
