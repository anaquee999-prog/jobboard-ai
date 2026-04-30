# STEP 9 — Auto Job Engine

ระบบนำเข้างานราชการ/งานสาธารณะอัตโนมัติแบบ MVP

## คำสั่งหลัก

```bash
python auto_job_engine.py --demo
```

หรือ

```bash
python run_auto_jobs.py
```

## Live Mode แบบปลอดภัย

```bash
python auto_job_engine.py --live
```

Live mode ตอนนี้เป็น safe fetch + fallback demo เพื่อป้องกันระบบล่มหากเว็บต้นทางเปลี่ยน

## ดูผล

รันเว็บ:

```bash
python app.py
```

เปิด:

```text
http://127.0.0.1:5000/jobs
```

## Admin

เข้า `/admin` แล้วกด:

```text
รัน Auto Job Engine
```

ดูประวัติได้ที่:

```text
/admin/import-runs
```

## ขั้น Production ต่อไป

- เพิ่ม Playwright extractor เฉพาะแต่ละเว็บ
- เพิ่ม OpenAI JSON extraction
- ตั้ง GitHub Actions cron ทุกวัน
- เปลี่ยน SQLite เป็น Supabase/PostgreSQL
- ตรวจ robots.txt และจำกัดความถี่ request
