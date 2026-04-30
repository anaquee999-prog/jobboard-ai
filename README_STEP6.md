# STEP 6 — Government Job Scraper

เพิ่มไฟล์ `government_scraper.py` สำหรับนำเข้าข่าวงานราชการเข้า JobBoard

## วิธีทดสอบ

```bash
python government_scraper.py --demo
```

จากนั้นรันเว็บ แล้วเปิด:

```text
http://127.0.0.1:5006/jobs
```

หรือเข้า `/admin` แล้วกดปุ่ม:

```text
ดึงข่าวราชการ
```

ระบบจะนำเข้างานราชการ demo และกันข้อมูลซ้ำด้วย `source_url`

## Live Mode เบื้องต้น

```bash
python government_scraper.py --live
```

Live Mode ตอนนี้เป็นแค่ smoke test เชื่อมต่อเว็บราชการเบื้องต้น

## Production ต่อไป

- เพิ่ม Playwright extractor
- เพิ่ม OpenAI JSON extraction
- เพิ่ม GitHub Actions cron
- เปลี่ยน SQLite เป็น Supabase/PostgreSQL
- ตรวจ robots.txt และจำกัดความถี่ในการดึงข้อมูล
