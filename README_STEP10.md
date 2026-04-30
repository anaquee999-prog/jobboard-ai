# STEP 10 — AI Scam Center

เพิ่มระบบตรวจจับประกาศงานเสี่ยงแบบ Rule-based AI Scanner

## คำสั่งรัน Scanner

```bash
python scam_engine.py
```

หรือ

```bash
python run_scam_scan.py
```

## ดูผลในเว็บ

รันเว็บ:

```bash
python app.py
```

เข้า:

```text
/admin/scam-center
```

แล้วกด:

```text
สแกนประกาศทั้งหมด
```

## สิ่งที่ระบบตรวจ

- โอนเงินก่อน
- ค่าประกันอุปกรณ์
- ค่าสมัคร / ค่ามัดจำ
- งานออนไลน์รายได้สูง
- ไม่ต้องสัมภาษณ์
- แอดไลน์ / ทักไลน์
- Trust Score ต่ำ
- Report count สูง

## ผลลัพธ์

- LOW → ACTIVE
- MEDIUM → PENDING_AI_REVIEW
- HIGH → REJECTED
