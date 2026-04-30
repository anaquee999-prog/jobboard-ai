from pathlib import Path
from PIL import Image, ImageDraw, ImageFont
import textwrap


BASE_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = BASE_DIR / "static" / "generated_jobs"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def load_font(size):
    font_paths = [
        "C:/Windows/Fonts/tahoma.ttf",
        "C:/Windows/Fonts/arial.ttf",
        "C:/Windows/Fonts/seguiemj.ttf",
    ]

    for font_path in font_paths:
        try:
            return ImageFont.truetype(font_path, size)
        except Exception:
            continue

    return ImageFont.load_default()


def draw_wrapped_text(draw, text, xy, font, fill, max_width, line_spacing=10):
    x, y = xy
    words = str(text or "").split()
    lines = []
    current_line = ""

    for word in words:
        test_line = f"{current_line} {word}".strip()

        bbox = draw.textbbox((0, 0), test_line, font=font)
        line_width = bbox[2] - bbox[0]

        if line_width <= max_width:
            current_line = test_line
        else:
            if current_line:
                lines.append(current_line)
            current_line = word

    if current_line:
        lines.append(current_line)

    for line in lines:
        draw.text((x, y), line, font=font, fill=fill)
        bbox = draw.textbbox((0, 0), line, font=font)
        y += (bbox[3] - bbox[1]) + line_spacing

    return y


def generate_job_graphic(job):
    job_id = job["id"]
    title = job["title"]
    company_name = job["company_name"] or "งานใกล้บ้าน.com"
    location = job["location"] or "ไม่ระบุพื้นที่"
    salary = job["salary_range"] or "ตามตกลง"
    risk_score = job["ai_risk_score"] if job["ai_risk_score"] is not None else 0

    width, height = 1200, 630
    image = Image.new("RGB", (width, height), "#0f172a")
    draw = ImageDraw.Draw(image)

    title_font = load_font(58)
    company_font = load_font(34)
    body_font = load_font(30)
    small_font = load_font(24)
    badge_font = load_font(26)

    draw.rounded_rectangle((50, 50, 1150, 580), radius=36, fill="#ffffff")

    draw.rounded_rectangle((85, 85, 360, 135), radius=25, fill="#2563eb")
    draw.text((115, 98), "ประกาศรับสมัครงาน", font=badge_font, fill="#ffffff")

    draw.rounded_rectangle((885, 85, 1115, 135), radius=25, fill="#16a34a")
    draw.text((925, 98), "AI ตรวจแล้ว", font=badge_font, fill="#ffffff")

    y = 175
    y = draw_wrapped_text(
        draw=draw,
        text=title,
        xy=(90, y),
        font=title_font,
        fill="#111827",
        max_width=1020,
        line_spacing=14,
    )

    y += 18
    draw.text((90, y), company_name, font=company_font, fill="#374151")
    y += 55

    draw.text((90, y), f"📍 {location}", font=body_font, fill="#111827")
    y += 45

    draw.text((90, y), f"💰 {salary}", font=body_font, fill="#111827")
    y += 50

    draw.line((90, y, 1110, y), fill="#e5e7eb", width=3)
    y += 30

    draw.text((90, y), "ปลอดภัยขึ้นด้วยระบบ AI Anti-Scam", font=small_font, fill="#475569")
    draw.text((90, y + 34), f"Risk Score: {risk_score}/100", font=small_font, fill="#475569")

    draw.rounded_rectangle((780, 470, 1115, 535), radius=28, fill="#f97316")
    draw.text((825, 488), "ดูรายละเอียด / สมัครงาน", font=badge_font, fill="#ffffff")

    filename = f"job_{job_id}.png"
    output_path = OUTPUT_DIR / filename
    image.save(output_path)

    return f"/static/generated_jobs/{filename}"