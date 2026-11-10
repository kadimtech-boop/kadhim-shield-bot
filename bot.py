import asyncio
import base64
import ipaddress
import logging
import os
import re
import socket
import sys
import time
from urllib.parse import unquote, urljoin, urlparse

import aiohttp
from aiohttp import web
import aiosqlite
from bs4 import BeautifulSoup
import cloudscraper

from aiogram import Bot, Dispatcher, F
from aiogram.enums import ParseMode
from aiogram.filters import Command, CommandStart
from aiogram.types import (
    FSInputFile,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    InlineQuery,
    InlineQueryResultArticle,
    InputTextMessageContent,
    Message,
)

# =====================================================================
# 1. إعدادات البوت والبيئة
# =====================================================================
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("CyberShield")

BOT_TOKEN = os.environ.get("BOT_TOKEN", "8978592122:AAHgCsvC5opgX-61suoA7e6Tck6GFeNHbto").strip()
PORT = int(os.environ.get("PORT", 8080))
DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cyber_shield_v7.db")

ADMIN_ID = int(os.environ.get("ADMIN_ID", "0"))
DEV_NAME = "Kadhim Zeyad"
DEV_INSTA = "https://www.instagram.com/_.vrr?psln=amM5NmZmNDN3YjEy"
BOT_USERNAME = "KadhimlinkBot"

# =====================================================================
# 2. درع الأمان ضد هجمات SSRF وحماية الشبكات الداخلية
# =====================================================================
BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),     # CGNAT
    ipaddress.ip_network("127.0.0.0/8"),      # Loopback
    ipaddress.ip_network("169.254.0.0/16"),    # Cloud Metadata (AWS, GCP, Azure, Render)
    ipaddress.ip_network("172.16.0.0/12"),     # Private LAN
    ipaddress.ip_network("192.168.0.0/16"),    # Private LAN
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

def is_safe_url(url: str) -> bool:
    """التحقق الصارم من الروابط لحماية خادم الاستضافة من هجمات SSRF"""
    try:
        parsed = urlparse(url)
        if parsed.scheme.lower() not in ("http", "https"):
            return False
        hostname = parsed.hostname
        if not hostname:
            return False
        if hostname.lower() in ("metadata.google.internal", "instance-data", "localhost"):
            return False

        addr_info = socket.getaddrinfo(hostname, None)
        for item in addr_info:
            ip = ipaddress.ip_address(item[4][0])
            for blocked in BLOCKED_NETWORKS:
                if ip in blocked or ip.is_private or ip.is_loopback or ip.is_reserved:
                    return False
        return True
    except Exception:
        return False

# =====================================================================
# 3. قاعدة البيانات غير المتزامنة (aiosqlite + WAL Mode)
# =====================================================================
class AsyncDatabase:
    def __init__(self, db_path=DB_FILE):
        self.db_path = db_path

    async def init(self):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("PRAGMA journal_mode=WAL;")
            await db.execute("""
                CREATE TABLE IF NOT EXISTS link_cache (
                    short_url TEXT PRIMARY KEY,
                    clean_url TEXT,
                    safety_status TEXT,
                    content_info TEXT,
                    hops_count INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            await db.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    user_id INTEGER PRIMARY KEY,
                    joined_at TEXT
                )
            """)
            await db.execute("""
                CREATE TABLE IF NOT EXISTS stats (
                    key TEXT PRIMARY KEY,
                    val INTEGER
                )
            """)
            for k in ["total_scans", "cache_hits", "threats_warned"]:
                await db.execute("INSERT OR IGNORE INTO stats VALUES (?, 0)", (k,))
            await db.commit()

    async def register_user(self, user_id: int):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("INSERT OR IGNORE INTO users VALUES (?, date('now'))", (user_id,))
            await db.commit()

    async def get_all_users(self):
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute("SELECT user_id FROM users") as cur:
                return [row[0] async for row in cur]

    async def get_cached(self, short_url: str):
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(
                "SELECT clean_url, safety_status, content_info, hops_count FROM link_cache WHERE short_url = ?",
                (short_url,)
            ) as cur:
                row = await cur.fetchone()
                if row:
                    await db.execute("UPDATE stats SET val = val + 1 WHERE key = 'cache_hits'")
                    await db.commit()
                    return {
                        "clean_url": row[0],
                        "safety_status": row[1],
                        "content_info": row[2],
                        "hops_count": row[3],
                        "cached": True
                    }
        return None

    async def save_result(self, short_url: str, clean_url: str, safety: str, info: str, hops: int, is_threat: bool):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "INSERT OR REPLACE INTO link_cache (short_url, clean_url, safety_status, content_info, hops_count) VALUES (?, ?, ?, ?, ?)",
                (short_url, clean_url, safety, info, hops)
            )
            await db.execute("UPDATE stats SET val = val + 1 WHERE key = 'total_scans'")
            if is_threat:
                await db.execute("UPDATE stats SET val = val + 1 WHERE key = 'threats_warned'")
            await db.commit()

    async def get_stats(self):
        async with aiosqlite.connect(self.db_path) as db:
            stats = {}
            async with db.execute("SELECT key, val FROM stats") as cur:
                async for row in cur:
                    stats[row[0]] = row[1]
            async with db.execute("SELECT COUNT(*) FROM link_cache") as cur:
                stats["saved_links"] = (await cur.fetchone())[0]
            async with db.execute("SELECT COUNT(*) FROM users") as cur:
                stats["total_users"] = (await cur.fetchone())[0]
            return stats

db = AsyncDatabase()

# =====================================================================
# 4. الرادار الأمني وفحص التواقيع الثنائية (Threat & Magic Bytes Radar)
# =====================================================================
class AsyncThreatAuditor:
    DANGEROUS_EXTS = (".apk", ".exe", ".msi", ".bat", ".scr", ".vbs", ".cmd", ".ps1", ".dex", ".iso")
    MAGIC_SIGNATURES = {
        b"MZ": "🚨 تطبيق تنفيذي مباشر لنظام ويندوز (.EXE/.DLL)",
        b"dex\n": "🚨 حزمة تطبيق أندرويد تنفيذية (.DEX)",
        b"\x7fELF": "🚨 ملف تنفيذي لأنظمة لينكس / أندرويد (ELF)"
    }
    TRUSTED_PLATFORMS = (
        "youtube.com", "youtu.be", "t.me", "telegram.me", "udemy.com", "coursera.org"
    )

    @classmethod
    async def audit_url(cls, session: aiohttp.ClientSession, target_url: str) -> dict:
        if not is_safe_url(target_url):
            return {
                "is_threat": True,
                "badge": "🚨 رابط محظور أمنياً (SSRF Attack Blocked)",
                "details": "تم إحباط محاولة مسح الشبكة الداخلية للسيرفر"
            }

        parsed = urlparse(target_url)
        path = unquote(parsed.path).lower()
        domain = parsed.netloc.lower()

        # فحص امتداد المسار
        if path.endswith(cls.DANGEROUS_EXTS):
            ext = os.path.splitext(path)[1]
            return {
                "is_threat": True,
                "badge": f"🚨 خطر شديد! ملف تنفيذي مباشر ({ext})",
                "details": f"تحذير: لا تقم بتثبيت هذا الملف على جهازك ({domain})"
            }

        # فحص الرؤوس والـ Magic Bytes (حد أقصى 2MB لمنع DoS)
        content_info = f"المنصة: {domain}"
        try:
            async with session.get(
                target_url,
                allow_redirects=False,
                timeout=aiohttp.ClientTimeout(total=8)
            ) as resp:
                ctype = resp.headers.get("Content-Type", "").lower()
                cdisp = resp.headers.get("Content-Disposition", "").lower()
                clength = resp.headers.get("Content-Length")

                size_str = f"{round(int(clength) / (1024 * 1024), 2)} MB" if clength and clength.isdigit() else "غير محدد"

                if any(ext in cdisp for ext in cls.DANGEROUS_EXTS) or "android.package-archive" in ctype or "x-msdownload" in ctype:
                    return {
                        "is_threat": True,
                        "badge": "🚨 تحذير: الرابط يحمّل تطبيقاً أو ملفاً ملغماً (.APK/.EXE)!",
                        "details": f"النوع: {ctype} | الحجم: {size_str}"
                    }

                first_bytes = await resp.content.read(16)
                for sig, threat_label in cls.MAGIC_SIGNATURES.items():
                    if first_bytes.startswith(sig):
                        return {
                            "is_threat": True,
                            "badge": threat_label,
                            "details": f"تم كشف البصمة الثنائية التنفيذية | الحجم: {size_str}"
                        }

                if clength:
                    content_info = f"المنصة: {domain} | الحجم: {size_str}"
        except Exception:
            pass

        if any(tp in domain for tp in cls.TRUSTED_PLATFORMS):
            return {
                "is_threat": False,
                "badge": "🟢 آمن وموثوق (منصة رسمية نظيفة)",
                "details": content_info
            }

        return {
            "is_threat": False,
            "badge": "🛡️ نظيف (تم فك وتطهير الطبقات الإعلانية بنجاح)",
            "details": content_info
        }

# =====================================================================
# 5. محرك التفكيك الذكي العميق (Cloudscraper + Referer Loopback Engine)
# =====================================================================
class AsyncBypassEngine:
    KNOWN_SHORTENERS = (
        "linkjust.com", "bit.ly", "tinyurl.com", "cuty.io", "exe.io", "ouo.io",
        "shrtfly.com", "clicksfly.com", "fc.lc", "za.gl", "t.co", "is.gd", "rebrand.ly"
    )

    @classmethod
    def is_shortener(cls, url: str) -> bool:
        domain = urlparse(url).netloc.lower().replace("www.", "")
        return any(s in domain for s in cls.KNOWN_SHORTENERS)

    @staticmethod
    def extract_hidden_links(html: str, current_domain: str):
        patterns = [
            r'atob\(["\']([A-Za-z0-9+/=]{12,})["\']\)',
            r'wpsafelink\s*=\s*["\']([A-Za-z0-9+/=]{12,})["\']',
            r'[?&](?:url|link|dest|target|go)=([A-Za-z0-9+/=%_-]{12,})',
            r'window\.location(?:\.href|\.replace)?\s*=?\s*\(?["\'](https?://[^"\']+)["\']\)?',
            r'content=["\']\d+;\s*url=(https?://[^"\']+)["\']'
        ]
        for pattern in patterns:
            for match in re.findall(pattern, html, re.I):
                candidate = unquote(match)
                if candidate.startswith("http") and current_domain not in candidate:
                    return candidate
                try:
                    decoded = base64.b64decode(candidate).decode("utf-8", errors="ignore")
                    if decoded.startswith("http") and current_domain not in decoded:
                        return decoded
                except Exception:
                    continue
        return None

    @classmethod
    def get_stealth_session(cls):
        try:
            from curl_cffi import requests as cffi_requests
            return cffi_requests.Session(impersonate="chrome124")
        except Exception:
            import cloudscraper
            return cloudscraper.create_scraper(browser={"browser": "chrome", "platform": "windows", "desktop": True})

    @classmethod
    def sync_single_hop(cls, url: str, session):
        parsed_orig = urlparse(url)
        base_domain = f"{parsed_orig.scheme}://{parsed_orig.netloc}"

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9,ar;q=0.8"
        }

        r1 = session.get(url, headers=headers, allow_redirects=True, timeout=20)
        current_url = str(r1.url)
        html = r1.text

        # كشف المدونة الوسيطة (AdLinkFly Intermediary Blog مثل primepropertynow.com)
        if parsed_orig.netloc not in urlparse(current_url).netloc:
            if "viewarticle=" in current_url.lower() or "wpsafelink" in html.lower() or "linkjust" in html.lower():
                inter_blog = urlparse(current_url).netloc
                inter_origin = f"{urlparse(current_url).scheme}://{inter_blog}/"
                headers["Referer"] = inter_origin
                r1 = session.get(url, headers=headers, allow_redirects=True, timeout=20)
                html = r1.text
                current_url = str(r1.url)
            else:
                return current_url

        soup = BeautifulSoup(html, "html.parser")
        go_form = soup.find("form", {"id": "go-link"})
        if not go_form:
            headers["Referer"] = base_domain + "/"
            r2 = session.get(url, headers=headers, allow_redirects=True, timeout=20)
            if "go-link" in r2.text:
                html = r2.text
                soup = BeautifulSoup(html, "html.parser")
                go_form = soup.find("form", {"id": "go-link"})

        if go_form:
            action = go_form.get("action") or "/links/go"
            post_url = urljoin(base_domain, action)
            payload = {inp.get("name"): inp.get("value", "") for inp in go_form.find_all("input") if inp.get("name")}

            time.sleep(6)

            ajax_headers = {
                "X-Requested-With": "XMLHttpRequest",
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                "Accept": "application/json, text/javascript, */*; q=0.01",
                "Origin": base_domain,
                "Referer": current_url
            }
            res = session.post(post_url, data=payload, headers=ajax_headers, timeout=20)
            try:
                js = res.json()
                if js.get("url"):
                    return js["url"]
            except Exception:
                pass

        extracted = cls.extract_hidden_links(html, parsed_orig.netloc)
        if extracted:
            return extracted

        return current_url if current_url != url else None

    @classmethod
    def sync_resolve_deep(cls, initial_url: str, max_hops: int = 4):
        session = cls.get_stealth_session()
        current_target = initial_url
        hops = 0

        for hop in range(1, max_hops + 1):
            hops = hop
            next_url = cls.sync_single_hop(current_target, session)
            if not next_url or next_url == current_target:
                break
            current_target = next_url
            if not cls.is_shortener(current_target):
                break

        return current_target, hops

    @classmethod
    async def resolve_deep(cls, initial_url: str, session: aiohttp.ClientSession, max_hops: int = 4):
        start_time = time.time()

        if not is_safe_url(initial_url):
            return {
                "status": "error",
                "message": "رابط محظور أمنياً: يشير إلى عنوان شبكة محلية أو سحابية غير مسموحة."
            }

        cached = await db.get_cached(initial_url)
        if cached:
            elapsed = round(time.time() - start_time, 3)
            return {
                "status": "success",
                "url": cached["clean_url"],
                "safety_badge": cached["safety_status"],
                "content_info": cached["content_info"],
                "hops": f"{cached['hops_count']} (استرجاع فوري من الكاش ⚡)",
                "elapsed": f"{elapsed} ثانية"
            }

        # تشغيل التفكيك العميق في خيط منفصل لتفادي تجميد حلقة الأحداث وبدون الحظر من Cloudflare
        debug_err = None
        try:
            current_target, hops = await asyncio.to_thread(cls.sync_resolve_deep, initial_url, max_hops)
        except Exception as e:
            logger.error(f"Error during deep bypass: {e}")
            debug_err = str(e)
            current_target, hops = None, 0

        if current_target and current_target != initial_url:
            audit = await AsyncThreatAuditor.audit_url(session, current_target)
            await db.save_result(initial_url, current_target, audit["badge"], audit["details"], hops, audit["is_threat"])
            elapsed = round(time.time() - start_time, 2)
            return {
                "status": "success",
                "url": current_target,
                "safety_badge": audit["badge"],
                "content_info": audit["details"],
                "hops": f"تم تفكيك {hops} طبقة حماية",
                "elapsed": f"{elapsed} ثانية"
            }

        err_msg = "تعذر كسر الرابط تلقائياً (قد يتطلب حل Captcha صورية معقدة أو أن الرابط غير صالح)."
        if debug_err:
            err_msg += f"\nالتفاصيل: `{debug_err}`"

        return {
            "status": "error",
            "message": err_msg
        }

# =====================================================================
# 6. واجهة البوت التفاعلية في تيليجرام (Aiogram 3.x)
# =====================================================================
bot = Bot(token=BOT_TOKEN, default=None)
dp = Dispatcher()
USER_LAST_ACTION = {}

def build_keyboard(clean_urls=None):
    buttons = []
    if clean_urls:
        for idx, u in enumerate(clean_urls, 1):
            label = "🚀 فتح الرابط النظيف والآمن" if len(clean_urls) == 1 else f"🚀 فتح الرابط النظيف ({idx})"
            buttons.append([InlineKeyboardButton(text=label, url=u)])
    buttons.append([
        InlineKeyboardButton(text=f"👑 المطور: {DEV_NAME}", url=DEV_INSTA),
        InlineKeyboardButton(text="📊 إحصائيات الدرع", callback_data="show_stats")
    ])
    return InlineKeyboardMarkup(inline_keyboard=buttons)

@dp.message(CommandStart())
async def cmd_start(message: Message):
    await db.register_user(message.from_user.id)
    text = (
        f"⚡ **مرحباً بك في {DEV_NAME} Cyber Shield v7.0**\n"
        f"━━━━━━━━━━━━━━━━━━━━━━\n"
        f"المنظومة الأقوى عالمياً لتفكيك سلاسل الروابط المختصرة والملغمة وتخطي الإعلانات الخبيثة تلقائياً.\n\n"
        f"🔥 **المميزات الخارقة:**\n"
        f"• 🚀 **تفكيك متعدد الطبقات:** كسر حتى 4 روابط مختصرة متداخلة.\n"
        f"• 🛡️ **فحص أمني متقدم:** رصد الملفات التنفيذية وحزم أندرويد (.apk / .exe).\n"
        f"• ⚡ **محرك غير متزامن فائق السرعة:** يعمل 24/7 دون أي توقف أو تجمد.\n"
        f"• 🔍 **دعم Inline:** جرب كتابة `@{BOT_USERNAME}` في أي محادثة ثم ضع الرابط!\n\n"
        f"🔗 **أرسل أي رابط الآن أو وجّه منشوراً لتنظيفه فوراً!**\n"
        f"━━━━━━━━━━━━━━━━━━━━━━\n"
        f"👨‍💻 *Architected by:* **{DEV_NAME}**"
    )
    await message.reply(text, parse_mode=ParseMode.MARKDOWN, reply_markup=build_keyboard())

@dp.message(Command("stats"))
async def cmd_stats(message: Message):
    st = await db.get_stats()
    text = (
        f"📊 **إحصائيات منظومة {DEV_NAME} Cyber Shield:**\n"
        f"━━━━━━━━━━━━━━━━━━━━━━\n"
        f"👥 المستخدمون المسجلون: `{st.get('total_users', 0)}`\n"
        f"🔍 إجمالي عمليات الفحص: `{st.get('total_scans', 0)}`\n"
        f"⚡ استرجاع فوري من الكاش: `{st.get('cache_hits', 0)}`\n"
        f"💾 روابط مخزنة بالقاعدة: `{st.get('saved_links', 0)}`\n"
        f"🚨 تهديدات تم إحباطها: `{st.get('threats_warned', 0)}`"
    )
    await message.reply(text, parse_mode=ParseMode.MARKDOWN)

@dp.callback_query(F.data == "show_stats")
async def cb_stats(call):
    st = await db.get_stats()
    alert_text = (
        f"📊 إحصائيات منظومة {DEV_NAME} v7.0:\n"
        f"👥 المستخدمون: {st.get('total_users', 0)}\n"
        f"🔍 إجمالي الفحوصات: {st.get('total_scans', 0)}\n"
        f"⚡ من الكاش السريع: {st.get('cache_hits', 0)}\n"
        f"💾 الروابط المخزنة: {st.get('saved_links', 0)}\n"
        f"🚨 التهديدات المكتشفة: {st.get('threats_warned', 0)}"
    )
    await call.answer(alert_text, show_alert=True)

@dp.message(Command("broadcast"))
async def cmd_broadcast(message: Message):
    if ADMIN_ID and message.from_user.id != ADMIN_ID:
        return
    text_to_send = message.text.replace("/broadcast", "", 1).strip()
    if not text_to_send:
        await message.reply("⚠️ استخدم الأمر هكذا:\n`/broadcast رسالتك هنا`", parse_mode=ParseMode.MARKDOWN)
        return

    users = await db.get_all_users()
    sent_count = 0
    for uid in users:
        try:
            await bot.send_message(uid, text_to_send, parse_mode=ParseMode.MARKDOWN)
            sent_count += 1
            await asyncio.sleep(0.05)
        except Exception:
            pass
    await message.reply(f"📢 **تم إرسال الإذاعة إلى ({sent_count}/{len(users)}) مستخدم بنجاح!**", parse_mode=ParseMode.MARKDOWN)

@dp.message(Command("backup"))
async def cmd_backup(message: Message):
    if ADMIN_ID and message.from_user.id != ADMIN_ID:
        return
    if os.path.exists(DB_FILE):
        await message.reply_document(
            document=FSInputFile(DB_FILE),
            caption=f"💾 **نسخة احتياطية لقاعدة بيانات {DEV_NAME} Cyber Shield**"
        )
    else:
        await message.reply("⚠️ ملف قاعدة البيانات غير موجود بعد.")

@dp.message(F.text | F.caption)
async def handle_incoming_links(message: Message):
    user_id = message.from_user.id
    await db.register_user(user_id)

    # حماية من الإغراق والتكرار (3 ثوانٍ)
    now = time.time()
    if now - USER_LAST_ACTION.get(user_id, 0) < 3.0:
        await message.reply("⏳ يرجى الانتظار بضع ثوانٍ قبل إرسال طلب جديد.")
        return
    USER_LAST_ACTION[user_id] = now

    text = message.text or message.caption or ""
    # استخراج الروابط المباشرة والروابط المخفية
    found_urls = re.findall(r"https?://[^\s<>\"]+", text)
    entities = (message.entities or []) + (message.caption_entities or [])
    for ent in entities:
        if ent.type == "text_link" and ent.url:
            found_urls.append(ent.url)

    urls = list(dict.fromkeys(found_urls))[:3]
    if not urls:
        if message.chat.type == "private":
            await message.reply("⚠️ لم يتم العثور على أي رابط! أرسل رابطاً يبدأ بـ `https://` لتطهيره.")
        return

    wait_msg = await message.reply("🛰️ **جاري تفكيك وفحص الروابط بالرادار الاستباقي...**", parse_mode=ParseMode.MARKDOWN)

    reports = []
    clean_buttons = []

    async with aiohttp.ClientSession() as session:
        tasks = [AsyncBypassEngine.resolve_deep(target, session) for target in urls]
        results = await asyncio.gather(*tasks)

        for idx, (target, res) in enumerate(zip(urls, results), 1):
            prefix = f"🔹 **[رابط {idx}/{len(urls)}]** " if len(urls) > 1 else ""
            if res["status"] == "success":
                clean_buttons.append(res["url"])
                reports.append(
                    f"✅ {prefix}**تم التطهير بنجاح!**\n"
                    f"🔗 **الهدف:** `{res['url']}`\n"
                    f"🛡️ **الأمان:** {res['safety_badge']}\n"
                    f"📦 **الوجهة:** `{res['content_info']}`\n"
                    f"⛓️ **المسار:** `{res['hops']}` | ⏱️ `{res['elapsed']}`"
                )
            else:
                reports.append(f"❌ {prefix}**تعذر الفك:** `{target}`\nالسبب: {res['message']}")

    final_text = (
        f"🛡️ **تقرير الفحص الأمني الشامل - {DEV_NAME}**\n"
        f"━━━━━━━━━━━━━━━━━━━━━━\n"
        + "\n━━━━━━━━━━━━━━━━━━━━━━\n".join(reports) +
        f"\n━━━━━━━━━━━━━━━━━━━━━━\n"
        f"👑 **حقوق البرمجة والتطوير:** [{DEV_NAME}]({DEV_INSTA})"
    )

    try:
        await wait_msg.edit_text(
            final_text,
            parse_mode=ParseMode.MARKDOWN,
            disable_web_page_preview=True,
            reply_markup=build_keyboard(clean_buttons)
        )
    except Exception as e:
        logger.error(f"Error editing message: {e}")

@dp.inline_query()
async def inline_query_handler(query: InlineQuery):
    url = query.query.strip()
    if not url.startswith("http"):
        return

    async with aiohttp.ClientSession() as session:
        res = await AsyncBypassEngine.resolve_deep(url, session)

    if res["status"] == "success":
        clean = res["url"]
        result_item = InlineQueryResultArticle(
            id="1",
            title="🚀 اضغط لإرسال الرابط النظيف",
            description=clean,
            input_message_content=InputTextMessageContent(
                message_text=(
                    f"🛡️ **تم تطهير الرابط بنجاح!**\n\n"
                    f"🔗 **الرابط النظيف:** {clean}\n"
                    f"🛡️ **الحالة:** {res['safety_badge']}\n\n"
                    f"👑 *بواسطة @{BOT_USERNAME}*"
                ),
                parse_mode=ParseMode.MARKDOWN,
                disable_web_page_preview=False
            )
        )
        await query.answer([result_item], cache_time=120)

# =====================================================================
# 7. خادم الويب للإنتاج والبقاء نشطاً 24/7 (Keep-Alive Health Endpoint)
# =====================================================================
async def web_health_handler(request):
    return web.Response(
        text=f"""<!DOCTYPE html>
<html>
<head><title>{DEV_NAME} Cyber Shield</title><meta charset='utf-8'></head>
<body style='background:#0f172a;color:#38bdf8;font-family:sans-serif;text-align:center;padding:50px;'>
  <h1>🛡️ {DEV_NAME} Cyber Shield v7.0 is ACTIVE 24/7</h1>
  <p style='color:#94a3b8;'>Telegram Bot: <a style='color:#4ade80;' href='https://t.me/{BOT_USERNAME}'>@{BOT_USERNAME}</a></p>
  <p style='color:#a855f7;'>Engine: Aiogram 3.x Non-blocking Async Event Loop</p>
</body>
</html>""",
        content_type="text/html"
    )

async def web_debug_bypass(request):
    test_url = request.query.get("url", "https://linkjust.com/YiS")
    logs = []
    def log(msg): logs.append(str(msg))

    try:
        session = AsyncBypassEngine.get_stealth_session()
        log(f"Session type: {type(session)}")

        r1 = session.get(test_url, allow_redirects=True, timeout=20)
        current_url = str(r1.url)
        log(f"R1: status={r1.status_code}, url={current_url}")
        log(f"R1 text sample: {r1.text[:300]}")

        parsed_orig = urlparse(test_url)
        if parsed_orig.netloc not in urlparse(current_url).netloc:
            inter_blog = urlparse(current_url).netloc
            inter_origin = f"{urlparse(current_url).scheme}://{inter_blog}/"
            log(f"Detected inter blog: {inter_blog}")
            r2 = session.get(test_url, headers={"Referer": inter_origin}, allow_redirects=True, timeout=20)
            current_url = str(r2.url)
            log(f"R2 (loopback): status={r2.status_code}, url={current_url}")
            log(f"R2 text sample: {r2.text[:300]}")
            soup = BeautifulSoup(r2.text, "html.parser")
        else:
            soup = BeautifulSoup(r1.text, "html.parser")

        go_form = soup.find("form", {"id": "go-link"})
        log(f"Go form present: {bool(go_form)}")
        if go_form:
            action = go_form.get("action") or "/links/go"
            base_domain = f"{parsed_orig.scheme}://{parsed_orig.netloc}"
            post_url = urljoin(base_domain, action)
            payload = {inp.get("name"): inp.get("value", "") for inp in go_form.find_all("input") if inp.get("name")}
            log(f"Inputs: {list(payload.keys())}")
            log(f"Waiting 6s...")
            await asyncio.sleep(6)
            ajax_headers = {
                "X-Requested-With": "XMLHttpRequest",
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                "Accept": "application/json, text/javascript, */*; q=0.01",
                "Origin": base_domain,
                "Referer": current_url
            }
            res = session.post(post_url, data=payload, headers=ajax_headers, timeout=20)
            log(f"POST status: {res.status_code}")
            log(f"POST text: {res.text}")
    except Exception as e:
        log(f"EXCEPTION: {e}")
        import traceback
        log(traceback.format_exc())

    return web.Response(text="\n\n".join(logs), content_type="text/plain", charset="utf-8")

async def start_web_server():
    """تشغيل خادم الويب ليجتاز الفحص السحابي لـ Render و Koyeb و UptimeRobot"""
    app = web.Application()
    app.router.add_get("/", web_health_handler)
    app.router.add_get("/health", web_health_handler)
    app.router.add_get("/debug_bypass", web_debug_bypass)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", PORT)
    await site.start()
    logger.info(f"🌐 Keep-Alive Web Server started on port {PORT}")

# =====================================================================
# 8. الإقلاع الموحد (Main Async Runner)
# =====================================================================
async def main():
    logger.info("Initializing Database...")
    await db.init()
    logger.info("Starting Keep-Alive Web Server...")
    await start_web_server()
    logger.info(f"🤖 Bot @{BOT_USERNAME} is listening for updates...")
    await bot.delete_webhook(drop_pending_updates=True)
    await dp.start_polling(bot, allowed_updates=["message", "callback_query", "inline_query"])

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        logger.info("Bot stopped.")
