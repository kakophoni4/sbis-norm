"""
Показать, что наскачано в RequirementDocument: сводка по типам (PDF/ZIP/XML), размеры, список записей.
При необходимости сохранить один файл на диск для просмотра (--id N --save-dir /path).

Пример:
  python manage.py list_requirement_documents
  python manage.py list_requirement_documents --limit 30
  python manage.py list_requirement_documents --inn 9715501379
  python manage.py list_requirement_documents --id 5 --save-dir /tmp/req_view
"""
import base64
import io
import zipfile
from pathlib import Path

from django.core.management.base import BaseCommand

from reports.models import RequirementDocument


def detect_type(data: bytes) -> tuple[str, str]:
    """Возвращает (короткий_тип, описание)."""
    if not data:
        return "empty", "пусто"
    if data.startswith(b"%PDF"):
        ver = data[:8].decode("ascii", errors="ignore").strip()
        return "PDF", f"{ver}, {len(data)} Б"
    if data.startswith(b"PK\x03\x04"):
        try:
            zf = zipfile.ZipFile(io.BytesIO(data), "r")
            names = zf.namelist()
            zf.close()
            # Проверяем, что внутри ZIP (DOCX, XLSX и т.д.)
            if any(n.endswith(".docx") for n in names):
                return "DOCX", f"Word (ZIP), файлов: {len(names)}"
            if any(n.endswith(".xlsx") for n in names):
                return "XLSX", f"Excel (ZIP), файлов: {len(names)}"
            if any(n.endswith(".pptx") for n in names):
                return "PPTX", f"PowerPoint (ZIP), файлов: {len(names)}"
            return "ZIP", f"архив, файлов: {len(names)} ({', '.join(names[:3])}{'...' if len(names) > 3 else ''})"
        except Exception:
            return "ZIP", "архив (ошибка чтения списка)"
    if data.strip().startswith(b"<") or data.strip().startswith(b"<?xml"):
        return "XML", f"XML, {len(data)} Б"
    # Проверяем другие форматы по magic bytes
    if data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):  # OLE2 (DOC, XLS, PPT старые)
        if b"WordDocument" in data[:4096]:
            return "DOC", f"Word (старый формат), {len(data)} Б"
        if b"Workbook" in data[:4096] or b"Book" in data[:4096]:
            return "XLS", f"Excel (старый формат), {len(data)} Б"
        return "OLE2", f"OLE2 документ (DOC/XLS/PPT), {len(data)} Б"
    if data.startswith(b"\x50\x4b"):  # ZIP signature (может быть в середине)
        return "ZIP?", f"возможно ZIP (не в начале), {len(data)} Б"
    if data.startswith(b"\x89PNG"):
        return "PNG", f"изображение PNG, {len(data)} Б"
    if data.startswith(b"\xff\xd8\xff"):
        return "JPEG", f"изображение JPEG, {len(data)} Б"
    if data.startswith(b"GIF8"):
        return "GIF", f"изображение GIF, {len(data)} Б"
    # PKCS#7 / CMS (подписи) — начинается с ASN.1 SEQUENCE (0x30) и содержит OID PKCS#7
    if data.startswith(b"\x30") and b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x03" in data[:200]:
        return "PKCS7", f"PKCS#7/CMS подпись, {len(data)} Б"
    # Неопознанный формат — показываем первые байты (hex), чтобы понять что это
    first_n = 32
    hex_preview = data[:first_n].hex() if len(data) >= first_n else data.hex()
    return "other", hex_preview


class Command(BaseCommand):
    help = "Показать сводку по скачанным требованиям (PDF/ZIP/XML) и список записей"

    def add_arguments(self, parser):
        parser.add_argument("--limit", type=int, default=50, help="Макс. записей в таблице (0 = все)")
        parser.add_argument("--inn", type=str, help="Фильтр по ИНН")
        parser.add_argument("--id", type=int, help="Показать одну запись и при --save-dir сохранить файл")
        parser.add_argument("--save-dir", type=str, help="Каталог, куда сохранить файл (нужен --id)")

    def handle(self, *args, **options):
        save_dir = options.get("save_dir")
        rec_id = options.get("id")

        if rec_id:
            self._show_one(rec_id, save_dir)
            return

        qs = RequirementDocument.objects.all().order_by("-created_at")
        if options.get("inn"):
            qs = qs.filter(inn=options["inn"])
        limit = options.get("limit", 50)
        if limit > 0:
            qs = qs[:limit]

        total = RequirementDocument.objects.count()
        self.stdout.write(f"Всего записей в RequirementDocument: {total}")
        self.stdout.write("")

        # Сводка по типам
        type_counts = {}
        for r in RequirementDocument.objects.all():
            try:
                data = base64.b64decode(r.file_b64)
            except Exception:
                data = b""
            t, _ = detect_type(data)
            type_counts[t] = type_counts.get(t, 0) + 1
        self.stdout.write("По типам содержимого:")
        for t in sorted(type_counts.keys()):
            self.stdout.write(f"  {t}: {type_counts[t]}")
        self.stdout.write("")

        # Таблица записей
        self.stdout.write(f"Последние записи (макс. {limit}):")
        self.stdout.write("-" * 130)
        self.stdout.write(f"{'ID':<6} {'ИНН':<12} {'Дата док.':<12} {'Размер':<10} {'Тип':<6} Имя файла (экспорт)  |  Первые байты (hex)")
        self.stdout.write("-" * 130)

        for r in qs:
            try:
                data = base64.b64decode(r.file_b64)
                size = len(data)
            except Exception:
                data = b""
                size = 0
            t, desc = detect_type(data)
            if size >= 1024:
                size_str = f"{size // 1024} КБ"
            else:
                size_str = f"{size} Б"
            name = (r.storage_file_name or "")[:40] or "(не задано)"
            # Для неопознанных (other) desc — это hex первых байт; для остальных — описание
            first_bytes = desc if t == "other" else ""
            self.stdout.write(f"{r.id:<6} {r.inn:<12} {str(r.document_date):<12} {size_str:<10} {t:<6} {name}  |  {first_bytes}")

        self.stdout.write("-" * 130)
        self.stdout.write("")
        self.stdout.write("Подробно одну запись: python manage.py list_requirement_documents --id <ID>")
        self.stdout.write("Сохранить файл на диск:  python manage.py list_requirement_documents --id <ID> --save-dir /tmp/req")

    def _show_one(self, rec_id: int, save_dir: str | None):
        r = RequirementDocument.objects.filter(pk=rec_id).first()
        if not r:
            self.stdout.write(self.style.ERROR(f"Запись с id={rec_id} не найдена."))
            return
        try:
            data = base64.b64decode(r.file_b64)
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Ошибка декодирования base64: {e}"))
            return

        t, desc = detect_type(data)
        self.stdout.write(f"ID: {r.id}")
        self.stdout.write(f"ИНН: {r.inn}  Дата документа: {r.document_date}")
        self.stdout.write(f"Название: {r.doc_title or '(нет)'}")
        self.stdout.write(f"Размер: {len(data)} Б  Тип: {t} — {desc}")
        self.stdout.write("")

        if t == "ZIP":
            try:
                zf = zipfile.ZipFile(io.BytesIO(data), "r")
                for name in zf.namelist():
                    info = zf.getinfo(name)
                    self.stdout.write(f"  В архиве: {name!r}  {info.file_size} Б")
                zf.close()
            except Exception as e:
                self.stdout.write(self.style.ERROR(f"  Ошибка чтения ZIP: {e}"))

        if save_dir:
            path = Path(save_dir)
            path.mkdir(parents=True, exist_ok=True)
            name = (r.storage_file_name or "").strip()
            if not name:
                name = f"Требование ФНС ({r.inn}) ({r.document_date}).pdf" if t == "PDF" else f"requirement_{r.id}.bin"
            out = path / name
            out.write_bytes(data)
            self.stdout.write(self.style.SUCCESS(f"Сохранён: {out}"))
