"""
Короткая выписка книги продаж по контрагенту + визуальный штамп исходной книги Saby.
"""
from __future__ import annotations

import io
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# COMPARE_ROW_0000090_5_12_АФ-000413003_13.04.2026_6382093534_638201001_24
COMPARE_ROW_RE = re.compile(
    r"COMPARE_ROW_(?P<form>\d+)_(?P<a>\d+)_(?P<b>\d+)_(?P<invoice>.+?)_"
    r"(?P<date>\d{2}\.\d{2}\.\d{4})_(?P<inn>\d{10,12})_(?P<kpp>[^_]*)_(?P<n>\d+)\b"
)
STAMP_ID_RE = re.compile(
    r"Идентификатор:\s*([0-9a-fA-F-]{36})",
    re.IGNORECASE,
)
STAMP_CERT_RE = re.compile(
    r"Сертификат\s+([0-9A-Fa-f]{16,64})",
)
STAMP_TIME_RE = re.compile(
    r"(\d{2}\.\d{2}\.\d{2,4}\s+\d{2}:\d{2}\s*\([^)]+\))",
)
MONEY_RE = re.compile(r"-?\d+(?:[.,]\d{2})")


@dataclass
class SalesBookStampMeta:
    document_id: str = ""
    sent_line: str = ""
    signed_at: str = ""
    certificate: str = ""
    operator: str = "Оператор ЭДО ООО \"Компания \"Тензор\""
    raw_tail: str = ""


@dataclass
class SalesBookTitleMeta:
    org_name: str = ""
    inn_kpp: str = ""
    period_line: str = ""
    section_title: str = (
        "Раздел 9. Сведения из книги продаж об операциях, отражаемых за истекший налоговый период"
    )
    relevance: str = "Признак актуальности ранее представленных сведений: 0"


@dataclass
class SalesBookRow:
    n: str = ""
    buyer_name: str = ""
    buyer_inn: str = ""
    buyer_kpp: str = ""
    invoice_num: str = ""
    invoice_date: str = ""
    amount_with_vat: str = ""
    amount_without_vat: str = ""
    vat_amount: str = ""
    attrs: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "n": self.n,
            "buyer_name": self.buyer_name,
            "buyer_inn": self.buyer_inn,
            "buyer_kpp": self.buyer_kpp,
            "invoice_num": self.invoice_num,
            "invoice_date": self.invoice_date,
            "amount_with_vat": self.amount_with_vat,
            "amount_without_vat": self.amount_without_vat,
            "vat_amount": self.vat_amount,
            "attrs": self.attrs,
        }


def _resolve_font_paths() -> tuple[str | None, str | None]:
    """Возвращает (regular, bold) TTF с кириллицей."""
    candidates_reg = [
        Path(__file__).resolve().parents[3] / "assets" / "fonts" / "DejaVuSans.ttf",
        Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
        Path("/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf"),
        Path(r"C:\Windows\Fonts\arial.ttf"),
        Path(r"C:\Windows\Fonts\calibri.ttf"),
    ]
    candidates_bold = [
        Path(__file__).resolve().parents[3] / "assets" / "fonts" / "DejaVuSans-Bold.ttf",
        Path("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"),
        Path("/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf"),
        Path(r"C:\Windows\Fonts\arialbd.ttf"),
        Path(r"C:\Windows\Fonts\calibrib.ttf"),
    ]
    reg = next((str(p) for p in candidates_reg if p.exists()), None)
    bold = next((str(p) for p in candidates_bold if p.exists()), None) or reg
    return reg, bold


def extract_title_meta_from_pdf(pdf_bytes: bytes) -> SalesBookTitleMeta:
    """Заголовок раздела 9 с первой страницы полного PDF Saby."""
    try:
        from pypdf import PdfReader
    except ImportError as e:
        raise RuntimeError("Нужен пакет pypdf для разбора PDF") from e

    reader = PdfReader(io.BytesIO(pdf_bytes))
    if not reader.pages:
        return SalesBookTitleMeta()
    text = reader.pages[0].extract_text() or ""
    meta = SalesBookTitleMeta()
    m = re.search(
        r"COMPARE_TAG_BEGIN[^\n]*\n(?P<body>.*?)\nCOMPARE_TAG_END",
        text,
        re.DOTALL,
    )
    block = m.group("body") if m else text.split("№п/п")[0]
    lines = [" ".join(x.split()) for x in block.splitlines() if x.strip()]
    # типично: org, inn/kpp, period, section title, relevance
    if lines:
        meta.org_name = lines[0]
    for line in lines[1:]:
        if re.search(r"\d{10,12}\s*/\s*\d{9}", line) and not meta.inn_kpp:
            meta.inn_kpp = line
        elif re.search(r"\d{2}\.\d{2}\.\d{2,4}.+\d{2}\.\d{2}\.\d{2,4}", line) and not meta.period_line:
            meta.period_line = line
        elif line.lower().startswith("раздел"):
            meta.section_title = line
        elif "актуальности" in line.lower():
            meta.relevance = line
    return meta


def extract_stamp_meta_from_pdf(pdf_bytes: bytes) -> SalesBookStampMeta:
    """Реквизиты синего штампа с последней страницы полного PDF Saby."""
    try:
        from pypdf import PdfReader
    except ImportError as e:
        raise RuntimeError("Нужен пакет pypdf для разбора штампа PDF") from e

    reader = PdfReader(io.BytesIO(pdf_bytes))
    if not reader.pages:
        return SalesBookStampMeta()

    # штамп обычно на последней странице; подстрахуемся хвостом всего текста
    chunks: list[str] = []
    for page in reader.pages[-3:]:
        chunks.append(page.extract_text() or "")
    text = "\n".join(chunks)
    meta = SalesBookStampMeta(raw_tail=text[-2500:])

    m = STAMP_ID_RE.search(text)
    if m:
        meta.document_id = m.group(1).strip()

    m = STAMP_CERT_RE.search(text)
    if m:
        meta.certificate = m.group(1).strip().upper()

    m = STAMP_TIME_RE.search(text)
    if m:
        meta.signed_at = m.group(1).strip()

    lines = [" ".join(x.split()) for x in text.splitlines() if x.strip()]
    for i, s in enumerate(lines):
        if s.upper().startswith("ОТПРАВЛЕНО"):
            chunk = [s]
            for nxt in lines[i + 1 : i + 3]:
                if nxt.upper().startswith("ОПЕРАТОР") or STAMP_TIME_RE.search(nxt):
                    break
                chunk.append(nxt)
            meta.sent_line = " ".join(chunk)
        if "Оператор ЭДО" in s or "ОПЕРАТОР ЭДО" in s.upper():
            meta.operator = s

    if not meta.sent_line:
        compact = re.sub(r"\s+", " ", text)
        m = re.search(r"ОТПРАВЛЕНО.{10,220}?ДИРЕКТОР", compact, re.IGNORECASE)
        if m:
            meta.sent_line = m.group(0).strip()

    return meta


def parse_sales_rows_from_saby_pdf(
    pdf_bytes: bytes,
    *,
    counterparty_id: str | None = None,
) -> list[SalesBookRow]:
    """
    Строки из COMPARE_ROW_* маркеров PDF Saby (надёжнее, чем сырые attrs XML).
    """
    try:
        from pypdf import PdfReader
    except ImportError as e:
        raise RuntimeError("Нужен пакет pypdf для разбора строк PDF") from e

    target = (counterparty_id or "").strip()
    reader = PdfReader(io.BytesIO(pdf_bytes))
    lines: list[str] = []
    for page in reader.pages:
        page_text = page.extract_text() or ""
        lines.extend(page_text.splitlines())

    rows: list[SalesBookRow] = []
    for i, line in enumerate(lines):
        m = COMPARE_ROW_RE.search(line.replace(" ", ""))
        if not m:
            # markers sometimes keep spaces only around them
            m = COMPARE_ROW_RE.search(line)
        if not m:
            continue
        inn = m.group("inn")
        if target and inn != target:
            continue

        invoice = m.group("invoice")
        date = m.group("date")
        kpp = (m.group("kpp") or "").strip()
        n = m.group("n")

        buyer_name = ""
        amount_with_vat = ""
        amount_without_vat = ""
        vat_amount = ""

        window = lines[max(0, i - 40) : i]
        for w in reversed(window):
            ws = " ".join(w.split())
            if inn in ws and ("ООО" in ws or "ИП" in ws or "/" in ws or "," in ws):
                # "24 ООО "ГЛАЗУРЬ", 6382093534 / 638201001"
                name_part = re.sub(rf"^\d+\s*", "", ws)
                name_part = re.sub(rf",?\s*{re.escape(inn)}.*$", "", name_part).strip(" ,")
                buyer_name = name_part
                break

        for w in reversed(window):
            ws = w.strip()
            if not ws.startswith("-"):
                continue
            parts = ws.replace(",", ".").split()
            nums = [p for p in parts if MONEY_RE.fullmatch(p)]
            if len(nums) < 3:
                continue
            amount_with_vat = nums[0]
            amount_without_vat = nums[1]
            nonzero = [p for p in nums[2:] if p not in ("0", "0.00", "0,00")]
            vat_amount = nonzero[0] if nonzero else nums[2]
            break

        rows.append(
            SalesBookRow(
                n=n,
                buyer_name=buyer_name,
                buyer_inn=inn,
                buyer_kpp=kpp,
                invoice_num=invoice,
                invoice_date=date,
                amount_with_vat=amount_with_vat,
                amount_without_vat=amount_without_vat,
                vat_amount=vat_amount,
                attrs={
                    "ИННЮЛ": inn,
                    "КПП": kpp,
                    "НомерСчФ": invoice,
                    "ДатаСчФ": date,
                    "НомПП": n,
                },
            )
        )
    return rows


def normalize_xml_sales_rows(raw_rows: list[dict], *, counterparty_id: str | None = None) -> list[SalesBookRow]:
    """Нормализация строк из _collect_sales_book_rows / родительских КнПродСтр."""
    target = (counterparty_id or "").strip()
    out: list[SalesBookRow] = []
    seen: set[tuple[str, str, str]] = set()

    for raw in raw_rows or []:
        attrs = dict(raw.get("attrs") or {})
        # иногда attrs лежат плоско, иногда вложенные ключи уже смержены
        inn = (
            attrs.get("ИННЮЛ")
            or attrs.get("ИННФЛ")
            or attrs.get("ИНН")
            or ""
        ).strip()
        if target and inn and inn != target:
            continue
        if target and not inn:
            # строка без ИНН — пропускаем, если фильтр задан
            blob = " ".join(f"{k}={v}" for k, v in attrs.items())
            if target not in blob:
                continue
            inn = target

        invoice = (attrs.get("НомерСчФ") or attrs.get("НомСчФПрод") or attrs.get("Номер") or "").strip()
        date = (attrs.get("ДатаСчФ") or attrs.get("ДатаСчФПрод") or attrs.get("Дата") or "").strip()
        kpp = (attrs.get("КПП") or attrs.get("КППЮЛ") or "").strip()
        name = (attrs.get("НаимОрг") or attrs.get("Наименование") or attrs.get("ФИО") or "").strip()
        n = (attrs.get("НомПП") or attrs.get("НомерПП") or "").strip()
        amount_with = (
            attrs.get("СтоимПродСФ")
            or attrs.get("СтоимПродСФВ")
            or attrs.get("СтоимПродОсв")
            or ""
        ).strip()
        amount_base = (
            attrs.get("СтоимПродСФВ")
            or attrs.get("СтТовУчНалВсего")
            or ""
        ).strip()
        vat = (attrs.get("СумНДСВыч") or attrs.get("СумНДС") or attrs.get("СумНал") or "").strip()

        key = (invoice, date, inn or target)
        if key in seen and invoice:
            continue
        seen.add(key)

        out.append(
            SalesBookRow(
                n=n,
                buyer_name=name,
                buyer_inn=inn or target,
                buyer_kpp=kpp,
                invoice_num=invoice,
                invoice_date=date,
                amount_with_vat=amount_with,
                amount_without_vat=amount_base if amount_base != amount_with else "",
                vat_amount=vat,
                attrs=attrs,
            )
        )
    return out


def _parse_money(value: str) -> float:
    s = (value or "").strip().replace(" ", "").replace(",", ".")
    if not s or s == "-":
        return 0.0
    try:
        return float(s)
    except ValueError:
        return 0.0


# Высота строки данных в PDF книги продаж Saby (замерено по COMPARE_ROW).
_SABY_ROW_H = 38.894


def _iter_compare_markers(page) -> list[tuple[float, str, str]]:
    """[(y, inn, raw_text), ...] по маркерам COMPARE_ROW на странице."""
    items: list[tuple[float, str, str]] = []
    for block in page.get_text("dict").get("blocks", []):
        if block.get("type") != 0:
            continue
        for line in block.get("lines", []):
            text = "".join(span.get("text", "") for span in line.get("spans", []))
            if not text.startswith("COMPARE_ROW_") or "_total" in text:
                continue
            m = re.search(r"_(\d{10,12})_", text)
            inn = m.group(1) if m else ""
            items.append((float(line["bbox"][1]), inn, text))
    items.sort(key=lambda x: x[0])
    return items


def _hline_ys(page) -> list[float]:
    """Y горизонтальных линий сетки Saby (тонкие filled-rect)."""
    ys: list[float] = []
    for d in page.get_drawings():
        r = d.get("rect")
        if not r:
            continue
        if float(r.width) > 200 and 0.2 <= float(r.height) < 1.6:
            ys.append(round(float(r.y0), 2))
    return sorted(set(ys))


def _find_name_top(page, *, target_inn: str, y_lo: float, y_hi: float) -> float | None:
    name_top: float | None = None
    for block in page.get_text("dict").get("blocks", []):
        if block.get("type") != 0:
            continue
        for line in block.get("lines", []):
            y0 = float(line["bbox"][1])
            if y0 < y_lo or y0 >= y_hi:
                continue
            text = "".join(span.get("text", "") for span in line.get("spans", []))
            if text.startswith("COMPARE_ROW"):
                continue
            if target_inn in text:
                name_top = y0 if name_top is None else min(name_top, y0)
    return name_top


def _snap_row_band(
    page,
    *,
    y_mark: float,
    name_top: float | None,
) -> tuple[float, float]:
    """
    Полоса строки по сетке: от линии над именем до линии под COMPARE.
    Типичная высота полной строки Saby ≈ 38.9 pt.
    """
    hs = _hline_ys(page)
    if not hs:
        top = (name_top - 1.0) if name_top is not None else (y_mark - 20.0)
        return top, y_mark + 8.0

    anchor = name_top if name_top is not None else (y_mark - 19.0)
    tops = [h for h in hs if h <= anchor + 0.8]
    top = max(tops) if tops else max(0.0, anchor - 1.0)

    bottoms = [h for h in hs if h >= y_mark - 0.5]
    sized = [h for h in bottoms if 28.0 <= (h - top) <= 45.0]
    if sized:
        bottom = sized[0]
    elif bottoms:
        bottom = bottoms[0]
    else:
        bottom = min(float(page.rect.height), top + 38.9)
    return top, bottom


def _snap_name_tail_band(page, *, target_inn: str, after_y: float) -> tuple[float, float] | None:
    """Имя контрагента внизу страницы (строка разрезана на 2 страницы)."""
    name_top = _find_name_top(page, target_inn=target_inn, y_lo=after_y, y_hi=float(page.rect.height))
    if name_top is None:
        return None
    hs = _hline_ys(page)
    tops = [h for h in hs if h <= name_top + 0.8]
    top = max(tops) if tops else (name_top - 1.0)
    bottoms = [h for h in hs if h > top + 2.0]
    bottom = bottoms[0] if bottoms else min(float(page.rect.height), top + 10.0)
    return top, bottom


def _snap_continuation_amount_band(page, *, y_mark: float) -> tuple[float, float]:
    """
    Суммы/детали разрезанной строки сразу под шапкой продолжения.

    Важно: первая полная строка на странице продолжения — уже СЛЕДУЮЩАЯ.
    Нужный хвост (суммы нашей строки) лежит ВЫШЕ первой линии сетки данных
    (пример: суммы 197 на y≈130…151, линия 159.16, а строка 198 начинается с 160).
    """
    hs = _hline_ys(page)
    bottoms = [h for h in hs if h >= y_mark + 4.0]
    bottom = bottoms[0] if bottoms else (y_mark + 20.0)

    num_bottom: float | None = None
    for block in page.get_text("dict").get("blocks", []):
        if block.get("type") != 0:
            continue
        for line in block.get("lines", []):
            text = "".join(span.get("text", "") for span in line.get("spans", [])).strip()
            if text in {"1", "2", "3", "26"} and float(line["bbox"][0]) < 80 and float(line["bbox"][1]) < y_mark:
                num_bottom = float(line["bbox"][3]) if num_bottom is None else max(num_bottom, float(line["bbox"][3]))
    if num_bottom is not None:
        top = num_bottom + 0.4
    else:
        top = max(0.0, bottom - 29.0)
    # не захватываем имя следующей строки под нижней линией
    return top, bottom


def _header_end_y(page0) -> float:
    """Низ шапки таблицы на 1-й странице = первая линия сетки данных."""
    hs = _hline_ys(page0)
    if hs:
        return hs[0]
    markers = _iter_compare_markers(page0)
    if markers:
        return max(0.0, markers[0][0] - _SABY_ROW_H)
    return 208.0


def _total_band_ys(page) -> tuple[float, float]:
    """Полоса «Итого» по сетке (на последней странице обычно 198.05–207.08)."""
    hs = _hline_ys(page)
    for block in page.get_text("dict").get("blocks", []):
        if block.get("type") != 0:
            continue
        for line in block.get("lines", []):
            text = "".join(span.get("text", "") for span in line.get("spans", []))
            if "того" in text.lower() and any(ch.isdigit() for ch in text):
                y0 = float(line["bbox"][1])
                above = [h for h in hs if h <= y0 + 1.0]
                below = [h for h in hs if h >= y0 - 1.0]
                top = max(above) if above else (y0 - 2.0)
                # нижняя линия полосы — следующая после top
                after = [h for h in hs if h > top + 2.0]
                bottom = after[0] if after else (float(line["bbox"][3]) + 2.0)
                if below and after:
                    return top, bottom
                return top, bottom
    if len(hs) >= 2:
        return hs[0], hs[1]
    return 198.05, 207.08


def _stamp_top_y(page) -> float:
    top = float(page.rect.height) - 80.0
    for block in page.get_text("dict").get("blocks", []):
        if block.get("type") != 0:
            continue
        for line in block.get("lines", []):
            text = "".join(span.get("text", "") for span in line.get("spans", []))
            if "ПОДПИСАН" in text.upper() or "Оператор ЭДО" in text or "Тензор" in text:
                top = min(top, float(line["bbox"][1]) - 14.0)
    # синий блок штампа чуть выше текста
    return max(0.0, top)


# Толщина горизонтальной линии сетки Saby (filled-rect).
_SABY_LINE_H = 0.70


def _right_align_text(page, text: str, *, right_x: float, baseline_y: float, fontname: str, fontsize: float = 7.0):
    import pymupdf as fitz

    try:
        w = fitz.get_text_length(text, fontname=fontname, fontsize=fontsize)
    except Exception:
        w = len(text) * fontsize * 0.5
    page.insert_text((right_x - w, baseline_y), text, fontname=fontname, fontsize=fontsize, color=(0, 0, 0))


def _redact_compare_markers(page) -> None:
    import pymupdf as fitz

    hits = list(page.search_for("COMPARE_ROW"))
    if not hits:
        return
    page_w = float(page.rect.width)
    for inst in hits:
        r = fitz.Rect(inst)
        r.x0 = max(0.0, r.x0 - 2.0)
        r.x1 = page_w
        r.y0 -= 1.0
        r.y1 += 1.0
        page.add_redact_annot(r, fill=(1, 1, 1))
    page.apply_redactions()


def _show_band(
    dest_page,
    src,
    page_index: int,
    clip,
    dest_y: float,
    *,
    skip_top_line: bool = False,
    skip_bottom_line: bool = False,
) -> float:
    """Вставляет полосу страницы; skip_*_line избегает двойной линии на стыке."""
    import pymupdf as fitz

    c = fitz.Rect(clip)
    if skip_top_line:
        c.y0 = min(c.y1 - 1.0, c.y0 + _SABY_LINE_H)
    if skip_bottom_line:
        c.y1 = max(c.y0 + 1.0, c.y1 - _SABY_LINE_H)
    h = float(c.height)
    page_w = float(dest_page.rect.width)
    dest_page.show_pdf_page(fitz.Rect(0, dest_y, page_w, dest_y + h), src, page_index, clip=c)
    return dest_y + h


def _ensure_font(page, font_path: str | None) -> str:
    if not font_path:
        return "helv"
    try:
        page.insert_font(fontname="sbextract2", fontfile=font_path)
        return "sbextract2"
    except Exception:
        return "helv"


_SABY_TABLE_X0 = 21.64
_SABY_TABLE_X1 = 828.0

# Полная сетка колонок раздела 9 (из drawings Saby).
_SABY_GRID_VERT_X = (
    21.64,
    34.84,
    82.06,
    131.38,
    153.6,
    190.41,
    213.33,
    244.59,
    275.84,
    307.1,
    336.27,
    371.69,
    398.77,
    434.2,
    471.01,
    511.29,
    526.57,
    541.85,
    555.05,
    568.24,
    580.05,
    619.64,
    634.92,
    650.2,
    663.39,
    676.59,
    727.99,
    749.52,
    769.66,
    792.58,
    827.31,
)


def _paint_clean_grid(
    page,
    *,
    y_top: float,
    y_bottom: float,
    h_lines: list[float],
) -> None:
    """
    Стирает битую сетку в зоне сумм и рисует ровные линии.
    Важно: горизонтали сначала, вертикали поверх — иначе wipe горизонтали
    оставлял белые разрывы в вертикалях (как раз «побитые линии»).
    """
    import pymupdf as fitz

    pad = 0.40
    # 1) стереть старые вертикали (с запасом на сдвиг клипов)
    for x in _SABY_GRID_VERT_X:
        page.draw_rect(
            fitz.Rect(x - pad, y_top, x + _SABY_LINE_H + pad, y_bottom),
            color=(1, 1, 1),
            fill=(1, 1, 1),
            width=0,
        )
    # 2) стереть старые горизонтали (чуть шире линии)
    for y in h_lines:
        if y < y_top - 1 or y > y_bottom + 0.5:
            continue
        # wipe вверх ~1.6pt — старые линии клипа часто чуть выше нашего шва
        page.draw_rect(
            fitz.Rect(_SABY_TABLE_X0 - 0.2, y - 1.6, _SABY_TABLE_X1 + 0.2, y + _SABY_LINE_H + 0.25),
            color=(1, 1, 1),
            fill=(1, 1, 1),
            width=0,
        )
    # 3) горизонтали
    for y in h_lines:
        if y < y_top - 1 or y > y_bottom + 0.5:
            continue
        page.draw_rect(
            fitz.Rect(_SABY_TABLE_X0, y, _SABY_TABLE_X1, y + _SABY_LINE_H),
            color=(0, 0, 0),
            fill=(0, 0, 0),
            width=0,
        )
    # 4) вертикали поверх — непрерывные, без разрывов на швах
    for x in _SABY_GRID_VERT_X:
        page.draw_rect(
            fitz.Rect(x, y_top, x + _SABY_LINE_H, y_bottom),
            color=(0, 0, 0),
            fill=(0, 0, 0),
            width=0,
        )


def _detail_band_on_page(page, clip) -> tuple[float, float] | None:
    """Относительно clip: (y0, y1) зоны полных вертикалей внутри полосы."""
    hs = [h for h in _hline_ys(page) if clip.y0 - 0.1 <= h <= clip.y1 + 0.1]
    # полная строка: top, mid (под именем), bottom → детали mid..bottom
    if len(hs) >= 3:
        return hs[1], hs[-1]
    # узкая полоса только с именем (разрезанная строка) — без оверлея вертикалей
    return None


# Вертикали только денежных колонок в строке «Итого» (как в Saby).
_SABY_TOTAL_VERT_X = (
    21.64,
    471.01,
    511.29,
    526.57,
    541.85,
    555.05,
    568.24,
    580.05,
    619.64,
    634.92,
    650.2,
    663.39,
    676.59,
    727.99,
    827.31,
)


def _draw_total_row(
    page,
    *,
    y0: float,
    height: float,
    fontname: str,
    sum_with: float,
    sum_base: float,
    sum_vat: float,
) -> float:
    """Текст «Итого» + суммы (сетку рисует _paint_clean_grid)."""
    y1 = y0 + height
    baseline = y0 + 6.7
    for rx in (526.11, 541.39, 554.59, 567.78, 579.59, 634.46, 649.74, 662.94, 676.13, 727.53):
        page.insert_text((rx - 2.2, baseline), "-", fontname=fontname, fontsize=7, color=(0, 0, 0))

    page.insert_text((404.0, baseline), "Итого", fontname=fontname, fontsize=7, color=(0, 0, 0))
    _right_align_text(page, f"{sum_with:.2f}", right_x=470.54, baseline_y=baseline, fontname=fontname)
    if sum_base > 0:
        _right_align_text(page, f"{sum_base:.2f}", right_x=510.82, baseline_y=baseline, fontname=fontname)
    else:
        page.insert_text((523.95, baseline), "-", fontname=fontname, fontsize=7, color=(0, 0, 0))
    _right_align_text(page, f"{sum_vat:.2f}", right_x=619.18, baseline_y=baseline, fontname=fontname)
    return y1


def build_sales_book_extract_pdf(
    *,
    seller_inn: str,
    seller_kpp: str | None,
    seller_name: str | None,
    counterparty_id: str,
    period_from: str,
    period_to: str,
    sbis_doc_id: str,
    rows: list[SalesBookRow],
    stamp: SalesBookStampMeta,
    title: SalesBookTitleMeta | None = None,
    source_pdf_name: str | None = None,
    source_pdf_bytes: bytes | None = None,
) -> bytes:
    """
    Собирает PDF 1:1 как книга Saby: шапка + строки контрагента + «Итого» + штамп.

    Куски копируются векторно (show_pdf_page) с клипами по горизонтальным линиям сетки.
    """
    if not source_pdf_bytes:
        raise RuntimeError("Для PDF 1:1 нужен исходный PDF книги продаж (source_pdf_bytes)")

    try:
        import pymupdf as fitz
    except ImportError as e:
        raise RuntimeError("Нужен пакет pymupdf для нарезки PDF книги продаж") from e

    target = (counterparty_id or "").strip()
    if not target:
        raise RuntimeError("counterparty_id обязателен для нарезки PDF")

    src = fitz.open(stream=source_pdf_bytes, filetype="pdf")
    try:
        if src.page_count < 1:
            raise RuntimeError("Исходный PDF пуст")

        page0 = src[0]
        page_w = float(page0.rect.width)
        page_h = float(page0.rect.height)
        if not _iter_compare_markers(page0):
            raise RuntimeError("В исходном PDF не найдены строки COMPARE_ROW")

        header_end = _header_end_y(page0)

        row_clips: list[tuple] = []
        for pi in range(src.page_count):
            page = src[pi]
            markers = _iter_compare_markers(page)
            for idx, (y_mark, inn, _raw) in enumerate(markers):
                if inn != target:
                    continue

                if idx == 0 and pi > 0:
                    prev = src[pi - 1]
                    prev_markers = _iter_compare_markers(prev)
                    after_y = prev_markers[-1][0] if prev_markers else 0.0
                    name_band = _snap_name_tail_band(prev, target_inn=target, after_y=after_y)
                    if name_band is not None:
                        n0, n1 = name_band
                        a0, a1 = _snap_continuation_amount_band(page, y_mark=y_mark)
                        row_clips.append(
                            (
                                "split",
                                pi - 1,
                                fitz.Rect(0, n0, page_w, n1),
                                pi,
                                fitz.Rect(0, a0, page_w, a1),
                            )
                        )
                        continue

                prev_y = markers[idx - 1][0] if idx > 0 else header_end
                next_y = markers[idx + 1][0] if idx + 1 < len(markers) else (y_mark + _SABY_ROW_H)
                name_top = _find_name_top(page, target_inn=target, y_lo=prev_y, y_hi=next_y)
                y0, y1 = _snap_row_band(page, y_mark=y_mark, name_top=name_top)
                row_clips.append(("row", pi, fitz.Rect(0, y0, page_w, y1)))

        if not row_clips:
            raise RuntimeError(f"В PDF нет строк контрагента {target}")

        sum_with = sum(_parse_money(r.amount_with_vat) for r in rows)
        sum_base = sum(_parse_money(r.amount_without_vat) for r in rows)
        sum_vat = sum(_parse_money(r.vat_amount) for r in rows)

        last_i = src.page_count - 1
        last = src[last_i]
        total_y0, total_y1 = _total_band_ys(last)
        total_h = total_y1 - total_y0

        stamp_top = min(_stamp_top_y(last), 534.0)
        stamp_h = page_h - stamp_top

        rows_h = 0.0
        for item in row_clips:
            if item[0] == "split":
                # name: skip_top и include bottom компенсируются
                rows_h += float(item[2].height)
                # amt: без skip_top, + нижняя линия
                rows_h += float(item[4].height) + _SABY_LINE_H
            else:
                rows_h += float(item[2].height)

        final_h = header_end + _SABY_LINE_H + rows_h + total_h + 10.0 + stamp_h + 8.0
        final_h = max(final_h, header_end + 120.0)

        out = fitz.open()
        new = out.new_page(width=page_w, height=final_h)
        font_path, _ = _resolve_font_paths()

        # 1) шапка (нижняя линия сетки остаётся — общая с первой строкой)
        new.show_pdf_page(
            fitz.Rect(0, 0, page_w, header_end + _SABY_LINE_H),
            src,
            0,
            clip=fitz.Rect(0, 0, page_w, header_end + _SABY_LINE_H),
        )
        # 2) строки — pixmap 3× (внутри строки сетка = оригинал 1:1)
        zoom = 3.0
        mat = fitz.Matrix(zoom, zoom)
        y = header_end + _SABY_LINE_H
        detail_bands: list[tuple[float, float]] = []

        def _place_pixmap(pi: int, clip, *, skip_top: bool, whole_is_detail: bool = False) -> None:
            nonlocal y
            # clip.y1 — y0 линии; включаем толщину линии
            c = fitz.Rect(
                clip.x0,
                clip.y0,
                clip.x1,
                min(float(src[pi].rect.height), float(clip.y1) + _SABY_LINE_H),
            )
            if skip_top:
                c.y0 = min(c.y1 - 1.0, c.y0 + _SABY_LINE_H)
            y0 = y
            pix = src[pi].get_pixmap(matrix=mat, clip=c, alpha=False)
            x_cut = int(690 * zoom)
            if x_cut < pix.width:
                pix.set_rect(fitz.IRect(x_cut, 0, pix.width, pix.height), (255, 255, 255))
            h = float(c.height)
            new.insert_image(fitz.Rect(0, y, page_w, y + h), pixmap=pix, keep_proportion=False)
            y += h
            if whole_is_detail:
                detail_bands.append((y0, y))
            else:
                rel = _detail_band_on_page(src[pi], clip)
                if rel is not None:
                    d0 = y0 + (rel[0] - float(c.y0))
                    d1 = y0 + (min(rel[1], float(clip.y1)) - float(c.y0)) + _SABY_LINE_H
                    detail_bands.append((max(y0, d0), min(y, d1)))

        for item in row_clips:
            if item[0] == "split":
                _, pi_name, name_clip, pi_amt, amt_clip = item
                _place_pixmap(pi_name, name_clip, skip_top=True, whole_is_detail=False)
                _place_pixmap(pi_amt, amt_clip, skip_top=False, whole_is_detail=True)
            else:
                _, pi, clip = item
                _place_pixmap(pi, clip, skip_top=True, whole_is_detail=False)

        # 3) место под «Итого» (текст/линии — после оверлея вертикалей)
        total_y0_dest = y
        detail_bands.append((total_y0_dest, total_y0_dest + total_h))
        fontname = _ensure_font(new, font_path)
        y = total_y0_dest + total_h + 10.0

        # 4) штамп
        stamp_clip = fitz.Rect(0, stamp_top, page_w, page_h)
        stamp_dest = fitz.Rect(0, y, page_w, y + stamp_h)
        new.show_pdf_page(stamp_dest, src, last_i, clip=stamp_clip)

        # 5) ровные вертикали в зонах сумм; горизонтали поверх (закрывают дырки wipe)
        pad = 0.30
        h_ys: list[float] = []
        for gy0, gy1 in detail_bands:
            if gy1 - gy0 < 2:
                continue
            for x in _SABY_GRID_VERT_X:
                new.draw_rect(
                    fitz.Rect(x - pad, gy0, x + _SABY_LINE_H + pad, gy1),
                    color=(1, 1, 1),
                    fill=(1, 1, 1),
                    width=0,
                )
            for x in _SABY_GRID_VERT_X:
                new.draw_rect(
                    fitz.Rect(x, gy0, x + _SABY_LINE_H, gy1),
                    color=(0, 0, 0),
                    fill=(0, 0, 0),
                    width=0,
                )
            h_ys.extend((gy0, gy1 - _SABY_LINE_H))

        h_uniq: list[float] = []
        for hy in sorted(set(round(v, 2) for v in h_ys)):
            if not h_uniq or abs(hy - h_uniq[-1]) > 1.0:
                h_uniq.append(hy)
        for hy in h_uniq:
            new.draw_rect(
                fitz.Rect(_SABY_TABLE_X0, hy, _SABY_TABLE_X1, hy + _SABY_LINE_H),
                color=(0, 0, 0),
                fill=(0, 0, 0),
                width=0,
            )
        # вертикали ещё раз поверх горизонталей — непрерывные столбцы
        for gy0, gy1 in detail_bands:
            if gy1 - gy0 < 2:
                continue
            for x in _SABY_GRID_VERT_X:
                new.draw_rect(
                    fitz.Rect(x, gy0, x + _SABY_LINE_H, gy1),
                    color=(0, 0, 0),
                    fill=(0, 0, 0),
                    width=0,
                )

        _draw_total_row(
            new,
            y0=total_y0_dest,
            height=total_h,
            fontname=fontname,
            sum_with=sum_with,
            sum_base=sum_base,
            sum_vat=sum_vat,
        )

        buf = io.BytesIO()
        out.save(buf, garbage=4, deflate=True)
        out.close()
        return buf.getvalue()
    finally:
        src.close()
