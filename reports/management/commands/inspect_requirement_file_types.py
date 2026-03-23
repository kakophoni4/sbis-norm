"""
Сводка по типам файлов в RequirementDocument: расширение в storage_file_name,
фактическая сигнатура содержимого (по декодированному file_b64), префикс content_sha256.

Почему бывает .bin / .p7m:
  Раньше PKCS#7/CMS (контейнер ФНС) помечался как .bin; теперь при скачивании — .p7m.
  .bin остаётся для прочего нераспознанного бинарника.

Пример:
  python manage.py inspect_requirement_file_types
  python manage.py inspect_requirement_file_types --limit 5
"""
import base64
from collections import Counter, defaultdict

from django.core.management.base import BaseCommand

from reports.models import RequirementDocument
from reports.requirement_file_sniff import sniff_kind_label


def _ext_from_storage(name: str | None) -> str:
    if not name or "." not in name:
        return "(нет расширения)"
    return "." + name.rsplit(".", 1)[-1].lower()


class Command(BaseCommand):
    help = "Сводка типов файлов RequirementDocument: расширение, сигнатура, префиксы SHA256"

    def add_arguments(self, parser):
        parser.add_argument(
            "--limit-examples",
            type=int,
            default=3,
            help="Сколько примеров id на каждую группу сигнатуры (по умолчанию 3)",
        )

    def handle(self, *args, **options):
        lim = max(0, int(options.get("limit_examples", 3)))
        qs = RequirementDocument.objects.all().order_by("id")
        total = qs.count()
        if total == 0:
            self.stdout.write("В RequirementDocument нет записей.")
            return

        by_ext = Counter()
        by_sniff = Counter()
        examples: dict[str, list[tuple[int, str, str]]] = defaultdict(list)

        for r in qs.iterator(chunk_size=200):
            name = (r.storage_file_name or "").strip()
            ext = _ext_from_storage(name)
            by_ext[ext] += 1

            try:
                data = base64.b64decode(r.file_b64)
            except Exception as e:
                by_sniff[f"Ошибка_b64decode: {e!s}"] += 1
                continue

            kind = sniff_kind_label(data)
            by_sniff[kind] += 1
            if len(examples[kind]) < lim:
                sha = (r.content_sha256 or "")[:16]
                examples[kind].append((r.id, r.inn, sha))

        self.stdout.write(self.style.SUCCESS(f"Всего записей: {total}\n"))

        self.stdout.write("=== По расширению в storage_file_name ===")
        for ext, n in sorted(by_ext.items(), key=lambda x: (-x[1], x[0])):
            self.stdout.write(f"  {ext:28} {n:6}")
        self.stdout.write("")

        self.stdout.write("=== По сигнатуре содержимого (после base64 decode) ===")
        for kind, n in sorted(by_sniff.items(), key=lambda x: (-x[1], x[0])):
            self.stdout.write(f"  {kind:40} {n:6}")
            for tid, inn, sha_p in examples.get(kind, []):
                self.stdout.write(f"      пример id={tid} ИНН={inn} sha256[:16]={sha_p}…")
        self.stdout.write("")
        self.stdout.write(
            "Префикс content_sha256 — первые 16 hex-символов (из 64); "
            "для сравнения дублей используется полный SHA256 в БД."
        )
