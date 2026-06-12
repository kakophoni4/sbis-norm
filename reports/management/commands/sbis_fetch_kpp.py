"""
Список организаций (ИНН/КПП) из ответа СБИС после авторизации по сертификату.

СБИС.СписокСлужебныхЭтапов на многих контурах требует КПП в фильтре. КПП берётся:
  1) флаг --kpp
  2) Organization.kpp в БД (по ИНН)
  3) разбор Subject экспортированного .cer (openssl / certmgr): KPP=, КПП=, OID 1.2.643.100.5

Запуск:
  cd ~/sbis_api_backend
  sudo .venv/bin/python manage.py sbis_fetch_kpp 9729337785
  sudo .venv/bin/python manage.py sbis_fetch_kpp 9729337785 --kpp 773301001

Опции:
  --kpp КПП         — явно (если авто не сработало)
  --target-inn ИНН  — подсветить строку (по умолчанию = ИНН сертификата)
  --days N          — период ДатаС..ДатаПо (по умолчанию 90)
  --json            — вывести organizations в JSON
  --try-legacy-info — дополнительно СБИС.ИнформацияОСлужебныхЭтапах (часто -32601)
"""
import json
import sys

from django.core.management.base import BaseCommand

from reports.models import Certificate, Organization
from reports.services.sbis import (
    auth_sbis_by_cert,
    export_cert_der,
    get_certmgr_list_file_output,
    get_thumbprint_from_certmgr_listing,
    parse_kpp_from_cert_file,
    sbis_list_organizations_from_service_info,
    sbis_list_organizations_from_service_stages,
)


class Command(BaseCommand):
    help = "СвЮЛ из СБИС.СписокСлужебныхЭтапов (нужен КПП в фильтре); опционально legacy API"

    def add_arguments(self, parser):
        parser.add_argument("inn", nargs="?", help="ИНН организации (сертификат в Certificate)")
        parser.add_argument(
            "--kpp",
            dest="kpp",
            default="",
            help="КПП для фильтра СБИС (если не задан — БД Organization / Subject серта)",
        )
        parser.add_argument(
            "--target-inn",
            dest="target_inn",
            default="",
            help="ИНН для подсветки (по умолчанию совпадает с inn)",
        )
        parser.add_argument(
            "--days",
            type=int,
            default=90,
            help="Период запроса списка этапов, дней назад от сегодня (по умолчанию 90)",
        )
        parser.add_argument(
            "--json",
            action="store_true",
            dest="as_json",
            help="Вывести organizations как JSON",
        )
        parser.add_argument(
            "--try-legacy-info",
            action="store_true",
            dest="try_legacy_info",
            help="Если основной путь не дал КПП — попробовать СБИС.ИнформацияОСлужебныхЭтапах",
        )

    def handle(self, *args, **options):
        inn = (options.get("inn") or "").strip()
        if not inn:
            self.stdout.write(self.style.ERROR("Укажите ИНН: manage.py sbis_fetch_kpp 9729337785"))
            sys.exit(1)

        target = (options.get("target_inn") or inn).strip()
        days = max(1, int(options.get("days") or 90))

        cert = Certificate.objects.filter(inn=inn, has_private_key=True).first()
        if not cert:
            cert = Certificate.objects.filter(inn=inn).first()
        if not cert:
            self.stdout.write(self.style.ERROR(f"Сертификат для ИНН {inn} не найден в БД"))
            sys.exit(1)
        if not cert.csptest_name:
            self.stdout.write(self.style.ERROR("У сертификата не заполнен csptest_name"))
            sys.exit(1)

        self.stdout.write(f"ИНН (серт): {inn}")
        self.stdout.write(f"Контейнер: {(cert.csptest_name or '')[:70]}...")

        cert_path = f"/tmp/sbis_kpp_probe_{inn}.cer"
        try:
            export_cert_der(cert.csptest_name, cert_path)
            certmgr_listing = get_certmgr_list_file_output(cert_path)
            thumbprint = get_thumbprint_from_certmgr_listing(certmgr_listing)
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Ошибка экспорта сертификата: {e}"))
            sys.exit(1)

        org = Organization.objects.filter(inn=inn).first()
        kpp = (options.get("kpp") or "").strip()
        kpp_source = ""
        if kpp:
            kpp_source = "аргумент --kpp"
        if not kpp and org and (org.kpp or "").strip():
            kpp = org.kpp.strip()
            kpp_source = "Organization.kpp в БД"
        if not kpp and cert and (getattr(cert, "kpp", None) or "").strip():
            kpp = cert.kpp.strip()
            kpp_source = "Certificate.kpp в БД"
        if not kpp:
            parsed = parse_kpp_from_cert_file(cert_path, certmgr_listing=certmgr_listing)
            if parsed:
                kpp = parsed
                kpp_source = "Subject сертификата (openssl/certmgr)"

        org_name = (org.name or "").strip() if org else ""

        if not kpp:
            self.stdout.write(
                self.style.ERROR(
                    "КПП не найден: укажите --kpp, заполните Organization.kpp / Certificate.kpp, "
                    "запустите sync_org_kpp, или проверьте Subject серта (openssl x509 -subject)."
                )
            )
            sys.exit(2)

        self.stdout.write(f"КПП для запроса СБИС: {kpp} ({kpp_source})")

        try:
            self.stdout.write("Авторизация в СБИС...")
            session_id = auth_sbis_by_cert(cert_path, thumbprint, inn=inn)
            self.stdout.write(self.style.SUCCESS(f"Сессия получена ({session_id[:16]}...)"))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Ошибка авторизации: {e}"))
            sys.exit(1)

        from datetime import datetime, timedelta

        today = datetime.now()
        date_to = today.strftime("%d.%m.%Y")
        date_from = (today - timedelta(days=days)).strftime("%d.%m.%Y")

        self.stdout.write(
            f"Запрос СБИС.СписокСлужебныхЭтапов (период {date_from} — {date_to}, ИНН+КПП в фильтре)..."
        )
        pack = sbis_list_organizations_from_service_stages(
            inn,
            session_id,
            kpp=kpp,
            org_name=org_name,
            date_from=date_from,
            date_to=date_to,
            page_size=50,
        )

        orgs: list[dict] = []
        if pack.get("success"):
            orgs = list(pack.get("organizations") or [])
            dc = pack.get("docs_count")
            if dc is not None:
                self.stdout.write(f"Документов в ответе: {dc}")
            self.stdout.write(f"Найдено уникальных СвЮЛ (ИНН+КПП): {len(orgs)}")
        else:
            self.stdout.write(self.style.ERROR(f"СписокСлужебныхЭтапов: {pack.get('error')}"))

        if not orgs and options.get("try_legacy_info"):
            self.stdout.write("Пробуем СБИС.ИнформацияОСлужебныхЭтапах (--try-legacy-info)...")
            legacy = sbis_list_organizations_from_service_info(inn, session_id)
            if legacy.get("success"):
                orgs = list(legacy.get("organizations") or [])
                self.stdout.write(f"Legacy: записей: {len(orgs)}")
            else:
                self.stdout.write(self.style.WARNING(f"Legacy: {legacy.get('error')}"))

        if not pack.get("success") and not orgs:
            sys.exit(1)

        if options.get("as_json"):
            self.stdout.write(json.dumps(orgs, ensure_ascii=False, indent=2))
            return

        if not orgs:
            self.stdout.write(
                self.style.WARNING(
                    "КПП в ответе не найден (нет блоков СвЮЛ с КПП). "
                    "Проверьте XML отчёта (НПЮЛ/@КПП) или certmgr -list (Subject). "
                    "Увеличьте период: --days 365"
                )
            )
            sys.exit(0)

        w_inn = max(len("ИНН"), max(len(o["inn"]) for o in orgs), 12)
        w_kpp = max(len("КПП"), max(len(o["kpp"]) for o in orgs), 9)
        line = f"{'ИНН':<{w_inn}}  {'КПП':<{w_kpp}}  Название"
        self.stdout.write(line)
        self.stdout.write("-" * min(100, len(line) + 40))

        for o in orgs:
            mark = "  <-- target" if o["inn"] == target else ""
            name = (o["name"] or "")[:60]
            self.stdout.write(f"{o['inn']:<{w_inn}}  {o['kpp'] or '(пусто)':<{w_kpp}}  {name}{mark}")

        match = next((x for x in orgs if x["inn"] == target), None)
        if match:
            self.stdout.write("")
            if match.get("kpp"):
                self.stdout.write(self.style.SUCCESS(f"КПП для ИНН {target}: {match['kpp']}"))
            else:
                self.stdout.write(
                    self.style.WARNING(
                        f"Для ИНН {target} в СвЮЛ КПП пустой — смотрите Subject серта или XML отчёта."
                    )
                )
        elif target != inn:
            self.stdout.write(self.style.WARNING(f"ИНН {target} не найден среди строк ответа."))
