"""
Заполнение КПП по ИНН через внешний JSON (по умолчанию star-pro organizationSuggestion).

Источник ИНН:
  • по умолчанию — модель Organization (пустой kpp);
  • --from-certificates — уникальные ИНН из Certificate (если в БД нет организаций).

Примеры:
  python manage.py sync_org_kpp --dry-run
  python manage.py sync_org_kpp --from-certificates --dry-run
  python manage.py sync_org_kpp --from-certificates --delay 1.5 --ensure-organization
  python manage.py sync_org_kpp --only-inn 9729337785 --from-certificates

Перед продакшеном проверьте ToS источника и лимиты запросов.
"""
import inspect
import sys
from pathlib import Path

import time

import requests
from django.core.management.base import BaseCommand
from django.db import transaction
from django.db.models import Q

from reports.models import Certificate, Organization
from reports.services.kpp_external import DEFAULT_SUGGESTION_URL, fetch_kpp_star_pro


class Command(BaseCommand):
    help = "Заполнить КПП по ИНН (Organization и/или Certificate) через внешний API"

    def _fetch_kpp_http(
        self,
        inn: str,
        *,
        base_url: str,
        session: requests.Session,
        cookie: str | None,
        referer: str | None,
    ) -> dict:
        """
        Совместимость со старым kpp_external.py на сервере (без аргументов cookie/referer):
        не падаем с TypeError; Cookie сработает только после обновления файла из репозитория.
        """
        sig = inspect.signature(fetch_kpp_star_pro)
        kw: dict = {"base_url": base_url, "session": session}
        if "cookie" in sig.parameters:
            kw["cookie"] = cookie
        elif (cookie or "").strip():
            if not getattr(self, "_kpp_old_module_warned", False):
                self.stdout.write(
                    self.style.WARNING(
                        "На сервере старый reports/services/kpp_external.py (нет cookie=). "
                        "Скопируйте актуальный файл из репозитория — иначе --cookie-file не отправляется.\n"
                    )
                )
                self._kpp_old_module_warned = True
        if "referer" in sig.parameters:
            kw["referer"] = referer
        return fetch_kpp_star_pro(inn, **kw)

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Только показать, что бы изменилось, без записи в БД",
        )
        parser.add_argument(
            "--force",
            action="store_true",
            help="Обновлять даже если КПП уже заполнен",
        )
        parser.add_argument(
            "--delay",
            type=float,
            default=1.0,
            help="Пауза между HTTP-запросами, сек (по умолчанию 1.0)",
        )
        parser.add_argument(
            "--only-inn",
            dest="only_inn",
            default="",
            help="Обработать только этот ИНН",
        )
        parser.add_argument(
            "--url",
            default=DEFAULT_SUGGESTION_URL,
            help="URL подсказок (JSON с полем items[].kpp)",
        )
        parser.add_argument(
            "--sync-certificates",
            action="store_true",
            help="(режим Organization) Проставить Certificate.kpp всем сертификатам с тем же ИНН",
        )
        parser.add_argument(
            "--from-certificates",
            action="store_true",
            help="Брать уникальные ИНН из Certificate; писать в Certificate.kpp (+ опционально Organization)",
        )
        parser.add_argument(
            "--ensure-organization",
            action="store_true",
            help="С --from-certificates: создать/обновить Organization (inn, kpp, name из ответа API)",
        )
        parser.add_argument(
            "--cookie",
            default="",
            help="Заголовок Cookie (как в DevTools). Или env KPP_SYNC_COOKIE",
        )
        parser.add_argument(
            "--cookie-file",
            dest="cookie_file",
            default="",
            help="Файл с одной строкой Cookie (удобнее, чем в shell)",
        )
        parser.add_argument(
            "--referer",
            default="",
            help="Referer для запроса. Или env KPP_SYNC_REFERER",
        )

    def handle(self, *args, **options):
        dry = options["dry_run"]
        force = options["force"]
        delay = max(0.0, float(options["delay"] or 0))
        only_inn = (options.get("only_inn") or "").strip()
        url = (options.get("url") or DEFAULT_SUGGESTION_URL).strip()
        sync_certs = options["sync_certificates"]
        from_certs = options["from_certificates"]
        ensure_org = options["ensure_organization"]
        cookie = (options.get("cookie") or "").strip()
        cf = (options.get("cookie_file") or "").strip()
        if cf:
            try:
                cookie = Path(cf).read_text(encoding="utf-8").strip()
            except OSError as e:
                self.stderr.write(self.style.ERROR(f"--cookie-file: {e}\n"))
                sys.exit(1)
        referer = (options.get("referer") or "").strip() or None

        if from_certs:
            self._run_from_certificates(
                dry=dry,
                force=force,
                delay=delay,
                only_inn=only_inn,
                url=url,
                ensure_org=ensure_org,
                cookie=cookie or None,
                referer=referer,
            )
        else:
            self._run_from_organizations(
                dry=dry,
                force=force,
                delay=delay,
                only_inn=only_inn,
                url=url,
                sync_certs=sync_certs,
                cookie=cookie or None,
                referer=referer,
            )

    def _run_from_organizations(
        self, *, dry, force, delay, only_inn, url, sync_certs, cookie, referer
    ):
        qs = Organization.objects.all().order_by("inn")
        if only_inn:
            qs = qs.filter(inn=only_inn)
        if not force:
            qs = qs.filter(Q(kpp__isnull=True) | Q(kpp=""))

        total = qs.count()
        self.stdout.write(
            f"[Organization] записей к обработке: {total} (dry-run={dry}, force={force})"
        )

        if total == 0:
            self.stdout.write(
                self.style.WARNING(
                    "Нечего обрабатывать. Если ИНН только в сертификатах — добавьте "
                    "--from-certificates"
                )
            )
            return

        session = requests.Session()
        ok_n = skip_n = err_n = 0
        first = True

        for org in qs.iterator(chunk_size=100):
            if not first and delay > 0:
                time.sleep(delay)
            first = False

            res = self._fetch_kpp_http(
                org.inn,
                base_url=url,
                session=session,
                cookie=cookie,
                referer=referer,
            )
            if not res.get("ok"):
                self.stdout.write(
                    self.style.WARNING(f"ИНН {org.inn}: {res.get('error')}")
                )
                err_n += 1
                continue

            new_kpp = res["kpp"]
            if org.kpp == new_kpp and not dry:
                skip_n += 1
                continue

            self.stdout.write(
                f"ИНН {org.inn}: КПП {org.kpp!r} → {new_kpp!r} "
                f"({res.get('name_short') or ''})"
            )

            if dry:
                ok_n += 1
                continue

            with transaction.atomic():
                Organization.objects.filter(pk=org.pk).update(kpp=new_kpp)
                if sync_certs:
                    Certificate.objects.filter(inn=org.inn).update(kpp=new_kpp)
            ok_n += 1

        self._summary(ok_n, err_n, skip_n, dry)

    def _run_from_certificates(
        self, *, dry, force, delay, only_inn, url, ensure_org, cookie, referer
    ):
        base = Certificate.objects.exclude(inn__isnull=True).exclude(inn="")
        if only_inn:
            base = base.filter(inn=only_inn)

        if not force:
            need_inns = (
                base.filter(Q(kpp__isnull=True) | Q(kpp=""))
                .values_list("inn", flat=True)
                .distinct()
            )
        else:
            need_inns = base.values_list("inn", flat=True).distinct()

        inns = sorted(set(need_inns))
        total = len(inns)
        self.stdout.write(
            f"[Certificate] уникальных ИНН к обработке: {total} (dry-run={dry}, force={force})"
        )

        if total == 0:
            self.stdout.write(self.style.WARNING("Нечего обрабатывать."))
            return

        session = requests.Session()
        ok_n = skip_n = err_n = 0
        first = True

        for inn in inns:
            if not first and delay > 0:
                time.sleep(delay)
            first = False

            res = self._fetch_kpp_http(
                inn,
                base_url=url,
                session=session,
                cookie=cookie,
                referer=referer,
            )
            if not res.get("ok"):
                self.stdout.write(
                    self.style.WARNING(f"ИНН {inn}: {res.get('error')}")
                )
                err_n += 1
                continue

            new_kpp = res["kpp"]
            name = (res.get("name_short") or "").strip() or f"ИНН {inn}"

            certs = Certificate.objects.filter(inn=inn)

            # Показать текущее состояние (первый серт)
            sample = certs.first()
            old_repr = repr(sample.kpp) if sample else "—"

            self.stdout.write(f"ИНН {inn}: КПП {old_repr} → {new_kpp!r} ({name})")

            if dry:
                ok_n += 1
                continue

            with transaction.atomic():
                if force:
                    certs.update(kpp=new_kpp)
                else:
                    certs.filter(Q(kpp__isnull=True) | Q(kpp="")).update(kpp=new_kpp)

                if ensure_org:
                    Organization.objects.update_or_create(
                        inn=inn,
                        defaults={
                            "kpp": new_kpp,
                            "name": name[:255],
                        },
                    )
            ok_n += 1

        self._summary(ok_n, err_n, skip_n, dry)

    def _summary(self, ok_n, err_n, skip_n, dry):
        self.stdout.write(
            self.style.SUCCESS(
                f"Готово: обновлено/принято {ok_n}, ошибок {err_n}, пропусков {skip_n}"
            )
        )
        if dry:
            self.stdout.write(self.style.WARNING("--dry-run: в БД ничего не записано"))
