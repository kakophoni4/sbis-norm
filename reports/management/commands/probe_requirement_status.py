"""
Диагностика статусов требований ФНС в СБИС (эталон vs дока Saby).

  docker compose exec -T web python manage.py probe_requirement_status --inn 9707039440
  docker compose exec -T web python manage.py probe_requirement_status --inn 9707039440 --days 10
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta

from django.core.management.base import BaseCommand

from reports.models import Certificate, Organization, RequirementDocument
from reports.services.sbis.crypto import export_cert_der, get_fio_from_cert_file, get_thumbprint_from_cert
from reports.services.sbis.auth import auth_sbis_by_cert
from reports.services.sbis.requirements import sbis_list_service_stages
from reports.services.sbis.client import sbis_rpc
from reports.services.sbis.constants import REPORTING_URL


class Command(BaseCommand):
    help = "Прочитать статусы требований в СБИС (ПрочитатьДокумент + СписокСлужебныхЭтапов)"

    def add_arguments(self, parser):
        parser.add_argument("--inn", required=True)
        parser.add_argument("--days", type=int, default=10)
        parser.add_argument("--limit-docs", type=int, default=20)

    def handle(self, *args, **options):
        inn = str(options["inn"]).strip()
        days = max(1, int(options["days"]))
        limit_docs = max(1, int(options["limit_docs"]))

        cert = (
            Certificate.objects.filter(inn=inn, is_active=True, has_private_key=True)
            .exclude(csptest_name="")
            .order_by("-id")
            .first()
        )
        if not cert:
            cert = Certificate.objects.filter(inn=inn, is_active=True).exclude(csptest_name="").order_by("-id").first()
        org = Organization.objects.filter(inn=inn).first()
        kpp = ((cert.kpp if cert else "") or (org.kpp if org else "") or "").strip()
        if not cert or not kpp:
            self.stderr.write(f"нет cert/kpp для {inn}")
            return

        cert_path = f"/tmp/probe_{inn}.cer"
        export_cert_der(cert.csptest_name, cert_path)
        thumb = get_thumbprint_from_cert(cert_path)
        session_id = auth_sbis_by_cert(cert_path, thumb, inn=inn)
        self.stdout.write(f"INN={inn} KPP={kpp} session={session_id[:12]}...")

        date_to = datetime.now()
        date_from = date_to - timedelta(days=days)
        stages = sbis_list_service_stages(
            inn,
            date_from=date_from.strftime("%d.%m.%Y"),
            date_to=date_to.strftime("%d.%m.%Y"),
            page_size=50,
            only_reporting=False,
        )
        docs = ((stages.get("result") or {}).get("docs") or []) if stages.get("success") else []
        self.stdout.write(f"\n=== СписокСлужебныхЭтапов: {len(docs)} docs (success={stages.get('success')}) ===")
        if not stages.get("success"):
            self.stdout.write(json.dumps(stages.get("error"), ensure_ascii=False, indent=2)[:800])

        for i, d in enumerate(docs[:limit_docs], 1):
            doc_id = (d.get("Идентификатор") or "")[:40]
            title = (d.get("Название") or "")[:60]
            direction = d.get("Направление")
            self.stdout.write(f"\n[{i}] {doc_id} | {direction} | {title}")
            for st in d.get("Этап") or []:
                if not isinstance(st, dict):
                    continue
                st_name = st.get("Название") or ""
                st_id = (st.get("Идентификатор") or "")[:36]
                actions = st.get("Действие") or []
                if isinstance(actions, dict):
                    actions = [actions]
                anames = []
                for a in actions:
                    if isinstance(a, dict):
                        anames.append(
                            f"{a.get('Название')} sign={a.get('ТребуетПодписание')} decr={a.get('ТребуетРасшифровки')}"
                        )
                self.stdout.write(f"    stage={st_name!r} id={st_id} actions={anames}")

        db_docs = list(RequirementDocument.objects.filter(inn=inn).order_by("-document_date")[:limit_docs])
        self.stdout.write(f"\n=== RequirementDocument in DB: {len(db_docs)} ===")
        for r in db_docs:
            self.stdout.write(f"\n--- DB {r.sbis_doc_id} date={r.document_date} title={r.doc_title[:50]}")
            data = sbis_rpc(
                inn=inn,
                session_id=session_id,
                method="СБИС.ПрочитатьДокумент",
                params={"Документ": {"Идентификатор": r.sbis_doc_id}},
                timeout=45,
            )
            if data.get("error"):
                self.stdout.write(f"  ПрочитатьДокумент ERROR: {data['error']}")
                continue
            result = data.get("result") or {}
            state = (result.get("Состояние") or {})
            self.stdout.write(f"  Состояние: {state.get('Код')} {state.get('Название')} | {state.get('Описание')}")
            for st in result.get("Этап") or []:
                if not isinstance(st, dict):
                    continue
                actions = st.get("Действие") or []
                if isinstance(actions, dict):
                    actions = [actions]
                for a in actions:
                    if not isinstance(a, dict):
                        continue
                    self.stdout.write(
                        f"  Этап={st.get('Название')!r} Действие={a.get('Название')!r} "
                        f"sign={a.get('ТребуетПодписание')} decr={a.get('ТребуетРасшифровки')}"
                    )
                    if (a.get("Название") or "").strip() == "Утверждение":
                        self.stdout.write("  >>> нужен ack квитанции (Утверждение) по доке Saby")

        self.stdout.write("\nDONE probe")
