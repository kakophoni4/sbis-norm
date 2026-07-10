"""
Пошаговый прогон одного требования ФНС (для отладки полного цикла Saby).

  docker compose exec -T web python manage.py debug_requirement_one \\
    --inn 9707039440 \\
    --doc-id 019f36c5-ceb0-79fe-934d-c5c1bfe5d256 \\
    --stage-id 5b81ed01-bd93-5489-9c50-fc518816daa8

Без --doc-id берёт первое «Требование ФНС» из СписокСлужебныхЭтапов за --days.
Флаг --stop-after STEP: list|prepare|download|execute|read|ack (по умолчанию весь цикл).
"""
from __future__ import annotations

import json
import traceback
from datetime import datetime, timedelta

from django.core.management.base import BaseCommand

from reports.models import Certificate, Organization
from reports.services.sbis.auth import auth_sbis_by_cert
from reports.services.sbis.crypto import export_cert_der, get_fio_from_cert_file, get_thumbprint_from_cert
from reports.services.sbis.requirements import (
    _build_execute_attachments_from_prepare,
    _try_decrypt_bytes_with_cert,
    acknowledge_requirement_receipt,
    sbis_download_file_by_link,
    sbis_execute_action,
    sbis_list_service_stages,
    sbis_prepare_action,
    sbis_read_document,
)


STEPS = ("list", "prepare", "download", "execute", "read", "ack")


class Command(BaseCommand):
    help = "Пошаговый debug одного требования ФНС (prepare→decrypt→execute→ack)"

    def add_arguments(self, parser):
        parser.add_argument("--inn", required=True)
        parser.add_argument("--doc-id", default="")
        parser.add_argument("--stage-id", default="")
        parser.add_argument("--action", default="Обработать служебное")
        parser.add_argument("--days", type=int, default=30)
        parser.add_argument(
            "--stop-after",
            default="ack",
            choices=STEPS,
            help="Остановиться после шага (по умолчанию весь цикл)",
        )
        parser.add_argument(
            "--skip-execute",
            action="store_true",
            help="Не вызывать ВыполнитьДействие (только до download/read)",
        )
        parser.add_argument(
            "--ack-only",
            action="store_true",
            help="Только ПрочитатьДокумент + Утверждение (без prepare/download/execute)",
        )

    def handle(self, *args, **options):
        inn = str(options["inn"]).strip()
        days = max(1, int(options["days"]))
        stop_after = options["stop_after"]
        action_name = options["action"]
        skip_execute = bool(options["skip_execute"])

        cert = (
            Certificate.objects.filter(inn=inn, is_active=True, has_private_key=True)
            .exclude(csptest_name="")
            .order_by("-id")
            .first()
        ) or Certificate.objects.filter(inn=inn, is_active=True).exclude(csptest_name="").order_by("-id").first()
        org = Organization.objects.filter(inn=inn).first()
        kpp = ((cert.kpp if cert else "") or (org.kpp if org else "") or "").strip()
        if not cert or not kpp:
            self.stderr.write(self.style.ERROR(f"нет cert/kpp для {inn}"))
            return

        cert_path = f"/tmp/debug_req_{inn}.cer"
        export_cert_der(cert.csptest_name, cert_path)
        thumb = get_thumbprint_from_cert(cert_path)
        fio = (get_fio_from_cert_file(cert_path) or "—").strip() or "—"
        session_id = auth_sbis_by_cert(cert_path, thumb, inn=inn)
        self.stdout.write(f"INN={inn} KPP={kpp} thumb={thumb[:16]}... session={session_id[:12]}...")

        date_to = datetime.now()
        date_from = date_to - timedelta(days=days)
        date_from_str = date_from.strftime("%d.%m.%Y")
        date_to_str = date_to.strftime("%d.%m.%Y")

        # --- 1. LIST ---
        self.stdout.write(self.style.MIGRATE_HEADING(f"\n=== 1/6 LIST СписокСлужебныхЭтапов ({date_from_str}..{date_to_str}) ==="))
        listed = sbis_list_service_stages(
            inn,
            kpp=kpp,
            date_from=date_from_str,
            date_to=date_to_str,
            page_size=50,
            only_reporting=False,
        )
        if not listed.get("success"):
            self.stdout.write(self.style.ERROR(f"LIST FAIL: {json.dumps(listed.get('error'), ensure_ascii=False)[:800]}"))
            return
        docs = ((listed.get("result") or {}).get("docs") or [])
        self.stdout.write(f"docs={len(docs)}")
        for i, d in enumerate(docs, 1):
            did = (d.get("Идентификатор") or "")[:40]
            self.stdout.write(f"  [{i}] {did} | {d.get('Направление')} | {(d.get('Название') or '')[:50]}")

        doc_id = (options.get("doc_id") or "").strip()
        stage_id = (options.get("stage_id") or "").strip()
        if not doc_id:
            for d in docs:
                if "требование" in (d.get("Название") or "").lower():
                    doc_id = (d.get("Идентификатор") or "").strip()
                    for st in d.get("Этап") or []:
                        if isinstance(st, dict) and (st.get("Идентификатор") or "").strip():
                            stage_id = (st.get("Идентификатор") or "").strip()
                            acts = st.get("Действие") or []
                            if isinstance(acts, dict):
                                acts = [acts]
                            if acts and isinstance(acts[0], dict) and acts[0].get("Название"):
                                action_name = acts[0]["Название"]
                            break
                    break
        if not doc_id or not stage_id:
            self.stdout.write(self.style.ERROR("не удалось выбрать doc_id/stage_id — передай --doc-id и --stage-id"))
            return
        self.stdout.write(f"SELECTED doc_id={doc_id}")
        self.stdout.write(f"SELECTED stage_id={stage_id} action={action_name!r}")
        if stop_after == "list":
            return

        if options.get("ack_only"):
            self.stdout.write(self.style.WARNING("\n--ack-only: skip prepare/download/execute → READ + ACK"))
            stop_after = "ack"
        else:
            # --- 2. PREPARE ---
            self.stdout.write(self.style.MIGRATE_HEADING("\n=== 2/6 PREPARE ПодготовитьДействие ==="))
            try:
                prep = sbis_prepare_action(
                    inn,
                    kpp=kpp,
                    doc_id=doc_id,
                    stage_id=stage_id,
                    action_name=action_name,
                )
            except Exception:
                self.stdout.write(self.style.ERROR(traceback.format_exc()))
                return
            if not prep.get("success"):
                err_s = json.dumps(prep.get("error"), ensure_ascii=False)
                self.stdout.write(self.style.ERROR(f"PREPARE FAIL: {err_s[:1200]}"))
                if "уже обработано" in err_s.lower():
                    self.stdout.write(self.style.WARNING("Действие уже обработано → переходим к READ + ACK"))
                else:
                    return
            else:
                prepare_raw = (prep.get("result") or {}).get("raw") or {}
                session_id = (prep.get("result") or {}).get("session_id") or session_id
                thumb = (prep.get("result") or {}).get("thumbprint") or thumb
                st_list = prepare_raw.get("Этап") or []
                if isinstance(st_list, dict):
                    st_list = [st_list]
                st0 = (st_list[0] if st_list else {}) or {}
                atts = [a for a in (st0.get("Вложение") or []) if isinstance(a, dict)]
                self.stdout.write(f"PREPARE OK attachments={len(atts)}")
                for a in atts:
                    fo = a.get("Файл") or {}
                    href = (fo.get("Ссылка") or "") if isinstance(fo, dict) else ""
                    self.stdout.write(
                        f"  att id={(a.get('Идентификатор') or '')[:20]} "
                        f"name={(fo.get('Имя') if isinstance(fo, dict) else '')} "
                        f"enc={a.get('Зашифрован')} sign={a.get('ТребуетПодписание')} "
                        f"href={'yes' if href else 'no'}"
                    )
                if stop_after == "prepare":
                    return

                # --- 3. DOWNLOAD + DECRYPT ---
                self.stdout.write(self.style.MIGRATE_HEADING("\n=== 3/6 DOWNLOAD + DECRYPT ==="))
                decrypted_by_id: dict[str, bytes] = {}
                for a in atts:
                    att_id = (a.get("Идентификатор") or "").strip()
                    fo = a.get("Файл") or {}
                    if not isinstance(fo, dict):
                        continue
                    href = (fo.get("Ссылка") or "").strip()
                    if not att_id or not href:
                        self.stdout.write(f"  skip {att_id[:16] if att_id else '?'}: no href")
                        continue
                    try:
                        content, ctype = sbis_download_file_by_link(inn, session_id=session_id, href=href)
                        self.stdout.write(f"  downloaded {att_id[:20]} bytes={len(content)} ctype={ctype}")
                        if str(a.get("Зашифрован") or "").strip() == "Да":
                            content2, how = _try_decrypt_bytes_with_cert(inn=inn, thumbprint=thumb, content=content)
                            self.stdout.write(f"  decrypted {att_id[:20]} bytes={len(content2)} how={how}")
                            content = content2
                        decrypted_by_id[att_id] = content
                        head = content[:8]
                        self.stdout.write(f"  head_hex={head.hex()} head_ascii={content[:40]!r}")
                    except Exception as e:
                        self.stdout.write(self.style.ERROR(f"  DOWNLOAD/DECR FAIL {att_id[:20]}: {e}"))
                        self.stdout.write(traceback.format_exc()[-800:])
                self.stdout.write(f"decrypted_ok={len(decrypted_by_id)}/{len(atts)}")
                if stop_after == "download":
                    return

                # --- 4. EXECUTE ---
                self.stdout.write(self.style.MIGRATE_HEADING("\n=== 4/6 EXECUTE ВыполнитьДействие ==="))
                if skip_execute:
                    self.stdout.write("SKIPPED (--skip-execute)")
                else:
                    try:
                        attachments = _build_execute_attachments_from_prepare(
                            prepare_raw=prepare_raw,
                            decrypted_by_id=decrypted_by_id,
                            thumbprint=thumb,
                            csptest_name=cert.csptest_name,
                        )
                        self.stdout.write(f"execute attachments prepared: {len(attachments)}")
                        for item in attachments:
                            keys = list(item.keys())
                            has_sig = "Подпись" in item
                            has_file = "Файл" in item
                            self.stdout.write(
                                f"  {item.get('Идентификатор', '')[:20]} keys={keys} file={has_file} sig={has_sig}"
                            )
                        exe = sbis_execute_action(
                            inn,
                            session_id=session_id,
                            doc_id=doc_id,
                            stage_id=stage_id,
                            action_name=action_name,
                            thumbprint=thumb,
                            fio=fio,
                            attachments=attachments,
                        )
                        if exe.get("success"):
                            self.stdout.write(
                                self.style.SUCCESS(
                                    f"EXECUTE OK keys={list((exe.get('result') or {}).keys())[:20]}"
                                )
                            )
                        else:
                            self.stdout.write(
                                self.style.ERROR(
                                    f"EXECUTE FAIL: {json.dumps(exe.get('error'), ensure_ascii=False)[:1500]}"
                                )
                            )
                    except Exception:
                        self.stdout.write(self.style.ERROR(traceback.format_exc()))
                if stop_after == "execute":
                    return

        # --- 5. READ ---
        self.stdout.write(self.style.MIGRATE_HEADING("\n=== 5/6 READ ПрочитатьДокумент ==="))
        try:
            read = sbis_read_document(inn, session_id=session_id, doc_id=doc_id)
        except Exception:
            self.stdout.write(self.style.ERROR(traceback.format_exc()))
            return
        if not read.get("success"):
            self.stdout.write(self.style.ERROR(f"READ FAIL: {json.dumps(read.get('error'), ensure_ascii=False)[:800]}"))
            return
        result = read.get("result") or {}
        state = result.get("Состояние") or {}
        self.stdout.write(f"Состояние: {state.get('Код')} {state.get('Название')} | {state.get('Описание')}")
        stages = result.get("Этап") or []
        self.stdout.write(f"Этап count={len(stages) if isinstance(stages, list) else type(stages)}")
        # полный дамп этапов (без огромных ДвоичныеДанные)
        try:
            dump = json.loads(json.dumps(stages, ensure_ascii=False, default=str))
            def _strip(o):
                if isinstance(o, dict):
                    return {
                        k: (f"<b64 {len(v)}>" if k == "ДвоичныеДанные" and isinstance(v, str) and len(v) > 80 else _strip(v))
                        for k, v in o.items()
                    }
                if isinstance(o, list):
                    return [_strip(x) for x in o]
                return o
            self.stdout.write(json.dumps(_strip(dump), ensure_ascii=False, indent=2)[:4000])
        except Exception as e:
            self.stdout.write(f"(dump stages failed: {e})")
        has_utv = False
        for st in stages if isinstance(stages, list) else []:
            if not isinstance(st, dict):
                continue
            actions = st.get("Действие") or []
            if isinstance(actions, dict):
                actions = [actions]
            for a in actions:
                if not isinstance(a, dict):
                    continue
                aname = (a.get("Название") or "").strip()
                self.stdout.write(
                    f"  Этап={st.get('Название')!r} id={(st.get('Идентификатор') or '')[:36]} "
                    f"Действие={aname!r} sign={a.get('ТребуетПодписание')} decr={a.get('ТребуетРасшифровки')}"
                )
                if aname == "Утверждение":
                    has_utv = True
        self.stdout.write(f"has_Утверждение={has_utv}")
        if stop_after == "read":
            return

        # --- 6. ACK ---
        self.stdout.write(self.style.MIGRATE_HEADING("\n=== 6/6 ACK Утверждение (квитанция) ==="))
        if skip_execute and not options.get("ack_only"):
            self.stdout.write("SKIPPED (because --skip-execute)")
            return
        try:
            ack = acknowledge_requirement_receipt(
                inn,
                session_id=session_id,
                doc_id=doc_id,
                kpp=kpp,
                thumbprint=thumb,
                fio=fio,
                csptest_name=cert.csptest_name,
            )
            self.stdout.write(json.dumps(ack, ensure_ascii=False, default=str)[:2000])
            if ack.get("receipt_sent"):
                self.stdout.write(self.style.SUCCESS("ACK receipt_sent=True"))
            elif ack.get("skipped"):
                self.stdout.write(self.style.WARNING(f"ACK skipped: {ack.get('comment')}"))
                st = ack.get("state") or {}
                self.stdout.write(f"  state={st.get('Код')} {st.get('Название')} | {st.get('Описание')}")
            else:
                self.stdout.write(self.style.ERROR(f"ACK FAIL: {ack.get('error')}"))
        except Exception:
            self.stdout.write(self.style.ERROR(traceback.format_exc()))

        self.stdout.write(self.style.MIGRATE_HEADING("\n=== DONE debug_requirement_one ==="))
