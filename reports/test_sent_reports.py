import base64
import copy
import tempfile
from datetime import datetime
from pathlib import Path
from unittest.mock import patch, Mock
from zoneinfo import ZoneInfo

from django.test import SimpleTestCase, override_settings
from django.urls import path
from rest_framework.test import APIClient

from reports.api.views.sent_reports import SentReports1CView, SentReportXml1CView
from reports.services.sbis import sent_reports as s

urlpatterns = [path("list/", SentReports1CView.as_view()), path("xml/", SentReportXml1CView.as_view())]
INN = "9729355495"
DOC_ID = "eea440ed-6d5d-4ec4-9565-ca7d9bf91045"


def document():
    now = datetime.now(ZoneInfo("Europe/Moscow"))
    return {
        "Идентификатор": DOC_ID, "Дата": "01.01.2020", "Тип": "ОтчетФНС",
        "Направление": "Исходящий", "НашаОрганизация": {"СвЮЛ": {"ИНН": INN}},
        "Расширение": {"Год": "2025", "КодПериода": "21", "НомерКорректировки": "0",
                       "ЕстьДокументооборот": "Да", "НомерОтправки": "1"},
        "Состояние": {"Код": "9", "Название": "Отчет не сдан"},
        "Событие": [{"Название": "ДекларацияНП", "ДатаВремя": now.strftime("%d.%m.%Y %H.%M.%S")}],
    }


def attachment(name, **kwargs):
    return {"Направление": "Исходящий", "Служебный": "Нет",
            "Файл": {"Имя": name, "Ссылка": "https://disk.sbis.ru/test"}, **kwargs}


class SentReportsTests(SimpleTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        override = override_settings(ONEC_SENT_REPORTS_CACHE_DIR=self.temp.name)
        override.enable()
        self.addCleanup(override.disable)
        auth = patch.object(s, "_session", return_value="secret-session")
        self.auth = auth.start()
        self.addCleanup(auth.stop)
        self.doc = document()
        self.day = s._sent_at(self.doc)[:10]

    def page(self, docs, more="Нет"):
        return {"Документ": docs, "Навигация": {"ЕстьЕще": more}}

    def test_all_pages_old_document_recent_send_and_date_cache(self):
        draft = copy.deepcopy(self.doc)
        draft.update(Идентификатор="parent", Направление="Внутренний")
        with patch.object(s, "_rpc", side_effect=[self.page([draft], "Да"), self.page([self.doc]), self.doc]) as rpc:
            result = s.list_sent_reports(INN, 30)
        self.assertTrue(result["complete"])
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["items"][0]["document_date"], "2020-01-01")
        self.assertEqual(result["items"][0]["period_code"], "21")
        self.assertNotIn("ДатаС", rpc.call_args_list[0].args[3]["Фильтр"])
        self.assertNotIn("НашаОрганизация", rpc.call_args_list[0].args[3]["Фильтр"])
        self.assertEqual(rpc.call_args_list[1].args[3]["Фильтр"]["Навигация"]["Страница"], "1")
        with patch.object(s, "_rpc", return_value=self.page([self.doc])) as rpc:
            self.assertTrue(s.list_sent_reports(INN, 30)["success"])
            self.assertEqual(rpc.call_count, 1)

    def test_unknown_date_not_replaced_by_creation(self):
        self.doc["Событие"] = []
        self.doc["ДатаВремяСоздания"] = "01.10.2026 12.00.00"
        with patch.object(s, "_rpc", side_effect=[self.page([self.doc]), self.doc]):
            result = s.list_sent_reports(INN, 30)
        self.assertFalse(result["complete"])
        self.assertEqual(result["errors"][0]["code"], "send_date_unknown")

    def test_pagination_failure_is_partial(self):
        with patch.object(s, "_rpc", side_effect=[self.page([self.doc], "Да"), self.doc,
                                                   s.ReportError("sbis_error", "failed")]):
            result = s.list_sent_reports(INN, 30)
        self.assertFalse(result["success"])
        self.assertEqual(result["count"], 1)

    def test_repeated_page_stops(self):
        with patch.object(s, "_rpc", side_effect=[self.page([self.doc], "Да"), self.doc,
                                                   self.page([self.doc], "Да")]):
            self.assertEqual(s.list_sent_reports(INN, 30)["errors"][-1]["code"], "pagination_error")

    def test_other_inn_and_unsent_excluded(self):
        other = copy.deepcopy(self.doc)
        other["НашаОрганизация"]["СвЮЛ"]["ИНН"] = "0000000000"
        self.doc["Состояние"]["Код"] = "0"
        with patch.object(s, "_rpc", return_value=self.page([other, self.doc])):
            self.assertEqual(s.list_sent_reports(INN, 30)["items"], [])

    def test_validation_before_auth(self):
        for days in (0, -1, True, "30", 3661, None):
            with self.assertRaises(s.ReportError):
                s.list_sent_reports(INN, days)
        for args in (("../x", DOC_ID, self.day), (INN, "../x", self.day), (INN, DOC_ID, "2026-02-30")):
            with self.assertRaises(s.ReportError):
                s.download_sent_report(*args)
        self.auth.assert_not_called()

    def test_package_exact_bytes_books_and_no_receipts_cached(self):
        self.doc["Вложение"] = [attachment("NO_NDS_test.xml"), attachment("NO_NDS.8_test.xml"),
                                  attachment("NO_NDS.9_test.xml"), attachment("KV_test.xml", Служебный="Да")]
        content = '<?xml version="1.0" encoding="windows-1251"?><Файл/>'.encode("cp1251")
        with patch.object(s, "_card", return_value=self.doc), patch.object(s, "_download", return_value=content) as download:
            result = s.download_sent_report(INN, DOC_ID, self.day)
            self.assertEqual(download.call_count, 3)
        self.assertEqual([f["role"] for f in result["files"]], ["report", "purchase_book", "sales_book"])
        self.assertEqual(base64.b64decode(result["files"][0]["content_base64"]), content)
        self.auth.reset_mock()
        with patch.object(s, "_card") as card:
            self.assertTrue(s.download_sent_report(INN, DOC_ID, self.day)["cached"])
            card.assert_not_called()
            self.auth.assert_not_called()

    def test_wrong_date_no_download(self):
        with patch.object(s, "_card", return_value=self.doc), patch.object(s, "_download") as download:
            with self.assertRaisesRegex(s.ReportError, "не совпадает"):
                s.download_sent_report(INN, DOC_ID, "2000-01-01")
            download.assert_not_called()

    def test_foreign_card_denied(self):
        self.doc["НашаОрганизация"] = {}
        with patch.object(s, "_rpc", return_value=self.doc):
            with self.assertRaises(s.ReportError):
                s.download_sent_report(INN, DOC_ID, self.day)

    def test_failed_book_never_caches_partial_package(self):
        self.doc["Вложение"] = [attachment("NO_NDS_test.xml"), attachment("NO_NDS.9_test.xml")]
        with patch.object(s, "_card", return_value=self.doc), patch.object(s, "_download", side_effect=[
                '<Файл/>'.encode(), s.ReportError("failed", "failed")]):
            with self.assertRaises(s.ReportError):
                s.download_sent_report(INN, DOC_ID, self.day)
        self.assertFalse(list(Path(self.temp.name).rglob("*.json")))

    def test_html_and_dtd_rejected(self):
        self.doc["Вложение"] = [attachment("NO_NDS_test.xml")]
        for content in (b"<html>error</html>", b'<!DOCTYPE x [<!ENTITY a "x">]><x>&a;</x>'):
            with patch.object(s, "_card", return_value=self.doc), patch.object(s, "_download", return_value=content):
                with self.assertRaises(s.ReportError):
                    s.download_sent_report(INN, DOC_ID, self.day)

    def test_send_event_files_preferred_to_newer_revision(self):
        self.doc["Вложение"] = [attachment("NO_NDS_new.xml")]
        self.doc["Событие"][0]["Вложение"] = [attachment("NO_NDS_sent.xml")]
        with patch.object(s, "_card", return_value=self.doc), patch.object(s, "_download", return_value='<Файл/>'.encode()):
            result = s.download_sent_report(INN, DOC_ID, self.day)
        self.assertEqual(result["files"][0]["name"], "NO_NDS_sent.xml")

    def test_missing_main_and_missing_url_not_success(self):
        for attachments in ([], [attachment("NO_NDS.8_test.xml")],
                            [{"Направление": "Исходящий", "Служебный": "Нет", "Файл": {"Имя": "NO_NDS_test.xml"}}]):
            self.doc["Вложение"] = attachments
            with patch.object(s, "_card", return_value=self.doc), patch.object(s, "_download", return_value='<Файл/>'.encode()):
                with self.assertRaises(s.ReportError):
                    s.download_sent_report(INN, DOC_ID, self.day)

    def test_cache_corruption_forces_refetch(self):
        self.doc["Вложение"] = [attachment("NO_NDS_test.xml")]
        with patch.object(s, "_card", return_value=self.doc), patch.object(s, "_download", return_value='<Файл/>'.encode()) as download:
            s.download_sent_report(INN, DOC_ID, self.day)
            path = next(Path(self.temp.name).rglob("*.json"))
            data = s._read(path)
            data["files"][0]["sha256"] = "corrupt"
            s._write(path, data)
            self.assertFalse(s.download_sent_report(INN, DOC_ID, self.day)["cached"])
            self.assertEqual(download.call_count, 2)

    @override_settings(ONEC_API_TOKEN="", ONEC_API_TOKEN_PREVIOUS="")
    def test_missing_server_token_fail_closed(self):
        for route in ("/list/", "/xml/"):
            self.assertIn(APIClient().post(route, {}, format="json", HTTP_X_1C_API_TOKEN="anything").status_code, (401, 403))
        self.auth.assert_not_called()

    @override_settings(ONEC_API_TOKEN="test-token")
    def test_api_success_and_partial_contract(self):
        with patch("reports.api.views.sent_reports.list_sent_reports", return_value={"success":False, "complete":False, "items":[]}):
            response = APIClient().post("/list/", {"inn":INN,"days":30}, format="json", HTTP_X_1C_API_TOKEN="test-token")
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.data["complete"])
        with patch("reports.api.views.sent_reports.download_sent_report", return_value={"success":True, "files":[]}):
            response = APIClient().post("/xml/", {"inn":INN,"sbis_doc_id":DOC_ID,"sent_date":self.day}, format="json", HTTP_X_1C_API_TOKEN="test-token")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data["success"])

    def test_url_allowlist_and_redirect(self):
        for url in ("http://disk.sbis.ru/a", "https://127.0.0.1/a", "https://sbis.ru.evil.com/a"):
            with self.assertRaises(s.ReportError):
                s._download(INN, "session", url)
        response = Mock(status_code=302)
        with patch.object(s, "_sbis_request", return_value=response) as request:
            with self.assertRaises(s.ReportError):
                s._download(INN, "session", "https://disk.sbis.ru/a")
            self.assertFalse(request.call_args.kwargs["allow_redirects"])
            response.close.assert_called_once()

    def test_missing_kpp_is_not_retried_as_proxy_failure(self):
        from reports.services.sbis import client
        response = Mock(status_code=500, text='{"error":{"message":"Ошибка в реквизитах: КПП должен быть заполнен."}}')
        session = Mock()
        session.request.return_value = response
        with patch.object(client, "_thread_local_sbis_session", return_value=session):
            result = client._sbis_request("POST", "https://online.sbis.ru/service/",
                headers={}, proxy_url_override="http://proxy.example:8080")
        self.assertIs(result, response)
        self.assertEqual(session.request.call_count, 1)

    @override_settings(ONEC_API_TOKEN="test-token")
    def test_api_token_and_input(self):
        client = APIClient()
        for route in ("/list/", "/xml/"):
            self.assertIn(client.post(route, {}, format="json").status_code, (401, 403))
            self.assertIn(client.post(route, {}, format="json", HTTP_X_1C_API_TOKEN="wrong").status_code, (401, 403))
            self.assertEqual(client.post(route, [], format="json", HTTP_X_1C_API_TOKEN="test-token").status_code, 400)
            self.assertEqual(client.post(route, {}, format="json", HTTP_X_1C_API_TOKEN="test-token").status_code, 400)
        self.auth.assert_not_called()
