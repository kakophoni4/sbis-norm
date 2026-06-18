from django.core.management.base import BaseCommand

from reports.services.sbis.client import _mask_proxy_url, _nodemaven_client, _nodemaven_proxies


class Command(BaseCommand):
    help = "Проверка NodeMaven: API key, credentials, proxy URL"

    def handle(self, *args, **options):
        client = _nodemaven_client()
        self.stdout.write("NodeMaven client: OK")

        try:
            info = client.get_user_info()
            user = info.get("proxy_username") or info.get("username") or "?"
            self.stdout.write(f"  proxy_username: {user}")
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"get_user_info FAIL: {e}"))
            return

        try:
            cfg = _nodemaven_proxies("7707329152", "test", city=None)
            url = (cfg.get("http") or "").strip()
            self.stdout.write(f"  proxy: {_mask_proxy_url(url)}")
            self.stdout.write(self.style.SUCCESS("NodeMaven proxy: OK"))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"getProxyConfig FAIL: {e}"))
