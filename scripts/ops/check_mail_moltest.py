#!/usr/bin/env python
import imaplib
import os
import ssl


IMAP_HOST = os.environ.get("MOLTEST_IMAP_HOST", "imap.example.com")
IMAP_PORT = int(os.environ.get("MOLTEST_IMAP_PORT", "993"))
IMAP_USER = os.environ.get("MOLTEST_IMAP_USER", "[email protected]")
IMAP_PASS = os.environ.get("MOLTEST_IMAP_PASS", "PASSWORD")


def main():
    print("=== Подключение к IMAP ===")
    print(f"HOST: {IMAP_HOST}")
    print(f"PORT: {IMAP_PORT}")
    print(f"USER: {IMAP_USER}")

    ctx = ssl.create_default_context()
    mail = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT, ssl_context=ctx)

    mail.login(IMAP_USER, IMAP_PASS)
    print("LOGIN: OK")

    print("\n=== Список ящиков (LIST) ===")
    typ, mailboxes = mail.list()
    print("STATUS:", typ)
    for m in mailboxes:
        try:
            print(m.decode())
        except Exception:
            print(m)

    print("\n=== STATUS INBOX (MESSAGES / UNSEEN) ===")
    typ, data = mail.status("INBOX", "(MESSAGES UNSEEN)")
    print("STATUS:", typ, data)

    print("\n=== SELECT INBOX ===")
    typ, data = mail.select("INBOX", readonly=True)
    print("SELECT:", typ, data)

    print("\n=== SEARCH ALL в INBOX ===")
    typ, msgnums = mail.search(None, "ALL")
    print("SEARCH ALL:", typ, msgnums)

    if typ == "OK":
        ids = msgnums[0].split()
        print(f"Всего сообщений в INBOX по SEARCH ALL: {len(ids)}")
        # покажем первые несколько UID/номеров
        print("Первые 10 msg ids:", ids[:10])

    print("\n=== SEARCH UNSEEN в INBOX ===")
    typ, msgnums = mail.search(None, "UNSEEN")
    print("SEARCH UNSEEN:", typ, msgnums)
    if typ == "OK":
        ids = msgnums[0].split()
        print(f"Непрочитанных сообщений: {len(ids)}")

    mail.logout()
    print("\nLOGOUT: OK")


if __name__ == "__main__":
    main()
