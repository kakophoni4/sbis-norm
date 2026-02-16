#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import base64
from pycades._pycades import CadesStore, CadesEnvelopedData

def decrypt_b64_with_pycades(encrypted_b64, inn):
    """Расшифровывает строку Base64 с помощью pycades."""
    try:
        # Декодируем Base64
        encrypted_data = base64.b64decode(encrypted_b64)

        # Открываем хранилище личных сертификатов пользователя
        store = CadesStore()
        store.open(CadesStore.STORE_LOCATION_CURRENT_USER, "My", CadesStore.STORE_OPEN_MODE_READ_ONLY)

        # Ищем сертификат по ИНН
        # Примечание: pycades не имеет прямого способа поиска по ИНН.
        # Мы перебираем все сертификаты и ищем ИНН в поле Subject.
        recipient_cert = None
        for cert in store.certificates:
            subject_name = cert.get_subject()
            if f"ИНН={inn}" in subject_name or f"INN={inn}" in subject_name:
                recipient_cert = cert
                break
        
        if not recipient_cert:
            print(f"[!] Сертификат с ИНН {inn} не найден в личном хранилище.")
            store.close()
            return None

        print(f"[+] Найден сертификат: {recipient_cert.get_subject()}")

        # Создаем объект для расшифровки
        enveloped_data = CadesEnvelopedData()
        
        # Добавляем получателя (наш сертификат)
        enveloped_data.recipients.add(recipient_cert)
        
        # Расшифровываем
        enveloped_data.decrypt(encrypted_data)
        
        decrypted_content = enveloped_data.get_content()
        
        store.close()
        
        # pycades может вернуть байты, декодируем в строку
        return decrypted_content.decode('utf-8', errors='ignore').strip()

    except Exception as e:
        print(f"[!] Ошибка при расшифровке с помощью pycades: {e}")
        return None

def main():
    parser = argparse.ArgumentParser(description="Расшифровка токена СБИС с помощью pycades.")
    parser.add_argument("encrypted_b64_string", help="Зашифрованная строка Base64.")
    parser.add_argument("--inn", required=True, help="ИНН владельца сертификата.")
    # Аргумент --container больше не нужен, так как pycades работает с хранилищем Windows
    
    args = parser.parse_args()

    decrypted_token = decrypt_b64_with_pycades(args.encrypted_b64_string, args.inn)

    if decrypted_token:
        print("\n" + "="*50)
        print("Расшифрованный токен:")
        print(decrypted_token)
        print("="*50)
    else:
        print("\n[!] Расшифровка не удалась.")

if __name__ == "__main__":
    main()
