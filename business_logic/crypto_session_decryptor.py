# -*- coding: utf-8 -*-
import ctypes
from ctypes import wintypes
import base64
import sys

# --- Константы для CryptoAPI ---
PROV_GOST_2012_256 = 80
PROV_GOST_2001_DH = 75
PROV_GOST_94_DH = 71
CRYPT_VERIFYCONTEXT = 0xF0000000
CRYPT_MACHINE_KEYSET = 0x20
CRYPT_FIRST = 1
CRYPT_NEXT = 2
PP_ENUMCONTAINERS = 2
KP_CERTIFICATE = 26
AT_KEYEXCHANGE = 1
AT_SIGNATURE = 2
X509_ASN_ENCODING = 1
PKCS_7_ASN_ENCODING = 0x00010000
CERT_NAME_SIMPLE_DISPLAY_TYPE = 3
CMSG_ENVELOPED = 3
CMSG_CTRL_DECRYPT = 2
CMSG_CONTENT_PARAM = 2
CMSG_TYPE_PARAM = 1
CMSG_RECIPIENT_COUNT_PARAM = 17
CMSG_RECIPIENT_INFO_PARAM = 19

# --- Загрузка библиотек ---
advapi32 = ctypes.windll.advapi32
crypt32 = ctypes.windll.crypt32
kernel32 = ctypes.windll.kernel32

# --- Определение типов ---
HCRYPTPROV = ctypes.c_ulonglong
HCRYPTKEY = ctypes.c_ulonglong
HCRYPTMSG = ctypes.c_void_p

# --- Прототипы функций ---
kernel32.GetLastError.argtypes = []
kernel32.GetLastError.restype = wintypes.DWORD

advapi32.CryptAcquireContextA.argtypes = [ctypes.POINTER(HCRYPTPROV), ctypes.c_char_p, ctypes.c_char_p, wintypes.DWORD,
                                          wintypes.DWORD]
advapi32.CryptAcquireContextA.restype = wintypes.BOOL
advapi32.CryptReleaseContext.argtypes = [HCRYPTPROV, wintypes.DWORD]
advapi32.CryptReleaseContext.restype = wintypes.BOOL
advapi32.CryptGetUserKey.argtypes = [HCRYPTPROV, wintypes.DWORD, ctypes.POINTER(HCRYPTKEY)]
advapi32.CryptGetUserKey.restype = wintypes.BOOL
advapi32.CryptDestroyKey.argtypes = [HCRYPTKEY]
advapi32.CryptDestroyKey.restype = wintypes.BOOL
advapi32.CryptGetKeyParam.argtypes = [HCRYPTKEY, wintypes.DWORD, ctypes.POINTER(wintypes.BYTE),
                                      ctypes.POINTER(wintypes.DWORD), wintypes.DWORD]
advapi32.CryptGetKeyParam.restype = wintypes.BOOL
advapi32.CryptGetProvParam.argtypes = [HCRYPTPROV, wintypes.DWORD, ctypes.POINTER(wintypes.BYTE),
                                       ctypes.POINTER(wintypes.DWORD), wintypes.DWORD]
advapi32.CryptGetProvParam.restype = wintypes.BOOL

crypt32.CertCreateCertificateContext.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.BYTE), wintypes.DWORD]
crypt32.CertCreateCertificateContext.restype = ctypes.c_void_p
crypt32.CertGetNameStringW.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                       wintypes.LPWSTR, wintypes.DWORD]
crypt32.CertGetNameStringW.restype = wintypes.DWORD
crypt32.CertFreeCertificateContext.argtypes = [ctypes.c_void_p]
crypt32.CertFreeCertificateContext.restype = wintypes.BOOL
crypt32.CryptMsgOpenToDecode.argtypes = [wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, HCRYPTPROV, ctypes.c_void_p,
                                         ctypes.c_void_p]
crypt32.CryptMsgOpenToDecode.restype = HCRYPTMSG
crypt32.CryptMsgUpdate.argtypes = [HCRYPTMSG, ctypes.POINTER(wintypes.BYTE), wintypes.DWORD, wintypes.BOOL]
crypt32.CryptMsgUpdate.restype = wintypes.BOOL
crypt32.CryptMsgControl.argtypes = [HCRYPTMSG, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p]
crypt32.CryptMsgControl.restype = wintypes.BOOL
crypt32.CryptMsgGetParam.argtypes = [HCRYPTMSG, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                     ctypes.POINTER(wintypes.DWORD)]
crypt32.CryptMsgGetParam.restype = wintypes.BOOL
crypt32.CryptMsgClose.argtypes = [HCRYPTMSG]
crypt32.CryptMsgClose.restype = wintypes.BOOL


# Структура для параметров расшифровки
class CMSG_CTRL_DECRYPT_PARA(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("hCryptProv", HCRYPTPROV),
        ("dwKeySpec", wintypes.DWORD),
        ("dwRecipientIndex", wintypes.DWORD)
    ]


class CryptoSessionDecryptor:
    """
    Улучшенная версия класса для расшифровки сессии СБИС с помощью CryptoAPI.
    """

    def __init__(self, certificate_fio):
        if not certificate_fio:
            raise ValueError("Необходимо указать ФИО владельца сертификата.")
        self.certificate_fio = certificate_fio.lower()
        self._h_prov = None
        self._p_cert_context = None
        self._container_name = None

    def _find_certificate(self):
        """
        Ищет сертификат по ФИО в хранилище пользователя, а затем компьютера.
        """
        print(f"Поиск сертификата для: {self.certificate_fio.upper()}")

        # Попробуем разные провайдеры
        providers = [PROV_GOST_2012_256, PROV_GOST_2001_DH, PROV_GOST_94_DH]

        for provider in providers:
            print(f"Пробуем провайдер: {provider}")

            for flag_set in [0, CRYPT_MACHINE_KEYSET]:
                storage_name = "Пользователь" if flag_set == 0 else "Машина"
                print(f"Поиск в хранилище: {storage_name}")

                h_prov_verify = HCRYPTPROV()
                if not advapi32.CryptAcquireContextA(
                        ctypes.byref(h_prov_verify),
                        None, None,
                        provider,
                        CRYPT_VERIFYCONTEXT | flag_set
                ):
                    continue

                try:
                    dw_flags = CRYPT_FIRST
                    dw_data_len = wintypes.DWORD(0)

                    if not advapi32.CryptGetProvParam(h_prov_verify, PP_ENUMCONTAINERS, None, ctypes.byref(dw_data_len),
                                                      dw_flags):
                        continue

                    pb_data = (wintypes.BYTE * dw_data_len.value)()

                    while advapi32.CryptGetProvParam(h_prov_verify, PP_ENUMCONTAINERS, pb_data,
                                                     ctypes.byref(dw_data_len), dw_flags):
                        dw_flags = CRYPT_NEXT

                        try:
                            container_name = None
                            for encoding in ['cp1251', 'utf-8', 'latin-1']:
                                try:
                                    container_name = ctypes.string_at(pb_data).decode(encoding, errors='ignore')
                                    break
                                except:
                                    continue

                            if not container_name:
                                continue

                            print(f"Проверяем контейнер: {container_name}")

                            # Получаем контекст для конкретного контейнера
                            h_cert_prov = HCRYPTPROV()
                            if not advapi32.CryptAcquireContextA(
                                    ctypes.byref(h_cert_prov),
                                    container_name.encode('cp1251'),
                                    None,
                                    provider,
                                    flag_set
                            ):
                                continue

                            # Проверяем оба типа ключей
                            for key_type in [AT_KEYEXCHANGE, AT_SIGNATURE]:
                                h_key = HCRYPTKEY()
                                if not advapi32.CryptGetUserKey(h_cert_prov, key_type, ctypes.byref(h_key)):
                                    continue

                                try:
                                    # Получаем сертификат из ключа
                                    cb_cert = wintypes.DWORD(0)
                                    if not advapi32.CryptGetKeyParam(h_key, KP_CERTIFICATE, None, ctypes.byref(cb_cert),
                                                                     0):
                                        continue

                                    pb_cert = (wintypes.BYTE * cb_cert.value)()
                                    if not advapi32.CryptGetKeyParam(h_key, KP_CERTIFICATE, pb_cert,
                                                                     ctypes.byref(cb_cert), 0):
                                        continue

                                    # Создаем контекст сертификата
                                    p_cert_context = crypt32.CertCreateCertificateContext(
                                        X509_ASN_ENCODING, pb_cert, cb_cert.value
                                    )
                                    if not p_cert_context:
                                        continue

                                    # Получаем имя из сертификата
                                    name_size = crypt32.CertGetNameStringW(
                                        p_cert_context, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, None, 0
                                    )
                                    if name_size > 0:
                                        cert_name_buffer = (ctypes.c_wchar * name_size)()
                                        crypt32.CertGetNameStringW(
                                            p_cert_context, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None,
                                            cert_name_buffer, name_size
                                        )

                                        cert_name = cert_name_buffer.value.lower()
                                        print(f"Найден сертификат: {cert_name_buffer.value}")

                                        # Проверяем, подходит ли сертификат
                                        if self.certificate_fio in cert_name:
                                            print(f"Сертификат подходит! Контейнер: {container_name}, Ключ: {key_type}")
                                            self._p_cert_context = p_cert_context
                                            self._h_prov = h_cert_prov
                                            self._container_name = container_name
                                            return True
                                        else:
                                            crypt32.CertFreeCertificateContext(p_cert_context)
                                    else:
                                        crypt32.CertFreeCertificateContext(p_cert_context)

                                finally:
                                    advapi32.CryptDestroyKey(h_key)

                            if self._h_prov != h_cert_prov:
                                advapi32.CryptReleaseContext(h_cert_prov, 0)

                        except Exception as e:
                            print(f"Ошибка при обработке контейнера: {e}")
                            continue

                        # Подготавливаем буфер для следующего контейнера
                        dw_data_len = wintypes.DWORD(dw_data_len.value)
                        pb_data = (wintypes.BYTE * dw_data_len.value)()

                finally:
                    advapi32.CryptReleaseContext(h_prov_verify, 0)

        print("Подходящий сертификат не найден")
        return False

    def decrypt(self, encrypted_session_key_b64):
        """
        Расшифровывает ключ сессии СБИС с улучшенной обработкой ошибок.
        """
        if not self._find_certificate():
            print(f"Ошибка: Сертификат для '{self.certificate_fio.upper()}' не найден в хранилище.")
            return None

        try:
            print("Начинаем расшифровку...")
            print(f"Размер зашифрованной строки: {len(encrypted_session_key_b64)} символов")

            encrypted_bytes = base64.b64decode(encrypted_session_key_b64)
            print(f"Размер зашифрованных данных: {len(encrypted_bytes)} байт")

            encrypted_array = (ctypes.c_ubyte * len(encrypted_bytes))(*encrypted_bytes)

            # Открываем сообщение для декодирования
            h_msg = crypt32.CryptMsgOpenToDecode(
                PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
                0,  # dwFlags
                0,  # dwMsgType (0 = автоопределение)
                self._h_prov,  # Используем наш провайдер
                None,  # pRecipientInfo
                None  # pStreamInfo
            )

            if not h_msg:
                error_code = kernel32.GetLastError()
                print(f"Ошибка CryptMsgOpenToDecode: {error_code}")
                return None

            try:
                # Обновляем сообщение зашифрованными данными
                if not crypt32.CryptMsgUpdate(h_msg, ctypes.cast(encrypted_array, ctypes.POINTER(wintypes.BYTE)),
                                              len(encrypted_bytes), True):
                    error_code = kernel32.GetLastError()
                    print(f"Ошибка CryptMsgUpdate: {error_code}")
                    return None

                # Получаем количество получателей
                recipient_count = wintypes.DWORD()
                recipient_count_size = wintypes.DWORD(ctypes.sizeof(wintypes.DWORD))
                if crypt32.CryptMsgGetParam(h_msg, CMSG_RECIPIENT_COUNT_PARAM, 0, ctypes.byref(recipient_count),
                                            ctypes.byref(recipient_count_size)):
                    print(f"Количество получателей: {recipient_count.value}")

                # Пробуем расшифровать для каждого получателя
                for recipient_index in range(recipient_count.value if recipient_count.value else 1):
                    print(f"Попытка расшифровки для получателя {recipient_index}")

                    # Настраиваем параметры расшифровки
                    decrypt_para = CMSG_CTRL_DECRYPT_PARA()
                    decrypt_para.cbSize = ctypes.sizeof(CMSG_CTRL_DECRYPT_PARA)
                    decrypt_para.hCryptProv = self._h_prov
                    decrypt_para.dwRecipientIndex = recipient_index

                    # Пробуем разные типы ключей
                    for key_spec in [AT_KEYEXCHANGE, AT_SIGNATURE]:
                        decrypt_para.dwKeySpec = key_spec
                        key_name = "обмена" if key_spec == AT_KEYEXCHANGE else "подписи"
                        print(f"  Попытка с ключом {key_name}...")

                        success = crypt32.CryptMsgControl(h_msg, 0, CMSG_CTRL_DECRYPT, ctypes.byref(decrypt_para))

                        if success:
                            print(f"  Расшифровка успешна с ключом {key_name}!")

                            # Получаем размер расшифрованных данных
                            dw_data_len = wintypes.DWORD(0)
                            if not crypt32.CryptMsgGetParam(h_msg, CMSG_CONTENT_PARAM, 0, None,
                                                            ctypes.byref(dw_data_len)):
                                error_code = kernel32.GetLastError()
                                print(f"  Ошибка получения размера данных: {error_code}")
                                continue

                            print(f"  Размер расшифрованных данных: {dw_data_len.value} байт")

                            # Получаем расшифрованные данные
                            pb_data = (wintypes.BYTE * dw_data_len.value)()
                            if not crypt32.CryptMsgGetParam(h_msg, CMSG_CONTENT_PARAM, 0, pb_data,
                                                            ctypes.byref(dw_data_len)):
                                error_code = kernel32.GetLastError()
                                print(f"  Ошибка получения данных: {error_code}")
                                continue

                            decrypted_bytes = bytes(pb_data[:dw_data_len.value])
                            print(f"  Первые 50 байт: {decrypted_bytes[:50].hex()}")

                            # Декодируем результат
                            try:
                                session_id = decrypted_bytes.decode('utf-8')
                            except UnicodeDecodeError:
                                try:
                                    session_id = decrypted_bytes.decode('latin-1')
                                except UnicodeDecodeError:
                                    session_id = decrypted_bytes.decode('cp1251', errors='ignore')

                            return session_id.strip()
                        else:
                            error_code = kernel32.GetLastError()
                            print(f"  Ошибка с ключом {key_name}: {error_code}")

                print("Не удалось расшифровать сообщение")
                return None

            finally:
                if h_msg:
                    crypt32.CryptMsgClose(h_msg)

        except Exception as e:
            print(f"Произошла ошибка во время расшифровки: {e}")
            import traceback
            traceback.print_exc()
            return None
        finally:
            # Освобождаем ресурсы
            if self._p_cert_context:
                crypt32.CertFreeCertificateContext(self._p_cert_context)
                self._p_cert_context = None
            if self._h_prov:
                advapi32.CryptReleaseContext(self._h_prov, 0)
                self._h_prov = None


def main():
    """
    Основная функция для демонстрации работы из командной строки.
    """
    if len(sys.argv) != 3:
        print("Использование: python crypto_session_decryptor.py \"<encrypted_session_key_base64>\" \"<fio>\"")
        print("Пример: python crypto_session_decryptor.py \"MIICnQYJKoZIhvcNAQcDoIICjjCCAooCAQAx...\" \"ЗОТОВ\"")
        sys.exit(1)

    encrypted_key = sys.argv[1]
    fio = "ЗОТОВ"

    print(f"Попытка расшифровать сессию для сертификата с ФИО: {fio}")

    try:
        decryptor = CryptoSessionDecryptor(certificate_fio=fio)
        session_id = decryptor.decrypt(encrypted_key)

        if session_id:
            print("\n" + "=" * 50)
            print("УСПЕШНО РАСШИФРОВАНО!")
            print("Ключ сессии:", session_id)
            print("=" * 50)
        else:
            print("\nНе удалось расшифровать ключ сессии.")

    except Exception as e:
        print(f"Критическая ошибка: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()