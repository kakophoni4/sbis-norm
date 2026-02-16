# -*- coding: utf-8 -*-
import ctypes
from ctypes import wintypes
import sys

# --- Константы CryptoAPI ---
PROV_GOST_2012_256 = 80
CRYPT_MACHINE_KEYSET = 0x20
CRYPT_VERIFYCONTEXT = 0xF0000000
PP_ENUMCONTAINERS = 2
CRYPT_FIRST = 1
CRYPT_NEXT = 2
AT_KEYEXCHANGE = 1
KP_CERTIFICATE = 26
X509_ASN_ENCODING = 1
CERT_NAME_SIMPLE_DISPLAY_TYPE = 3
CERT_HASH_PROP_ID = 3

# --- Загрузка библиотек ---
advapi32 = ctypes.WinDLL('advapi32.dll')
crypt32 = ctypes.WinDLL('crypt32.dll')

# --- Определение типов ---
wintypes.HCRYPTPROV = wintypes.HANDLE
wintypes.LPCSTR = ctypes.c_char_p

# --- Настройка прототипов функций ---
advapi32.CryptAcquireContextA.argtypes = [ctypes.POINTER(wintypes.HCRYPTPROV), wintypes.LPCSTR, wintypes.LPCSTR, wintypes.DWORD, wintypes.DWORD]
advapi32.CryptAcquireContextA.restype = wintypes.BOOL
advapi32.CryptGetProvParam.argtypes = [wintypes.HCRYPTPROV, wintypes.DWORD, ctypes.POINTER(wintypes.BYTE), ctypes.POINTER(wintypes.DWORD), wintypes.DWORD]
advapi32.CryptGetProvParam.restype = wintypes.BOOL
advapi32.CryptReleaseContext.argtypes = [wintypes.HCRYPTPROV, wintypes.DWORD]
advapi32.CryptReleaseContext.restype = wintypes.BOOL
advapi32.CryptGetUserKey.argtypes = [wintypes.HCRYPTPROV, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
advapi32.CryptGetUserKey.restype = wintypes.BOOL
advapi32.CryptGetKeyParam.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.BYTE), ctypes.POINTER(wintypes.DWORD), wintypes.DWORD]
advapi32.CryptGetKeyParam.restype = wintypes.BOOL
crypt32.CertCreateCertificateContext.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.BYTE), wintypes.DWORD]
crypt32.CertCreateCertificateContext.restype = ctypes.c_void_p
crypt32.CertGetNameStringW.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.LPWSTR, wintypes.DWORD]
crypt32.CertGetNameStringW.restype = wintypes.DWORD
crypt32.CertFreeCertificateContext.argtypes = [ctypes.c_void_p]
crypt32.CertFreeCertificateContext.restype = wintypes.BOOL
crypt32.CertGetCertificateContextProperty.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD)]
crypt32.CertGetCertificateContextProperty.restype = wintypes.BOOL

def get_thumbprint_by_fio(fio):
    """
    Находит сертификат по ФИО в хранилище пользователя или машины
    и возвращает его отпечаток (thumbprint).
    """
    fio_lower = fio.lower()
    # Поиск сначала в хранилище текущего пользователя (флаг 0), затем в хранилище машины
    for flag_set in [0, CRYPT_MACHINE_KEYSET]:
        storage_name = "Пользователь" if flag_set == 0 else "Машина"
        hProv = wintypes.HCRYPTPROV()
        
        if not advapi32.CryptAcquireContextA(ctypes.byref(hProv), None, None, PROV_GOST_2012_256, CRYPT_VERIFYCONTEXT | flag_set):
            continue

        try:
            dwFlags = CRYPT_FIRST
            dwDataLen = wintypes.DWORD(0)
            if not advapi32.CryptGetProvParam(hProv, PP_ENUMCONTAINERS, None, ctypes.byref(dwDataLen), dwFlags):
                continue

            pbData = (wintypes.BYTE * dwDataLen.value)()
            while advapi32.CryptGetProvParam(hProv, PP_ENUMCONTAINERS, pbData, ctypes.byref(dwDataLen), dwFlags):
                dwFlags = CRYPT_NEXT
                container_name = ctypes.string_at(pbData).decode('cp1251', errors='ignore')

                hCertProv = wintypes.HCRYPTPROV()
                # Используем CRYPT_SILENT, так как нам не нужен доступ к закрытому ключу, только к данным сертификата
                if advapi32.CryptAcquireContextA(ctypes.byref(hCertProv), container_name.encode('cp1251'), None, PROV_GOST_2012_256, flag_set | 0x40): # 0x40 = CRYPT_SILENT
                    hKey = wintypes.HANDLE()
                    if advapi32.CryptGetUserKey(hCertProv, AT_KEYEXCHANGE, ctypes.byref(hKey)):
                        cbCert = wintypes.DWORD(0)
                        if advapi32.CryptGetKeyParam(hKey, KP_CERTIFICATE, None, ctypes.byref(cbCert), 0):
                            pbCert = (wintypes.BYTE * cbCert.value)()
                            if advapi32.CryptGetKeyParam(hKey, KP_CERTIFICATE, pbCert, ctypes.byref(cbCert), 0):
                                pCertContext = crypt32.CertCreateCertificateContext(X509_ASN_ENCODING, pbCert, cbCert.value)
                                if pCertContext:
                                    try:
                                        name_size = crypt32.CertGetNameStringW(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, None, 0)
                                        if name_size > 0:
                                            cert_name_buffer = (ctypes.c_wchar * name_size)()
                                            crypt32.CertGetNameStringW(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, cert_name_buffer, name_size)
                                            
                                            if fio_lower in cert_name_buffer.value.lower():
                                                print(f"Найден сертификат для '{fio}' в хранилище '{storage_name}'")
                                                dwHashSize = wintypes.DWORD(0)
                                                crypt32.CertGetCertificateContextProperty(pCertContext, CERT_HASH_PROP_ID, None, ctypes.byref(dwHashSize))
                                                pbHash = (wintypes.BYTE * dwHashSize.value)()
                                                if crypt32.CertGetCertificateContextProperty(pCertContext, CERT_HASH_PROP_ID, pbHash, ctypes.byref(dwHashSize)):
                                                    thumbprint = bytes(pbHash).hex().upper()
                                                    return thumbprint
                                    finally:
                                        crypt32.CertFreeCertificateContext(pCertContext)
                    advapi32.CryptReleaseContext(hCertProv, 0)
        finally:
            advapi32.CryptReleaseContext(hProv, 0)

    print(f"Ошибка: Сертификат для '{fio}' не найден ни в одном хранилище.")
    return None

if __name__ == "__main__":
    fio_to_find = "ЗОТОВ"
    print(f"--- Тестовый запуск: Поиск отпечатка для ФИО: {fio_to_find} ---")
    
    thumbprint = get_thumbprint_by_fio(fio_to_find)
    
    print("\n" + "="*50)
    if thumbprint:
        print(f"  УСПЕХ! Найден отпечаток:")
        print(f"  {thumbprint}")
    else:
        print(f"  ОШИБКА! Отпечаток для '{fio_to_find}' не найден.")
    print("="*50)