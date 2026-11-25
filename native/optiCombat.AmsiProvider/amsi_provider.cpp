#include <windows.h>
#include <amsi.h>
#include <objbase.h>
#include <wincrypt.h>
#include <new>
#include <string>
#include <vector>
#include "pipe_client.h"

#pragma comment(lib, "crypt32.lib")

namespace
{
    // {A8F4E2B1-9C3D-4E5F-8A7B-1C2D3E4F5A6B} — même GUID que PlatformRegistration.
    constexpr CLSID kClsid = { 0xa8f4e2b1, 0x9c3d, 0x4e5f, { 0x8a, 0x7b, 0x1c, 0x2d, 0x3e, 0x4f, 0x5a, 0x6b } };
    constexpr wchar_t kDisplayName[] = L"optiCombat";

    // Le base64 d'un bloc de 512 Kio reste largement sous la requête IPC. Le recouvrement
    // laisse un motif à cheval sur deux blocs visible dans au moins l'un des deux.
    constexpr ULONG kChunkBytes = 512 * 1024;
    constexpr ULONG kChunkOverlap = 64 * 1024;
    // Au-delà, on s'arrête sans déclarer le contenu « connu sain » : le reste n'a pas été vu.
    constexpr ULONGLONG kMaxScanBytes = 8ull * 1024ull * 1024ull;

    LONG g_objects = 0;
    LONG g_locks = 0;

    std::string EncodeBase64(const BYTE* data, DWORD size)
    {
        if (size == 0)
            return {};

        DWORD encodedLen = 0;
        if (!CryptBinaryToStringA(
                data,
                size,
                CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
                nullptr,
                &encodedLen))
        {
            return {};
        }

        std::string encoded(encodedLen, '\0');
        if (!CryptBinaryToStringA(
                data,
                size,
                CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
                encoded.data(),
                &encodedLen))
        {
            return {};
        }

        while (!encoded.empty() && encoded.back() == '\0')
            encoded.pop_back();

        return encoded;
    }

    std::wstring ReadStringAttribute(IAmsiStream* stream, AMSI_ATTRIBUTE attribute)
    {
        ULONG needed = 0;
        const HRESULT probe = stream->GetAttribute(attribute, 0, nullptr, &needed);
        if (probe != E_NOT_SUFFICIENT_BUFFER || needed == 0 || needed > 64 * 1024)
            return {};

        std::vector<BYTE> buffer(static_cast<size_t>(needed) + sizeof(wchar_t), 0);
        ULONG written = 0;
        if (FAILED(stream->GetAttribute(attribute, needed, buffer.data(), &written)))
            return {};

        return std::wstring(reinterpret_cast<const wchar_t*>(buffer.data()));
    }

    bool ContainsInsensitive(const std::wstring& haystack, const wchar_t* needle)
    {
        std::wstring h = haystack;
        std::wstring n = needle;
        if (!h.empty())
            CharLowerBuffW(h.data(), static_cast<DWORD>(h.size()));
        if (!n.empty())
            CharLowerBuffW(n.data(), static_cast<DWORD>(n.size()));
        return h.find(n) != std::wstring::npos;
    }

    // Extension fixe, jamais reprise du contenu : elle oriente seulement le moteur.
    const char* ContentNameFor(const std::wstring& appName)
    {
        if (ContainsInsensitive(appName, L"powershell"))
            return "amsi_content.ps1";
        if (ContainsInsensitive(appName, L"jscript"))
            return "amsi_content.js";
        if (ContainsInsensitive(appName, L"vbscript"))
            return "amsi_content.vbs";
        if (ContainsInsensitive(appName, L"vba") || ContainsInsensitive(appName, L"office"))
            return "amsi_content.vba";
        if (ContainsInsensitive(appName, L"dotnet") || ContainsInsensitive(appName, L"coreclr"))
            return "amsi_content.bin";
        return "amsi_content.txt";
    }

    // Menace seulement si le service a terminé l'analyse et l'a marquée non saine.
    // Une erreur, un délai ou un refus de débit ne bloque pas l'application hôte.
    bool IsThreatResponse(const std::string& response)
    {
        return response.find("\"ok\":true") != std::string::npos
            && response.find("\"clean\":false") != std::string::npos;
    }
}

class OpticombatAmsiProvider final : public IAntimalwareProvider
{
    LONG _ref = 1;

public:
    OpticombatAmsiProvider() { InterlockedIncrement(&g_objects); }
    ~OpticombatAmsiProvider() { InterlockedDecrement(&g_objects); }

    STDMETHODIMP QueryInterface(REFIID riid, void** ppv) override
    {
        if (!ppv)
            return E_POINTER;
        if (riid == IID_IUnknown || riid == __uuidof(IAntimalwareProvider))
        {
            *ppv = static_cast<IAntimalwareProvider*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }

    STDMETHODIMP_(ULONG) AddRef() override { return InterlockedIncrement(&_ref); }
    STDMETHODIMP_(ULONG) Release() override
    {
        const ULONG r = InterlockedDecrement(&_ref);
        if (r == 0)
            delete this;
        return r;
    }

    STDMETHODIMP Scan(IAmsiStream* stream, AMSI_RESULT* result) override
    {
        if (!stream || !result)
            return E_POINTER;

        // NOT_DETECTED, pas CLEAN : CLEAN est un « connu sain » qui peut court-circuiter
        // les autres fournisseurs. Un échec ou un contenu trop gros ne doit pas l'affirmer.
        *result = AMSI_RESULT_NOT_DETECTED;

        try
        {
            ULONGLONG size = 0;
            ULONG written = 0;
            if (FAILED(stream->GetAttribute(
                    AMSI_ATTRIBUTE_CONTENT_SIZE,
                    sizeof(size),
                    reinterpret_cast<unsigned char*>(&size),
                    &written))
                || written != sizeof(size)
                || size == 0)
            {
                return S_OK;
            }

            const ULONGLONG limit = size < kMaxScanBytes ? size : kMaxScanBytes;
            const std::wstring appName = ReadStringAttribute(stream, AMSI_ATTRIBUTE_APP_NAME);
            const char* contentName = ContentNameFor(appName);

            ULONGLONG offset = 0;
            while (offset < limit)
            {
                const ULONGLONG remaining = limit - offset;
                const ULONG toRead = remaining > kChunkBytes ? kChunkBytes : static_cast<ULONG>(remaining);
                std::vector<BYTE> data(toRead);
                ULONG read = 0;
                if (FAILED(stream->Read(offset, toRead, data.data(), &read)) || read == 0)
                    return S_OK;

                const std::string b64data = EncodeBase64(data.data(), read);
                if (b64data.empty())
                    return S_OK;

                std::string request;
                request.reserve(b64data.size() + 96);
                request += R"({"op":"scan_buffer","buffer_b64":")";
                request += b64data;
                request += R"(","content_name":")";
                request += contentName;
                request += R"("})";

                std::string response;
                if (!opticombat::ipc::ScanBufferViaPipe(L"\\\\.\\pipe\\optiCombat_Protection", request, response))
                    return S_OK;
                if (IsThreatResponse(response))
                {
                    *result = AMSI_RESULT_DETECTED;
                    return S_OK;
                }

                if (offset + read >= limit)
                    break;

                const ULONG step = read > kChunkOverlap ? read - kChunkOverlap : read;
                if (step == 0)
                    break;
                offset += step;
            }
        }
        catch (...)
        {
            *result = AMSI_RESULT_NOT_DETECTED;
        }

        return S_OK;
    }

    STDMETHODIMP_(void) CloseSession(ULONGLONG) override {}

    STDMETHODIMP DisplayName(LPWSTR* displayName) override
    {
        if (!displayName)
            return E_POINTER;

        const size_t bytes = sizeof(kDisplayName);
        auto* copy = static_cast<LPWSTR>(CoTaskMemAlloc(bytes));
        if (!copy)
            return E_OUTOFMEMORY;
        memcpy(copy, kDisplayName, bytes);
        *displayName = copy;
        return S_OK;
    }
};

class OpticombatClassFactory final : public IClassFactory
{
    LONG _ref = 1;

public:
    STDMETHODIMP QueryInterface(REFIID riid, void** ppv) override
    {
        if (!ppv)
            return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IClassFactory)
        {
            *ppv = static_cast<IClassFactory*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }

    STDMETHODIMP_(ULONG) AddRef() override { return InterlockedIncrement(&_ref); }
    STDMETHODIMP_(ULONG) Release() override
    {
        const ULONG r = InterlockedDecrement(&_ref);
        if (r == 0)
            delete this;
        return r;
    }

    STDMETHODIMP CreateInstance(IUnknown* outer, REFIID riid, void** ppv) override
    {
        if (outer)
            return CLASS_E_NOAGGREGATION;
        auto* provider = new (std::nothrow) OpticombatAmsiProvider();
        if (!provider)
            return E_OUTOFMEMORY;
        const HRESULT hr = provider->QueryInterface(riid, ppv);
        provider->Release();
        return hr;
    }

    STDMETHODIMP LockServer(BOOL lock) override
    {
        if (lock)
            InterlockedIncrement(&g_locks);
        else
            InterlockedDecrement(&g_locks);
        return S_OK;
    }
};

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
        DisableThreadLibraryCalls(module);
    return TRUE;
}

STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, void** ppv)
{
    if (!ppv)
        return E_POINTER;
    if (!IsEqualCLSID(rclsid, kClsid))
        return CLASS_E_CLASSNOTAVAILABLE;

    auto* factory = new (std::nothrow) OpticombatClassFactory();
    if (!factory)
        return E_OUTOFMEMORY;
    const HRESULT hr = factory->QueryInterface(riid, ppv);
    factory->Release();
    return hr;
}

STDAPI DllCanUnloadNow()
{
    return (g_locks == 0 && g_objects == 0) ? S_OK : S_FALSE;
}

STDAPI DllRegisterServer()
{
    return S_OK;
}

STDAPI DllUnregisterServer()
{
    return S_OK;
}
