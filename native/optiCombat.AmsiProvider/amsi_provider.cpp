#include <windows.h>
#include <amsi.h>
#include <objbase.h>
#include <wincrypt.h>
#include <string>
#include <vector>
#include "pipe_client.h"

#pragma comment(lib, "crypt32.lib")

namespace
{
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
}

// GUID : {A8F4E2B1-9C3D-4E5F-8A7B-1C2D3E4F5A6B}
static const CLSID CLSID_OpticombatAmsiProvider =
{ 0xa8f4e2b1, 0x9c3d, 0x4e5f, { 0x8a, 0x7b, 0x1c, 0x2d, 0x3e, 0x4f, 0x5a, 0x6b } };

class OpticombatAmsiProvider final : public IAntimalwareProvider
{
    LONG _ref = 1;

public:
    STDMETHODIMP QueryInterface(REFIID riid, void** ppv) override
    {
        if (!ppv) return E_POINTER;
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
        if (r == 0) delete this;
        return r;
    }

    STDMETHODIMP Scan(
        IAmsiStream* stream,
        AMSI_RESULT* result) override
    {
        if (!stream || !result)
            return E_POINTER;

        *result = AMSI_RESULT_CLEAN;

        ULONGLONG size = 0;
        if (FAILED(stream->GetAttribute(AMSI_ATTRIBUTE_CONTENT_SIZE, &size)) || size == 0 || size > 4 * 1024 * 1024)
            return S_OK;

        std::vector<BYTE> data(static_cast<size_t>(size));
        ULONG read = 0;
        if (FAILED(stream->Read(data.data(), static_cast<ULONG>(data.size()), &read)) || read == 0)
            return S_OK;

        const std::string b64data = EncodeBase64(data.data(), read);
        if (b64data.empty())
            return S_OK;

        const std::string request = std::string(R"({"op":"scan_buffer","buffer_b64":")") + b64data + R"(","content_name":"amsi_buffer"})";
        std::string response;
        if (!opticombat::ipc::ScanBufferViaPipe(L"\\\\.\\pipe\\optiCombat_Protection", request, response))
            return S_OK;

        if (response.find("\"clean\":false") != std::string::npos)
            *result = AMSI_RESULT_DETECTED;

        return S_OK;
    }

    STDMETHODIMP CloseSession() override { return S_OK; }
};

class OpticombatClassFactory final : public IClassFactory
{
    LONG _ref = 1;

public:
    STDMETHODIMP QueryInterface(REFIID riid, void** ppv) override
    {
        if (!ppv) return E_POINTER;
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
        if (r == 0) delete this;
        return r;
    }

    STDMETHODIMP CreateInstance(IUnknown* outer, REFIID riid, void** ppv) override
    {
        if (outer) return CLASS_E_NOAGGREGATION;
        auto* provider = new (std::nothrow) OpticombatAmsiProvider();
        if (!provider) return E_OUTOFMEMORY;
        const HRESULT hr = provider->QueryInterface(riid, ppv);
        provider->Release();
        return hr;
    }

    STDMETHODIMP LockServer(BOOL lock) override
    {
        if (lock) InterlockedIncrement(&g_lockCount);
        else InterlockedDecrement(&g_lockCount);
        return S_OK;
    }

    static LONG g_lockCount;
};

LONG OpticombatClassFactory::g_lockCount = 0;

BOOL APIENTRY DllMain(HMODULE, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
        DisableThreadLibraryCalls(GetModuleHandleW(nullptr));
    return TRUE;
}

STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, void** ppv)
{
    if (!ppv) return E_POINTER;
    if (!IsEqualCLSID(rclsid, CLSID_OpticombatAmsiProvider))
        return CLASS_E_CLASSNOTAVAILABLE;

    auto* factory = new (std::nothrow) OpticombatClassFactory();
    if (!factory) return E_OUTOFMEMORY;
    const HRESULT hr = factory->QueryInterface(riid, ppv);
    factory->Release();
    return hr;
}

STDAPI DllCanUnloadNow()
{
    return OpticombatClassFactory::g_lockCount == 0 ? S_OK : S_FALSE;
}

STDAPI DllRegisterServer()
{
    return S_OK;
}

STDAPI DllUnregisterServer()
{
    return S_OK;
}
