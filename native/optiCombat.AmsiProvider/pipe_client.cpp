#include "pipe_client.h"
#include <windows.h>
#include <tlhelp32.h>
#include <vector>

#pragma comment(lib, "advapi32.lib")

namespace opticombat::ipc {

namespace {

// Sans service, le tube est absent : l'échec doit être immédiat pour ne pas figer PowerShell.
constexpr DWORD kConnectTimeoutMs = 250;
// Au-delà, le contenu passe (NOT_DETECTED côté fournisseur). Le scan IPC côté service
// peut durer plus longtemps ; ici on borne le processus hôte.
constexpr DWORD kIoTimeoutMs = 10000;
constexpr size_t kMaxResponseBytes = 1024 * 1024;
constexpr wchar_t kServiceName[] = L"optiCombatProtection";

bool WaitIo(HANDLE pipe, OVERLAPPED& ov, BOOL started, DWORD& transferred)
{
    if (!started && GetLastError() != ERROR_IO_PENDING)
        return false;
    if (!GetOverlappedResultEx(pipe, &ov, &transferred, kIoTimeoutMs, FALSE))
    {
        CancelIoEx(pipe, &ov);
        GetOverlappedResult(pipe, &ov, &transferred, TRUE);
        return false;
    }
    return true;
}

DWORD QueryServiceProcessId()
{
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm)
        return 0;

    DWORD pid = 0;
    SC_HANDLE service = OpenServiceW(scm, kServiceName, SERVICE_QUERY_STATUS);
    if (service)
    {
        SERVICE_STATUS_PROCESS status{};
        DWORD needed = 0;
        if (QueryServiceStatusEx(
                service,
                SC_STATUS_PROCESS_INFO,
                reinterpret_cast<LPBYTE>(&status),
                sizeof(status),
                &needed))
        {
            pid = status.dwProcessId;
        }
        CloseServiceHandle(service);
    }
    CloseServiceHandle(scm);
    return pid;
}

DWORD QueryParentProcessId(DWORD pid)
{
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
        return 0;

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    DWORD parent = 0;
    if (Process32FirstW(snapshot, &entry))
    {
        do
        {
            if (entry.th32ProcessID == pid)
            {
                parent = entry.th32ParentProcessID;
                break;
            }
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return parent;
}

bool ImageNameIs(DWORD pid, const wchar_t* expected)
{
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process)
        return false;

    wchar_t image[MAX_PATH] = {};
    DWORD size = MAX_PATH;
    const BOOL ok = QueryFullProcessImageNameW(process, 0, image, &size);
    CloseHandle(process);
    if (!ok)
        return false;

    const wchar_t* name = wcsrchr(image, L'\\');
    name = name ? name + 1 : image;
    return _wcsicmp(name, expected) == 0;
}

bool ProcessCreatedAfter(DWORD child, DWORD parent)
{
    auto creation = [](DWORD pid, ULONGLONG& out) {
        HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!process)
            return false;
        FILETIME created{}, exited{}, kernel{}, user{};
        const BOOL ok = GetProcessTimes(process, &created, &exited, &kernel, &user);
        CloseHandle(process);
        if (!ok)
            return false;
        out = (static_cast<ULONGLONG>(created.dwHighDateTime) << 32) | created.dwLowDateTime;
        return true;
    };

    ULONGLONG childTime = 0;
    ULONGLONG parentTime = 0;
    if (!creation(child, childTime) || !creation(parent, parentTime))
        return true;
    return childTime >= parentTime;
}

// Le tube est créé par optiCombat.exe, lui-même lancé par le service optiCombatProtection
// (session 0). Un autre processus local qui prendrait le nom ne reçoit pas le script.
bool IsTrustedServer(HANDLE pipe)
{
    ULONG session = 0;
    if (!GetNamedPipeServerSessionId(pipe, &session) || session != 0)
        return false;

    ULONG serverPid = 0;
    if (!GetNamedPipeServerProcessId(pipe, &serverPid) || serverPid == 0)
        return false;
    if (!ImageNameIs(serverPid, L"optiCombat.exe"))
        return false;

    const DWORD servicePid = QueryServiceProcessId();
    if (servicePid == 0 || serverPid == servicePid)
        return false;

    return QueryParentProcessId(serverPid) == servicePid
        && ImageNameIs(servicePid, L"optiCombat.Service.exe")
        && ProcessCreatedAfter(serverPid, servicePid);
}

bool ResponseLooksComplete(const std::string& response)
{
    if (response.find("\"ok\":") == std::string::npos)
        return false;
    for (size_t i = response.size(); i > 0; --i)
    {
        const char c = response[i - 1];
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\0')
            continue;
        return c == '}';
    }
    return false;
}

} // namespace

bool ScanBufferViaPipe(const wchar_t* pipeName, const std::string& jsonRequest, std::string& jsonResponse)
{
    if (jsonRequest.size() > 0x7fffffffu)
        return false;
    if (!WaitNamedPipeW(pipeName, kConnectTimeoutMs))
        return false;

    HANDLE pipe = CreateFileW(
        pipeName,
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
        nullptr);
    if (pipe == INVALID_HANDLE_VALUE)
        return false;

    bool ok = false;
    HANDLE event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (event != nullptr && IsTrustedServer(pipe))
    {
        DWORD mode = PIPE_READMODE_BYTE;
        SetNamedPipeHandleState(pipe, &mode, nullptr, nullptr);

        OVERLAPPED ov{};
        ov.hEvent = event;
        DWORD transferred = 0;
        const BOOL started = WriteFile(
            pipe,
            jsonRequest.data(),
            static_cast<DWORD>(jsonRequest.size()),
            nullptr,
            &ov);
        if (WaitIo(pipe, ov, started, transferred) && transferred == jsonRequest.size())
        {
            std::string response;
            std::vector<char> buffer(8192);
            for (;;)
            {
                if (ResponseLooksComplete(response))
                {
                    ok = true;
                    break;
                }

                ResetEvent(event);
                ov = OVERLAPPED{};
                ov.hEvent = event;
                transferred = 0;
                const BOOL readStarted = ReadFile(
                    pipe,
                    buffer.data(),
                    static_cast<DWORD>(buffer.size()),
                    nullptr,
                    &ov);
                if (!WaitIo(pipe, ov, readStarted, transferred))
                {
                    const DWORD err = GetLastError();
                    ok = (err == ERROR_BROKEN_PIPE || err == ERROR_PIPE_NOT_CONNECTED) && !response.empty();
                    break;
                }
                if (transferred == 0)
                {
                    ok = !response.empty();
                    break;
                }
                response.append(buffer.data(), transferred);
                if (response.size() > kMaxResponseBytes)
                    break;
            }
            if (ok)
                jsonResponse.swap(response);
        }
    }

    if (event != nullptr)
        CloseHandle(event);
    CloseHandle(pipe);
    return ok;
}

} // namespace opticombat::ipc
