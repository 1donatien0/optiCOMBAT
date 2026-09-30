#include "pipe_client.h"
#include <windows.h>
#include <vector>

namespace opticombat::ipc {

bool ScanBufferViaPipe(const wchar_t* pipeName, const std::string& jsonRequest, std::string& jsonResponse)
{
    HANDLE pipe = CreateFileW(
        pipeName,
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        0,
        nullptr);

    if (pipe == INVALID_HANDLE_VALUE)
        return false;

    DWORD mode = PIPE_READMODE_BYTE;
    SetNamedPipeHandleState(pipe, &mode, nullptr, nullptr);

    DWORD written = 0;
    if (!WriteFile(pipe, jsonRequest.data(), static_cast<DWORD>(jsonRequest.size()), &written, nullptr))
    {
        CloseHandle(pipe);
        return false;
    }

    FlushFileBuffers(pipe);

    std::vector<char> buffer(8192);
    DWORD read = 0;
    if (!ReadFile(pipe, buffer.data(), static_cast<DWORD>(buffer.size()), &read, nullptr))
    {
        CloseHandle(pipe);
        return false;
    }

    CloseHandle(pipe);
    jsonResponse.assign(buffer.data(), read);
    return true;
}

}
