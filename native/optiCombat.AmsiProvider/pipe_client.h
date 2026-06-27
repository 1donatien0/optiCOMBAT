#pragma once
#include <string>

namespace opticombat::ipc {

bool ScanBufferViaPipe(const wchar_t* pipeName, const std::string& jsonRequest, std::string& jsonResponse);

}
