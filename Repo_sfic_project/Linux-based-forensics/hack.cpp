#ifndef _GNU_SOURCE
#define _GNU_SOURCE   // exposes process_vm_writev() from <sys/uio.h>
#endif
#include <iostream>
#include <fstream>
#include <string>
#include <cstdint>
#include <ctime>
#include <sstream>
#include <cerrno>
#include <cstring>
#include <sys/types.h>
#include <sys/uio.h>   // process_vm_writev
#include <unistd.h>

void LogEvent(const std::string& message) {
    std::ofstream logFile("security_audit_log.txt", std::ios::app);
    if (logFile.is_open()) {
        std::time_t now = std::time(nullptr);
        char timeStr[100];
        std::strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", std::localtime(&now));
        logFile << "[" << timeStr << "] " << message << std::endl;
        logFile.close();
    }
}

int main() {
    std::cout << "--- State Injector ---" << std::endl;

    pid_t targetPID;
    uintptr_t targetAddress;

    std::cout << "Enter the Target PID: ";
    std::cin >> std::dec >> targetPID;

    std::cout << "Enter the Target Memory Address (Hex): ";
    std::cin >> std::hex >> targetAddress;

    std::stringstream ss;
    ss << std::hex << targetAddress;
    LogEvent("[HACK] INJECTION INITIATED: Attempting to overwrite memory at 0x" + ss.str() + " for PID " + std::to_string(targetPID) + ".");

    // UPGRADE: Changed to 'int 1' to match the new environmentState logic
    int exploitValue = 1;
    std::cout << "Attempting to inject true state into memory..." << std::endl;

    // process_vm_writev() is the Linux analogue of
    // OpenProcess(PROCESS_VM_WRITE|PROCESS_VM_OPERATION) + WriteProcessMemory().
    // There is no separate "handle" step - the PID is passed directly. The
    // call succeeds only if the caller shares the target's UID (or holds
    // CAP_SYS_PTRACE) and the kernel's Yama ptrace_scope policy allows it.
    struct iovec local[1];
    struct iovec remote[1];

    local[0].iov_base = &exploitValue;
    local[0].iov_len  = sizeof(exploitValue);
    remote[0].iov_base = (void*)targetAddress;
    remote[0].iov_len  = sizeof(exploitValue);

    ssize_t written = process_vm_writev(targetPID, local, 1, remote, 1, 0);

    if (written == static_cast<ssize_t>(sizeof(exploitValue))) {
        std::cout << "[SUCCESS] Memory overwritten. Hidden event triggered." << std::endl;
        LogEvent("[HACK] PAYLOAD DELIVERED: Memory successfully overwritten. Hidden event triggered.");
    } else {
        std::cout << "[FAILED] Write operation blocked. errno: " << errno << " (" << std::strerror(errno) << ")" << std::endl;
        LogEvent("[HACK] FAILED: process_vm_writev failed with errno " + std::to_string(errno) + ".");
    }

    std::cout << "Press Enter to exit." << std::endl;
    std::cin.ignore();
    std::cin.get();
    return 0;
}
