#ifndef _GNU_SOURCE
#define _GNU_SOURCE   // exposes process_vm_readv()/process_vm_writev() from <sys/uio.h>
#endif
#include <iostream>
#include <fstream>
#include <string>
#include <cstdint>
#include <ctime>
#include <sstream>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <cctype>
#include <dirent.h>
#include <sys/types.h>
#include <sys/uio.h>     // process_vm_readv / process_vm_writev
#include <signal.h>      // kill()
#include <unistd.h>
#include <termios.h>
#include <fcntl.h>

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

// Equivalent of Windows' SetConsoleTitleA().
void SetTerminalTitle(const std::string& title) {
    std::cout << "\033]0;" << title << "\007" << std::flush;
}

// Equivalent of conio.h's _kbhit(): non-blocking check for a waiting keypress.
int _kbhit() {
    termios oldt, newt;
    int oldf;

    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    oldf = fcntl(STDIN_FILENO, F_GETFL, 0);
    fcntl(STDIN_FILENO, F_SETFL, oldf | O_NONBLOCK);

    int ch = getchar();

    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    fcntl(STDIN_FILENO, F_SETFL, oldf);

    if (ch != EOF) {
        ungetc(ch, stdin);
        return 1;
    }
    return 0;
}

// Equivalent of conio.h's _getch(): reads one keypress, no Enter, no echo.
int _getch() {
    termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    int ch = getchar();

    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    return ch;
}

// Terminal-bell approximation of Windows' Beep(freq, durationMs). The Linux
// terminal bell has no controllable frequency, so this rings the bell and
// sleeps for the requested duration to preserve the original pacing.
void Beep(unsigned int /*freq*/, unsigned int durationMs) {
    std::cout << '\a' << std::flush;
    usleep(durationMs * 1000);
}

// Linux analogue of CreateToolhelp32Snapshot + Process32First/Next: scans
// /proc for a process whose executable name matches procName.
pid_t GetProcId(const std::string& procName) {
    pid_t procId = 0;
    DIR* dir = opendir("/proc");
    if (dir == nullptr) {
        return 0;
    }

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        std::string name(entry->d_name);
        bool isPid = !name.empty();
        for (char c : name) {
            if (!isdigit((unsigned char)c)) { isPid = false; break; }
        }
        if (!isPid) continue;

        std::ifstream commFile("/proc/" + name + "/comm");
        if (!commFile.is_open()) continue;

        std::string comm;
        std::getline(commFile, comm);

        if (comm == procName) {
            procId = static_cast<pid_t>(std::stoi(name));
            break;
        }
    }

    closedir(dir);
    return procId;
}

int main() {
    SetTerminalTitle("Watchdog Security Monitor - ACTIVE");
    std::cout << "--- Watchdog Security Monitor ---" << std::endl;

    // On Linux the target binary is typically just named "app" (no .exe
    // extension); /proc/<pid>/comm reflects this.
    pid_t targetPID = GetProcId("app");
    if (targetPID == 0) {
        std::cout << "\033[31m" << "[ERROR] app process not found. Is it running?" << "\033[0m" << std::endl;
        usleep(2000 * 1000);
        return 1;
    }

    std::cout << "\033[32m" << "[SUCCESS] Found app process (PID: " << targetPID << ")" << "\033[0m" << std::endl;

    LogEvent("[WATCHDOG] INITIALIZED: Successfully attached to app target (PID: " + std::to_string(targetPID) + ").");

    uintptr_t targetAddress;
    std::cout << "Enter the memory address of 'environmentState' (e.g., 0x55d1a2b3c04c): ";
    std::cin >> std::hex >> targetAddress;

    // process_vm_readv()/process_vm_writev() are the Linux analogues of
    // OpenProcess(PROCESS_VM_READ|PROCESS_VM_WRITE|PROCESS_VM_OPERATION) +
    // ReadProcessMemory()/WriteProcessMemory(). No persistent "handle" is
    // needed - the target PID is passed directly on every call. These calls
    // require matching UID (or CAP_SYS_PTRACE) and a permissive Yama
    // ptrace_scope setting - the rough equivalent of "Run as Administrator".

    int currentValue = 0;
    std::cout << "[INFO] Monitoring memory address..." << std::endl;

    std::stringstream ss;
    ss << std::hex << targetAddress;
    LogEvent("[WATCHDOG] MONITORING: Actively scanning virtual memory address 0x" + ss.str() + ".");

    struct iovec localRead[1];
    struct iovec remoteRead[1];
    localRead[0].iov_base = &currentValue;
    localRead[0].iov_len  = sizeof(currentValue);
    remoteRead[0].iov_base = (void*)targetAddress;
    remoteRead[0].iov_len  = sizeof(currentValue);

    // 4. The Active Monitoring Loop
    while (true) {
        process_vm_readv(targetPID, localRead, 1, remoteRead, 1, 0);

        if (currentValue == 1) {

            // THE NEUTRALIZER
            int lockdownSignal = 99;
            struct iovec localWrite[1];
            struct iovec remoteWrite[1];
            localWrite[0].iov_base = &lockdownSignal;
            localWrite[0].iov_len  = sizeof(lockdownSignal);
            remoteWrite[0].iov_base = (void*)targetAddress;
            remoteWrite[0].iov_len  = sizeof(lockdownSignal);
            process_vm_writev(targetPID, localWrite, 1, remoteWrite, 1, 0);

            LogEvent("[WATCHDOG] SECURITY ALARM: Illegal state change detected at address 0x" + ss.str() + "!");
            LogEvent("[WATCHDOG] ACTION TAKEN: Neutralizing signal sent. Forcing safe shutdown sequence.");

            SetTerminalTitle("!!! SECURITY BREACH DETECTED !!!");
            std::cout << "\n[VIOLATION] Illegal state change detected at address 0x" << std::hex << targetAddress << std::endl;
            std::cout << "[ACTION] Hack neutralized. Signaled app to initiate safe shutdown." << std::endl;

            usleep(2500 * 1000);

            // TerminateProcess(hKill, 1) forcibly (and un-catchably) kills the
            // target; SIGKILL is the direct POSIX equivalent.
            kill(targetPID, SIGKILL);

            std::cout << "\n>>> SYSTEM ALERT: Press ANY KEY to acknowledge threat and exit Watchdog <<<" << std::endl;

            bool isRedBackground = true;

            while (!_kbhit()) {
                if (isRedBackground) {
                    std::cout << "\033[47m" << std::flush;   // white background
                    Beep(880, 500);
                } else {
                    std::cout << "\033[0m" << std::flush;    // reset
                    Beep(659, 500);
                }
                isRedBackground = !isRedBackground;
            }

            _getch();
            LogEvent("[WATCHDOG] SYSTEM ALERT: Administrator acknowledged threat. Shutting down monitor.");
            std::cout << "\033[0m" << std::flush;
            break;
        }

        // THE FIX: Lightning Fast EDR scanning. Scans every 10ms.
        usleep(10 * 1000);
    }

    return 0;
}
