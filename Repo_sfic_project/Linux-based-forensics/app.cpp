#include <iostream>
#include <fstream>
#include <string>
#include <cstdint>
#include <ctime>
#include <sstream>
#include <chrono>
#include <thread>
#include <unistd.h>   // getpid()

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

// Equivalent of Windows' SetConsoleTitleA(): sets the terminal window title
// via an ANSI/xterm escape sequence.
void SetTerminalTitle(const std::string& title) {
    std::cout << "\033]0;" << title << "\007" << std::flush;
}

int main() {
    SetTerminalTitle("Shipwreck Environment (Target)");

    int collectedWood = 0;
    int environmentState = 0;

    pid_t pid = getpid();

    std::cout << "--- Shipwreck Island Survival ---" << std::endl;
    std::cout << "[INFO] Process ID (PID): " << pid << std::endl;
    std::cout << "[INFO] Address of 'environmentState': 0x" << std::hex << (uintptr_t)&environmentState << std::endl;
    std::cout << "---------------------------------" << std::endl;

    LogEvent("[APP] SYSTEM STARTUP: Shipwreck Island Environment initialized. (PID: " + std::to_string(pid) + ")");
    std::stringstream ss;
    ss << std::hex << (uintptr_t)&environmentState;
    LogEvent("[APP] STATE GENERATED: 'environmentState' allocated at 0x" + ss.str() + ".");

    // The Game Loop
    while (true) {

        // 1. Did the hack slip through?
        if (environmentState == 1) {
            std::cout << "\n[CRITICAL EVENT] The raft is built! You escaped the island!" << std::endl;
            break;
        }

        // 2. Did the Watchdog save us?
        else if (environmentState == 99) {
            std::cout << "\n\n[SYSTEM] WATCHDOG INTERVENTION DETECTED." << std::endl;
            std::cout << "[SYSTEM] Tampered state neutralized. Changes reversed." << std::endl;
            std::cout << "[SYSTEM] Process over / return 0 success. You may exit safely." << std::endl;
            LogEvent("[APP] SAFE SHUTDOWN: Watchdog signal received. Exiting cleanly.");
            break;
        }

        std::cout << "Exploring... Wood: " << std::dec << collectedWood << ". State: " << environmentState << "    \r" << std::flush;

        // THE FIX: Slow game loop. The app only checks its status every 800ms.
        std::this_thread::sleep_for(std::chrono::milliseconds(800));
    }

    std::cout << "\nGame Over. Press Enter to exit." << std::endl;
    std::cin.get();
    return 0;
}
