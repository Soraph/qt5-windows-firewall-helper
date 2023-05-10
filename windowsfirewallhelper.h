#ifndef WINDOWSFIREWALLHELPER_H
#define WINDOWSFIREWALLHELPER_H

#include <windows.h>
#include <QString>

struct WindowsFirewallHelper
{
public:
    WindowsFirewallHelper() = default;

    static bool authorize() noexcept;

private:
    static QString toWinHex(const HRESULT value) noexcept;
};

#endif // WINDOWSFIREWALLHELPER_H
