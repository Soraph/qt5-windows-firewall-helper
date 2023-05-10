#include "windowsfirewallhelper.h"
#include "mqttconnectorconfig.h"

#include <QtDebug>
#include <QCoreApplication>
#include <QDir>

#include <windows.h>
#include <netfw.h>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

/* Inspired by:
 * https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ics/c-registering-with-windows-firewall-no-ownership
 * https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ics/c-restricting-service
 */
bool WindowsFirewallHelper::authorize() noexcept
{
    bool success = false;
    const auto appPath = QCoreApplication::applicationFilePath();

    INetFwPolicy2* fwPolicy2 = nullptr;
    INetFwRule* fwRule = nullptr;
    INetFwRules* fwRules = nullptr;
    HRESULT hr = S_OK;
    HRESULT hrComInit = S_FALSE;
    BSTR bstrAppName = SysAllocString(BSTR(QString(APPLICATION_SHORT_NAME).toStdWString().c_str()));

    if (bstrAppName == nullptr) {
        qCritical().noquote() << "Failed to allocate bstrAppName:" << toWinHex(hr);
        goto Cleanup;
    }

    // Initialize COM library
    hrComInit = CoInitializeEx(0, COINIT_APARTMENTTHREADED);
    // Ignore RPC_E_CHANGED_MODE; this just means that COM has already been initialized with a
    // different mode. Since we don't care what the mode is, we'll just use the existing mode.
    if (hrComInit != RPC_E_CHANGED_MODE) {
        if (FAILED(hrComInit)) {
            qCritical().noquote() << "CoInitializeEx failed:" << toWinHex(hrComInit);
            goto Cleanup;
        }
    }

    // Create instance of INetFwPolicy2 interface
    hr = CoCreateInstance(__uuidof(NetFwPolicy2), nullptr, CLSCTX_INPROC_SERVER,
                          __uuidof(INetFwPolicy2), (void**)&fwPolicy2);
    if (FAILED(hr)) {
        qCritical().noquote() << "CoCreateInstance INetFwPolicy2 failed:" << toWinHex(hr);
        goto Cleanup;
    }

    // Retrieve all the firewall rules
    hr = fwPolicy2->get_Rules(&fwRules);
    if (FAILED(hr)) {
        qCritical().noquote() << "fwPolicy2->get_Rules failed:" << toWinHex(hr);
        goto Cleanup;
    }

    // Check if we have already defined the rule before, prevent duplication
    hr = fwRules->Item(bstrAppName, &fwRule);
    // Check for SUCCEEDED as FAILED means mostly that the record was not found
    if (SUCCEEDED(hr)) {
        qInfo() << "Rule already present in Windows Firewall, removing it";

        // TODO: If this operation is expensive consider checking the values from fwRule to see
        //       if they are actually the same as the one we expect
        // Remove old rule to ensure that the current one is always correct.
        hr = fwRules->Remove(bstrAppName);
        if (FAILED(hr)) {
            qCritical().noquote() << "Cannot remove firewall rule:" << toWinHex(hr);
            goto Cleanup;
        }
    }

    // Reset content after the search for the rule
    fwRule = nullptr;

    // Create instance of INetFwRule interface
    hr = CoCreateInstance(__uuidof(NetFwRule), nullptr, CLSCTX_INPROC_SERVER,
                          __uuidof(INetFwRule), (void**)&fwRule);
    if (FAILED(hr)) {
        qCritical().noquote() << "CoCreateInstance INetFwRule failed:" << toWinHex(hr);
        goto Cleanup;
    }

    // Set properties of the rule
    hr = fwRule->put_Name(bstrAppName);
    if (FAILED(hr)) {
        qCritical().noquote() << "fwRules->put_Name failed:" << toWinHex(hr);
        goto Cleanup;
    }

    hr = fwRule->put_ApplicationName(BSTR(QDir::toNativeSeparators(appPath).toStdWString().c_str()));
    if (FAILED(hr)) {
        qCritical().noquote() << "fwRules->put_ApplicationName failed:" << toWinHex(hr);
        goto Cleanup;
    }

    hr = fwRule->put_Action(NET_FW_ACTION_ALLOW);
    if (FAILED(hr)) {
        qCritical().noquote() << "fwRules->put_Action failed:" << toWinHex(hr);
        goto Cleanup;
    }

    hr = fwRule->put_Enabled(VARIANT_TRUE);
    if (FAILED(hr)) {
        qCritical().noquote() << "fwRules->put_Enabled failed:" << toWinHex(hr);
        goto Cleanup;
    }

    hr = fwRule->put_Direction(NET_FW_RULE_DIR_IN);
    if (FAILED(hr)) {
        qCritical().noquote() << "fwRules->put_Direction failed:" << toWinHex(hr);
        goto Cleanup;
    }

    // Add the rule to the Windows Firewall
    hr = fwRules->Add(fwRule);
    if (FAILED(hr)) {
        qCritical().noquote() << "fwRules->Add failed:" << toWinHex(hr);
        goto Cleanup;
    }

    success = true;
    qInfo() << "Rule added to Windows Firewall";

Cleanup:
    // Free BSTR
    SysFreeString(bstrAppName);

    // Release the INetFwRule object
    if (fwRule != NULL)
        fwRule->Release();

    // Release the INetFwRules object
    if (fwRules != NULL)
        fwRules->Release();

    // Release INetFwPolicy2
    if (fwPolicy2 != NULL)
        fwPolicy2->Release();

    // Uninitialize COM.
    if (SUCCEEDED(hrComInit))
        CoUninitialize();

    return success;
}

QString WindowsFirewallHelper::toWinHex(const HRESULT value) noexcept
{
    return QString("0x%1").arg(QString::number(static_cast<unsigned long>(value), 16).toUpper(), 8, QLatin1Char('0'));
}
