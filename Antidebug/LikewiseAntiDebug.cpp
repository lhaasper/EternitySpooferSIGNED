#include"../Antidebug/Headers.h"
#include "AntiDebugging/SharedUserData_KernelDebugger.h"

#define OUTPUT std::cout << "\n[ THREAT LEVEL = " << Level << " ]";
DWORD FLASEPOSITIVE = 0;
DWORD FLASEPOSITIVE1 = 1;
DWORD COOLDOWN = 100;


BOOL TLS_SECURITY = TRUE;
BOOL TIMING_ATTACKS = TRUE;
BOOL TRACE_SECURITY = TRUE;
BOOL ANTI_DUMPING_SECURITY = TRUE;
BOOL KILL_DEBUGGERS_SECURITY = TRUE;
BOOL ADVANCED_ANTI_DEBUGGING = TRUE;
BOOL NATIVE_DEBUGGER_SECURITY = TRUE;
BOOL UNAUTHORIZED_PUBLIC_DEBUGGER_SECURITY = TRUE;
BOOL UNAUTHORIZED_PUBLIC_DEBUGGER_TAB_SECURITY = TRUE;
BOOL ANTI_DISASSM_SECURITY = TRUE;

void ThreatDetected(int Level)
{
    if (FLASEPOSITIVE >= 2)
    {
        system(XorStr("cls").c_str());
        std::cout << "\n Debug Detected!\n";
        std::cout << "\n You Have Benn Banned! \n";
        std::ofstream Trace01;
        Trace01.open(XorStr("C:\\Program Files\\Win32Log.txt").c_str());
        Trace01 << Level;
        Trace01.close();

             exit(-1); 

              std::cin.get();
    }
    
        FLASEPOSITIVE = ++FLASEPOSITIVE1;
}



//Borderline Security (START)
DWORD_PTR ProcScanVal(const std::string& processName)
{
    PROCESSENTRY32 processInfo;
    processInfo.dwSize = sizeof(processInfo);

    HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (processesSnapshot == INVALID_HANDLE_VALUE)
        return 0;

    Process32First(processesSnapshot, &processInfo);
    if (!processName.compare(processInfo.szExeFile))
    {
        CloseHandle(processesSnapshot);
        return processInfo.th32ProcessID;
    }

    while (Process32Next(processesSnapshot, &processInfo))
    {
        if (!processName.compare(processInfo.szExeFile))
        {
            CloseHandle(processesSnapshot);
            return processInfo.th32ProcessID;
        }
    }

    CloseHandle(processesSnapshot);
    return 0;
}

void TerminateDebugger()
{
    /* Kill common known debuggers */
    if (KILL_DEBUGGERS_SECURITY)
    {
        while (true)
        {
            system(XorStr("SystemSettingsAdminFlows.exe SetInternetTime 1 >nul 2>&1").c_str());
            system(XorStr("taskkill /FI \"IMAGENAME eq fiddler*\" /IM * /F /T >nul 2>&1").c_str());
            system(XorStr("taskkill /FI \"IMAGENAME eq wireshark*\" /IM * /F /T >nul 2>&1").c_str());
            system(XorStr("taskkill /FI \"IMAGENAME eq rawshark*\" /IM * /F /T >nul 2>&1").c_str());
            system(XorStr("taskkill /FI \"IMAGENAME eq charles*\" /IM * /F /T >nul 2>&1").c_str());
            system(XorStr("taskkill /FI \"IMAGENAME eq cheatengine*\" /IM * /F /T >nul 2>&1").c_str());
            system(XorStr("taskkill /FI \"IMAGENAME eq ida*\" /IM * /F /T >nul 2>&1").c_str());
            system(XorStr("taskkill /FI \"IMAGENAME eq httpdebugger*\" /IM * /F /T >nul 2>&1").c_str());
            system(XorStr("taskkill /FI \"IMAGENAME eq processhacker*\" /IM * /F /T >nul 2>&1").c_str());
            system(XorStr("sc stop HTTPDebuggerPro >nul 2>&1").c_str());
            system(XorStr("sc stop KProcessHacker3 >nul 2>&1").c_str());
            system(XorStr("sc stop KProcessHacker2 >nul 2>&1").c_str());
            system(XorStr("sc stop KProcessHacker1 >nul 2>&1").c_str());
            system(XorStr("sc stop wireshark >nul 2>&1").c_str());
            system(XorStr("sc stop npf >nul 2>&1").c_str());
            Sleep((DWORD)COOLDOWN);
        }
    }
}

void TraceSecurity()
{
    if (TRACE_SECURITY)
    {
        if (std::filesystem::exists(XorStr("C:\\Program Files\\Win32Log.txt").c_str()))
        {
            ThreatDetected(1);
        }
    }
}

void NativeDebuggerSecurity()
{
    if (NATIVE_DEBUGGER_SECURITY)
    {
        if (IsDebuggerPresent())
        {
            ThreatDetected(1);
        }
    }
}

void UnauthorizedPublicDebuggerSecurity()
{

    if (UNAUTHORIZED_PUBLIC_DEBUGGER_SECURITY)
    {
        if (ProcScanVal(XorStr("http.exe").c_str()) != 0)
        {
            ThreatDetected(1);
        }

        if (ProcScanVal(XorStr("https.exe").c_str()) != 0)
        {
            ThreatDetected(1);
        }
        if (ProcScanVal(XorStr("HttpRequester.exe").c_str()) != 0)
        {
            ThreatDetected(1);
        }
        if (ProcScanVal(XorStr("HTTP Toolkit.exe").c_str()) != 0)
        {
            ThreatDetected(1);
        }
        if (ProcScanVal(XorStr("Toolkit.exe").c_str()) != 0)
        {
            ThreatDetected(1);
        }
        if (ProcScanVal(XorStr("memory.exe").c_str()) != 0)
        {
            ThreatDetected(1);
        }
        if (ProcScanVal(XorStr("memoryview.exe").c_str()) != 0)
        {
            ThreatDetected(1);
        }
        if (ProcScanVal(XorStr("viewmemory.exe").c_str()) != 0)
        {
            ThreatDetected(1);
        }
        if (ProcScanVal(XorStr("SmartSniff.exe").c_str()) != 0)
        {
            ThreatDetected(1);
        }
        if (ProcScanVal(XorStr("NetworkMiner.exe").c_str()) != 0)
        {
            ThreatDetected(1);
        }
        if (ProcScanVal(XorStr("SwagBellaSetup.exe").c_str()) != 0)
        {
            ThreatDetected(1);
        }
        if (ProcScanVal(XorStr("SwagBella.exe").c_str()) != 0)
        {
            ThreatDetected(1);
        }
        if (ProcScanVal(XorStr("KsDumper.exe").c_str()) != 0)
        {
            ThreatDetected(1);
        }
        if (ProcScanVal(XorStr("KsDump.exe").c_str()) != 0)
        {
            ThreatDetected(1);
        }
        if (ProcScanVal(XorStr("view.exe").c_str()) != 0)
        {
            ThreatDetected(1);
        }
        if (ProcScanVal(XorStr("outbuilt.exe").c_str()) != 0)
        {
            ThreatDetected(1);
        }
        if (ProcScanVal(XorStr("ida.exe").c_str()) != 0)
        {
            ThreatDetected(1);
        }
        if (ProcScanVal(XorStr("de3dot.exe").c_str()) != 0)
        {
            ThreatDetected(1);
        }
        if (ProcScanVal(XorStr("KsDumperClient.exe").c_str()) != 0)
        {
            ThreatDetected(1);
        }
        if (ProcScanVal(XorStr("outbuilt.exe").c_str()) != 0)
        {
            ThreatDetected(1);
        }
        if (ProcScanVal(XorStr("bypass.exe").c_str()) != 0)
        {
            ThreatDetected(1);
        }
        if (ProcScanVal(XorStr("Bypass.exe").c_str()) != 0)
        {
            ThreatDetected(1);
        }
        if (ProcScanVal(XorStr("BYPASS.exe").c_str()) != 0)
        {
            ThreatDetected(1);
        }
        if (ProcScanVal(XorStr("Outbuilt.exe").c_str()) != 0)
        {
            ThreatDetected(1);
        }
        if (ProcScanVal(XorStr("OUTBUILT.exe").c_str()) != 0)
        {
            ThreatDetected(1);
        }
        if (ProcScanVal(XorStr("ollydbg.exe").c_str()) != 0)
        {
            ThreatDetected(1);
        }
        else if (ProcScanVal(XorStr("ProcessHacker.exe").c_str()) != 0)
        {
            ThreatDetected(1);
        }
        else if (ProcScanVal(XorStr("tcpview.exe").c_str()) != 0)
        {
            ThreatDetected(1);
        }
        else if (ProcScanVal(XorStr("autoruns.exe").c_str()) != 0)
        {
            ThreatDetected(1);
        }
        else if (ProcScanVal(XorStr("autorunsc.exe").c_str()) != 0)
        {
            ThreatDetected(1);
        }
        else if (ProcScanVal(XorStr("filemon.exe").c_str()) != 0)
        {
            ThreatDetected(1);
        }
        else if (ProcScanVal(XorStr("procmon.exe").c_str()) != 0)
        {
            ThreatDetected(1);
        }
        else if (ProcScanVal(XorStr("regmon.exe").c_str()) != 0)
        {
            ThreatDetected(1);
        }
        else if (ProcScanVal(XorStr("procexp.exe").c_str()) != 0)
        {
            ThreatDetected(1);
        }
        else if (ProcScanVal(XorStr("idaq.exe").c_str()) != 0)
        {
            ThreatDetected(1);
        }
        else if (ProcScanVal(XorStr("idaq64.exe").c_str()) != 0)
        {
            ThreatDetected(1);
        }
        else if (ProcScanVal(XorStr("ImmunityDebugger.exe").c_str()) != 0)
        {
            ThreatDetected(1);
        }
        else if (ProcScanVal(XorStr("Wireshark.exe").c_str()) != 0)
        {
            ThreatDetected(1);
        }
        else if (ProcScanVal(XorStr("dumpcap.exe").c_str()) != 0)
        {
            ThreatDetected(1);
        }
        else if (ProcScanVal(XorStr("HookExplorer.exe").c_str()) != 0)
        {
            ThreatDetected(1);
        }
        else if (ProcScanVal(XorStr("ImportREC.exe").c_str()) != 0)
        {
            ThreatDetected(1);
        }
        else if (ProcScanVal(XorStr("PETools.exe").c_str()) != 0)
        {
            ThreatDetected(1);
        }
        else if (ProcScanVal(XorStr("LordPE.exe").c_str()) != 0)
        {
            ThreatDetected(1);
        }
        else if (ProcScanVal(XorStr("dumpcap.exe").c_str()) != 0)
        {
            ThreatDetected(1);
        }
        else if (ProcScanVal(XorStr("SysInspector.exe").c_str()) != 0)
        {
            ThreatDetected(1);
        }
        else if (ProcScanVal(XorStr("proc_analyzer.exe").c_str()) != 0)
        {
            ThreatDetected(1);
        }
        else if (ProcScanVal(XorStr("sysAnalyzer.exe").c_str()) != 0)
        {
            ThreatDetected(1);
        }
        else if (ProcScanVal(XorStr("sniff_hit.exe").c_str()) != 0)
        {
            ThreatDetected(1);
        }
        else if (ProcScanVal(XorStr("windbg.exe").c_str()) != 0)
        {
            ThreatDetected(1);
        }
        else if (ProcScanVal(XorStr("joeboxcontrol.exe").c_str()) != 0)
        {
            ThreatDetected(1);
        }
        else if (ProcScanVal(XorStr("Fiddler.exe").c_str()) != 0)
        {
            ThreatDetected(1);
        }
        else if (ProcScanVal(XorStr("joeboxserver.exe").c_str()) != 0)
        {
            ThreatDetected(1);
        }
        else if (ProcScanVal(XorStr("ida64.exe").c_str()) != 0)
        {
            ThreatDetected(1);
        }
        else if (ProcScanVal(XorStr("ida.exe").c_str()) != 0)
        {
            ThreatDetected(1);
        }
        else if (ProcScanVal(XorStr("Vmtoolsd.exe").c_str()) != 0)
        {
            ThreatDetected(1);
        }
        else if (ProcScanVal(XorStr("Vmwaretrat.exe").c_str()) != 0)
        {
            ThreatDetected(1);
        }
        else if (ProcScanVal(XorStr("Vmwareuser.exe").c_str()) != 0)
        {
            ThreatDetected(1);
        }
        else if (ProcScanVal(XorStr("Vmacthlp.exe").c_str()) != 0)
        {
            ThreatDetected(1);
        }
        else if (ProcScanVal(XorStr("vboxservice.exe").c_str()) != 0)
        {
            ThreatDetected(1);
        }
        else if (ProcScanVal(XorStr("vboxtray.exe").c_str()) != 0)
        {
            ThreatDetected(1);
        }
        else if (ProcScanVal(XorStr("ReClass.NET.exe").c_str()) != 0)
        {
            ThreatDetected(1);
        }
        else if (ProcScanVal(XorStr("x64dbg.exe").c_str()) != 0)
        {
            ThreatDetected(1);
        }
        else if (ProcScanVal(XorStr("OLLYDBG.exe").c_str()) != 0)
        {
            ThreatDetected(1);
        }
        else if (ProcScanVal(XorStr("HTTPDebuggerSvc.exe").c_str()) != 0)
        {
            ThreatDetected(1);
        }
        else if (ProcScanVal(XorStr("HTTPDebuggerUI.exe").c_str()) != 0)
        {
            ThreatDetected(1);
        }
        else if (ProcScanVal(XorStr("FolderChangesView.exe").c_str()) != 0)
        {
            ThreatDetected(1);
        }
        else if (ProcScanVal(XorStr("FileSystemWatcher.exe").c_str()) != 0)
        {
            ThreatDetected(1);
        }
        if (ProcScanVal(XorStr("ollydbg.exe").c_str()) != 0)
        {
            ThreatDetected(1);
        }
    }
}

void UnauthorizedPublicDebuggerTabSecurity()
{
    if (UNAUTHORIZED_PUBLIC_DEBUGGER_TAB_SECURITY)
    {
        if (FindWindow(NULL, XorStr("The Wireshark Network Analyzer").c_str()))
        {
            ThreatDetected(1);
        }

        if (FindWindow(NULL, XorStr("Progress Telerik Fiddler Web Debugger").c_str()))
        {

            ThreatDetected(1);
        }

        if (FindWindow(NULL, XorStr("Fiddler").c_str()))
        {
            ThreatDetected(1);
        }


        if (FindWindow(NULL, XorStr("HTTP Debugger").c_str()))
        {
            ThreatDetected(1);
        }

        if (FindWindow(NULL, XorStr("x64dbg").c_str()))
        {
            ThreatDetected(1);
        }

        if (FindWindow(NULL, XorStr("Process Monitor").c_str()))
        {
            ThreatDetected(1);
        }

        if (FindWindow(NULL, XorStr("http").c_str()))
        {
            ThreatDetected(1);
        }

        if (FindWindow(NULL, XorStr("Http").c_str()))
        {
            ThreatDetected(1);
        }

        if (FindWindow(NULL, XorStr("Bypass").c_str()))
        {
            ThreatDetected(1);
        }

        if (FindWindow(NULL, XorStr("ZeraX").c_str()))
        {
            ThreatDetected(1);
        }

        if (FindWindow(NULL, XorStr("GayCrack").c_str()))
        {
            ThreatDetected(1);
        }

        if (FindWindow(NULL, XorStr("BandCrack").c_str()))
        {
            ThreatDetected(1);
        }

        if (FindWindow(NULL, XorStr("NIGGER CRACK").c_str()))
        {
            ThreatDetected(1);
        }
    }
};
//Borderline Security (END)

void BorderlineSecurity()
{
    TraceSecurity();

    while (true)
    {
        NativeDebuggerSecurity();
        Sleep((DWORD)COOLDOWN);
        UnauthorizedPublicDebuggerSecurity();
        Sleep((DWORD)COOLDOWN);
        UnauthorizedPublicDebuggerTabSecurity();
        Sleep((DWORD)COOLDOWN);
        TerminateDebugger();
    }
}



void TLSSecurity()
{
    /* TLS Checks */
    if (TLS_SECURITY)
    {
        //while (true)
        {


            Sleep((DWORD)COOLDOWN);
        }
    }
}

void AdvancedAntiDebugging()
{
    /* Debugger Detection */
    if (ADVANCED_ANTI_DEBUGGING)
    {
       
        while (true)
        {


            Sleep((DWORD)COOLDOWN);
        }
    }
}

void TimingSecurity()
{
    /* Timing Attacks */
    if (TIMING_ATTACKS)
    {
        UINT delayInSeconds = 600U;
        UINT delayInMillis = delayInSeconds * 1000U;
        // Minutes = delayInSeconds / 60

        while (true)
        {
           

            Sleep((DWORD)COOLDOWN);
        }

    }
}

void AntiDump()
{
    /* Anti Dumping */
    if (ANTI_DUMPING_SECURITY)
    {
        //while (true)
        {
          //  ErasePEHeaderFromMemory();
            SizeOfImage();

            Sleep((DWORD)COOLDOWN);
        }
    }
}



int InitiateSecurityProtocol()
{

    if ((HANDLE)FindWindow(TEXT("WinDbgFrameClass"), NULL))
    {
        ThreatDetected(2);
    }
  std::thread SECURITY_THREAD_0(BorderlineSecurity);

  std::thread SECURITY_THREAD_2(AdvancedAntiDebugging);

  std::thread SECURITY_THREAD_3(TLSSecurity);

  std::thread SECURITY_THREAD_4(TimingSecurity);

  std::thread SECURITY_THREAD_5(AntiDump);

  return 1;
}