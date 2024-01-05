// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    MessageBoxW(NULL, L"DllMain", L"My_Dll", MB_OK);
    MessageBeep(0);

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        MessageBoxW(NULL, L"DLL_PROCESS_ATTACH", L"My_Dll", MB_OK);
        break;
    case DLL_THREAD_ATTACH:
        MessageBoxW(NULL, L"DLL_THREAD_ATTACH", L"My_Dll", MB_OK);
        break;
    case DLL_THREAD_DETACH:
        MessageBoxW(NULL, L"DLL_THREAD_DETACH", L"My_Dll", MB_OK);
        break;
    case DLL_PROCESS_DETACH:
        MessageBoxW(NULL, L"DLL_PROCESS_DETACH", L"My_Dll", MB_OK);
        break;
    }
    return TRUE;
}

