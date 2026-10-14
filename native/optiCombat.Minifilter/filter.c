/*
 * optiCombat Minifilter v8 — squelette WDK
 *
 * Compilation : Windows Driver Kit 10 + certificat EV (production) ou test signing (dev).
 * Ce fichier documente l'interface minimale ; le .sys n'est pas produit par la CI dotnet.
 *
 * Étapes :
 *   1. Créer un projet Empty WDM Driver dans Visual Studio (filtre activité)
 *   2. Lier fltMgr.lib, inclure fltKernel.h
 *   3. Signer et copier vers %SystemRoot%\System32\drivers\
 *   4. fltmc load optiCombatMinifilter
 */

#ifdef OPTICOMBAT_MINIFILTER_BUILD

#include <fltKernel.h>

PFLT_FILTER g_OpticombatFilter = NULL;

NTSTATUS OpticombatUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);
    if (g_OpticombatFilter != NULL)
    {
        FltUnregisterFilter(g_OpticombatFilter);
        g_OpticombatFilter = NULL;
    }
    return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    const FLT_OPERATION_REGISTRATION callbacks[] = {
        { IRP_MJ_CREATE, 0, NULL, NULL, NULL, NULL, NULL, NULL },
        { IRP_MJ_OPERATION_END }
    };

    const FLT_REGISTRATION registration = {
        sizeof(FLT_REGISTRATION),
        FLT_REGISTRATION_VERSION,
        0,
        NULL,
        callbacks,
        OpticombatUnload,
        NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
    };

    return FltRegisterFilter(DriverObject, &registration, &g_OpticombatFilter);
}

#endif /* OPTICOMBAT_MINIFILTER_BUILD */
