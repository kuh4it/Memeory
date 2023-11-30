///////////////////////////////////////////////////////////////////////////////
///
/// Copyright (c) 2023 - ultracage(rsa)
///
/// Original filename: FucnTS.h
/// Project          : FucnTS
/// Date of creation : <see FucnTS.c>
/// Author(s)        : <see FucnTS.c>
///
/// Purpose          : <see FucnTS.c>
///
/// Revisions:         <see FucnTS.c>
///
///////////////////////////////////////////////////////////////////////////////

// $Id$

#ifndef __FUCNTS_H_VERSION__
#define __FUCNTS_H_VERSION__ 100

#if defined(_MSC_VER) && (_MSC_VER >= 1020)
#pragma once
#endif

#ifdef __cplusplus
extern "C" {
#endif
#include <ntddk.h>
#include <string.h>
#include "layer.h"
#include "ldr.h"
#include "disasm.h"
#ifdef __cplusplus
}; // extern "C"
#endif


#include "drvcommon.h"
#include "drvversion.h"
#include "PE.h"

#define DEVICE_NAME			"\\Device\\FUCNTS_DeviceName"
#define SYMLINK_NAME		"\\DosDevices\\FUCNTS_DeviceName"
PRESET_UNICODE_STRING(usDeviceName, DEVICE_NAME);
PRESET_UNICODE_STRING(usSymlinkName, SYMLINK_NAME);

#define IOCTL_BASE          0x800
#define MY_CTL_CODE(i)        \
    CTL_CODE                  \
    (                         \
    FILE_DEVICE_UNKNOWN,  \
    IOCTL_BASE + i,       \
    METHOD_BUFFERED,      \
    FILE_ANY_ACCESS       \
    )
#define IOCTL_Memeory        MY_CTL_CODE(0)
#define IOCTL_UNMemeory      MY_CTL_CODE(1)


#ifndef FILE_DEVICE_FUCNTS
#define FILE_DEVICE_FUCNTS 0x8000
#endif

// Values defined for "Method"
// METHOD_BUFFERED
// METHOD_IN_DIRECT
// METHOD_OUT_DIRECT
// METHOD_NEITHER
// 
// Values defined for "Access"
// FILE_ANY_ACCESS
// FILE_READ_ACCESS
// FILE_WRITE_ACCESS

#define IOCTL_FUCNTS_OPERATION CTL_CODE(FILE_DEVICE_FUCNTS, 0x01, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define PAGEDCODE code_seg("PAGE")
#define LOCKEDCODE code_seg()
#define INITCODE code_seg("INIT")

#define PAGEDDATA data_seg("PAGE")
#define LOCKEDDATA data_seg()
#define INITDATA data_seg("INIT")
#define MAX_PATH 260

typedef struct _SystemServiceDescriptorTable
{
    PVOID ServiceTableBase;
    PULONG ServiceCounterTableBase;
    ULONG NumberOfService;
    PVOID ParamTableBase;
}SSDT;

#define EPROCESS_SIZE 0
#define PEB_OFFSET 1
#define FILE_NAME_OFFSET 2

#define PROCESS_LINK_OFFSET 3
#define PROCESS_ID_OFFSET 4
#define EXIT_TIME_OFFSET 5

// XP
#define NtWriteVirtualMemoryIndex 0x115
#define NtReadVirtualMemoryIndex  0xba

// 2003
// #define NtWriteVirtualMemoryIndex 0x11f
// #define NtReadVirtualMemoryIndex  0xc2

ULONG g_uOldNtWriteVirtualMemoryAddr = 0;
ULONG g_uOldNtReadVirtualMemoryAddr = 0;


NTSTATUS OpenKernelFile(PULONG puKernelBase, PULONG puImageBase);
PVOID GetKernelBase(PVOID pRawData, PANSI_STRING pFuncName, ULONG uFuncAddr);
BOOLEAN HookSSDT(ULONG uNewHookAddr, PULONG pOldFuncAddr, ULONG uIndex);
BOOLEAN UnHookSSDT(ULONG uOldFuncAddr, ULONG uIndex);
EXTERN_C __declspec(dllimport) NTSTATUS NTAPI ZwPulseEvent(__in HANDLE EventHandle,__out_opt PLONG PreviousState);
VOID CliAndDisableWP();
VOID EnableWPAndSti();
NTSTATUS  Hook();
ULONG GetSSDTAddr(ULONG KernelBase, ULONG ImageBase, ULONG uIndex);
void CopyFuncByte(ULONG uNewAddr, ULONG uOlduAddr, ULONG uFuncAddr);

void FuckNtWriteVirtualMemory();
void FuckNtReadVirtualMemory();
VOID EnableKiAttachProcessHook(ULONG uImageBase);
ULONG GetProcessId(PUCHAR pszProcessName);
BOOLEAN DisDebugZero();

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation,
    SystemProcessorInformation,             // obsolete...delete
    SystemPerformanceInformation,
    SystemTimeOfDayInformation,
    SystemPathInformation,
    SystemProcessInformation,
    SystemCallCountInformation,
    SystemDeviceInformation,
    SystemProcessorPerformanceInformation,
    SystemFlagsInformation,
    SystemCallTimeInformation,
    SystemModuleInformation,
    SystemLocksInformation,
    SystemStackTraceInformation,
    SystemPagedPoolInformation,
    SystemNonPagedPoolInformation,
    SystemHandleInformation,
    SystemObjectInformation,
    SystemPageFileInformation,
    SystemVdmInstemulInformation,
    SystemVdmBopInformation,
    SystemFileCacheInformation,
    SystemPoolTagInformation,
    SystemInterruptInformation,
    SystemDpcBehaviorInformation,
    SystemFullMemoryInformation,
    SystemLoadGdiDriverInformation,
    SystemUnloadGdiDriverInformation,
    SystemTimeAdjustmentInformation,
    SystemSummaryMemoryInformation,
    SystemMirrorMemoryInformation,
    SystemPerformanceTraceInformation,
    SystemObsolete0,
    SystemExceptionInformation,
    SystemCrashDumpStateInformation,
    SystemKernelDebuggerInformation,
    SystemContextSwitchInformation,
    SystemRegistryQuotaInformation,
    SystemExtendServiceTableInformation,
    SystemPrioritySeperation,
    SystemVerifierAddDriverInformation,
    SystemVerifierRemoveDriverInformation,
    SystemProcessorIdleInformation,
    SystemLegacyDriverInformation,
    SystemCurrentTimeZoneInformation,
    SystemLookasideInformation,
    SystemTimeSlipNotification,
    SystemSessionCreate,
    SystemSessionDetach,
    SystemSessionInformation,
    SystemRangeStartInformation,
    SystemVerifierInformation,
    SystemVerifierThunkExtend,
    SystemSessionProcessInformation,
    SystemLoadGdiDriverInSystemSpace,
    SystemNumaProcessorMap,
    SystemPrefetcherInformation,
    SystemExtendedProcessInformation,
    SystemRecommendedSharedDataAlignment,
    SystemComPlusPackage,
    SystemNumaAvailableMemory,
    SystemProcessorPowerInformation,
    SystemEmulationBasicInformation,
    SystemEmulationProcessorInformation,
    SystemExtendedHandleInformation,
    SystemLostDelayedWriteInformation,
    SystemBigPoolInformation,
    SystemSessionPoolTagInformation,
    SystemSessionMappedViewInformation,
    SystemHotpatchInformation,
    SystemObjectSecurityMode,
    SystemWatchdogTimerHandler,
    SystemWatchdogTimerInformation,
    SystemLogicalProcessorInformation,
    SystemWow64SharedInformation,
    SystemRegisterFirmwareTableInformationHandler,
    SystemFirmwareTableInformation,
    SystemModuleInformationEx,
    SystemVerifierTriageInformation,
    SystemSuperfetchInformation,
    SystemMemoryListInformation,
    SystemFileCacheInformationEx,
    MaxSystemInfoClass  // MaxSystemInfoClass should always be the last enum
} SYSTEM_INFORMATION_CLASS;

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;                 // Not filled in
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR  FullPathName[ 256 ];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;\


typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;


ULONG GetModuleBase(PCHAR szModuleName);

EXTERN_C
__declspec(dllimport)
NTSTATUS
NTAPI
ZwQuerySystemInformation(__in SYSTEM_INFORMATION_CLASS SystemInformationClass,
                        __out_bcount_opt(SystemInformationLength) PVOID SystemInformation,
                        __in ULONG SystemInformationLength,
                        __out_opt PULONG ReturnLength);

EXTERN_C ULONG ade32_disasm(IN PVOID opcode0);
EXTERN_C ULONG MeasureCodeLength(IN PVOID FuncPtr, IN ULONG NeedLength);
EXTERN_C BOOLEAN RelocateJumps(IN PVOID FuncPtr, IN ULONG Offset, IN ULONG Length);
EXTERN_C VOID WriteJump(PVOID FuncPtr, PVOID JumpPtr);



VOID EnableNtOpenProcessHook(BOOLEAN UnHook);
VOID EnableNtOpenThreadHook(BOOLEAN UnHook);

EXTERN_C POBJECT_TYPE IoDriverObjectType; 
EXTERN_C
NTKERNELAPI
NTSTATUS
ObReferenceObjectByName(__in PUNICODE_STRING ObjectName,
                        __in ULONG Attributes,
                        __in_opt PACCESS_STATE AccessState,
                        __in_opt ACCESS_MASK DesiredAccess,
                        __in POBJECT_TYPE ObjectType,
                        __in KPROCESSOR_MODE AccessMode,
                        __inout_opt PVOID ParseContext,
                        __out PVOID *Object);
EXTERN_C
NTKERNELAPI
NTSTATUS
PsLookupProcessByProcessId(
                           __in HANDLE ProcessId,
                           __deref_out PEPROCESS *Process
                           );

VOID HookTsUnLoad();
VOID UnHookTsUnLoad();
VOID HideProcess(PEPROCESS Process);
VOID EnableZwOpenProcsssook(ULONG uImageBase, BOOLEAN UnHook);
void EnableNtCreateFileHook(ULONG uImageBase, BOOLEAN UnHook);
BOOLEAN IsTpObjecExist();
#endif // __FUCNTS_H_VERSION__
