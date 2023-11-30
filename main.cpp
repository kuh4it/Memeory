#include "stdafx.h"

///////////////////////////////////////////////////////////////////////////////
///
/// Copyright (c) 2023 - ultracage(rsa)
///
/// Original filename: FucnTS.c
/// Project          : FucnTS
/// Date of creation : 2023-02-18
/// Author(s)        : <author name(s)>
///
/// Purpose          : <description>
///
/// Revisions:
///  0000 [2023-02-18] Initial revision.
///
///////////////////////////////////////////////////////////////////////////////

// $Id$
#include "FucnTS.h"
#ifdef __cplusplus
namespace { // anonymous namespace to limit the scope of this global variable!
#endif
	PDRIVER_OBJECT pdoGlobalDrvObj = 0;
#ifdef __cplusplus
}; // anonymous namespace
#endif

EXTERN_C SSDT KeServiceDescriptorTable;

VOID (*g_uOldUnLoad)(IN PDRIVER_OBJECT DriverObject);
// ULONG g_uOldUnLoad = 0;
BOOLEAN g_bUnLoad = FALSE;
ULONG g_uDnfPid = 0;

NTSTATUS
	NtQueryPerformanceCounter (__out PLARGE_INTEGER PerformanceCounter,
	__out_opt PLARGE_INTEGER PerformanceFrequency)
{
	return STATUS_SUCCESS;
}

NTSTATUS FUCNTS_DispatchCreateClose(
	IN PDEVICE_OBJECT		DeviceObject,
	IN PIRP					Irp
	)
{
	NTSTATUS status = STATUS_SUCCESS;
	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS FUCNTS_DispatchDeviceControl(
	IN PDEVICE_OBJECT		DeviceObject,
	IN PIRP					Irp
	)
{
	NTSTATUS status = STATUS_SUCCESS;
	PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);

	switch(irpSp->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_Memeory:
		{
			// 恢复这三个hook, TS没有检测。
			// KiAttachProcess
			// NtReadVritualMemory
			// NtWriteVirtualMemory
			// NtOpenProcess
			// NtOpenThread
			// KdBreakPoint();
			// DebugPort 清零

			Irp->IoStatus.Information = 0;
			status = STATUS_SUCCESS;
		}
		break;
	case IOCTL_UNMemeory:
		{
			KdPrint(("UnFuck TP!\n"));


			Irp->IoStatus.Information = 0;
			status = STATUS_SUCCESS;
		}
		break;
	default:
		Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
		Irp->IoStatus.Information = 0;
		break;
	}

	status = Irp->IoStatus.Status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}


VOID FUCNTS_DriverUnload(
	IN PDRIVER_OBJECT		DriverObject
	)
{

	//KdBreakPoint();
	PDEVICE_OBJECT pdoNextDeviceObj = pdoGlobalDrvObj->DeviceObject;
	IoDeleteSymbolicLink(&usSymlinkName);

	if (g_uOldUnLoad = 0)
	{
		UnHookTsUnLoad();
	}
	if (!g_bUnLoad)
	{
		ULONG uCurrentBuild = 0;
		PsGetVersion(NULL, NULL, &uCurrentBuild, NULL);

		// XP
		// #define NtWriteVirtualMemoryIndex 0x115
		// #define NtReadVirtualMemoryIndex  0xba

		// 2003
		// #define NtWriteVirtualMemoryIndex 0x11f
		// #define NtReadVirtualMemoryIndex  0xc2
		if (uCurrentBuild == 2600) // xp
		{

			UnHookSSDT(g_uOldNtReadVirtualMemoryAddr, 0xba);
			UnHookSSDT(g_uOldNtWriteVirtualMemoryAddr, 0x115);
		}
		else if (uCurrentBuild == 3790) // 2003
		{

			UnHookSSDT(g_uOldNtReadVirtualMemoryAddr, 0xc2);
			UnHookSSDT(g_uOldNtWriteVirtualMemoryAddr, 0x11f);
		}
		EnableNtOpenProcessHook(FALSE);
		EnableNtOpenThreadHook(FALSE);
		//EnableZwOpenProcsssook(0, FALSE);
	}

	// EnableNtCreateFileHook(0, FALSE);
	// Delete all the device objects
	while(pdoNextDeviceObj)
	{
		PDEVICE_OBJECT pdoThisDeviceObj = pdoNextDeviceObj;
		pdoNextDeviceObj = pdoThisDeviceObj->NextDevice;
		IoDeleteDevice(pdoThisDeviceObj);
	}
}

#ifdef __cplusplus
extern "C" {
#endif
	NTSTATUS DriverEntry( IN OUT PDRIVER_OBJECT   DriverObject,  IN PUNICODE_STRING      RegistryPath  )
	{
		//KdBreakPoint();
		PDEVICE_OBJECT pdoDeviceObj = 0;
		NTSTATUS status = STATUS_UNSUCCESSFUL;
		pdoGlobalDrvObj = DriverObject;

		// Create the device object.
		if(!NT_SUCCESS(status = IoCreateDevice(
			DriverObject,
			0,
			&usDeviceName,
			FILE_DEVICE_UNKNOWN,
			FILE_DEVICE_SECURE_OPEN,
			FALSE,
			&pdoDeviceObj
			)))
		{
			// Bail out (implicitly forces the driver to unload).
			return status;
		};

		// Now create the respective symbolic link object
		if(!NT_SUCCESS(status = IoCreateSymbolicLink(
			&usSymlinkName,
			&usDeviceName
			)))
		{
			IoDeleteDevice(pdoDeviceObj);
			return status;
		}

		// NOTE: You need not provide your own implementation for any major function that
		//       you do not want to handle. I have seen code using DDKWizard that left the
		//       *empty* dispatch routines intact. This is not necessary at all!
		DriverObject->MajorFunction[IRP_MJ_CREATE] =
			DriverObject->MajorFunction[IRP_MJ_CLOSE] = FUCNTS_DispatchCreateClose;
		DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = FUCNTS_DispatchDeviceControl;
		DriverObject->DriverUnload = FUCNTS_DriverUnload;

		ULONG uImageBase = 0;


		//     HookTsUnLoad();
		// 
		//     // KdBreakPoint();
		//     KdPrint(("Fuck TP!\n"));
		// 
		//if (DisDebugZero())
		//{
		Hook();
		KdPrint(("Fuck TP success!\n"));
		//}


		return STATUS_SUCCESS;
	}



#ifdef __cplusplus
}; // extern "C"
#endif


// 判断是否开启PAE
#pragma  LOCKEDCODE
BOOLEAN IsOpenPAE()
{
	ULONG uCR4 = 0;
	__asm
	{
		_emit 0x0F 
			_emit 0x20
			_emit 0xE0
			mov uCR4, eax
	}

	// 000006d9
	// 0110 1101 1001
	// 0000 0010 0000
	// 第5位为0,则未开启PAE选项
	if ((uCR4 & 0x00000020) == 0x00000020)
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

#pragma  LOCKEDCODE
VOID GetKernelFileName(PWCHAR pszKernelName)
{
	PWCHAR pszFullName = (IsOpenPAE() ? L"\\SystemRoot\\system32\\ntkrnlpa.exe" :
		L"\\SystemRoot\\system32\\ntoskrnl.exe");
RtlCopyMemory(pszKernelName, 
	pszFullName, 
	wcslen(pszFullName) * sizeof(WCHAR) + sizeof(WCHAR));
}



PVOID GetKernelBase(PVOID pRawData, PANSI_STRING pFuncName, ULONG uFuncAddr)
{
	// 获得该地址在文件中的RAW
	// PVOID pFuncAddr = MiFindExportedRoutineByNameByRaw(pRawData, pFuncName);

	PVOID pFuncRva = MiFindExportedRoutineRvaByNameByRaw(pRawData, pFuncName);
	if (pFuncRva == NULL)
	{
		return NULL;
	}
	// 8082d1f0 - 80800000 = 0x2d1f0;
	// 获得ntoskrnl.exe在内存中的基地址
	PVOID pKernelBase = (PVOID)(uFuncAddr - (ULONG)pFuncRva);
	return pKernelBase;
}

NTSTATUS OpenKernelFile(PULONG puKernelBase, PULONG puImageBase)
{

	WCHAR szKernelName[MAX_PATH];
	RtlZeroMemory(szKernelName, MAX_PATH * 2);
	GetKernelFileName(szKernelName);
	KdPrint(("the kernel file's name is %ws\n", szKernelName));

	OBJECT_ATTRIBUTES ObjectAttributes;
	UNICODE_STRING uniKernelName;
	RtlInitUnicodeString(&uniKernelName, szKernelName);

	InitializeObjectAttributes(&ObjectAttributes, 
		&uniKernelName, 
		OBJ_CASE_INSENSITIVE, 
		NULL, 
		NULL);

	HANDLE hFile = NULL;
	IO_STATUS_BLOCK  IoStatusBlock;
	NTSTATUS FileStatus = ZwCreateFile(&hFile, 
		GENERIC_READ, 
		&ObjectAttributes, 
		&IoStatusBlock, 
		NULL, 
		FILE_ATTRIBUTE_NORMAL, 
		FILE_SHARE_READ, 
		FILE_OPEN, 
		FILE_SYNCHRONOUS_IO_NONALERT, 
		NULL, 
		0);
	if (!NT_SUCCESS(FileStatus))
	{
		KdPrint(("Open File fails\n"));
		return FileStatus;

	}
	// 获得文件大小
	FILE_STANDARD_INFORMATION fsi;
	FileStatus = ZwQueryInformationFile(hFile, 
		&IoStatusBlock, 
		&fsi, 
		sizeof(FILE_STANDARD_INFORMATION), 
		FileStandardInformation);
	if (!NT_SUCCESS(FileStatus))
	{
		KdPrint(("get file length fails\n"));
		return FileStatus;
	}

	KdPrint(("file length:%u\n", fsi.EndOfFile.QuadPart));

	// 读取文件
	ULONG uRawDataSize = (ULONG)fsi.EndOfFile.QuadPart;
	PUCHAR pRawData = (PUCHAR)ExAllocatePool(NonPagedPool, uRawDataSize);
	RtlZeroMemory(pRawData, uRawDataSize);
	if (pRawData == NULL)
	{
		KdPrint(("ExAllocatePool file memory fails\n"));
		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	FileStatus = ZwReadFile(hFile, 
		NULL, 
		NULL, 
		NULL, 
		&IoStatusBlock, 
		pRawData,
		uRawDataSize,
		NULL, 
		NULL);

	if (!NT_SUCCESS(FileStatus))
	{
		KdPrint(("ZwReadFile file fails\n"));
		return FileStatus;
	}
	if (uRawDataSize != IoStatusBlock.Information)
	{
		KdPrint(("read file size error\n"));
		return FileStatus;
	}

	if (hFile != NULL)
	{
		ZwClose(hFile);
		hFile = NULL;
	}

	// 重定位用他LdrRelocateImage
	if (((PIMAGE_DOS_HEADER)pRawData)->e_magic != IMAGE_DOS_SIGNATURE) 
	{
		return STATUS_INVALID_IMAGE_FORMAT;
	}

	PIMAGE_NT_HEADERS pNtHeader = RtlImageNtHeader(pRawData);
	if (pNtHeader == NULL)
	{
		return STATUS_UNSUCCESSFUL;
	}
	if (pNtHeader->Signature != IMAGE_NT_SIGNATURE) 
	{
		return STATUS_INVALID_IMAGE_FORMAT;
	}

	ANSI_STRING FuncName;
	RtlInitAnsiString(&FuncName, "ZwPulseEvent");
	PVOID pKernelBase = GetKernelBase(pRawData, &FuncName, (ULONG)ZwPulseEvent);
	if (pKernelBase == NULL)
	{
		return STATUS_UNSUCCESSFUL;
	}
	ULONG uSizeOfImage = pNtHeader->OptionalHeader.SizeOfImage;
	PUCHAR pImageBase = (PUCHAR)ExAllocatePool(NonPagedPool, uSizeOfImage);
	RtlZeroMemory(pImageBase, uSizeOfImage);
	if (pImageBase == NULL)
	{
		KdPrint(("ExAllocatePool file memory fails\n"));
		return STATUS_MEMORY_NOT_ALLOCATED;
	}
	NTSTATUS status = 0;
	PUCHAR  UserModeZwPulseEvent = NULL;
	LoadImage(pImageBase, pRawData);
	LdrRelocateImage(pImageBase, uSizeOfImage, (ULONG)pKernelBase);

	*puImageBase = (ULONG)pImageBase;
	*puKernelBase = (ULONG)pKernelBase;
	if (pRawData != NULL)
	{
		ExFreePool(pRawData);
		pRawData = NULL;
	}
	return STATUS_SUCCESS;
}

#pragma LOCKEDCODE
ULONG GetSSDTAddr(ULONG KernelBase, ULONG ImageBase, ULONG uIndex)
{
	ULONG SSDTAddr = 0;
	// 获得原始SSDT表
	ULONG uSSDTVa = *(PULONG)KeServiceDescriptorTable.ServiceTableBase 
		- KernelBase + ImageBase;
	SSDTAddr = *(PULONG)(uSSDTVa + uIndex * 4);
	return SSDTAddr;
}

#pragma LOCKEDCODE
void CopyFuncByte(ULONG uNewAddr, ULONG uOlduAddr, ULONG uFuncAddr)
{
	ULONG OldLen = DisassembleUntil((PUCHAR)uOlduAddr, 6);

	CliAndDisableWP();
	RtlMoveMemory((PCHAR)uFuncAddr, (PCHAR)uOlduAddr, OldLen);
	*(PUCHAR)(uFuncAddr + OldLen) = 0x68;
	*(PULONG)(uFuncAddr + OldLen + 1) = (ULONG)(uNewAddr + OldLen);
	*(PUCHAR)(uFuncAddr + OldLen + 5) = 0xc3;
	EnableWPAndSti();
}

NTSTATUS Hook()
{
	NTSTATUS status;
	ULONG uKernelBase = 0;
	ULONG uImageBase = 0;
	// KdBreakPoint();
	OpenKernelFile(&uKernelBase, &uImageBase);
	INSTRUCTION Instruction;
	ULONG uLength = 0;
	ANSI_STRING FuncName;
	UNICODE_STRING SymbolName;

	PVOID SymbolAddress = NULL;;
	PVOID OldSymbolAddress = NULL;
	ULONG uCurrentBuild = 0;
	PsGetVersion(NULL, NULL, &uCurrentBuild, NULL);

	// XP
	// #define NtWriteVirtualMemoryIndex 0x115
	// #define NtReadVirtualMemoryIndex  0xba

	// 2003
	// #define NtWriteVirtualMemoryIndex 0x11f
	// #define NtReadVirtualMemoryIndex  0xc2
	if (uCurrentBuild == 2600) // xp
	{
		ULONG uNewSSDTAddr = GetSSDTAddr(uKernelBase, uImageBase, 0x115);
		ULONG uOlduSSDTAddr = uNewSSDTAddr - uKernelBase + uImageBase;
		CopyFuncByte(uNewSSDTAddr, uOlduSSDTAddr, (ULONG)FuckNtWriteVirtualMemory);
		HookSSDT((ULONG)FuckNtWriteVirtualMemory, &g_uOldNtWriteVirtualMemoryAddr, 0x115);

		uNewSSDTAddr = GetSSDTAddr(uKernelBase, uImageBase, 0xba);
		uOlduSSDTAddr = uNewSSDTAddr - uKernelBase + uImageBase;
		CopyFuncByte(uNewSSDTAddr, uOlduSSDTAddr, (ULONG)FuckNtReadVirtualMemory);
		HookSSDT((ULONG)FuckNtReadVirtualMemory, &g_uOldNtReadVirtualMemoryAddr, 0xba);
	}
	else if (uCurrentBuild == 3790) // 2003
	{
		ULONG uNewSSDTAddr = GetSSDTAddr(uKernelBase, uImageBase, 0x11f);
		ULONG uOlduSSDTAddr = uNewSSDTAddr - uKernelBase + uImageBase;
		CopyFuncByte(uNewSSDTAddr, uOlduSSDTAddr, (ULONG)FuckNtWriteVirtualMemory);
		HookSSDT((ULONG)FuckNtWriteVirtualMemory, &g_uOldNtWriteVirtualMemoryAddr, 0x11f);

		uNewSSDTAddr = GetSSDTAddr(uKernelBase, uImageBase, 0xc2);
		uOlduSSDTAddr = uNewSSDTAddr - uKernelBase + uImageBase;
		CopyFuncByte(uNewSSDTAddr, uOlduSSDTAddr, (ULONG)FuckNtReadVirtualMemory);
		HookSSDT((ULONG)FuckNtReadVirtualMemory, &g_uOldNtReadVirtualMemoryAddr, 0xc2);
	}
	else
	{
		KdPrint(("Hook SSDT fails\n"));
	}

	//EnableKiAttachProcessHook(uImageBase);
	EnableNtOpenProcessHook(TRUE);
	//EnableNtOpenThreadHook(TRUE);

	//     EnableZwOpenProcsssook(uImageBase, TRUE);
	//     EnableNtCreateFileHook(uImageBase, TRUE);
	if (uImageBase != 0)
	{
		ExFreePool((PVOID)uImageBase);
	}
	return STATUS_SUCCESS;
}
BOOLEAN HookSSDT(ULONG uNewHookAddr, PULONG pOldFuncAddr, ULONG uIndex)
{
	ULONG dwAddr
		= *(PULONG)KeServiceDescriptorTable.ServiceTableBase + uIndex * 4;

	*pOldFuncAddr = *(PULONG)dwAddr;
	__try
	{
		CliAndDisableWP();
		*(PULONG)dwAddr = (ULONG)uNewHookAddr;
		EnableWPAndSti();
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		return FALSE;
	}
	return TRUE;
}

BOOLEAN UnHookSSDT(ULONG uOldFuncAddr, ULONG uIndex)
{
	ULONG dwAddr
		= *(PULONG)KeServiceDescriptorTable.ServiceTableBase + uIndex * 4;
	__try
	{
		CliAndDisableWP();
		*(PULONG)dwAddr = uOldFuncAddr;
		EnableWPAndSti();
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		return FALSE;
	}
	return TRUE;
}

VOID CliAndDisableWP()
{
	__asm
	{
		cli;
		push eax;
		mov eax, cr0;
		and eax, 0FFFEFFFFh;
		mov cr0, eax;
		pop eax;
	}
}

VOID EnableWPAndSti()
{
	__asm
	{
		push eax;
		mov eax, cr0;
		or eax, 10000h;
		mov cr0, eax;
		pop eax;
		sti;
	}
}

#pragma  LOCKEDCODE
__declspec( naked ) void FuckNtWriteVirtualMemory()
{
	__asm
	{
		mov ecx, 0x10
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
	}
}

#pragma  LOCKEDCODE
__declspec( naked ) void FuckNtReadVirtualMemory()
{
	__asm
	{
		mov ecx, 0x1232434
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
	}
}


UCHAR BackupKiAttachProcess[15] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
#pragma LOCKEDCODE
VOID EnableKiAttachProcessHook(ULONG uImageBase)
{
	//KdBreakPoint();
	KIRQL OldIrql;
	ULONG uLength = 0;
	ANSI_STRING FuncName;
	UNICODE_STRING SymbolName;

	PVOID SymbolAddress = NULL;;
	PVOID OldSymbolAddress = NULL;
	ULONG uReg = 0;
	ULONG uKiAttachProcessAddr = 0;
	ULONG uOldKiAttachProcessAddr = 0;
	RtlInitUnicodeString(&SymbolName, L"KeAttachProcess");

	RtlInitAnsiString(&FuncName, "KeAttachProcess");

	OldSymbolAddress = MiFindExportedRoutineByName((PVOID)uImageBase, &FuncName);
	if ((SymbolAddress = MmGetSystemRoutineAddress(
		&SymbolName)) && OldSymbolAddress)
	{
		// KiAttachProcess 没有被导出。 搜索KeAttachProcess的第一个0xE8处。既是KiAttachProcess的地址。
		// 后面有个字节0xC2.这样确定是否找到KiAttachProcess。

		//         nt!KeAttachProcess+0x2a:
		//         804f8906 ff1514874d80    call    dword ptr [nt!_imp__KeRaiseIrqlToDpcLevel (804d8714)]
		//         804f890c 884508          mov     byte ptr [ebp+8],al
		//         804f890f 8d864c010000    lea     eax,[esi+14Ch]
		//         804f8915 50              push    eax
		//         804f8916 ff7508          push    dword ptr [ebp+8]
		//         804f8919 57              push    edi
		//         804f891a 56              push    esi
		//         804f891b e8b8feffff      call    nt!KiAttachProcess (804f87d8)
		// 
		//         nt!KeAttachProcess+0x44:
		//         804f8920 5f              pop     edi
		//         804f8921 5e              pop     esi
		//         804f8922 5d              pop     ebp
		//         804f8923 c20400          ret     4
		CliAndDisableWP();


		ULONG uCurrentBuild = 0;
		PsGetVersion(NULL, NULL, &uCurrentBuild, NULL);

		// XP
		// #define NtWriteVirtualMemoryIndex 0x115
		// #define NtReadVirtualMemoryIndex  0xba

		// 2003
		// #define NtWriteVirtualMemoryIndex 0x11f
		// #define NtReadVirtualMemoryIndex  0xc2


		PUCHAR pStart = (PUCHAR)SymbolAddress;
		for (INT i = 0; i < 512; i++)
		{
			if (uCurrentBuild == 2600) // xp
			{
				if (*(PUCHAR)pStart == 0xe8)
				{
					// 找到KiAttachProcess
					// call addr
					// addr - CurAddr - 5 = op; 
					// addr = CurAddr + 5 + op
					uKiAttachProcessAddr = (ULONG)(pStart + 0x5 + *(PULONG)(pStart + 1));
					break;
				}
				pStart++;
			}
			else if (uCurrentBuild == 3790) // 2003
			{
				if (*(PUCHAR)pStart == 0xe8)
				{
					// 找到KiAttachProcess
					// call addr
					// addr - CurAddr - 5 = op; 
					// addr = CurAddr + 5 + op
					// uKiAttachProcessAddr = (ULONG)(pStart + 0x5 + *(PULONG)(pStart + 1));
					PUCHAR pStartEx = (PUCHAR)pStart + 1;
					for (int j = 0; j < 512; j++)
					{
						if (*(PUCHAR)pStartEx == 0xe8)
						{
							// 找到KiAttachProcess
							// call addr
							// addr - CurAddr - 5 = op; 
							// addr = CurAddr + 5 + op
							uKiAttachProcessAddr = (ULONG)(pStartEx + 0x5 + *(PULONG)(pStartEx + 1));
							break;
						}
						pStartEx++;
					}
					break;
				}
				pStart++;
			}

		}

		pStart = (PUCHAR)OldSymbolAddress;
		for (INT i = 0; i < 512; i++)
		{
			if (uCurrentBuild == 2600) // xp
			{
				if (*(PUCHAR)pStart == 0xe8)
				{
					// 找到KiAttachProcess
					// call addr
					// addr - CurAddr - 5 = op; 
					// addr = CurAddr + 5 + op
					uOldKiAttachProcessAddr = (ULONG)(pStart + 0x5 + *(PULONG)(pStart + 1));
					break;
				}
				pStart++;
			}
			else if (uCurrentBuild == 3790) // 2003
			{
				if (*(PUCHAR)pStart == 0xe8)
				{
					// 找到KiAttachProcess
					// call addr
					// addr - CurAddr - 5 = op; 
					// addr = CurAddr + 5 + op
					// uOldKiAttachProcessAddr = (ULONG)(pStart + 0x5 + *(PULONG)(pStart + 1));

					PUCHAR pStartEx = (PUCHAR)pStart + 1;
					for (int j = 0; j < 512; j++)
					{
						if (*(PUCHAR)pStartEx == 0xe8)
						{
							// 找到KiAttachProcess
							// call addr
							// addr - CurAddr - 5 = op; 
							// addr = CurAddr + 5 + op
							uOldKiAttachProcessAddr = (ULONG)(pStartEx + 0x5 + *(PULONG)(pStartEx + 1));
							break;
						}
						pStartEx++;
					}
					break;
				}
				pStart++;
			}
		}

		EnableWPAndSti();
		ULONG OldLen = 9; DisassembleUntil((PUCHAR)uKiAttachProcessAddr, 9);

		CliAndDisableWP();
		RtlMoveMemory((PCHAR)BackupKiAttachProcess, (PCHAR)uOldKiAttachProcessAddr, OldLen);
		EnableWPAndSti();


		OldIrql = KeRaiseIrqlToDpcLevel();
		CliAndDisableWP();
		RtlMoveMemory((PVOID)uKiAttachProcessAddr, BackupKiAttachProcess, 9);
		EnableWPAndSti();
		KeLowerIrql(OldIrql);
	}

}

ULONG GetModuleBase(PCHAR szModuleName)
{
	ULONG uSize = 0x10000;
	PVOID pModuleInfo = ExAllocatePoolWithTag(NonPagedPool, 
		uSize, 
		'GetB');
	if (pModuleInfo == NULL)
	{
		KdPrint(("ExAllocatePoolWithTag failed\n"));
		return 0;
	}
	RtlZeroMemory(pModuleInfo, uSize);

	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, 
		pModuleInfo, 
		uSize, 
		NULL);

	if(!NT_SUCCESS(status))
	{
		KdPrint(("FindModuleByAddress query failed\n"));
		//打印错误
		KdPrint(("FindModuleByAddress status: 0x%x\n", status));
		if (pModuleInfo != NULL)
		{
			ExFreePool(pModuleInfo);
			pModuleInfo = NULL;
		}
		return 0;
	}

	ULONG uNumberOfModules = *(PULONG)pModuleInfo;
	if (uNumberOfModules == 0)
	{
		return 0;
	}

	PRTL_PROCESS_MODULE_INFORMATION pStart = 
		(PRTL_PROCESS_MODULE_INFORMATION)((ULONG)pModuleInfo + sizeof(ULONG));

	for (ULONG uCount = 0; uCount < uNumberOfModules; uCount++)
	{
		PUCHAR pszFullPathName = (PUCHAR)pStart->FullPathName;

		ULONG uOffsetName = pStart->OffsetToFileName;

		PUCHAR pszName = (PUCHAR)(pszFullPathName + uOffsetName);

		if (_stricmp((const char *)pszName, szModuleName) == 0)
		{
			ULONG uImageBase = (ULONG)pStart->ImageBase;
			if (pModuleInfo != NULL)
			{
				ExFreePool(pModuleInfo);
				pModuleInfo = NULL;
			}
			return uImageBase;
		}

		pStart++;
	}

	if (pModuleInfo != NULL)
	{
		ExFreePool(pModuleInfo);
		pModuleInfo = NULL;
	}
	return 0;
}

BOOLEAN DisDebugZero()
{

	// 获得TesSafe.sys的加载基地址
	ULONG uImageBase = GetModuleBase("TesSafe.sys");
	if (uImageBase == 0)
	{
		return FALSE;
	}

	// 修改三处
	// 修改此三处即可修复DebugPort清零问题。
	// 1. 0x41E0 0xc3
	// 2. 0x2638 0xc3
	// 3. 0x4F2C 0xc3
	KIRQL OldIrql;
	OldIrql = KeRaiseIrqlToDpcLevel();
	CliAndDisableWP();
	// 总检查代码处
	*(PUCHAR)(uImageBase + 0x3658) = 0xc3;
	// 第一处DebugPort清零
	*(PUCHAR)(uImageBase + 0x5556) = 0xc3;
	// 第二处DebugPort清零
	*(PUCHAR)(uImageBase + 0x1E4E) = 0xc3;
	EnableWPAndSti();
	KeLowerIrql(OldIrql);

	// 每次更新其实变动最大的就是这三处修改了
	// 更新一次。偏移就会变。最好呢。用特征码匹配来做
	// 那每次更新了。就不会再取麻烦的调试了。
	return TRUE;
}

VOID GetDpcRoutine()
{
	//     Index = 0;
	//     do {
	//         ListHead = &KiTimerTableListHead[Index].Entry;
	//         NextEntry = ListHead->Flink;
	//         while (NextEntry != ListHead) {
	//             Timer = CONTAINING_RECORD(NextEntry, KTIMER, TimerListEntry);
	//             NextEntry = NextEntry->Flink;
	//             if (Timer->DueTime.QuadPart <= CurrentTime.QuadPart) {
	// 
	//                 //
	//                 // If the timer expiration DPC is queued, then the time has
	//                 // been change and the DPC has not yet had the chance to run
	//                 // and clear out the expired timers.
	//                 //
	// 
	//                 if ((KeGetCurrentPrcb()->TimerRequest == 0) &&
	//                     *((volatile PKSPIN_LOCK *)(&KiTimerExpireDpc.DpcData)) == NULL) {
	//                         DbgBreakPoint();
	//                 }
	//             }
	//         }
	// 
	//         Index += 1;
	//     } while(Index < TIMER_TABLE_SIZE);
}

ULONG GetPlantformDependentInfo(ULONG dwFlag)   
{    
	ULONG current_build;    
	ULONG ans = 0;    

	PsGetVersion(NULL, NULL, &current_build, NULL);    

	switch ( dwFlag )   
	{    
	case EPROCESS_SIZE:    
		if (current_build == 2195) ans = 0 ;        // 2000，当前不支持2000，下同   
		if (current_build == 2600) ans = 0x25C;     // xp   
		if (current_build == 3790) ans = 0x270;     // 2003   
		break;    
	case PEB_OFFSET:    
		if (current_build == 2195)  ans = 0;    
		if (current_build == 2600)  ans = 0x1b0;    
		if (current_build == 3790)  ans = 0x1a0;   
		break;    
	case FILE_NAME_OFFSET:    
		if (current_build == 2195)  ans = 0;    
		if (current_build == 2600)  ans = 0x174;    
		if (current_build == 3790)  ans = 0x164;   
		break;    
	case PROCESS_LINK_OFFSET:    
		if (current_build == 2195)  ans = 0;    
		if (current_build == 2600)  ans = 0x088;    
		if (current_build == 3790)  ans = 0x098;   
		break;    
	case PROCESS_ID_OFFSET:    
		if (current_build == 2195)  ans = 0;    
		if (current_build == 2600)  ans = 0x084;    
		if (current_build == 3790)  ans = 0x094;   
		break;    
	case EXIT_TIME_OFFSET:    
		if (current_build == 2195)  ans = 0;    
		if (current_build == 2600)  ans = 0x078;    
		if (current_build == 3790)  ans = 0x088;   

		break;    
	}    
	return ans;    
}

void GetFuckHookAddr(ULONG uFuckAddr, ULONG& uFirst, ULONG & uSecond)
{

	//     00011660 90             nop
	//     00011661 FF D7          call    edi
	//     00011663 50             push    eax
	//     00011664 90             nop
	// 
	//     00011690 90             nop
	//     00011691 FF D0          call    eax
	//     00011693 57             push    edi
	//     00011694 90             nop


	CliAndDisableWP();
	PUCHAR p = (PUCHAR)uFuckAddr;
	while (1)
	{
		if ((*(p) == 0x90) && 
			(*(p + 0x1) == 0xff) &&
			(*(p + 0x2) == 0xd7) &&
			(*(p + 0x3) == 0x50) &&
			(*(p + 0x4) == 0x90))
		{
			KdPrint(("%0X \n",(ULONG)p));
			break;
		}
		//推动指针向前走
		p++;
	}
	uFirst = (ULONG)p;

	p = (PUCHAR)uFuckAddr;
	while (1)
	{
		if ((*(p) == 0x90) && 
			(*(p + 0x1) == 0xff) &&
			(*(p + 0x2) == 0xd0) &&
			(*(p + 0x3) == 0x57) &&
			(*(p + 0x4) == 0x90))
		{
			KdPrint(("%0X \n",(ULONG)p));
			break;
		}
		//推动指针向前走
		p++;
	}
	uSecond = (ULONG)p;
	EnableWPAndSti();
}


#define OLLYDBG  "C9.EXE"
#define CE "TENSAFE.EXE"

PVOID g_pCurEprocess = NULL;
ANSI_STRING g_StrGet, g_StrOd, g_StrCe, g_StrJnject;
// 大写
ULONG g_uTSNtOpenHookAddress = 0;
ULONG g_uObOpenObjectByPointer = 0;
ULONG g_uNtOpenProcessRet = 0;
ULONG g_uNtOpenHookAddress = 0;

#pragma  LOCKEDCODE
__declspec( naked ) void FuckNtOpenProcess()
{
	// 获得当前进程EPROCESS
	g_pCurEprocess = IoGetCurrentProcess();

	RtlInitAnsiString(&g_StrGet, 
		(PSZ)((ULONG)g_pCurEprocess + GetPlantformDependentInfo(FILE_NAME_OFFSET)));

	RtlInitAnsiString(&g_StrOd, OLLYDBG);
	RtlInitAnsiString(&g_StrCe, CE);
	// RtlInitAnsiString(&g_StrJnject, INJECT);

	_strupr(g_StrGet.Buffer);
	if ((RtlCompareString(&g_StrGet, &g_StrOd, TRUE) == 0 ||
		RtlCompareString(&g_StrGet, &g_StrCe, TRUE) == 0) &&
		IsTpObjecExist())
	{
		// 跳回到TShook代码处
		__asm
		{
			nop
				call edi
				push eax
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				push g_uNtOpenProcessRet
				mov eax, g_uTSNtOpenHookAddress
				jmp eax
		}
	}
	else
	{
		// 直接跳回到ObOpenObjectByPointer代码中
		__asm
		{
			nop
				call eax
				push edi
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				push g_uNtOpenProcessRet
				mov eax, g_uObOpenObjectByPointer
				jmp eax
		}
	}
}


ULONG NtOpenProcessHookLen = 0;
UCHAR BackupNtOpenProcessHook[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
UCHAR RealNtOpenProcessHook[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
BOOLEAN NtOpenProcessHookEnabled = FALSE;
#pragma LOCKEDCODE
VOID EnableNtOpenProcessHook(BOOLEAN UnHook)
{

	KIRQL OldIrql;
	ULONG uLength = 0;
	ANSI_STRING FuncName;
	UNICODE_STRING SymbolName;

	PVOID SymbolAddress = NULL;;
	PVOID OldSymbolAddress = NULL;
	ULONG uReg = 0;

	if (UnHook == NtOpenProcessHookEnabled) 
	{        
		return;
	}
	// ntkrnlpa:805C252B 8D 45 E0                  lea     eax, [ebp-20h]
	// ntkrnlpa:805C252E 50                        push    eax
	// ntkrnlpa:805C252F FF 75 CC                  push    dword ptr [ebp-34h]
	// ntkrnlpa:805C2532 FF 35 D8 B2 55 80         push    dword ptr ds:8055B2D8h
	// ntkrnlpa:805C2538 56                        push    esi
	// ntkrnlpa:805C2539 8D 85 48 FF FF FF         lea     eax, [ebp-0B8h]
	// ntkrnlpa:805C253F 50                        push    eax
	// ntkrnlpa:805C2540 FF 75 C8                  push    dword ptr [ebp-38h]
	// ntkrnlpa:805C2543 FF 75 DC                  push    dword ptr [ebp-24h]
	// ntkrnlpa:805C2546 E8 8B FE FE FF            call    nt_ObOpenObjectByPointer
	// ntkrnlpa:805C254B 8B F8                     mov     edi, eax
	// ntkrnlpa:805C254D 8D 85 48 FF FF FF         lea     eax, [ebp-0B8h]
	// ntkrnlpa:805C2553 50                        push    eax
	// ntkrnlpa:805C2554 E8 87 59 02 00            call    nt_SeDeleteAccessState
	// ntkrnlpa:805C2559 8B 4D D0                  mov     ecx, [ebp-30h]
	// ntkrnlpa:805C255C 3B CE                     cmp     ecx, esi
	// ntkrnlpa:805C255E 74 05                     jz      short loc_805C2565
	// ntkrnlpa:805C2560 E8 0D 16 F6 FF            call    nt_ObfDereferenceObject




	if (UnHook)
	{
		// 查找NtOpenProcess被hook的代码。
		RtlInitUnicodeString(&SymbolName, L"NtOpenProcess");
		SymbolAddress = MmGetSystemRoutineAddress(&SymbolName);
		PUCHAR p = NULL;

		CliAndDisableWP();
		if (SymbolAddress)
		{
			p = (PUCHAR)SymbolAddress;
			//用一个无限循环来判断给定的特征码来确定被HOOK位置
			while (1)
			{
				if ((*(p - 7) == 0x50) && 
					(*(p - 0xE) == 0x56) &&
					(*(p + 0xd) == 0x50) &&
					(*(p + 0x16) == 0x3b) &&
					(*(p + 0x17) == 0xce) &&
					(*p == 0xE8) &&
					(*(p + 5)    == 0x8b) &&
					(*(p + 6)    == 0xf8))
				{
					KdPrint(("%0X \n",(ULONG)p));
					break;
				}
				//推动指针向前走
				p++;
			}
		}

		EnableWPAndSti();

		// 获得TSH指向的地址
		g_uTSNtOpenHookAddress = (ULONG)p + *(PULONG)(p + 1) + 5;

		RtlInitUnicodeString(&SymbolName, L"ObOpenObjectByPointer");
		g_uObOpenObjectByPointer = (ULONG)MmGetSystemRoutineAddress(&SymbolName);
		g_uNtOpenHookAddress = (ULONG)p - 0x6;
		g_uNtOpenProcessRet = (ULONG)p + 0x5;

		ULONG uFirst = 0;
		ULONG uSecond = 0;
		GetFuckHookAddr((ULONG)FuckNtOpenProcess, uFirst, uSecond);


		ULONG OldLen = DisassembleUntil((PUCHAR)g_uNtOpenHookAddress, 6);

		CliAndDisableWP();
		RtlMoveMemory((PCHAR)uFirst, 
			(PCHAR)g_uNtOpenHookAddress, 
			OldLen);

		RtlMoveMemory((PCHAR)uSecond, 
			(PCHAR)g_uNtOpenHookAddress, 
			OldLen);

		EnableWPAndSti();

		// 拷贝要hook前的内容

		// Measure the code length to be copied
		NtOpenProcessHookLen = 
			MeasureCodeLength((PVOID)g_uNtOpenHookAddress, 5);

		if (NtOpenProcessHookLen == 0 
			|| NtOpenProcessHookLen > 11)
		{
			return;
		}
		// Copy the code
		RtlMoveMemory(BackupNtOpenProcessHook, 
			(PVOID)g_uNtOpenHookAddress, NtOpenProcessHookLen);
		RtlMoveMemory(RealNtOpenProcessHook, 
			(PVOID)g_uNtOpenHookAddress, NtOpenProcessHookLen);

		// Relocate jmps and calls
		if (!RelocateJumps(RealNtOpenProcessHook, 
			(ULONG)RealNtOpenProcessHook 
			- (ULONG)g_uNtOpenHookAddress, 
			NtOpenProcessHookLen))
		{
			return;
		}
		// Write jumps
		WriteJump(&RealNtOpenProcessHook[NtOpenProcessHookLen], 
			(PVOID)(g_uNtOpenHookAddress
			+ NtOpenProcessHookLen));
		WriteJump((PVOID)g_uNtOpenHookAddress, FuckNtOpenProcess);

	}
	else
	{
		OldIrql = KeRaiseIrqlToDpcLevel();
		CliAndDisableWP();
		RtlMoveMemory((PVOID)g_uNtOpenHookAddress, 
			BackupNtOpenProcessHook, 
			NtOpenProcessHookLen);
		EnableWPAndSti();
		KeLowerIrql(OldIrql);

	}
	NtOpenProcessHookEnabled = UnHook;
}




PVOID g_pNtOpenThreadCurEprocess = NULL;
ANSI_STRING g_NtOpenThreadStrGet, g_NtOpenThreadStrOd, g_NtOpenThreadCE, g_NtOpenThreadStrInject;
// 大写
ULONG g_uTSNtOpenThreadAddress = 0;
ULONG g_uNtOpenThreadObOpenObjectByPointer = 0;
ULONG g_uNtOpenThreadRet = 0;
ULONG g_uNtOpenThreadHookAddress = 0;
#pragma  LOCKEDCODE
__declspec( naked ) void FuckNtOpenThread()
{
	// 获得当前进程EPROCESS
	g_pNtOpenThreadCurEprocess = IoGetCurrentProcess();

	RtlInitAnsiString(&g_NtOpenThreadStrGet, 
		(PSZ)((ULONG)g_pNtOpenThreadCurEprocess + GetPlantformDependentInfo(FILE_NAME_OFFSET)));

	RtlInitAnsiString(&g_NtOpenThreadStrOd, OLLYDBG);
	RtlInitAnsiString(&g_NtOpenThreadCE, CE);
	// RtlInitAnsiString(&g_NtOpenThreadStrInject, INJECT);

	_strupr(g_NtOpenThreadStrGet.Buffer);

	if ((RtlCompareString(&g_NtOpenThreadStrGet, &g_NtOpenThreadStrOd, TRUE) == 0 || 
		RtlCompareString(&g_NtOpenThreadStrGet, &g_NtOpenThreadCE, TRUE) == 0) &&
		IsTpObjecExist())
	{
		// 跳回到TShook代码处
		__asm
		{
			nop
				call edi
				push eax
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				push g_uNtOpenThreadRet
				mov eax, g_uTSNtOpenThreadAddress
				jmp eax
		}
	}
	else
	{
		// 直接跳回到ObOpenObjectByPointer代码中
		__asm
		{
			nop
				call eax
				push edi
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				nop
				push g_uNtOpenThreadRet
				mov eax, g_uNtOpenThreadObOpenObjectByPointer
				jmp eax
		}
	}
}


ULONG NtOpenThreadHookLen = 0;
UCHAR BackupNtOpenThreadHook[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
UCHAR RealNtOpenThreadHook[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
BOOLEAN NtOpenThreadHookEnabled = FALSE;
#pragma LOCKEDCODE
VOID EnableNtOpenThreadHook(BOOLEAN UnHook)
{

	// KdBreakPoint();
	KIRQL OldIrql;
	ULONG uLength = 0;
	ANSI_STRING FuncName;
	UNICODE_STRING SymbolName;

	PVOID SymbolAddress = NULL;;
	PVOID OldSymbolAddress = NULL;
	ULONG uReg = 0;

	if (UnHook == NtOpenThreadHookEnabled) 
	{        
		return;
	}

	if (UnHook)
	{

		// 查找NtOpenProcess被hook的代码。
		RtlInitUnicodeString(&SymbolName, L"NtOpenThread");
		SymbolAddress = MmGetSystemRoutineAddress(&SymbolName);
		PUCHAR p = NULL;

		CliAndDisableWP();
		if (SymbolAddress)
		{
			//         nt!NtOpenThread+0x1ff:
			//         805c27ad 8d45dc          lea     eax,[ebp-24h]
			//         805c27b0 50              push    eax
			//         805c27b1 ff75d0          push    dword ptr [ebp-30h]
			//         805c27b4 ff35dcb25580    push    dword ptr [nt!PsThreadType (8055b2dc)]
			//         805c27ba 56              push    esi
			//         805c27bb 8d 85 4c ff ff ff    lea     eax,[ebp-0B4h]
			//         805c27c1 50              push    eax
			//         805c27c2 ff75cc          push    dword ptr [ebp-34h]
			//         805c27c5 ff75e0          push    dword ptr [ebp-20h]
			//         805c27c8 e8 09 fc fe ff      call    nt!ObOpenObjectByPointer (805b23d6)
			//         805c27cd 8b f8            mov     edi,eax
			//         805c27cf 8d 85 4c ff ff ff    lea     eax,[ebp-0B4h]
			//         805c27d5 50              push    eax
			//         805c27d6 e8 05 57 02 00      call    nt!SeDeleteAccessState (805e7ee0)
			//         805c27db 8b 4d e0          mov     ecx,dword ptr [ebp-20h]
			//         805c27de e8 8f 13 f6 ff      call    nt!ObfDereferenceObject (80523b72)
			//         805c27e3 3b fe            cmp     edi,esi
			//         805c27e5 0f 8c 6a ff ff ff    jl      nt!NtOpenThread+0x1a7 (805c2755)
			p = (PUCHAR)SymbolAddress;
			//用一个无限循环来判断给定的特征码来确定被HOOK位置
			while (1)
			{
				if ((*(p - 7) == 0x50) && 
					(*(p - 0xE) == 0x56) &&
					(*(p + 0xd) == 0x50) &&
					(*(p + 0xe) == 0xE8) &&
					(*(p + 0x16) == 0xE8) &&
					(*(p + 0x1b) == 0x3b) &&
					(*(p + 0x1c) == 0xfe) &&
					(*p == 0xE8) &&
					(*(p + 5)    == 0x8b) &&
					(*(p + 6)    == 0xf8))
				{
					KdPrint(("%0X \n",(ULONG)p));
					break;
				}
				//推动指针向前走
				p++;
			}
		}
		EnableWPAndSti();

		// 获得TSH指向的地址
		g_uTSNtOpenThreadAddress = (ULONG)p + *(PULONG)(p + 1) + 5;

		RtlInitUnicodeString(&SymbolName, L"ObOpenObjectByPointer");
		g_uNtOpenThreadObOpenObjectByPointer = (ULONG)MmGetSystemRoutineAddress(&SymbolName);
		g_uNtOpenThreadHookAddress = (ULONG)p - 0x6;
		g_uNtOpenThreadRet = (ULONG)p + 0x5;

		ULONG uFirst = 0;
		ULONG uSecond = 0;
		GetFuckHookAddr((ULONG)FuckNtOpenThread, uFirst, uSecond);


		ULONG OldLen = DisassembleUntil((PUCHAR)g_uNtOpenThreadHookAddress, 6);

		CliAndDisableWP();
		RtlMoveMemory((PCHAR)uFirst, 
			(PCHAR)g_uNtOpenThreadHookAddress, 
			OldLen);

		RtlMoveMemory((PCHAR)uSecond, 
			(PCHAR)g_uNtOpenThreadHookAddress, 
			OldLen);

		EnableWPAndSti();

		// 拷贝要hook前的内容

		// Measure the code length to be copied
		NtOpenThreadHookLen = 
			MeasureCodeLength((PVOID)g_uNtOpenThreadHookAddress, 5);

		if (NtOpenThreadHookLen == 0 
			|| NtOpenThreadHookLen > 11)
		{
			return;
		}
		// Copy the code
		RtlMoveMemory(BackupNtOpenThreadHook, 
			(PVOID)g_uNtOpenThreadHookAddress, NtOpenThreadHookLen);
		RtlMoveMemory(RealNtOpenThreadHook, 
			(PVOID)g_uNtOpenThreadHookAddress, NtOpenThreadHookLen);

		// Relocate jmps and calls
		if (!RelocateJumps(RealNtOpenThreadHook, 
			(ULONG)RealNtOpenThreadHook 
			- (ULONG)g_uNtOpenThreadHookAddress, 
			NtOpenThreadHookLen))
		{
			return;
		}
		// Write jumps
		WriteJump(&RealNtOpenThreadHook[NtOpenThreadHookLen], 
			(PVOID)(g_uNtOpenThreadHookAddress
			+ NtOpenThreadHookLen));
		WriteJump((PVOID)g_uNtOpenThreadHookAddress, FuckNtOpenThread);

	}
	else
	{
		OldIrql = KeRaiseIrqlToDpcLevel();
		CliAndDisableWP();
		RtlMoveMemory((PVOID)g_uNtOpenThreadHookAddress, 
			BackupNtOpenThreadHook, 
			NtOpenThreadHookLen);
		EnableWPAndSti();
		KeLowerIrql(OldIrql);

	}
	NtOpenThreadHookEnabled = UnHook;
}



VOID FuckUnLoad(IN PDRIVER_OBJECT DriverObject)
{
	if (!g_bUnLoad)
	{
		g_bUnLoad = TRUE;
		UnHookSSDT(g_uOldNtReadVirtualMemoryAddr, NtReadVirtualMemoryIndex);
		UnHookSSDT(g_uOldNtWriteVirtualMemoryAddr, NtWriteVirtualMemoryIndex);
		EnableNtOpenProcessHook(FALSE);
		EnableNtOpenThreadHook(FALSE);
		EnableZwOpenProcsssook(0, FALSE);
	}

	g_uOldUnLoad(DriverObject);
}

#pragma  LOCKEDCODE

// __declspec( naked ) void FuckUnLoad()
// {
//     g_uTSNtOpenHookAddress = g_uNtOpenThreadObOpenObjectByPointer;
// 	g_uTSNtOpenThreadAddress = g_uNtOpenThreadObOpenObjectByPointer;
//     __asm
//     {
//         mov eax, g_uOldUnLoad
//         jmp eax
//     }
// }

void HookTsUnLoad()
{
	//     GetDriverObject proc 
	//         ;mov ecx,$CCOUNTED_UNICODE_STRING ("\\Driver\\TesSafe")
	//         ;call GetDriverObject
	//         ;edx == return value
	//         xor eax,eax
	//         push eax
	//         push esp
	//         push eax
	//         push eax
	//         push [IoDriverObjectType]
	//     push eax
	//         push eax
	//         push 40h
	//         push ecx
	//         call ObReferenceObjectByName
	//         pop edx
	//         or edx,edx
	//         je @F
	//         push edx
	//         call ObDereferenceObject
	//         @@:  ret
	//         GetDriverObject endp
	// hook TesSafe 的UnLoad例程
	// KdBreakPoint();
	UNICODE_STRING UniStrDriver;
	RtlInitUnicodeString(&UniStrDriver, L"\\Driver\\TesSafe");
	PVOID TsObject;;
	// OBJ_CASE_INSENSITIVE
	NTSTATUS status = ObReferenceObjectByName(&UniStrDriver, 
		0x40, 
		0, 
		0, 
		IoDriverObjectType, 
		KernelMode,
		NULL,
		&TsObject);

	if (!NT_SUCCESS(status))
	{
		KdPrint(("fails\n"));
		return;
	}   
	DRIVER_OBJECT *pObject =  (PDRIVER_OBJECT)TsObject;
	g_uOldUnLoad = pObject->DriverUnload;
	pObject->DriverUnload = (PDRIVER_UNLOAD)FuckUnLoad;
	//     g_uOldUnLoad = (ULONG)pObject->MajorFunction[IRP_MJ_QUERY_VOLUME_INFORMATION];
	//     pObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = (PDRIVER_DISPATCH)g_uOldUnLoad;
	ObDereferenceObject(TsObject);
	KdPrint(("IRP_MJ_DEVICE_CONTROL"));
}

void UnHookTsUnLoad()
{
	//     GetDriverObject proc 
	//         ;mov ecx,$CCOUNTED_UNICODE_STRING ("\\Driver\\TesSafe")
	//         ;call GetDriverObject
	//         ;edx == return value
	//         xor eax,eax
	//         push eax
	//         push esp
	//         push eax
	//         push eax
	//         push [IoDriverObjectType]
	//     push eax
	//         push eax
	//         push 40h
	//         push ecx
	//         call ObReferenceObjectByName
	//         pop edx
	//         or edx,edx
	//         je @F
	//         push edx
	//         call ObDereferenceObject
	//         @@:  ret
	//         GetDriverObject endp
	// hook TesSafe 的UnLoad例程
	UNICODE_STRING UniStrDriver;
	RtlInitUnicodeString(&UniStrDriver, L"\\Driver\\TesSafe");
	PVOID TsObject;;
	// OBJ_CASE_INSENSITIVE
	NTSTATUS status = ObReferenceObjectByName(&UniStrDriver, 
		0x40, 
		0, 
		0, 
		IoDriverObjectType, 
		KernelMode,
		NULL,
		&TsObject);

	if (!NT_SUCCESS(status))
	{
		KdPrint(("fails\n"));
		return;
	}   
	DRIVER_OBJECT *pObject =  (PDRIVER_OBJECT)TsObject;
	//pObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = pObject->MajorFunction[IRP_MJ_QUERY_VOLUME_INFORMATION];
	pObject->DriverUnload = (PDRIVER_UNLOAD)g_uOldUnLoad;
	ObDereferenceObject(TsObject);
	KdPrint(("Pass \\Driver\\TesSafe\n"));
}


// 文件不存在 STATUS_NO_SUCH_FILE 
// ObReferenceObjectByHandle


VOID RemoveListEntry(PLIST_ENTRY ListEntry)
{
	KIRQL OldIrql;
	OldIrql = KeRaiseIrqlToDpcLevel();
	if (ListEntry->Flink != ListEntry &&
		ListEntry->Blink != ListEntry &&
		ListEntry->Blink->Flink == ListEntry &&
		ListEntry->Flink->Blink == ListEntry) {
			ListEntry->Flink->Blink = ListEntry->Blink;
			ListEntry->Blink->Flink = ListEntry->Flink;
			ListEntry->Flink = ListEntry;
			ListEntry->Blink = ListEntry;
	}
	KeLowerIrql(OldIrql);
}

VOID HideProcess(PEPROCESS Process)
{
	ULONG MagicPtr;

	// Remove Process from ActiveProcessLinks
	RemoveListEntry((PLIST_ENTRY)((ULONG)Process + 0x88));

	// Remove ObjectTable from HandleTableList
	MagicPtr = (ULONG)Process + 0xc4;
	if (MmIsAddressValid((PVOID)MagicPtr)) {
		MagicPtr = *(PULONG)MagicPtr;
		RemoveListEntry((PLIST_ENTRY)(MagicPtr + 0x1c));
	}
}



#pragma  LOCKEDCODE
PEPROCESS pCurEprocess = NULL;
ULONG uPID = 0;
NTSTATUS status;

__declspec(naked) void FuckZwOpenProcsss()
{
	__asm
	{
		push eax
			mov eax, [esp + 0x14]
		mov eax, [eax]
		mov uPID, eax
	}
	status = PsLookupProcessByProcessId((HANDLE)uPID, &pCurEprocess);
	if (NT_SUCCESS(status))
	{
		if (_strnicmp("Fingering.exe", (char *)((ULONG)pCurEprocess + 0x174), 13) == 0)
		{
			__asm
			{
				pop eax
					mov eax, 0xC0000022
					ret 0x10
			}

		}

	}
	__asm
	{
		pop eax
	}
	__asm
	{
		nop
			call    edi
			push    eax
			nop
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
	}
}
ULONG ZwOpenProcsssHookLen = 0;
UCHAR BackupZwOpenProcsss[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
UCHAR RealZwOpenProcsss[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
BOOLEAN ZwOpenProcsssEnabled = FALSE;
#pragma LOCKEDCODE
VOID EnableZwOpenProcsssook(ULONG uImageBase, BOOLEAN UnHook)
{
	// KdBreakPoint();
	KIRQL OldIrql;
	INSTRUCTION Instruction;
	ULONG uLength = 0;
	ANSI_STRING FuncName;
	UNICODE_STRING SymbolName;

	PVOID SymbolAddress = NULL;;
	PVOID OldSymbolAddress = NULL;
	ULONG uReg = 0;

	if (UnHook == ZwOpenProcsssEnabled) 
	{        
		return;
	}
	if (UnHook)
	{
		RtlInitUnicodeString(&SymbolName, L"NtOpenProcess");

		RtlInitAnsiString(&FuncName, "NtOpenProcess");

		OldSymbolAddress = MiFindExportedRoutineByName((PVOID)uImageBase, &FuncName);
		if ((SymbolAddress = MmGetSystemRoutineAddress(
			&SymbolName)) && OldSymbolAddress)
		{
			CliAndDisableWP();
			PUCHAR p = (PUCHAR)FuckZwOpenProcsss;
			while (1)
			{
				if ((*(p) == 0x90) && 
					(*(p + 0x1) == 0xff) &&
					(*(p + 0x2) == 0xd7) &&
					(*(p + 0x3) == 0x50) &&
					(*(p + 0x4) == 0x90))
				{
					KdPrint(("%0X \n",(ULONG)p));
					break;
				}
				//推动指针向前走
				p++;
			}

			EnableWPAndSti();
			CopyFuncByte((ULONG)SymbolAddress, (ULONG)OldSymbolAddress, 
				(ULONG)p);

			// Measure the code length to be copied
			ZwOpenProcsssHookLen = 
				MeasureCodeLength((PVOID)SymbolAddress, 5);

			if (ZwOpenProcsssHookLen == 0 
				|| ZwOpenProcsssHookLen > 11)
			{
				return;
			}
			// Copy the code
			RtlMoveMemory(BackupZwOpenProcsss, 
				(PVOID)SymbolAddress, ZwOpenProcsssHookLen);
			RtlMoveMemory(RealZwOpenProcsss, 
				(PVOID)SymbolAddress, ZwOpenProcsssHookLen);

			// Relocate jmps and calls
			if (!RelocateJumps(RealZwOpenProcsss, 
				(ULONG)RealZwOpenProcsss 
				- (ULONG)SymbolAddress, 
				ZwOpenProcsssHookLen))
			{
				return;
			}
			// Write jumps
			WriteJump(&RealZwOpenProcsss[ZwOpenProcsssHookLen], 
				(PVOID)((ULONG)SymbolAddress 
				+ ZwOpenProcsssHookLen));
			WriteJump((PVOID)SymbolAddress, FuckZwOpenProcsss);
		}
	}
	else
	{

		RtlInitUnicodeString(&SymbolName, L"NtOpenProcess");
		if ((SymbolAddress = MmGetSystemRoutineAddress(&SymbolName)))
		{ 
			OldIrql = KeRaiseIrqlToDpcLevel();
			CliAndDisableWP();
			RtlMoveMemory((PVOID)SymbolAddress, BackupZwOpenProcsss, ZwOpenProcsssHookLen);
			EnableWPAndSti();
			KeLowerIrql(OldIrql);
		}
	}
	ZwOpenProcsssEnabled = UnHook;
}


UNICODE_STRING ImagePath;
PVOID FullImageName;

__declspec(naked) void FuckNtCreateFile()
{
	__asm
	{
		push eax
			mov eax, [esp + 0x10]
		mov eax, [eax + 0x8]
		mov FullImageName, eax
	}
	RtlInitUnicodeString(&ImagePath, L"\\??\\d:\\bin\\Fingering.exe");
	if (RtlCompareUnicodeString((PCUNICODE_STRING)FullImageName, &ImagePath, TRUE) == 0)
	{
		__asm
		{
			pop eax
				mov eax, 0xC000000FL
				ret 0x2C
		}
	}
	__asm pop eax
	__asm
	{
		nop
			call edi
			push eax
			nop
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
			NOP
	}
}
ULONG NtCreateFileHookLen = 0;
UCHAR BackupNtCreateFile[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
UCHAR RealNtCreateFile[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
BOOLEAN NtCreateFileEnabled = FALSE;
#pragma LOCKEDCODE
VOID EnableNtCreateFileHook(ULONG uImageBase, BOOLEAN UnHook)
{
	// KdBreakPoint();
	KIRQL OldIrql;
	INSTRUCTION Instruction;
	ULONG uLength = 0;
	ANSI_STRING FuncName;
	UNICODE_STRING SymbolName;

	PVOID SymbolAddress = NULL;;
	PVOID OldSymbolAddress = NULL;
	ULONG uReg = 0;

	if (UnHook == NtCreateFileEnabled) 
	{        
		return;
	}
	if (UnHook)
	{
		RtlInitUnicodeString(&SymbolName, L"NtCreateFile");

		RtlInitAnsiString(&FuncName, "NtCreateFile");

		OldSymbolAddress = MiFindExportedRoutineByName((PVOID)uImageBase, &FuncName);
		if ((SymbolAddress = MmGetSystemRoutineAddress(
			&SymbolName)) && OldSymbolAddress)
		{
			CliAndDisableWP();
			PUCHAR p = (PUCHAR)FuckNtCreateFile;
			while (1)
			{
				if ((*(p) == 0x90) && 
					(*(p + 0x1) == 0xff) &&
					(*(p + 0x2) == 0xd7) &&
					(*(p + 0x3) == 0x50) &&
					(*(p + 0x4) == 0x90))
				{
					KdPrint(("%0X \n",(ULONG)p));
					break;
				}
				//推动指针向前走
				p++;
			}

			EnableWPAndSti();
			CopyFuncByte((ULONG)SymbolAddress, (ULONG)OldSymbolAddress, 
				(ULONG)p);

			// Measure the code length to be copied
			NtCreateFileHookLen = 
				MeasureCodeLength((PVOID)SymbolAddress, 5);

			if (NtCreateFileHookLen == 0 
				|| NtCreateFileHookLen > 11)
			{
				return;
			}
			// Copy the code
			RtlMoveMemory(BackupNtCreateFile, 
				(PVOID)SymbolAddress, NtCreateFileHookLen);
			RtlMoveMemory(RealNtCreateFile, 
				(PVOID)SymbolAddress, NtCreateFileHookLen);

			// Relocate jmps and calls
			if (!RelocateJumps(RealNtCreateFile, 
				(ULONG)RealNtCreateFile 
				- (ULONG)SymbolAddress, 
				NtCreateFileHookLen))
			{
				return;
			}
			// Write jumps
			WriteJump(&RealNtCreateFile[NtCreateFileHookLen], 
				(PVOID)((ULONG)SymbolAddress 
				+ NtCreateFileHookLen));
			WriteJump((PVOID)SymbolAddress, FuckNtCreateFile);
		}
	}
	else
	{

		RtlInitUnicodeString(&SymbolName, L"NtCreateFile");
		if ((SymbolAddress = MmGetSystemRoutineAddress(&SymbolName)))
		{ 
			OldIrql = KeRaiseIrqlToDpcLevel();
			CliAndDisableWP();
			RtlMoveMemory((PVOID)SymbolAddress, BackupNtCreateFile, NtCreateFileHookLen);
			EnableWPAndSti();
			KeLowerIrql(OldIrql);
		}
	}
	NtCreateFileEnabled = UnHook;
}

ULONG GetProcessId(PUCHAR pszProcessName)
{
	ULONG uRet = 0;
	if (pszProcessName != NULL)
	{
		return uRet;
	}
	ULONG uEprocess = 0;
	__asm
	{
		mov eax, fs:[0x124]    // _ethread
		mov eax, [eax+0x44]    // _kprocess
		mov uEprocess, eax
	}

	KdPrint(("EPROCESS: 0x%08x\n", uEprocess));
	//     LIST_ENTRY ListHead;
	//     InitializeListHead(&ListHead);

	ULONG uFirstEprocess = uEprocess;
	PLIST_ENTRY pActiveProcessLinks;

	ULONG uNameOffset = GetPlantformDependentInfo(FILE_NAME_OFFSET);
	ULONG uPidOffset = GetPlantformDependentInfo(PROCESS_ID_OFFSET);
	ULONG uLinkOffset = GetPlantformDependentInfo(PROCESS_LINK_OFFSET);
	ULONG uExitTime = GetPlantformDependentInfo(EXIT_TIME_OFFSET);
	// 遍历链表获得进程信息
	do 
	{
		PLARGE_INTEGER ExitTime;
		ExitTime = (PLARGE_INTEGER)(uEprocess + uExitTime);
		if (ExitTime->QuadPart == 0)
		{
			UCHAR pszFileName = uEprocess + uNameOffset;

			if (_stricmp((const char *)pszProcessName, (const char *)pszFileName) == 0)
			{
				uRet = *(PULONG)(uEprocess + uPidOffset);
				break;
			}
		}

		pActiveProcessLinks = (PLIST_ENTRY)(uEprocess + uLinkOffset);
		uEprocess = (ULONG)pActiveProcessLinks->Blink - uLinkOffset;
		if (uEprocess == uFirstEprocess)
		{
			break;
		}
	} while (uEprocess != 0);


	return uRet;
}

BOOLEAN IsTpObjecExist()
{
	BOOLEAN bRet = FALSE;
	UNICODE_STRING UniStrDriver;
	RtlInitUnicodeString(&UniStrDriver, L"\\Driver\\TesSafe");
	PVOID TsObject;;
	// OBJ_CASE_INSENSITIVE
	NTSTATUS status = ObReferenceObjectByName(&UniStrDriver, 
		0x40, 
		0, 
		0, 
		IoDriverObjectType, 
		KernelMode,
		NULL,
		&TsObject);

	if (!NT_SUCCESS(status))
	{
		KdPrint(("fails\n"));
		return FALSE;
	}   
	DRIVER_OBJECT *pObject =  (PDRIVER_OBJECT)TsObject;
	if (pObject == NULL)
	{
		bRet = FALSE;
	}
	else
	{
		bRet = TRUE;
	}
	//     g_uOldUnLoad = (ULONG)pObject->MajorFunction[IRP_MJ_QUERY_VOLUME_INFORMATION];
	//     pObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = (PDRIVER_DISPATCH)g_uOldUnLoad;
	ObDereferenceObject(TsObject);

	return bRet;
}