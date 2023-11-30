//#include "stdafx.h"
#include "PE.h"

NTSTATUS
NTAPI
RtlImageNtHeaderEx(
    ULONG Flags,
    PVOID Base,
    ULONG64 Size,
    OUT PIMAGE_NT_HEADERS * OutHeaders
    )

/*++

Routine Description:

    This function returns the address of the NT Header.

    This function is a bit complicated.
    It is this way because RtlImageNtHeader that it replaces was hard to understand,
      and this function retains compatibility with RtlImageNtHeader.

    RtlImageNtHeader was #ifed such as to act different in each of the three
        boot loader, kernel, usermode flavors.

    boot loader -- no exception handling
    usermode -- limit msdos header to 256meg, catch any exception accessing the msdos-header
                or the pe header
    kernel -- don't cross user/kernel boundary, don't catch the exceptions,
                no 256meg limit

Arguments:

    Flags - RTL_IMAGE_NT_HEADER_EX_FLAG_NO_RANGE_CHECK -- don't be so picky
                about the image, for compatibility with RtlImageNtHeader
    Base - Supplies the base of the image.
    Size - The size of the view, usually larger than the size of the file on disk.
            This is available from NtMapViewOfSection but not from MapViewOfFile.
    OutHeaders -

Return Value:

    STATUS_SUCCESS -- everything ok
    STATUS_INVALID_IMAGE_FORMAT -- bad filesize or signature value
    STATUS_INVALID_PARAMETER -- bad parameters

--*/

{
    PIMAGE_NT_HEADERS NtHeaders = 0;
    ULONG e_lfanew = 0;
    BOOLEAN RangeCheck = 0;
    NTSTATUS Status = 0;
    const ULONG ValidFlags = 
        RTL_IMAGE_NT_HEADER_EX_FLAG_NO_RANGE_CHECK;

    if (OutHeaders != NULL) {
        *OutHeaders = NULL;
    }
    if (OutHeaders == NULL) {
        Status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }
    if ((Flags & ~ValidFlags) != 0) {
        Status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }
    if (Base == NULL || Base == (PVOID)(LONG_PTR)-1) {
        Status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    RangeCheck = ((Flags & RTL_IMAGE_NT_HEADER_EX_FLAG_NO_RANGE_CHECK) == 0);
    if (RangeCheck) {
        if (Size < sizeof(IMAGE_DOS_HEADER)) {
            Status = STATUS_INVALID_IMAGE_FORMAT;
            goto Exit;
        }
    }

    //
    // Exception handling is not available in the boot loader, and exceptions
    // were not historically caught here in kernel mode. Drivers are considered
    // trusted, so we can't get an exception here due to a bad file, but we
    // could take an inpage error.
    //
#define EXIT goto Exit
    if (((PIMAGE_DOS_HEADER)Base)->e_magic != IMAGE_DOS_SIGNATURE) {
        Status = STATUS_INVALID_IMAGE_FORMAT;
        EXIT;
    }
    e_lfanew = ((PIMAGE_DOS_HEADER)Base)->e_lfanew;
    if (RangeCheck) {
        if (e_lfanew >= Size
#define SIZEOF_PE_SIGNATURE 4
            || e_lfanew >= (MAXULONG - SIZEOF_PE_SIGNATURE - sizeof(IMAGE_FILE_HEADER))
            || (e_lfanew + SIZEOF_PE_SIGNATURE + sizeof(IMAGE_FILE_HEADER)) >= Size
            ) {
            Status = STATUS_INVALID_IMAGE_FORMAT;
            EXIT;
        }
    }

    NtHeaders = (PIMAGE_NT_HEADERS)((PCHAR)Base + e_lfanew);

    //
    // In kernelmode, do not cross from usermode address to kernelmode address.
    //
    if (Base < MM_HIGHEST_USER_ADDRESS) {
        if ((PVOID)NtHeaders >= MM_HIGHEST_USER_ADDRESS) {
            Status = STATUS_INVALID_IMAGE_FORMAT;
            EXIT;
        }
        //
        // Note that this check is slightly overeager since IMAGE_NT_HEADERS has
        // a builtin array of data_directories that may be larger than the image
        // actually has. A better check would be to add FileHeader.SizeOfOptionalHeader,
        // after ensuring that the FileHeader does not cross the u/k boundary.
        //
        if ((PVOID)((PCHAR)NtHeaders + sizeof (IMAGE_NT_HEADERS)) >= MM_HIGHEST_USER_ADDRESS) {
            Status = STATUS_INVALID_IMAGE_FORMAT;
            EXIT;
        }
    }

    if (NtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        Status = STATUS_INVALID_IMAGE_FORMAT;
        EXIT;
    }
    Status = STATUS_SUCCESS;

Exit:
    if (NT_SUCCESS(Status)) {
        *OutHeaders = NtHeaders;
    }
    return Status;
}

PIMAGE_NT_HEADERS
NTAPI
RtlImageNtHeader(
				 PVOID Base
				 )
{
	PIMAGE_NT_HEADERS NtHeaders = NULL;
	(VOID)RtlImageNtHeaderEx(RTL_IMAGE_NT_HEADER_EX_FLAG_NO_RANGE_CHECK, Base, 0, &NtHeaders);
	return NtHeaders;
}

PIMAGE_SECTION_HEADER
RtlSectionTableFromVirtualAddress (
    IN PIMAGE_NT_HEADERS NtHeaders,
    IN PVOID Base,
    IN ULONG Address
    )

/*++

Routine Description:

    This function locates a VirtualAddress within the image header
    of a file that is mapped as a file and returns a pointer to the
    section table entry for that virtual address

Arguments:

    NtHeaders - Supplies the pointer to the image or data file.

    Base - Supplies the base of the image or data file.

    Address - Supplies the virtual address to locate.

Return Value:

    NULL - The file does not contain data for the specified directory entry.

    NON-NULL - Returns the pointer of the section entry containing the data.

--*/

{
    ULONG i;
    PIMAGE_SECTION_HEADER NtSection;

    NtSection = IMAGE_FIRST_SECTION( NtHeaders );
    for (i=0; i<NtHeaders->FileHeader.NumberOfSections; i++) {
        if ((ULONG)Address >= NtSection->VirtualAddress &&
            (ULONG)Address < NtSection->VirtualAddress + NtSection->SizeOfRawData
           ) {
            return NtSection;
            }
        ++NtSection;
        }

    return NULL;
}
PVOID
RtlAddressInSectionTable (
    IN PIMAGE_NT_HEADERS NtHeaders,
    IN PVOID Base,
    IN ULONG Address
    )

/*++

Routine Description:

    This function locates a VirtualAddress within the image header
    of a file that is mapped as a file and returns the seek address
    of the data the Directory describes.

Arguments:

    NtHeaders - Supplies the pointer to the image or data file.

    Base - Supplies the base of the image or data file.

    Address - Supplies the virtual address to locate.

Return Value:

    NULL - The file does not contain data for the specified directory entry.

    NON-NULL - Returns the address of the raw data the directory describes.

--*/

{
    PIMAGE_SECTION_HEADER NtSection;

    NtSection = RtlSectionTableFromVirtualAddress( NtHeaders,
                                                   Base,
                                                   Address
                                                 );
    if (NtSection != NULL) {
        return( ((PCHAR)Base + ((ULONG_PTR)Address - NtSection->VirtualAddress) + NtSection->PointerToRawData) );
        }
    else {
        return( NULL );
        }
}

PVOID
RtlpImageDirectoryEntryToData32 (
								 IN PVOID Base,
								 IN BOOLEAN MappedAsImage,
								 IN USHORT DirectoryEntry,
								 OUT PULONG Size,
								 PIMAGE_NT_HEADERS32 NtHeaders
								 )
{
	ULONG DirectoryAddress;

	if (DirectoryEntry >= NtHeaders->OptionalHeader.NumberOfRvaAndSizes) {
		return( NULL );
	}

	if (!(DirectoryAddress = NtHeaders->OptionalHeader.DataDirectory[ DirectoryEntry ].VirtualAddress)) {
		return( NULL );
	}

	if (Base < MM_HIGHEST_USER_ADDRESS) {
		if ((PVOID)((PCHAR)Base + DirectoryAddress) >= MM_HIGHEST_USER_ADDRESS) {
			return( NULL );
		}
	}

	*Size = NtHeaders->OptionalHeader.DataDirectory[ DirectoryEntry ].Size;
	if (MappedAsImage || DirectoryAddress < NtHeaders->OptionalHeader.SizeOfHeaders) {
		return( (PVOID)((PCHAR)Base + DirectoryAddress) );
	}

	return( RtlAddressInSectionTable((PIMAGE_NT_HEADERS)NtHeaders, Base, DirectoryAddress ));
}


PVOID
RtlpImageDirectoryEntryToData64 (
								 IN PVOID Base,
								 IN BOOLEAN MappedAsImage,
								 IN USHORT DirectoryEntry,
								 OUT PULONG Size,
								 PIMAGE_NT_HEADERS64 NtHeaders
								 )
{
	ULONG DirectoryAddress;

	if (DirectoryEntry >= NtHeaders->OptionalHeader.NumberOfRvaAndSizes) {
		return( NULL );
	}

	if (!(DirectoryAddress = NtHeaders->OptionalHeader.DataDirectory[ DirectoryEntry ].VirtualAddress)) {
		return( NULL );
	}

	if (Base < MM_HIGHEST_USER_ADDRESS) {
		if ((PVOID)((PCHAR)Base + DirectoryAddress) >= MM_HIGHEST_USER_ADDRESS) {
			return( NULL );
		}
	}

	*Size = NtHeaders->OptionalHeader.DataDirectory[ DirectoryEntry ].Size;
	if (MappedAsImage || DirectoryAddress < NtHeaders->OptionalHeader.SizeOfHeaders) {
		return( (PVOID)((PCHAR)Base + DirectoryAddress) );
	}

	return( RtlAddressInSectionTable((PIMAGE_NT_HEADERS)NtHeaders, Base, DirectoryAddress ));
}

PVOID
RtlImageDirectoryEntryToData (
    IN PVOID Base,
    IN BOOLEAN MappedAsImage,
    IN USHORT DirectoryEntry,
    OUT PULONG Size
    )

/*++

Routine Description:

    This function locates a Directory Entry within the image header
    and returns either the virtual address or seek address of the
    data the Directory describes.

Arguments:

    Base - Supplies the base of the image or data file.

    MappedAsImage - FALSE if the file is mapped as a data file.
                  - TRUE if the file is mapped as an image.

    DirectoryEntry - Supplies the directory entry to locate.

    Size - Return the size of the directory.

Return Value:

    NULL - The file does not contain data for the specified directory entry.

    NON-NULL - Returns the address of the raw data the directory describes.

--*/

{
    PIMAGE_NT_HEADERS NtHeaders;

    if (LDR_IS_DATAFILE(Base)) {
        Base = LDR_DATAFILE_TO_VIEW(Base);
        MappedAsImage = FALSE;
        }

    NtHeaders = RtlImageNtHeader(Base);

    if (!NtHeaders)
        return NULL;

    if (NtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        return (RtlpImageDirectoryEntryToData32(Base,
                                                MappedAsImage,
                                                DirectoryEntry,
                                                Size,
                                                (PIMAGE_NT_HEADERS32)NtHeaders));
    } else if (NtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        return (RtlpImageDirectoryEntryToData64(Base,
                                                MappedAsImage,
                                                DirectoryEntry,
                                                Size,
                                                (PIMAGE_NT_HEADERS64)NtHeaders));
    } else {
        return (NULL);
    }
}

PVOID
MiFindExportedRoutineByName (
    IN PVOID DllBase,
    IN PANSI_STRING AnsiImageRoutineName
    )

/*++

Routine Description:

    This function searches the argument module looking for the requested
    exported function name.

Arguments:

    DllBase - Supplies the base address of the requested module.

    AnsiImageRoutineName - Supplies the ANSI routine name being searched for.

Return Value:

    The virtual address of the requested routine or NULL if not found.

--*/

{
    USHORT OrdinalNumber;
    PULONG NameTableBase;
    PUSHORT NameOrdinalTableBase;
    PULONG Addr;
    LONG High;
    LONG Low;
    LONG Middle;
    LONG Result;
    ULONG ExportSize;
    PVOID FunctionAddress;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory;

    PAGED_CODE();

    ExportDirectory = (PIMAGE_EXPORT_DIRECTORY) RtlImageDirectoryEntryToData (
                                DllBase,
                                TRUE,
                                IMAGE_DIRECTORY_ENTRY_EXPORT,
                                &ExportSize);

    if (ExportDirectory == NULL) {
        return NULL;
    }

    //
    // Initialize the pointer to the array of RVA-based ansi export strings.
    //

    NameTableBase = (PULONG)((PCHAR)DllBase + (ULONG)ExportDirectory->AddressOfNames);

    //
    // Initialize the pointer to the array of USHORT ordinal numbers.
    //

    NameOrdinalTableBase = (PUSHORT)((PCHAR)DllBase + (ULONG)ExportDirectory->AddressOfNameOrdinals);

    //
    // Lookup the desired name in the name table using a binary search.
    //

    Low = 0;
    Middle = 0;
    High = ExportDirectory->NumberOfNames - 1;

    while (High >= Low) {

        //
        // Compute the next probe index and compare the import name
        // with the export name entry.
        //

        Middle = (Low + High) >> 1;

        Result = strcmp (AnsiImageRoutineName->Buffer,
                         (PCHAR)DllBase + NameTableBase[Middle]);

        if (Result < 0) {
            High = Middle - 1;
        }
        else if (Result > 0) {
            Low = Middle + 1;
        }
        else {
            break;
        }
    }

    //
    // If the high index is less than the low index, then a matching
    // table entry was not found. Otherwise, get the ordinal number
    // from the ordinal table.
    //

    if (High < Low) {
        return NULL;
    }

    OrdinalNumber = NameOrdinalTableBase[Middle];

    //
    // If the OrdinalNumber is not within the Export Address Table,
    // then this image does not implement the function.  Return not found.
    //

    if ((ULONG)OrdinalNumber >= ExportDirectory->NumberOfFunctions) {
        return NULL;
    }

    //
    // Index into the array of RVA export addresses by ordinal number.
    //

    Addr = (PULONG)((PCHAR)DllBase + (ULONG)ExportDirectory->AddressOfFunctions);

    FunctionAddress = (PVOID)((PCHAR)DllBase + Addr[OrdinalNumber]);

    //
    // Forwarders are not used by the kernel and HAL to each other.
    //

    ASSERT ((FunctionAddress <= (PVOID)ExportDirectory) ||
            (FunctionAddress >= (PVOID)((PCHAR)ExportDirectory + ExportSize)));

    return FunctionAddress;
}

PVOID
MiFindExportedRoutineByNameByRaw (
							 IN PVOID DllBase,
							 IN PANSI_STRING AnsiImageRoutineName
							 )
{
	USHORT OrdinalNumber;
	PULONG NameTableBase;
	PUSHORT NameOrdinalTableBase;
	PULONG Addr;
	LONG High;
	LONG Low;
	LONG Middle;
	LONG Result;
	ULONG ExportSize;
	PVOID FunctionAddress;
	PIMAGE_EXPORT_DIRECTORY ExportDirectory;

	PAGED_CODE();

	ExportDirectory = (PIMAGE_EXPORT_DIRECTORY) RtlImageDirectoryEntryToData (
		DllBase,
		FALSE,
		IMAGE_DIRECTORY_ENTRY_EXPORT,
		&ExportSize);

	if (ExportDirectory == NULL) 
	{
		return NULL;
	}

	//
	// Initialize the pointer to the array of RVA-based ansi export strings.
	//
	

	NameTableBase = (PULONG)RtlAddressInSectionTable((PIMAGE_NT_HEADERS)RtlImageNtHeader(DllBase), 
													DllBase, 
													ExportDirectory->AddressOfNames);
	
	//
	// Initialize the pointer to the array of USHORT ordinal numbers.
	//

	NameOrdinalTableBase = (PUSHORT)RtlAddressInSectionTable((PIMAGE_NT_HEADERS)RtlImageNtHeader(DllBase), 
													DllBase, 
													ExportDirectory->AddressOfNameOrdinals);
	//
	// Lookup the desired name in the name table using a binary search.
	//

	Low = 0;
	Middle = 0;
	High = ExportDirectory->NumberOfNames - 1;

	while (High >= Low) {

		//
		// Compute the next probe index and compare the import name
		// with the export name entry.
		//

		Middle = (Low + High) >> 1;

		// NameTableBase[Middle] rva
		// ULONG uNameRwa = 

		Result = strcmp (AnsiImageRoutineName->Buffer,
			(PCHAR)RtlAddressInSectionTable((PIMAGE_NT_HEADERS)RtlImageNtHeader(DllBase), 
											DllBase, 
											NameTableBase[Middle]));

		if (Result < 0) {
			High = Middle - 1;
		}
		else if (Result > 0) {
			Low = Middle + 1;
		}
		else {
			break;
		}
	}

	//
	// If the high index is less than the low index, then a matching
	// table entry was not found. Otherwise, get the ordinal number
	// from the ordinal table.
	//

	if (High < Low) {
		return NULL;
	}

	OrdinalNumber = NameOrdinalTableBase[Middle];

	//
	// If the OrdinalNumber is not within the Export Address Table,
	// then this image does not implement the function.  Return not found.
	//

	if ((ULONG)OrdinalNumber >= ExportDirectory->NumberOfFunctions) {
		return NULL;
	}

	//
	// Index into the array of RVA export addresses by ordinal number.
	//

	Addr = (PULONG)RtlAddressInSectionTable((PIMAGE_NT_HEADERS)RtlImageNtHeader(DllBase), 
											DllBase, 
											ExportDirectory->AddressOfFunctions);

	FunctionAddress = RtlAddressInSectionTable((PIMAGE_NT_HEADERS)RtlImageNtHeader(DllBase), 
											DllBase, 
											Addr[OrdinalNumber]);

	//
	// Forwarders are not used by the kernel and HAL to each other.
	//

	ASSERT ((FunctionAddress <= (PVOID)ExportDirectory) ||
		(FunctionAddress >= (PVOID)((PCHAR)ExportDirectory + ExportSize)));

	return FunctionAddress;
}

void LoadImage(IN PVOID pImageBase, IN PVOID pLoadData)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pLoadData;
    PIMAGE_NT_HEADERS pNtHeader = RtlImageNtHeader(pLoadData);
    ULONG uPeHeaderSize = pNtHeader->OptionalHeader.SizeOfHeaders;
    RtlCopyMemory(pImageBase, pLoadData, uPeHeaderSize);

    ULONG uSectionNum = pNtHeader->FileHeader.NumberOfSections;
    ULONG nSectionOffset = pDosHeader->e_lfanew
        + sizeof(pNtHeader->Signature)
        + sizeof(IMAGE_FILE_HEADER)
        + pNtHeader->FileHeader.SizeOfOptionalHeader;
    PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)((ULONG)pLoadData + nSectionOffset);
    for (ULONG i = 0; i < uSectionNum; i++)
    {
        PVOID pSectionInfo = (PVOID)(pSection[i].PointerToRawData + (ULONG)pLoadData);
        RtlCopyMemory((PVOID)((ULONG)pImageBase + pSection[i].VirtualAddress), 
            pSectionInfo, 
            pSection[i].SizeOfRawData);
        
    }
}


PVOID
MiFindExportedRoutineRvaByNameByRaw (
                                  IN PVOID DllBase,
                                  IN PANSI_STRING AnsiImageRoutineName
                                  )
{
    USHORT OrdinalNumber;
    PULONG NameTableBase;
    PUSHORT NameOrdinalTableBase;
    PULONG Addr;
    LONG High;
    LONG Low;
    LONG Middle;
    LONG Result;
    ULONG ExportSize;
    PVOID FunctionAddress;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory;

    PAGED_CODE();

    ExportDirectory = (PIMAGE_EXPORT_DIRECTORY) RtlImageDirectoryEntryToData (
        DllBase,
        FALSE,
        IMAGE_DIRECTORY_ENTRY_EXPORT,
        &ExportSize);

    if (ExportDirectory == NULL) 
    {
        return NULL;
    }

    //
    // Initialize the pointer to the array of RVA-based ansi export strings.
    //


    NameTableBase = (PULONG)RtlAddressInSectionTable((PIMAGE_NT_HEADERS)RtlImageNtHeader(DllBase), 
        DllBase, 
        ExportDirectory->AddressOfNames);

    //
    // Initialize the pointer to the array of USHORT ordinal numbers.
    //

    NameOrdinalTableBase = (PUSHORT)RtlAddressInSectionTable((PIMAGE_NT_HEADERS)RtlImageNtHeader(DllBase), 
        DllBase, 
        ExportDirectory->AddressOfNameOrdinals);
    //
    // Lookup the desired name in the name table using a binary search.
    //

    Low = 0;
    Middle = 0;
    High = ExportDirectory->NumberOfNames - 1;

    while (High >= Low) {

        //
        // Compute the next probe index and compare the import name
        // with the export name entry.
        //

        Middle = (Low + High) >> 1;

        // NameTableBase[Middle] rva
        // ULONG uNameRwa = 

        Result = strcmp (AnsiImageRoutineName->Buffer,
            (PCHAR)RtlAddressInSectionTable((PIMAGE_NT_HEADERS)RtlImageNtHeader(DllBase), 
            DllBase, 
            NameTableBase[Middle]));

        if (Result < 0) {
            High = Middle - 1;
        }
        else if (Result > 0) {
            Low = Middle + 1;
        }
        else {
            break;
        }
    }

    //
    // If the high index is less than the low index, then a matching
    // table entry was not found. Otherwise, get the ordinal number
    // from the ordinal table.
    //

    if (High < Low) {
        return NULL;
    }

    OrdinalNumber = NameOrdinalTableBase[Middle];

    //
    // If the OrdinalNumber is not within the Export Address Table,
    // then this image does not implement the function.  Return not found.
    //

    if ((ULONG)OrdinalNumber >= ExportDirectory->NumberOfFunctions) {
        return NULL;
    }

    //
    // Index into the array of RVA export addresses by ordinal number.
    //

    Addr = (PULONG)RtlAddressInSectionTable((PIMAGE_NT_HEADERS)RtlImageNtHeader(DllBase), 
                                            DllBase, 
                                            ExportDirectory->AddressOfFunctions);

    FunctionAddress = (PVOID)Addr[OrdinalNumber];

    //
    // Forwarders are not used by the kernel and HAL to each other.
    //


    return FunctionAddress;
}