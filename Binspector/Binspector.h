#pragma once
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

//Base types
typedef void VOID;
typedef int8_t CHAR;
typedef uint8_t UCHAR;
typedef wchar_t WCHAR;
typedef int16_t SHORT;
typedef uint16_t USHORT;
typedef int32_t LONG;
typedef uint32_t ULONG;
typedef int64_t LONGLONG;
typedef uint64_t ULONGLONG;
typedef LONG HRESULT;

//PE32+ Structures
#pragma pack(1)
typedef struct _IMAGE_DOS_HEADER
{
	USHORT e_magic;
	USHORT e_cblp;
	USHORT e_cp;
	USHORT e_crlc;
	USHORT e_cparhdr;
	USHORT e_minalloc;
	USHORT e_maxalloc;
	USHORT e_ss;
	USHORT e_sp;
	USHORT e_csum;
	USHORT e_ip;
	USHORT e_cs;
	USHORT e_lfarlc;
	USHORT e_ovno;
	USHORT e_res[4];
	USHORT e_oemid;
	USHORT e_oeminfo;
	USHORT e_res2[10];
	LONG e_lfanew;
}_IMAGE_DOS_HEADER;
typedef struct _IMAGE_FILE_HEADER
{
	USHORT Machine;
	USHORT NumberOfSections;
	ULONG TimeDateStamp;
	ULONG PointerToSymbolTable;
	ULONG NumberOfSymbols;
	USHORT SizeOfOptionalHeader;
	USHORT Characteristics;
}_IMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY
{
	ULONG VirtualAddress;
	ULONG Size;
}_IMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER64
{
	USHORT Magic;
	UCHAR MajorLinkerVersion;
	UCHAR MinorLinkerVersion;
	ULONG SizeOfCode;
	ULONG SizeOfInitializedData;
	ULONG SizeOfUninitializedData;
	ULONG AddressOfEntryPoint;
	ULONG BaseOfCode;
	ULONGLONG ImageBase;
	ULONG SectionAlignment;
	ULONG FileAlignment;
	USHORT MajorOperatingSystemVersion;
	USHORT MinorOperatingSystemVersion;
	USHORT MajorImageVersion;
	USHORT MinorImageVersion;
	USHORT MajorSubsystemVersion;
	USHORT MinorSubsystemVersion;
	ULONG Win32VersionValue;
	ULONG SizeOfImage;
	ULONG SizeOfHeaders;
	ULONG CheckSum;
	USHORT Subsystem;
	USHORT DllCharacteristics;
	ULONGLONG SizeOfStackReserve;
	ULONGLONG SizeOfStackCommit;
	ULONGLONG SizeOfHeapReserve;
	ULONGLONG SizeOfHeapCommit;
	ULONG LoaderFlags;
	ULONG NumberOfRvaAndSizes;
	struct _IMAGE_DATA_DIRECTORY DataDirectory[16];
}_IMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS64
{
	ULONG Signature;
	struct _IMAGE_FILE_HEADER FileHeader;
	struct _IMAGE_OPTIONAL_HEADER64 OptionalHeader;
}_IMAGE_NT_HEADERS64;

typedef struct _IMAGE_SECTION_HEADER
{
	UCHAR Name[8];
	union
	{
		ULONG PhysicalAddress;
		ULONG VirtualSize;
	} Misc;
	ULONG VirtualAddress;
	ULONG SizeOfRawData;
	ULONG PointerToRawData;
	ULONG PointerToRelocations;
	ULONG PointerToLinenumbers;
	USHORT NumberOfRelocations;
	USHORT NumberOfLinenumbers;
	ULONG Characteristics;
}_IMAGE_SECTION_HEADER;

typedef struct _IMAGE_IMPORT_DESCRIPTOR
{
	union
	{
		ULONG Characteristics;
		ULONG OriginalFirstThunk;
	};
	ULONG TimeDateStamp;
	ULONG ForwarderChain;
	ULONG Name;
	ULONG FirstThunk;
}_IMAGE_IMPORT_DESCRIPTOR;

typedef struct _IMAGE_THUNK_DATA
{
	union
	{
		ULONG* Function;
		ULONG Ordinal;
		ULONG AddressOfData;
		ULONG ForwarderString1;
	}u1;
}_IMAGE_THUNK_DATA;
#pragma pack(pop)

typedef struct peInfo
{
	_IMAGE_DOS_HEADER*			DH;
	_IMAGE_NT_HEADERS64*		NT;
	_IMAGE_SECTION_HEADER*		SHptr;
	_IMAGE_SECTION_HEADER		SH[9];
	_IMAGE_IMPORT_DESCRIPTOR*	IDT;
}peInfo;


typedef struct importLookupTableEntry
{
	union entry
	{
		struct
		{
			ULONGLONG identifierBit	:	 1;
			ULONGLONG ordImport		:	16;
			ULONGLONG namedImport	:	31;
		};
	};
}importLookupTable;

char* imageType[17] = { 
	"UNKNOWN", 
	"Windows Native", 
	"Windows GUI", 
	"Windows CLI", 
	"UNKNOWN", 
	"OS/2 CLI", 
	"UNKNOWN", 
	"Posix CLI", 
	"Windows 9X Driver", 
	"Windows CE",
	"EFI Application",
	"EFI Boot Services Driver", 
	"EFI Runtime Services Driver", 
	"EFI Rom Image",
	"XBOX",
	"Windows Boot Application"};

//Function Prototypes
UCHAR* copyFileToMemory(char* argv[]);
void printUsage();
void initializePeInfo(peInfo* binaryData, char* argv[], int argc);
void binspect(char* argv[], int argc);
void parseDosHeader(peInfo* binaryData);
void parseOptHeader(peInfo* binaryData);
void parsePeHeader(peInfo* binaryData);
void parseSectionHeaders(peInfo* binaryData);
void parseImportTable(peInfo* binaryData, UCHAR* buffer, UCHAR* index);
const char* calcRWX(ULONG flags);
const char* calcDATA(ULONG flags);
void optionSelector(int argc, char* argv[]);


#define DOS_HEADER		binaryData->DH
#define NT_HEADER		binaryData->NT
#define SECTION_HEADER	binaryData->SHptr
#define SECTION_HEADERS	binaryData->SH
#define IMPORT_DSCRPTR	binaryData->IDT
#define OPT_HEADER		NT_HEADER->OptionalHeader
#define DATA_DIRECTORY	OPT_HEADER.DataDirectory
#define PE_HEADER		NT_HEADER->FileHeader
#define SEC_START_ADDR	SECTION_HEADERS[i].VirtualAddress
#define SEC_END_ADDR	(SECTION_HEADERS[i].VirtualAddress + SECTION_HEADERS[i].SizeOfRawData)
#define IMP_TABLE_ADDR	DATA_DIRECTORY[1].VirtualAddress

#define NOT_FOUND		-1
