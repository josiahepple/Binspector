// binspector by Josiah Epple. PE32 tyPEdefs pulled from public pdb's owned by Microsoft

#define _CRT_SECURE_NO_WARNINGS
#include "binspector.h"

int numberOfSections = NOT_FOUND;
int sectionContainingImportTable = NOT_FOUND;

int main(int argc, char* argv[])
{
	system("cls");
	optionSelector(argc, argv);
	binspect(argv, argc);
	return 0;
}

void binspect(char* argv[], int argc)
{
	peInfo* binaryData;
	binaryData = (peInfo*)malloc(sizeof(peInfo));
	UCHAR* buffer = copyFileToMemory(argv);
	UCHAR* index = buffer;

	DOS_HEADER = (_IMAGE_DOS_HEADER*)index;
	index += DOS_HEADER->e_lfanew;

	NT_HEADER = (_IMAGE_NT_HEADERS64*)index;
	index += sizeof(_IMAGE_NT_HEADERS64);

	numberOfSections = PE_HEADER.NumberOfSections;
	for (int i = 0; i < numberOfSections; i++)
	{
		SECTION_HEADERS[i] = *(_IMAGE_SECTION_HEADER*)index;
		if ((IMP_TABLE_ADDR >= SEC_START_ADDR) && (IMP_TABLE_ADDR <= SEC_END_ADDR))
		{
			sectionContainingImportTable = i;
		}
		index += sizeof(_IMAGE_SECTION_HEADER);
	}	
	parseDosHeader(binaryData);
	parsePeHeader(binaryData);
	parseOptHeader(binaryData);
	parseSectionHeaders(binaryData);
	if (sectionContainingImportTable == NOT_FOUND)
		printf("\nImport Table could not be found.");
	else
		parseImportTable(binaryData, buffer, index);
}


void parseDosHeader(peInfo* binaryData)
{
	if (DOS_HEADER->e_magic != 0x5a4d)
	{
		printf("Error: File doesn't begin with MZ Header. Exiting.");
		puts("");
		exit(-2);
	}
}

void parseOptHeader(peInfo* binaryData)
{
	//Bitness of the Program
	if (OPT_HEADER.Magic == 0x10b)
	{
		printf("Exe Bitness:\t(x86)\n\n");
		printf("32-Bit files are not currently supported.\nExiting.\n");
		exit(3);
	}
	if (OPT_HEADER.Magic == 0x20b)
		printf("Exe Bitness:\t(x64)\n");
	printf("Entry Point:\t0x%lx\n", (OPT_HEADER.AddressOfEntryPoint));

	//Subsystem used
	for (int i = 0; i < 17; i++)
	{
		if (OPT_HEADER.Subsystem == i)
			printf("Subsystem:\t%s\n", imageType[i]);
	}

	//Print checksum if was compiled with one
	if (!(OPT_HEADER.CheckSum))
		printf("Checksum:\tNone\n");
	else
		printf("Checksum:\t%lu\n", OPT_HEADER.CheckSum);
	puts("");
}

void parsePeHeader(peInfo* binaryData)
{
	USHORT characteristics = (0x2000) & (PE_HEADER.Characteristics);

	//Target Architecture
	if (PE_HEADER.Machine == 0x8664)
		printf("CPU Arch:\tx86_x64\n");
	if (PE_HEADER.Machine == 0x0)
		printf("CPU Arch:\tUnknown\n");
	if (PE_HEADER.Machine == 0xaa64)
		printf("CPU Arch:\tARM64\n");
	if (PE_HEADER.Machine == 0x1c0)
		printf("CPU Arch:\tARM\n");

	//File Type, exe, dll, sys
	if (characteristics == 0x2000)
		printf("File Type:\tDLL\n");
	if (characteristics == 0x1000)
		printf("File Type:\tKernel Driver\n");
}

void parseSectionHeaders(peInfo* binaryData)
{
	ULONG RWXflags = 0x0;
	ULONG DATAflags = 0x0;
	printf("\n\t\tSECTIONS\n");
	printf("=================================================\n");
	printf("#  name\t\toffset\tsize\trwx   code/data\n");
	printf("=================================================\n");
	for (int i = 0; i < numberOfSections; i++)
	{
		SECTION_HEADER = &SECTION_HEADERS[i];
		RWXflags = (0xE0000000) & (SECTION_HEADER->Characteristics);
		DATAflags = (0x000000E0) & (SECTION_HEADER->Characteristics);
		if (SECTION_HEADER->SizeOfRawData != 0x0)
		{
			printf("%i: %s\t0x%lx\t0x%lx\t%s  %s\n", i, SECTION_HEADER->Name, SECTION_HEADER->PointerToRawData, SECTION_HEADER->SizeOfRawData, (calcRWX(RWXflags)), (calcDATA(DATAflags)));
		}
	}
}

void parseImportTable(peInfo * binaryData, UCHAR* buffer, UCHAR* index)
{
	printf("\n\n\t\tIMPORT TABLES\n");

	ULONG idtVA;
	ULONG sectionVA;
	ULONG sectionOffset;
	_IMAGE_THUNK_DATA* thunk;
	sectionOffset = SECTION_HEADERS[sectionContainingImportTable].PointerToRawData;
	idtVA = DATA_DIRECTORY[1].VirtualAddress;
	sectionVA = SECTION_HEADERS[sectionContainingImportTable].VirtualAddress;
	index = buffer;
	index += sectionOffset + idtVA - sectionVA;
	IMPORT_DSCRPTR = (_IMAGE_IMPORT_DESCRIPTOR*)index;
	while(IMPORT_DSCRPTR->Name != NULL)
	{
		printf("=================================================\n");
		printf("#  %s\n", buffer + sectionOffset + IMPORT_DSCRPTR->Name - sectionVA);
		printf("=================================================\n");
		
		if (IMPORT_DSCRPTR->Characteristics != 0)
			thunk = (_IMAGE_THUNK_DATA*)(buffer + sectionOffset + IMPORT_DSCRPTR->OriginalFirstThunk - sectionVA);
		else
			thunk = (_IMAGE_THUNK_DATA*)(buffer + sectionOffset + IMPORT_DSCRPTR->FirstThunk - sectionVA);
		
		for (int i = 0; thunk->u1.AddressOfData != 0; i++)
		{
			printf("0x%u\t\t%s\n", thunk->u1.AddressOfData, (buffer + sectionOffset + thunk->u1.AddressOfData - sectionVA + 2));
			thunk++;
		}
			IMPORT_DSCRPTR++;
			puts("");
	}
}

UCHAR* copyFileToMemory(char* argv[])
{
	FILE* file;
	ULONG fileSize;
	UCHAR* buffer;

	if (!(file = fopen(argv[1], "rb")))
	{
		puts("Error opening file, closing program.\n");
		exit(-2);
	}

	printf("\t\tFILE INFO\n");
	printf("================================================\n");
	printf("#  %s\n", argv[1]);
	printf("================================================\n");
	//get file size by skipping to end and saving the index
	fseek(file, 0L, SEEK_END);
	fileSize = ftell(file);
	rewind(file);
	buffer = malloc(fileSize);
	fread(buffer, 1, fileSize, file);
	fclose(file);
	return buffer;
}

const char* calcRWX(ULONG characteristics)
{
	if (characteristics == 0x20000000)
		return "  X";
	else if (characteristics == 0x40000000)
		return "R  ";
	else if (characteristics == 0x60000000)
		return "R X";
	else if (characteristics == 0x80000000)
		return " W ";
	else if (characteristics == 0xa0000000)
		return " WX";
	else if (characteristics == 0xc0000000)
		return "RW ";
	else if (characteristics == 0xe0000000)
		return "RWX";
	else
		return "   ";
}

const char* calcDATA(ULONG flags)
{
	if (flags == 0x20)
		return " C";
	else if (flags == 0x40)
		return " D ";
	else if (flags == 0x60)
		return " CD ";
	else if (flags == 0x80)
		return "  U";
	else if (flags == 0xA0)
		return " C U";
	else if (flags == 0xC0)
		return " DU";
	else if (flags == 0xE0)
		return " CDU";
	else
		return " ";
}
void optionSelector(int argc, char* argv[])
{
	if (argc == 1)
	{
		printUsage();
	}
	else if (argc == 2)
	{
		if (_stricmp(argv[1], "-help"))
			return;
		else
		{
			system("cls");
			puts("");
			printf("Usage: binspector filename\n");
			puts("");
			printf("Example Usage:\n");
			puts("");
			printf("binspector C:\\Windows\\System32\\notepad.exe");
			puts("");
			exit(-1);
		}
	}
}

void printUsage()
{
		puts("");
		printf("Usage: binspector filename\n");
		printf("For help: binspector -help");
		puts("");
		exit(-1);
}
