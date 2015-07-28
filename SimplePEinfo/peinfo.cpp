#include <cstdio>
#include <windows.h>

using namespace std;

int main(int argc, char **argv)
{
	puts("Simple PE info");

	if (argc != 2)
	{
		printf("usage: peinfo.exe <PE file>");
		return 1;
	}

	FILE *f;
	size_t FileSize;
	unsigned char *data;

	f = fopen(argv[1], "rb");

	if (!f)
	{
		puts("File not found");
		return 2;
	}

	fseek(f, 0, SEEK_END);
	FileSize = ftell(f);
	fseek(f, 0, SEEK_SET);

	data = (BYTE*)malloc(FileSize);

	if (!data)
	{
		fclose(f);
		return 0;
	}

	FileSize = fread(data, sizeof(char), FileSize, f);
	data[FileSize] = 0;

	IMAGE_DOS_HEADER* dos;
	dos = (IMAGE_DOS_HEADER*)data;

	IMAGE_NT_HEADERS* nt;
	nt = (IMAGE_NT_HEADERS*)(data + dos->e_lfanew);

	IMAGE_SECTION_HEADER* section;
	section = (IMAGE_SECTION_HEADER*)(data + dos->e_lfanew + sizeof(IMAGE_NT_SIGNATURE)+sizeof(IMAGE_FILE_HEADER)+sizeof(IMAGE_OPTIONAL_HEADER));

	printf("Offset to New EXE Header: 0x%x\n", dos->e_lfanew);

	printf("Image NT Header Signeture: 0x%x\n", nt->Signature);

	printf("Number of Sections: 0x%x\n", nt->FileHeader.NumberOfSections);

	printf("Machine: 0x%x\n", nt->FileHeader.Machine);

	printf("Subsystem: 0x%x\n", nt->OptionalHeader.Subsystem);

	printf("Adddress of Entry Point: 0x%x\n", nt->OptionalHeader.AddressOfEntryPoint);

	printf("Image Base: 0x%x\n", nt->OptionalHeader.ImageBase);

	printf("Section Names:\n");

	for (int i = 0; i < nt->FileHeader.NumberOfSections; i++)
	{
		printf("%.8s\n", section[i].Name);
	}

	fclose(f);

	return 0;
}