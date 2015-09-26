#include <cstdio>
#include <windows.h>
#include <iostream>
#include <string>

char code[] = "\xde\xc0\xed\xfe\x7a\xda\xed\xfe\x7a\xda\xed\xfe\xcc\xcc\xcc\xcc\xe8\x00\x00\x00"
	      "\x00\x58\x66\x25\x00\xf0\x56\x51\x8b\x70\x04\x8b\x48\x08\x80\x74\x0e\xff\x55\x28\x4c"
	      "\x0e\xff\xe2\xf5\x59\x5e\xff\x20";

int main(int argc, char **argv)
{
	puts("PE Packer/Protector");

	if(argc != 2)
	{
		printf("Usage: %s <PE file to package>\n", argv[0]);
		return 1;
	}

	FILE *f;
	FILE *c;
	size_t FileSize;
	BYTE *data;
	BYTE *loader;
	int numOfSec;
	size_t PointerToNewSec;
	int startSec;
	size_t load;

	f = fopen(argv[1], "rb");
	if(!f)
	{
		puts("File not found");
		return 2;
	}

	fseek(f, 0, SEEK_END);
	FileSize = ftell(f);
	fseek(f, 0, SEEK_SET);

	data = new BYTE[FileSize];

	if(!data)
	{
		fclose(f);
		return 0;
	}

	FileSize = fread(data, sizeof(char), FileSize, f);
	data[FileSize] = 0;

	IMAGE_DOS_HEADER *dos;
	dos = (IMAGE_DOS_HEADER*)data;

	IMAGE_NT_HEADERS *nt;
	nt = (IMAGE_NT_HEADERS*)(data + dos->e_lfanew);

	IMAGE_SECTION_HEADER *section;
	section = (IMAGE_SECTION_HEADER*)(data + dos->e_lfanew + sizeof(IMAGE_NT_SIGNATURE) + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER));

	numOfSec = nt->FileHeader.NumberOfSections;

	memset(&section[numOfSec], 0, sizeof(IMAGE_SECTION_HEADER));
	nt->FileHeader.NumberOfSections++;

	memcpy(section[numOfSec].Name, ".crypsec", 8);
	section[numOfSec].Misc.VirtualSize = 0x1000;
	section[numOfSec].VirtualAddress = ((nt->OptionalHeader.SizeOfImage -1) / 0x1000 + 1) * 0x1000;
	section[numOfSec].Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ |IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_CODE | IMAGE_SCN_CNT_INITIALIZED_DATA;

	load = 	sizeof(code) / sizeof(*code);

	section[numOfSec].SizeOfRawData = load;

	PointerToNewSec = section[numOfSec-1].PointerToRawData + section[numOfSec-1].SizeOfRawData;
	section[numOfSec].PointerToRawData = PointerToNewSec;

	nt->OptionalHeader.SizeOfImage = section[numOfSec].VirtualAddress + section[numOfSec].Misc.VirtualSize;

	DWORD OEP = nt->OptionalHeader.AddressOfEntryPoint + nt->OptionalHeader.ImageBase;
	DWORD encrSecStart = section[0].VirtualAddress + nt->OptionalHeader.ImageBase;
	
	memcpy(&code[0], &OEP, 4);
	memcpy(&code[4], &encrSecStart, 4);
	memcpy(&code[8], &section[0].SizeOfRawData, 4);

	nt->OptionalHeader.AddressOfEntryPoint = section[numOfSec].VirtualAddress + 0x10;

	startSec = section[0].PointerToRawData;

	for(int i = 0; i < section[0].SizeOfRawData; i++)
	{
		data[startSec] += (unsigned char)(startSec+1);
		data[startSec] ^= 0x55;
		startSec++;
	}

	section[0].Characteristics |= IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ;

	std::string name = "cryp.";
	std::string arg = argv[1];
	std::string fname = name+arg;

	c = fopen(fname.c_str(), "wb");
	fwrite(data, FileSize, 1, c);
	fwrite(code, load, 1, c);
	fclose(c);

	delete[] data;

	return 0;
}
