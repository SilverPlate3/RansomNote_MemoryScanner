#include <stdio.h>
#include <Windows.h>
#include <Psapi.h>
#include <shlwapi.h>
#include "File_Operations.h"

// Libraries to link
#pragma comment(lib, "Shlwapi.lib")


// Defines
#define Dynamic_Countof(size, obj) (size/sizeof(obj))  


//function prototypes
char* cli_arguments(int argc, char** argv);
void cleaning_up(PROCESS_INFORMATION* Ppi, keywords_data* Pkd);


// Printing System error's
int Error(const char* msg)
{
	printf("\n### ERROR ###  %s  (%d)", msg, ::GetLastError());
	return 1;
}



// Reallocating the dynamic arrays, which hold the child process memory
char* reallocation(LPVOID buffer, DWORD size)
{
	char* temp = (char*)realloc(buffer, size);
	if (temp == NULL)
	{
		printf("\nUnable to realloc");
		exit(EXIT_FAILURE);
	}

	return temp;
}



// Creating the Child process 
void Create_Child_Process(char child_process_path[], PROCESS_INFORMATION* Ppi)
{
	STARTUPINFOA struct_STARTUPINFOA = { sizeof(struct_STARTUPINFOA) };
	::ZeroMemory(Ppi, sizeof(*Ppi));

	int result = ::CreateProcessA(
		child_process_path,		// Path of executable we want to run
		NULL,				    // Arguments the process will run with.    
		NULL,					// Security_Attributes struct.  Null means that the handle to the new process won't be inherited.  
		NULL,					// Same thing as the above one, just for the main thread of the new process.   
		TRUE,					// If we want the new process to inherite the inheritable handles of our process.
		0,						// Process creation flags.  
		NULL,
		NULL,
		&struct_STARTUPINFOA,    // Pointer to a STARTUPINFO strcut. 
		Ppi						 // Pointer to a  PROCESS_INFORMATION struct, which will recive info and handles to the new process
	);
	if (!result)
	{
		Error("Creating the child process");
	}

	printf("\nPID: %u, TID: %u", Ppi->dwProcessId, Ppi->dwThreadId);

}



//Start & stop the debugging mode on the new process.
void Control_Debbugging(DWORD PID, int action)
{
	int result = 0;
	if (action == 1)
	{
		result = ::DebugActiveProcess(PID);
	}
	else
	{
		result = ::DebugActiveProcessStop(PID);
	}

	if (!result)
	{
		Error("Debugg function has failed.");
	}
}




int locate_keywords_in_extracted_strings(char* buffer_that_holds_only_text_that_is_extracted_from_memory_page, keywords_data* Pkd, unsigned long long* Pbase_address)
{
	int counter = 0;
	int past_key_words_indexes[3];
	char* lp_strstr_result;

	for (int i = 0; i < Pkd->number_of_lines; i++)
	{
		lp_strstr_result = strstr(buffer_that_holds_only_text_that_is_extracted_from_memory_page, Pkd->keywords[i]);
		if (lp_strstr_result)
		{
			past_key_words_indexes[counter] = i;
			counter += 1;
			if (counter >= 3)
			{
				printf("\n\n\n################# Found #################\n[+] Strings found:\n1) %s\n2) %s\n3) %s\n[+] Memory Page:  %llp", Pkd->keywords[past_key_words_indexes[0]], Pkd->keywords[past_key_words_indexes[1]], Pkd->keywords[i], *Pbase_address);
				write_ransom_note(buffer_that_holds_only_text_that_is_extracted_from_memory_page, lp_strstr_result, Pkd);
				return 1;
			}
		}

	}
	return 0;
}




//Extracts the valuble characters from buffer_that_holds_read_memory and stores them in buffer_that_holds_only_text_that_is_extracted_from_memory_page
int get_only_needed_bytes(char* buffer_that_holds_read_memory, char* buffer_that_holds_only_text_that_is_extracted_from_memory_page, MEMORY_BASIC_INFORMATION* Pmbi)
{
	DWORD i = 0, j = 0;

	for (i = 0; i < Dynamic_Countof(Pmbi->RegionSize, char); i++)
	{
		// Check if the byte is a valuble character
		if ((buffer_that_holds_read_memory[i] >= 32 && buffer_that_holds_read_memory[i] <= 125) || (buffer_that_holds_read_memory[i] == 10))
		{
			//If it is, insert it to buffer_that_holds_only_text_that_is_extracted_from_memory_page
			buffer_that_holds_only_text_that_is_extracted_from_memory_page[j] = buffer_that_holds_read_memory[i];
			j += 1;
		}
	}
	buffer_that_holds_only_text_that_is_extracted_from_memory_page[j] = '\0';

	return 1;
}




int extract_strings_from_process(char* buffer_that_holds_read_memory, char* buffer_that_holds_only_text_that_is_extracted_from_memory_page, PROCESS_INFORMATION* Ppi, keywords_data* Pkd)
{

	// Create a SYSTEM_INFO struct to find the MaximumApplicationAddress of the system
	SYSTEM_INFO si;
	GetSystemInfo(&si);


	// Variables for VirtualQueryEx() AND ReadProcessMemory()
	DWORD virtualQueryEx_result = 1;
	MEMORY_BASIC_INFORMATION mbi;
	unsigned long long base_address = 0;
	SIZE_T num_of_bytes_we_were_able_to_read;
	DWORD OldProtect;
	int result = 0;

	while (1)
	{

		// Get info about the virtual memory of the process.
		virtualQueryEx_result = ::VirtualQueryEx(
			Ppi->hProcess,			// Handle to the destination process
			(LPCVOID)base_address,	// Pointer to the base address of the memory region to be queried
			&mbi,					// Pointer to a MEMORY_BASIC_INFORMATION struct that will recive info about the memory region
			sizeof(mbi)				// Size of the above struct
		);
		if (!virtualQueryEx_result)
		{
			Error("VirtualQueryEx");
		}


		//Checks if the virtual memory region was allocated to physical memory.
		//This means its accessible and may contain strings 
		if (mbi.State == MEM_COMMIT)
		{
			// Reallocating the 2 destination buffers as the RegionSize, as they might hold all of it's content.
			buffer_that_holds_read_memory = reallocation(buffer_that_holds_read_memory, mbi.RegionSize);
			buffer_that_holds_only_text_that_is_extracted_from_memory_page = reallocation(buffer_that_holds_only_text_that_is_extracted_from_memory_page, mbi.RegionSize);


			// Checking if the memory page has PAGE_GUARD + XYZ  OR  PAGE_NOACCESS. If so, change it to PAGE_EXECUTE_READWRITE
			if (mbi.Protect == 0x104 || mbi.Protect == PAGE_NOACCESS)
			{
				if (!::VirtualProtectEx(Ppi->hProcess, (LPVOID)base_address, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &OldProtect))
				{
					Error("VirtualProtectEx()");
				}
			}


			int result = ::ReadProcessMemory(
				Ppi->hProcess,						  // Handle to the destination process
				(LPVOID)base_address,				  // Pointer to an address in the destination process, from which to start reading
				buffer_that_holds_read_memory,		  // Buffer that will recive all the read bytes from the destination process
				mbi.RegionSize,						  // Number of bytes we want to read from the destination process
				&num_of_bytes_we_were_able_to_read);  // Pointer to a variable that will recive the number of bytes we were able to recive 
			if (!result)
			{
				Error("Read Process memory");
				printf("\nPage:  %llp  protection: %x", base_address, mbi.Protect);
			}
			else
			{
				result = get_only_needed_bytes(buffer_that_holds_read_memory, buffer_that_holds_only_text_that_is_extracted_from_memory_page, &mbi);
				if (result != 1)
				{
					printf("\nget_only_needed_bytes had issue");
					exit(EXIT_FAILURE);
				}

				if (locate_keywords_in_extracted_strings(buffer_that_holds_only_text_that_is_extracted_from_memory_page, Pkd, &base_address))
				{
					free(buffer_that_holds_read_memory);
					free(buffer_that_holds_only_text_that_is_extracted_from_memory_page);
					return 1;

				}
			}
		}



		// Setting the new base address to the next memory region base address
		base_address += mbi.RegionSize;

		// For some reason, there were 2 outcomes for passing end of the memory region.
		// Either the next query would return BaseAddress = 0  OR  it will try to access the next region of memory and fail with an error.
		// This If() covers both scenarios 
		if (base_address == 0 || base_address >= (unsigned long long)si.lpMaximumApplicationAddress)
		{
			free(buffer_that_holds_read_memory);
			free(buffer_that_holds_only_text_that_is_extracted_from_memory_page);
			return 0;
		}

	}
}




int main(int argc, char** argv)
{
	//Ransom file path
	char* child_process_path = cli_arguments(argc, argv);
	printf("[+] %s", child_process_path);

	// ----------------------------------------------  Creating the keywords_data struct Start ---------------------------------------
	keywords_data kd;
	kd.number_of_lines = 0;
	kd.keywords = get_key_words(&kd);
	Find_file_hash(kd.hash, child_process_path);
	strcpy_s(kd.dst_filename, 72, kd.hash);
	strcat_s(kd.dst_filename, 72, ".txt");

	// ----------------------------------------------  Creating the keywords_data struct END -----------------------------------------


	// ---------------------------------------------- Creating child process START --------------------------------------

	PROCESS_INFORMATION pi;
	Create_Child_Process(child_process_path, &pi);

	// ---------------------------------------------- Creating child process END --------------------------------------


	int milliseconds_to_sleep = 150, result = 0;
	for (int i = 0; i < 100; i++)
	{
		// First iteration gives the ransomware enogh time to load few modules and strings but not enouh to encrypt.
		Sleep(milliseconds_to_sleep);

		// Pauses the child process and puts him in debbuged mode.
		Control_Debbugging(pi.dwProcessId, 1);


		// Creating 2 dynamic arrays.
		// buffer_that_holds_read_memory - Will hold all the memory of the current memory region
		// buffer_that_holds_only_text_that_is_extracted_from_memory_page - Will hold only the "good" characters extracted from buffer_that_holds_read_memory
		char* buffer_that_holds_read_memory = (char*)malloc(2);
		char* buffer_that_holds_only_text_that_is_extracted_from_memory_page = (char*)calloc(sizeof(char), 2);



		result = extract_strings_from_process(buffer_that_holds_read_memory, buffer_that_holds_only_text_that_is_extracted_from_memory_page, &pi, &kd);
		if (result)
		{
			printf("\n\nPress any button to kill the ransomware process and exit.....");
			getchar();
			break;
		}

		printf("\n\n------------------------------------------ Finished iteration!   Note wasn't found yet.....   Sleeping for another 50 milliseconds");

		Control_Debbugging(pi.dwProcessId, 2);

		milliseconds_to_sleep = 50;
	}


	cleaning_up(&pi, &kd);


	return 1;

}



//Checking and returning the argument given to the process
char* cli_arguments(int argc, char** argv)
{
	if (argc != 2)
	{
		printf("   #### Usage: ###\n[+] Command-Line tool that takes 1 argument. The argument is the full/relative file path of the ransomware you want to run");
		exit(EXIT_FAILURE);
	}

	return argv[1];
}



// Free memory, terminate child process, close handles
void cleaning_up(PROCESS_INFORMATION* Ppi, keywords_data* Pkd)
{
	//Free() memory
	for (int i = 0; i < Pkd->number_of_lines; i++)
	{
		free(Pkd->keywords[i]);
	}
	free(Pkd->keywords);


	//Once the ransom note was found We terminate the child process
	if (!::TerminateProcess(Ppi->hProcess, 0))
	{
		Error("Cant terminate child process");
	}

	//Close handles
	CloseHandle(Ppi->hProcess);
	CloseHandle(Ppi->hThread);
}







