#include <stdio.h>
#include <Windows.h>
#include <Wincrypt.h>
#include <string.h>
#include "File_Operations.h"

//Defines
#define SHA256LEN  32


// Printing System error's
void Error(const char* msg)
{
    printf("\n### ERROR ###  %s  (%d)", msg, ::GetLastError());
    exit(EXIT_FAILURE);
}




// Find_file_hash() - Calculates the Hash of the ransomware 
void Find_file_hash(char* full_hash_value, char child_process_path[])
{
    int result;
    OFSTRUCT file_info_struct = { sizeof(file_info_struct) };
    HFILE hfile;

    hfile = ::OpenFile(child_process_path, &file_info_struct, OF_SHARE_COMPAT);

    if (hfile == HFILE_ERROR)
    {
        Error("OpenFile failed");
    }



    HCRYPTPROV hProv = 0;
    result = ::CryptAcquireContext(
        &hProv,                 // This variable will recive a pointer to a key container within a particular cryptographic service provider (CSP)
        NULL,                   // Name of the container
        NULL,                   // Name of CSP we want. NULL says just use the default
        PROV_RSA_AES,          // type of provider to acquire.  Read about this specific https://docs.microsoft.com/en-us/windows/win32/seccrypto/prov-rsa-full
        CRYPT_VERIFYCONTEXT);    // Used by applications that perform only hashing.

    if (!result)
    {
        Error("CryptAcquireContext failed");
    }



    /*      ### CryptCreateHash() ###  - create a CSP hash object
        // Handle to a CSP we created with CryptAcquireContext
        // Algorithm ID we want to use
        // Must be zero for non-keyed apps
        // zero. This parameters isn't really used
        // pointer to rhe object that will recive the new hash object
    */
    HCRYPTPROV hHash = 0;
    result = ::CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash);

    if (!result)
    {
        Error("CryptCreateHash failed");
    }



    /*              ### ReadFile() parameters ###
        // Handle to the file. I covert it from HFILE -> HANDLE
        // Destination of the bytes we read
        // Amount of bytes we want to read
        // Number of bytes we were able to read successfully
        // Only relavent if the file was opened with FILE_FLAG_OVERLAPPED
    */
    BYTE file_output_buffer[1024];
    DWORD num_of_bytes_we_read = 0;
    while (result = ::ReadFile((HANDLE)hfile, file_output_buffer, 1024, &num_of_bytes_we_read, NULL))
    {
        // We didn't read any bytes. Probably finished all bytes
        if (num_of_bytes_we_read == 0)
        {
            break;
        }

        //Inserting data (bytes we read from the file) to the hash object. We can insert as much as we want
        result = ::CryptHashData(hHash, file_output_buffer, num_of_bytes_we_read, NULL);
        if (!result)
        {
            Error("CryptHashData failed");
        }
    }

    if (!result)
    {
        Error("ReadFile failed");

    }



    /*              ### CryptGetHashParam() ### - hash the data in the hash object
        // Handle to the hash object
        // What we are quering for. We can query for: algorithm ID, HASH size in bytes, Hash value.   HP_HASHVAL = hash value.
        // Buffer that will recive the actual hash.
        // Pointer to a hash lenth variable
        // Must be zero
    */
    BYTE buffer_of_hash_itself[SHA256LEN];
    DWORD hash_lenth = SHA256LEN;
    char chars_possible_to_use[] = "0123456789abcdef";
    char full_hash_val;
    int counter = 0;
    result = ::CryptGetHashParam(hHash, HP_HASHVAL, buffer_of_hash_itself, &hash_lenth, 0);
    if (result)
    {
        for (int i = 0; i < SHA256LEN; i++)
        {
            full_hash_value[counter] = chars_possible_to_use[buffer_of_hash_itself[i] >> 4];
            counter += 1;
            full_hash_value[counter] = chars_possible_to_use[buffer_of_hash_itself[i] & 0xf];
            counter += 1;
            //printf("%c%c", chars_possible_to_use[buffer_of_hash_itself[i] >> 4], chars_possible_to_use[buffer_of_hash_itself[i] & 0xf]);  ### This will print the hash
        }

        full_hash_value[counter] = '\0';

    }
    else
    {
        Error("CryptGetHashParam failed");
    }


    //Close all the handles
    ::CryptDestroyHash(hHash);
    ::CryptReleaseContext(hProv, 0);
    ::CloseHandle((HANDLE)hfile);
}




//num_of_lines_in_file() - calculate number of lines in keywords.txt . Presumes there is at least 1 line.
int num_of_lines_in_file(FILE* fp)
{
    int lines = 1;
    char ch;

    while (!feof(fp))
    {
        ch = fgetc(fp);
        if (ch == '\n')
        {
            lines++;
        }
    }

    fseek(fp, 0, SEEK_SET);
    return lines;
}




//get_key_words() - creates a an array of "strings". Each string represents a line in the kewords.txt file.
//Those strings are searched in the process memory. 
char** get_key_words(keywords_data* kd)
{
    FILE* fp;
    fopen_s(&fp, "Keywords.txt", "r");
    if (fp == NULL)
    {
        printf("Unable to open keywords.txt, make sure that file exists");
        exit(1);
    }

    kd->number_of_lines = num_of_lines_in_file(fp);

    kd->keywords = (char**)calloc(kd->number_of_lines, sizeof(char*));
    if (kd->keywords == NULL)
    {
        printf("Can't allocate memory from the heap for WCHAR ** keywords");
        exit(1);
    }

    for (int j = 0; j < kd->number_of_lines; j++)
    {
        kd->keywords[j] = (char*)calloc(60, sizeof(char));
        if (kd->keywords[j] == NULL)
        {
            printf("Can't allocate memory from the heap for kd->keywords[j]");
            exit(1);
        }
    }

    char temp_buffer[60];
    for (int i = 0; i < kd->number_of_lines; i++)
    {

        //Replacing the \n of fgets with NULL
        memset(temp_buffer, 0, 30);
        fgets(temp_buffer, 59, fp);
        for (int k = 0; k < strlen(temp_buffer); k++)
        {
            if (temp_buffer[k] == '\n')
            {
                temp_buffer[k] = '\0';
                break;
            }
        }

        strcpy_s(kd->keywords[i], 59, temp_buffer);
    }

    fclose(fp);
    return kd->keywords;
}




void write_ransom_note(char* buffer_that_holds_only_text_that_is_extracted_from_memory_page, char* lp_strstr_result, keywords_data* kd)
{
    //Get Current folder path
    char path[MAX_PATH];
    if (!::GetCurrentDirectoryA(MAX_PATH, path))
    {
        Error("GetCurrentDirectoryA failed");
    }


    //Create an output folder 
    if (!::CreateDirectoryA("Output_Folder", NULL))
    {
        if (::GetLastError() != ERROR_ALREADY_EXISTS)
        {
            Error("Couldn't Create the output folder");
        }
    }


    //Create the "ransom note" file path 
    FILE* fp;
    char dst_relative_file_path[95] = "Output_Folder/";
    strcat_s(dst_relative_file_path, 95, kd->dst_filename);
    fopen_s(&fp, dst_relative_file_path, "w");
    if (fp == NULL)
    {
        printf("Unable to open the destination file");
        exit(1);
    }


    //Get 800 bytes from the buffer_that_holds_only_text_that_is_extracted_from_memory_page which are likely to hold the ransom note.
    int index = lp_strstr_result - buffer_that_holds_only_text_that_is_extracted_from_memory_page;
    int start = 0, end = index + 400;

    if (index > 401)
    {
        start = index - 400;
    }

    int counter = start;
    while (buffer_that_holds_only_text_that_is_extracted_from_memory_page[counter] != '\0' && counter != end)
    {
        fputc(buffer_that_holds_only_text_that_is_extracted_from_memory_page[counter], fp);
        counter += 1;
    }

    fclose(fp);

}





















