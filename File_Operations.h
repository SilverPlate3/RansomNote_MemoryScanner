#ifndef FILE_OPERATIONS_H_INCLUDED
#define FILE_OPERATIONS_H_INCLUDED


//Struct that holds data on files (keyword & destination file)
typedef struct {
	char hash[65];
	char dst_filename[73];
	char** keywords;
	int number_of_lines;
} keywords_data;


/*
	Callculates the SHA256 of a file.
	The SHA will be used to name the destination .txt file that will hold the extracted Ransom note.

	Input:
	 #Pointer to a character array.
	 #File path of child process.

	Output:
	 #Void

	Remarks:
	  #Fills the input array with the SHA256 + '\0'.
*/
void Find_file_hash(char* full_hash_value, char child_process_path[]);





/*
	calculate number of lines in keywords.txt.

	Input:
	 #FILE pointer.

	Output:
	 #number of lines in file

	Remarks:
	  #Presumes there is at least 1 line.
*/
int num_of_lines_in_file(FILE* fp);





/*
	 creates a an array of "strings". Each string represents a line in the kewords.txt file.
	 Those strings are searched in the process memory.

	Input:
	 #Pointer to keywords_data struct.

	Output:
	 #Pointer to character array (so pointer to pointer)

*/
char** get_key_words(keywords_data* kd);





/*
	 Tires to write the ransom note into a .txt file that is named after the ransomware hash.
	 It does it by: Saving the index of the last keyword found, then writes 400 bytes before the index and 400 after (if possible) the index to the destination file.


	Input:
	 # Dynaic array that holds all the valuble text from the ransomware specified memory page
	 # pointer to the last found keyword
	 # pointer to keywords_data struct

	Output:
	 #No output.

	Remarks:
	 #The new .txt folder will be added to the output folder which will be created in the current process folder.


*/
void write_ransom_note(char* buffer_that_holds_only_text_that_is_extracted_from_memory_page, char* lp_strstr_result, keywords_data* kd);


#endif // !FILE_OPERATIONS_H_INCLUDED

