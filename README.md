# RansomNote_MemoryScanner


# Who does this serve:
As a security analyst in an EDR company, i know the importance of memory signatures.  
These signature are hard to produce and are very time consuming. With this tool research teams can create solid signatures (both memory and static) that are based on the ransom note, in minutes.  
 

# High-Level explanation on the tool
 * The tool executes the ransomware as a child to have full access to it.
 * It scannes all the Committed memory pages and extracts all the valuable bytes.
 * If the memory page has PAGE_NOACCESS or PAGE_GUARD protection attributes the tool changes it to PAGE_EXECUTE_READWRITE and scannes it as well. This is done so the     malware author won't use VirtualProtect() to hide data in these "inaccessible" pages.
 * The extracted characters against keywords given in keyword.txt.
 * Once 3 keywords are found in the same memory page, the tool calculates the hash of ransomware and creates a file called {ransomware hash}.txt
 * The above .txt file will receive and contain the ransom note (or part of it)


# Usage
  * **Input**:  
    {memory scanner compiled .exe} "{Full/relative path of the ransomware}"  
    Example: Memory_Scanner.exe  C:\Users\ariel\Desktop\Conti_sample.exe  
  * **Output**:  
    A) CLI will show the 3 keywords that were found by there order.  
    B) CLI will show the address of the memory page which contains the ransom note.  
    C) An output folder will be created with a .txt file that holds the ransom note or part of it. The .txt file will be named after the ransomware hash.  
       If shown in the static condition, the strings that are in the .txt file can be used to create a basic AV/Yara signatures as well.



# Showoff video
90 seconds that shows how to use the tool and the output we get from it:  https://youtu.be/LFcS3f5q2Us
