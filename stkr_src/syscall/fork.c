/*

Includes: 

fork()
exec(int pid, int *proc code)

*/

#include <entry.c>

int fork() {
    // Witchcraft to get the UID and PID of the calling proc, then fork the proc

    int pointer = __builtin_return_address(0);

    int PID = find_process_by_pointer(pointer);

    procTemp *process = find_process_by_pid(PID);

    addProcessEntry(process->procName, highest_used_pid + 1, process->ownerUID, process->codePointer);
    return 0;
}

// change_process_code_by_pid("0", *new_handler_function); - example

int exec(int pid, int *proc_code) {
    int result = change_process_code_by_pid(pid, proc_code);
    return result;
}