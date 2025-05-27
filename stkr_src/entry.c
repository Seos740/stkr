#include "stkr_user.h"
#include <file_io.h>
#include <mach/mach.h>

#define BUFFER_MULTIPLY_SIZE 12
#define PAGE_SIZE 4096
#define MAX_PERMISSIONS 32
#define STACK_SIZE (16 * PAGE_SIZE)

int highest_used_pid = 0;
int current_pid = 1;
const char *master_device_port = "/dev/";
int userCount = 0;

typedef struct {
    char procName[256];
    char pid[8];
    char ownerUID[8];
    void *codePointer;
    thread_act_t thread;  // Added: Mach thread handle
    void *stack;          // Added: pointer to allocated stack
} procTemp;

typedef struct {
    procTemp *table;
    size_t size;
    size_t capacity;
} ProcTable;

ProcTable globalProcTable;

// -- Memory Management --

void* mach_malloc(size_t size) {
    vm_address_t address = 0;
    kern_return_t kr = vm_allocate(mach_task_self(), &address, size, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) return NULL;
    return (void *)address;
}

void mach_free(void *ptr, size_t size) {
    vm_deallocate(mach_task_self(), (vm_address_t)ptr, size);
}

void* mach_realloc(void *ptr, size_t old_size, size_t new_size) {
    void *new_ptr = mach_malloc(new_size);
    if (!new_ptr) return NULL;

    for (size_t i = 0; i < (old_size < new_size ? old_size : new_size); i++) {
        ((char *)new_ptr)[i] = ((char *)ptr)[i];
    }

    mach_free(ptr, old_size);
    return new_ptr;
}

void safe_strcpy(char *dest, const char *src, size_t max_len) {
    size_t i = 0;
    while (i < max_len - 1 && src[i]) {
        dest[i] = src[i];
        i++;
    }
    dest[i] = '\0';
}

// -- String and Utility --

void mem_zero(void *ptr, size_t size) {
    for (size_t i = 0; i < size; i++)
        ((char *)ptr)[i] = 0;
}

int extract_token(const char* src, int start, char delimiter, char* dest, int max_len) {
    int i = 0;
    while (src[start] != delimiter && src[start] != '\0' && i < max_len - 1) {
        dest[i++] = src[start++];
    }
    dest[i] = '\0';
    return (src[start] == delimiter) ? start + 1 : start;
}

// -- User Logic --

void clear_user(struct userParams* user) {
    mem_zero(user, sizeof(struct userParams));
}

int parse_uid_list(char *uid_list) {
    int pos = 0;
    userCount = 0;

    while (uid_list[pos] != '\0' && userCount < MAX_USERS) {
        struct userParams* user = &userList[userCount];
        clear_user(user);

        pos = extract_token(uid_list, pos, ':', user->userName, sizeof(user->userName));
        pos++;

        pos = extract_token(uid_list, pos, ':', user->UID, sizeof(user->UID));
        pos = extract_token(uid_list, pos, ':', user->GID, sizeof(user->GID));
        pos++;

        if (uid_list[pos] == '"') pos++;
        pos = extract_token(uid_list, pos, '"', user->homeDirectory, sizeof(user->homeDirectory));
        pos++;

        if (uid_list[pos] == '"') pos++;
        pos = extract_token(uid_list, pos, '"', user->shellExecutableDirectory, sizeof(user->shellExecutableDirectory));
        pos += 2;

        char perms[MAX_PERMISSIONS];
        mem_zero(perms, MAX_PERMISSIONS);
        pos = extract_token(uid_list, pos, ':', perms, MAX_PERMISSIONS);

        for (int i = 0; perms[i] != '\0'; i++) {
            switch (perms[i]) {
                case 'r': user->canRead[0] = 1; break;
                case 'w': user->canWrite[0] = 1; break;
                case 'x': user->canExecute[0] = 1; break;
                case 's': user->canUseShell[0] = 1; break;
                case 'a': user->isAdmin[0] = 1; break;
                case 'm': user->canMount[0] = 1; break;
                case 'n': user->canNetwork[0] = 1; break;
                case 'd': user->deviceAccessEnabled[0] = 1; break;
                case 'l': user->logAccessEnabled[0] = 1; break;
                case 't': user->timeManagmentEnabled[0] = 1; break;
                case 'c': user->configManageRights[0] = 1; break;
                case 'b': user->bootParamManagment[0] = 1; break;
                case 'u': user->userManagment[0] = 1; break;
            }
        }

        pos++;

        int dirLen = 0;
        user->dirAccess[0] = '\0';
        while (uid_list[pos] != '-' && uid_list[pos] != '\0') {
            if (dirLen < sizeof(user->dirAccess) - 1) {
                user->dirAccess[dirLen++] = uid_list[pos++];
            } else {
                pos++;
            }
        }
        user->dirAccess[dirLen] = '\0';

        while (uid_list[pos] != '\n' && uid_list[pos] != '\0') pos++;
        if (uid_list[pos] == '\n') pos++;

        userCount++;
    }

    return userCount;
}

// -- Process Table --

int proccessTableSetup() {
    size_t initialCapacity = 10;

    globalProcTable.table = (procTemp *)mach_malloc(sizeof(procTemp) * initialCapacity);
    if (!globalProcTable.table) return -1;

    globalProcTable.size = 0;
    globalProcTable.capacity = initialCapacity;

    return 0;
}

int addProcessEntry(const char *name, const char *pid, const char *uid, void *codePtr) {
    if (globalProcTable.size == globalProcTable.capacity) {
        size_t newCapacity = globalProcTable.capacity * 2;
        size_t old_size = sizeof(procTemp) * globalProcTable.capacity;
        size_t new_size = sizeof(procTemp) * newCapacity;

        procTemp *newTable = (procTemp *)mach_realloc(globalProcTable.table, old_size, new_size);
        if (!newTable) return -1;

        globalProcTable.table = newTable;
        globalProcTable.capacity = newCapacity;
    }

    procTemp *entry = &globalProcTable.table[globalProcTable.size];

    safe_strcpy(entry->procName, name, sizeof(entry->procName));
    safe_strcpy(entry->pid, pid, sizeof(entry->pid));
    safe_strcpy(entry->ownerUID, uid, sizeof(entry->ownerUID));
    entry->codePointer = codePtr;

    // === Mach thread creation ===
    void *stack = mach_malloc(STACK_SIZE);
    if (!stack) return -1;

    thread_act_t thread;
    kern_return_t kr = thread_create(mach_task_self(), &thread);
    if (kr != KERN_SUCCESS) {
        mach_free(stack, STACK_SIZE);
        return -1;
    }

    x86_thread_state64_t state;
    mem_zero(&state, sizeof(state));

    state.__rip = (uint64_t)codePtr;
    uint64_t stack_top = (uint64_t)stack + STACK_SIZE - 8;
    stack_top &= ~0xFULL; // 16-byte align
    state.__rsp = stack_top;
    state.__rbp = 0;
    state.__rflags = 0x200; // Interrupt enable flag

    kr = thread_set_state(thread, x86_THREAD_STATE64, (thread_state_t)&state, x86_THREAD_STATE64_COUNT);
    if (kr != KERN_SUCCESS) {
        thread_terminate(thread);
        mach_free(stack, STACK_SIZE);
        return -1;
    }

    kr = thread_resume(thread);
    if (kr != KERN_SUCCESS) {
        thread_terminate(thread);
        mach_free(stack, STACK_SIZE);
        return -1;
    }

    entry->thread = thread;
    entry->stack = stack;
    // === End Mach thread creation ===

    globalProcTable.size++;

    int pid_num = str_to_int(pid);
    if (pid_num > highest_used_pid) {
        highest_used_pid = pid_num;
    }

    return 0;
}

void proccessTableCleanup() {
    if (!globalProcTable.table) return;

    // Terminate threads and free stacks
    for (size_t i = 0; i < globalProcTable.size; i++) {
        thread_terminate(globalProcTable.table[i].thread);
        mach_free(globalProcTable.table[i].stack, STACK_SIZE);
    }

    mach_free(globalProcTable.table, sizeof(procTemp) * globalProcTable.capacity);
    globalProcTable.table = NULL;
    globalProcTable.size = 0;
    globalProcTable.capacity = 0;
}

// -- Buffer Size Calculation --

int get_buffer_values(int bufferMultiplySize) {
    return (bufferMultiplySize * 2); // in bytes
}

// -- Main Logic --

int main() {
    if (proccessTableSetup() != 0) return 1;

    int buffer_bytes = get_buffer_values(BUFFER_MULTIPLY_SIZE);
    char *buffer = (char *)mach_malloc(buffer_bytes);
    if (!buffer) return 1;

    FILE *fp;
    open_file(master_device_port, "/etc/user/uid", &fp);
    read_file(fp, buffer, buffer_bytes);
    close_file(fp);

    buffer[buffer_bytes - 1] = '\0';

    int uidParseResult = parse_uid_list(buffer);

    addProcessEntry("kernel_task", "0", "1", *kernel_handler);

    mach_free(buffer, buffer_bytes);
    proccessTableCleanup();

    return 0;
}

int kernel_handler() {
    for (;;) {
        // do absolutely nothing
    }
}

int str_equals(const char *a, const char *b) {
    while (*a && *b) {
        if (*a != *b) return 0;
        a++;
        b++;
    }
    return (*a == '\0' && *b == '\0');
}

// Find process by name
procTemp* find_process_by_name(const char *name) {
    unsigned int i = 0;
    while (i < globalProcTable.size) {
        if (str_equals(globalProcTable.table[i].procName, name)) {
            return &globalProcTable.table[i];
        }
        i++;
    }
    return 0;
}

// Find process by PID
procTemp* find_process_by_pid(const char *pid) {
    unsigned int i = 0;
    while (i < globalProcTable.size) {
        if (str_equals(globalProcTable.table[i].pid, pid)) {
            return &globalProcTable.table[i];
        }
        i++;
    }
    return 0;
}

// Find process by code pointer
procTemp* find_process_by_pointer(void *pointer) {
    unsigned int i = 0;
    while (i < globalProcTable.size) {
        if (globalProcTable.table[i].codePointer == pointer) {
            return &globalProcTable.table[i];
        }
        i++;
    }
    return 0;
}

int str_to_int(const char *str) {
    int result = 0;
    int i = 0;
    while (str[i] >= '0' && str[i] <= '9') {
        result = result * 10 + (str[i] - '0');
        i++;
    }
    return result;
}

int change_process_code_by_pid(const char *pid, void *new_code_ptr) {
    procTemp *proc = find_process_by_pid(pid);
    if (!proc) {
        return -1; // Process with given PID not found
    }

    // Terminate old thread and free old stack
    if (proc->thread) {
        thread_terminate(proc->thread);
        proc->thread = 0;
    }
    if (proc->stack) {
        mach_free(proc->stack, STACK_SIZE);
        proc->stack = NULL;
    }

    // Allocate new stack
    void *stack = mach_malloc(STACK_SIZE);
    if (!stack) {
        return -1; // Failed to allocate stack
    }

    // Create new thread
    thread_act_t thread;
    kern_return_t kr = thread_create(mach_task_self(), &thread);
    if (kr != KERN_SUCCESS) {
        mach_free(stack, STACK_SIZE);
        return -1;
    }

    // Setup thread state for x86_64
    x86_thread_state64_t state;
    mem_zero(&state, sizeof(state));

    state.__rip = (uint64_t)new_code_ptr;
    uint64_t stack_top = (uint64_t)stack + STACK_SIZE - 8;
    stack_top &= ~0xFULL; // 16-byte align
    state.__rsp = stack_top;
    state.__rbp = 0;
    state.__rflags = 0x200; // Interrupt enable flag

    kr = thread_set_state(thread, x86_THREAD_STATE64, (thread_state_t)&state, x86_THREAD_STATE64_COUNT);
    if (kr != KERN_SUCCESS) {
        thread_terminate(thread);
        mach_free(stack, STACK_SIZE);
        return -1;
    }

    kr = thread_resume(thread);
    if (kr != KERN_SUCCESS) {
        thread_terminate(thread);
        mach_free(stack, STACK_SIZE);
        return -1;
    }

    // Update proc entry with new code pointer, thread, and stack
    proc->codePointer = new_code_ptr;
    proc->thread = thread;
    proc->stack = stack;

    return 0; // Success
}
