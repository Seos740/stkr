#include "stkr_user.h"
#include <file_io.h>
#include <mach/mach.h>

#define BUFFER_MULTIPLY_SIZE 12
#define PAGE_SIZE 4096
#define MAX_PERMISSIONS 32

const char *master_device_port = "/dev/";

int userCount = 0;

typedef struct {
    char procName[256];
    char pid[8];
    char ownerUID[8];
} procTemp;

typedef struct {
    procTemp *table;
    size_t size;
    size_t capacity;
} ProcTable;

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

    // Manual memory copy
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
        pos++; // skip ::

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

ProcTable* proccessTableSetup() {
    size_t initialCapacity = 10;

    ProcTable *procTable = (ProcTable *)mach_malloc(sizeof(ProcTable));
    if (!procTable) return NULL;

    procTable->table = (procTemp *)mach_malloc(sizeof(procTemp) * initialCapacity);
    if (!procTable->table) {
        mach_free(procTable, sizeof(ProcTable));
        return NULL;
    }

    procTable->size = 0;
    procTable->capacity = initialCapacity;

    return procTable;
}

int addProcessEntry(ProcTable *procTable, const char *name, const char *pid, const char *uid) {
    if (procTable->size == procTable->capacity) {
        size_t newCapacity = procTable->capacity * 2;
        size_t old_size = sizeof(procTemp) * procTable->capacity;
        size_t new_size = sizeof(procTemp) * newCapacity;

        procTemp *newTable = (procTemp *)mach_realloc(procTable->table, old_size, new_size);
        if (!newTable) return -1;

        procTable->table = newTable;
        procTable->capacity = newCapacity;
    }

    safe_strcpy(procTable->table[procTable->size].procName, name, sizeof(procTable->table[procTable->size].procName));
    safe_strcpy(procTable->table[procTable->size].pid, pid, sizeof(procTable->table[procTable->size].pid));
    safe_strcpy(procTable->table[procTable->size].ownerUID, uid, sizeof(procTable->table[procTable->size].ownerUID));

    procTable->size++;
    return 0;
}

void proccessTableCleanup(ProcTable *procTable) {
    if (!procTable) return;
    mach_free(procTable->table, sizeof(procTemp) * procTable->capacity);
    mach_free(procTable, sizeof(ProcTable));
}

// -- Buffer Size Calculation --

int get_buffer_values(int bufferMultiplySize) {
    return (bufferMultiplySize * 2); // in bytes
}

// -- Main Logic --

int main() {
    ProcTable *ptable = proccessTableSetup();
    if (!ptable) return 1;

    int buffer_bytes = get_buffer_values(BUFFER_MULTIPLY_SIZE);
    char *buffer = (char *)mach_malloc(buffer_bytes);
    if (!buffer) return 1;

    FILE *fp;
    open_file(master_device_port, "/etc/user/uid", &fp);
    read_file(fp, buffer, buffer_bytes);
    close_file(fp);

    buffer[buffer_bytes - 1] = '\0';

    int uidParseResult = parse_uid_list(buffer);
    // Assume there's a log or print replacement in kernel
    // log_info("Parsed users: ", uidParseResult);

    addProcessEntry(ptable, "kernel_task", "0", "1");

    mach_free(buffer, buffer_bytes);
    proccessTableCleanup(ptable);

    return 0;
}
