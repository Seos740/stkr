#include <string.h>
#include <stdio.h>
#include "stkr_user.h"
#include <file_io.h>

const char *master_device_port = "/dev/";
int get_buffer_values(int bufferMultiplySize) {
    // Multiply to get the correct storage data space
    int bufferValueSize = ((bufferMultiplySize^(2)) / 4096);
}

int buffer_values = (get_buffer_values(12) * 4096);

int main() {
    // Load UIDs and GIDs
    FILE *fp; open_file(master_device_port, "/etc/user/uid", &fp);
    char buffer[buffer_values]; fread(buffer, 1, sizeof(buffer)-1, fp); buffer[4195] = '\0'; fclose(fp);

    int uidParseResult = parse_uid_list(buffer);
}

void clear_user(struct userParams* user) {
    memset(user, 0, sizeof(struct userParams));
}

int extract_token(const char* src, int start, char delimiter, char* dest, int max_len) {
    int i = 0;
    while (src[start] != delimiter && src[start] != '\0' && i < max_len - 1) {
        dest[i++] = src[start++];
    }
    dest[i] = '\0';
    return src[start] == delimiter ? start + 1 : start;
}

int parse_uid_list(char uid_list[buffer_values]) {
    int pos = 0;
    userCount = 0;

    while (uid_list[pos] != '\0' && userCount < MAX_USERS) {
        struct userParams* user = &userList[userCount];
        clear_user(user);

        pos = extract_token(uid_list, pos, ':', user->userName, sizeof(user->userName));
        pos++; // skip "::"

        pos = extract_token(uid_list, pos, ':', user->UID, sizeof(user->UID));
        pos = extract_token(uid_list, pos, ':', user->GID, sizeof(user->GID));
        pos++; // skip "::"

        if (uid_list[pos] == '"') pos++;
        pos = extract_token(uid_list, pos, '"', user->homeDirectory, sizeof(user->homeDirectory));
        pos++; // skip ":"

        if (uid_list[pos] == '"') pos++;
        pos = extract_token(uid_list, pos, '"', user->shellExecutableDirectory, sizeof(user->shellExecutableDirectory));
        pos += 2; // skip "::"

        char perms[32] = {0};
        pos = extract_token(uid_list, pos, ':', perms, sizeof(perms));

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

        pos++; // skip ":"

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

        // Skip past "-\n"
        while (uid_list[pos] != '\n' && uid_list[pos] != '\0') pos++;
        if (uid_list[pos] == '\n') pos++;

        userCount++;
    }

    return userCount;
}
