#ifndef STKR_USER_H
#define STKR_USER_H

#define MAX_USERS 65536

struct userParams {
    char userName[128];
    char UID[8];
    char GID[8];
    char homeDirectory[512];
    char shellExecutableDirectory[1024];
    char canRead[1];
    char canWrite[1];
    char canExecute[1];
    char canUseShell[1];
    char isAdmin[1];
    char canMount[1];
    char canNetwork[1];
    char deviceAccessEnabled[1];
    char logAccessEnabled[1];
    char timeManagmentEnabled[1];
    char configManageRights[1];
    char bootParamManagment[1];
    char userManagment[1];
    char dirAccess[1024];
};

// Externally accessible global user array
extern struct userParams userList[MAX_USERS];
extern int userCount;

#endif // STKR_USER_H
