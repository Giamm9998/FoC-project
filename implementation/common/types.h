#ifndef types_h
#define types_h

typedef unsigned char uchar;
typedef unsigned short ushort;
typedef unsigned int uint;

typedef char mtype;
typedef uint seqnum;
typedef ushort flen;

enum mtypes {
    // Authentication
    AuthStart,
    AuthServerAns,
    AuthClientAns,

    // Upload
    UploadReq,
    UploadAns,
    UploadChunk,
    UploadEnd,
    UploadRes,

    // Download
    DownloadReq,
    DownloadChunk,
    DownloadEnd,

    // Delete
    DeleteReq,
    DeleteConfirm,
    DeleteAns,
    DeleteRes,

    // List
    ListReq,
    ListAns,

    // Rename
    RenameReq,
    RenameAns,

    // Logout
    LogoutReq,
    LogoutAns,

    // Generic error
    Error
};

#endif
