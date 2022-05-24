#ifndef types_h
#define types_h

typedef unsigned char uchar;
typedef unsigned short ushort;

typedef unsigned char mtype;
typedef unsigned int mlen;
typedef unsigned int seqnum;
typedef ushort flen;

#define SIZEOF_MLEN 3
#define MLEN_MAX ((1 << (SIZEOF_MLEN * 8)) - 1)

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
