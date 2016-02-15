/*
 * protobackend.h
 *
 *  Created on: 20150709
 *      Author: April
 */
#ifndef INCLUDE_PROTO_BACKEND_H_
#define INCLUDE_PROTO_BACKEND_H_

#include "common.h"

typedef enum {
	PackageType_OK = 0,      //authentication ok
	PackageType_KB = 2,      //kerberos v5
	PackageType_PLAN = 3,    //clear text password
	PackageType_CRYPT = 4,   //crypt password
	PackageType_MD5 = 5,     //md5
	PackageType_SCMC = 6     //SCMC
} PackageType;

//authentication ok message package.
typedef struct AuthPK{
	PackageHeadPK packageHead;//type:R,lenght:8
	PackageType   packageType;
	uint32_t      packageExtPara;//only valid when packageType > PackageTypePLan
}AuthPK;

//ssl response package
typedef struct SSLResponsePK{
	uint8_t byte;
}SSLResponsePK;

typedef struct RowData{
#define ROWNAMELENGTH 1024
	char rowName[ROWNAMELENGTH];
	uint32_t tableId;
	uint16_t rowId;
	uint32_t objectId;
	uint16_t rowLength;
	uint32_t typeAttribut;
	uint16_t format;
}RowData;
//RowDescription
typedef struct RowDescriptionPK{
	PackageHeadPK packageHead;
	uint16_t rowNum;
#define ROWNUM 1024
	RowData rowDescription[ROWNUM];
}RowDescriptionPK;

//ReadyForQuery package
typedef struct ReadyForQueryPK{
	PackageHeadPK packageHead;
	uint8_t backendStatus;
}ReadyForQueryPK;

//PortalSuspended
typedef struct PortalSuspendedPK{
	PackageHeadPK packageHead;
}PortalSuspendedPK;

//ParseComplete
typedef struct ParseCompletePK{
	PackageHeadPK packageHead;
}ParseCompletePK;

//ParameterStatus
typedef struct ParameterStatusPK{
	PackageHeadPK packageHead;
#define PARAMETERSTATUS_PARAMLENGTH 1024
	char paraName[PARAMETERSTATUS_PARAMLENGTH];
	char paraValue[PARAMETERSTATUS_PARAMLENGTH];
}ParameterStatusPK;

//ParameterDescription
typedef struct ParameterDescriptionPK{
	PackageHeadPK packageHead;
	uint16_t paramNum;
#define ParameterDescriptionPK_PARAMNUM 100
	uint32_t param[ParameterDescriptionPK_PARAMNUM];
}ParameterDescriptionPK;

//NotificationResponse
typedef struct NotificationResponsePK{
	PackageHeadPK packageHead;
	uint32_t pid;
#define NOTIFICATIONRESPONSEPK_STRINGLENGTH 1024
	char conditionName[NOTIFICATIONRESPONSEPK_STRINGLENGTH];
	char extMessage[NOTIFICATIONRESPONSEPK_STRINGLENGTH];
}NotificationResponsePK;

//NoticeResponse
typedef struct NoticeResponsePK{
	PackageHeadPK packageHead;
#define NOTICERESPONSE_NUM 100
	NoticeData  noticeData[NOTICERESPONSE_NUM];
}NoticeResponsePK;

//NoData
typedef struct NoDataPK{
	PackageHeadPK packageHead;
}NoDataPK;

//FunctionCallResponse
typedef struct FunctionCallResponsePK{
	PackageHeadPK packageHead;
	uint32_t resultLength;
#define FUNCTIONCALLRESPONSEPK_RESULTLENGTH 100
	uint8_t resultValue[FUNCTIONCALLRESPONSEPK_RESULTLENGTH];
}FunctionCallResponsePK;

//ErrorResponse
typedef struct ErrorResponsePK{
	PackageHeadPK packageHead;
#define ERRORRESPONSEPK_NUM 100
	NoticeData errorMsg[ERRORRESPONSEPK_NUM];
}ErrorResponsePK;

//EmptyQueryResponse
typedef struct EmptyQueryResponsePK{
	PackageHeadPK packageHead;
}EmptyQueryResponsePK;

//DataRow
typedef struct ColData{
	uint32_t valueLen;
#define COLDATA_LENGTH 1024
	uint8_t data[COLDATA_LENGTH];
}ColData;
typedef struct DataRowPK{
	PackageHeadPK packageHead;
	uint16_t colNum;
#define DATAROWPK_COLNUM 100
	ColData colData[DATAROWPK_COLNUM];
}DataRowPK;

//BackendKeyData
typedef struct BackendKeyDataPK{
	PackageHeadPK packageHead;
	uint32_t pid;
	uint32_t secketKey;
}BackendKeyDataPK;

//BindComplete
typedef struct BindCompletePK{
	PackageHeadPK packageHead;
}BindCompletePK;

//CloseComplete
typedef struct CloseCompletepK{
	PackageHeadPK packageHead;
}CloseCompletePK;

//CommandComplete
typedef struct CommandCompletePK{
	PackageHeadPK packageHead;
#define COMMANDCOMPLETEPK_COMANDLENGTH 1024
	char command[COMMANDCOMPLETEPK_COMANDLENGTH];
}CommandCompletePK;

typedef struct CopyDescription{
	PackageHeadPK packageHead;
	uint8_t type;
	uint16_t colNum;
#define COPYDESCRIPTION_COLNUM 100
	uint16_t colFmt[COPYDESCRIPTION_COLNUM];
}CopyDescription;
//CopyInResponse
typedef struct CopyInResponsePK{
	CopyDescription copyDescription;
}CopyInResponsePK;

//CopyOutResponse
typedef struct CopyOutResponsePK{
	CopyDescription copyDescription;
}CopyOutResponsePK;

int parse_backEndPackage(void *data, int len);
int parse_authPK(PackageHeadPK* pHeadPK, AuthPK* pAuthPK, struct MBuf *buf);
int parse_sslResponsePK(struct MBuf *buf, SSLResponsePK* pResponsePK);
int parse_backendKeyDataPK(PackageHeadPK* pHeadPK,
		BackendKeyDataPK* pBackendKeyDataPK, struct MBuf *buf);
int parse_rowDescriptionPK(PackageHeadPK* pHeadPK,
		RowDescriptionPK* pRowDescriptionPK, struct MBuf *buf);
int parse_readyForQueryPK(PackageHeadPK* pHeadPK,
		ReadyForQueryPK* pReadyForQueryPK, struct MBuf *buf);
int parse_portalSuspendedPK(PackageHeadPK* pHeadPK,
		PortalSuspendedPK* pPortalSuspendedPK, struct MBuf *buf);
int parse_parseCompletePK(PackageHeadPK* pHeadPK,
		ParseCompletePK* pParseCompletePK, struct MBuf *buf);
int parse_parameterStatusPK(PackageHeadPK* pHeadPK,
		ParameterStatusPK* pParameterStatusPK, struct MBuf *buf);
int parse_parameterDescriptionPK(PackageHeadPK* pHeadPK,
		ParameterDescriptionPK* pParameterDescriptionPK, struct MBuf *buf);
int parse_notificationResponsePK(PackageHeadPK* pHeadPK,
		NotificationResponsePK* pNotificationResponsePK, struct MBuf *buf);
int parse_noticeResponsePK(PackageHeadPK* pHeadPK, NoticeResponsePK* pNoticeResponsePK,
		struct MBuf *buf);
int parse_noDataPK(PackageHeadPK* pHeadPK, NoDataPK* pNoDataPK, struct MBuf *buf);
int parse_functionCallResponsePK(PackageHeadPK* pHeadPK,
		FunctionCallResponsePK* pFunctionCallResponsePK, struct MBuf *buf);
int parse_errorResponsePK(PackageHeadPK* pHeadPK,
		ErrorResponsePK* pErrorResponsePK, struct MBuf *buf);
int parse_emptyQueryResponsePK(PackageHeadPK* pHeadPK,
		EmptyQueryResponsePK* pEmptyQueryResponsePK, struct MBuf *buf);
int parse_dataRowPK(PackageHeadPK* pHeadPK, DataRowPK* pDataRowPK, struct MBuf *buf);
int parse_copyOutResponsePK(PackageHeadPK* pHeadPK, CopyOutResponsePK* pCopyOutResponsePK, struct MBuf* buf);
int parse_copyInResponsePK(PackageHeadPK* pHeadPK, CopyInResponsePK* pCopyInResponsePK, struct MBuf* buf);
int parse_commandCompletePK(PackageHeadPK* pHeadPK, CommandCompletePK* pCommandCompletePK, struct MBuf* buf);
int parse_closeCompletePK(PackageHeadPK* pHeadPK, CloseCompletePK* pCloseCompletePK, struct MBuf* buf);
int parse_bindCompletePK(PackageHeadPK* pHeadPK, BindCompletePK* pBindCompletePK, struct MBuf* buf);


#endif

