/*
 * protofrontend.h
 *
 *  Created on: 20150709
 *      Author: April
 */

#ifndef INCLUDE_PROTO_FRONTEND_H_
#define INCLUDE_PROTO_FRONTEND_H_

#include "common.h"

//ssl Request package
typedef struct SSLRequestPK{
	PackageHeadPK packageHead;
}SSLRequestPK;

typedef struct ParameterPair{
#define PARAMLENGTH 1024
	char key[PARAMLENGTH];
	char val[PARAMLENGTH];
	struct ParameterPair *next;
}ParameterPair;

//StartupMessage
typedef struct StartupMessagePK
{
	uint32_t length;
	uint32_t version;
	ParameterPair *head;
}StartupMessagePK;

//PasswordMessage
typedef struct PasswordMessagePK{
#define PASSWORDLENGTH 1024
	PackageHeadPK packageHeadPK;
	char password[PASSWORDLENGTH];
}PasswordMessagePK;

//Terminal package
typedef struct TerminatePK{
	PackageHeadPK packageHead;
}TerminatePK;

//Sync message
typedef struct SyncPK{
	PackageHeadPK packageHead;
}SyncPK;

//Query package
typedef struct QueryPK{
	PackageHeadPK packageHead;
#define QUERYSTRINGLENGTH 1024
	char queryStr[QUERYSTRINGLENGTH];
}QueryPK;

//Parse
typedef struct ParsePK{
#define PARSENAMELENGTH 1024
#define PARSESTRINGLENGTH 1024
#define PARSEPARANUM 100
	PackageHeadPK packageHead;
	char name[PARSENAMELENGTH];
	char queryStr[PARSESTRINGLENGTH];
	uint16_t paramNum;
	uint32_t paramId[PARSEPARANUM];
}ParsePK;

//Flush
typedef struct FlushPK{
	PackageHeadPK packageHead;
}FlushPK;

//Execute
typedef struct ExecutePK{
	PackageHeadPK packageHead;
#define EXECUTEPK_NAMELENGTH 1024
	char entryName[EXECUTEPK_NAMELENGTH];
	uint32_t maxRow;
}ExecutePK;

//Describe
typedef struct DescribePK{
	PackageHeadPK packageHead;
	uint8_t type;
#define DESCRIBEPK_NAMELENGTH 1024
	char string[DESCRIBEPK_NAMELENGTH];
}DescribePK;

//Bind
typedef struct BindPK{
	PackageHeadPK packageHead;
#define BINDPK_ENTRYLENGTH 100
	char dstEntry[BINDPK_ENTRYLENGTH];
#define BINDPK_PREPARESTRLENGTH 1024
	char prepareStr[BINDPK_PREPARESTRLENGTH];
	uint16_t fmtNum;
#define BINDPK_PARAMNUM 100
	uint16_t paratFmt[BINDPK_PARAMNUM];
	uint16_t paramValNum;
	DataPair paramVal[BINDPK_PARAMNUM];
#define BINDPK_RESULTNUM 100
	uint16_t resultFmtNum;
	uint16_t resultFmt[BINDPK_RESULTNUM];
}BindPK;

//CancelRequest
typedef struct CancelRequestPK{
	PackageHeadPK packageHead;
	uint32_t pid;
	uint32_t secketKey;
}CancelRequestPK;

//Close
typedef struct ClosePK{
	PackageHeadPK packageHead;
	uint8_t type;
#define CLOSEPK_STRINGLENGTH 1024
	char prepareStr[CLOSEPK_STRINGLENGTH];
}ClosePK;

//CopyFail
typedef struct CopyFailPK{
	PackageHeadPK packageHead;
#define COPYFAILPK_STRINGLENGTH 1024
	char result[COPYFAILPK_STRINGLENGTH];
}CopyFailPK;

//FunctionCall
typedef struct FunctionCallPK{
	PackageHeadPK packageHead;
	uint32_t functionObjId;
	uint16_t paraFmtNum;
#define FUNCTIONCALLPK_PARAMNUM 20
	uint16_t paraFmt[FUNCTIONCALLPK_PARAMNUM];
	uint16_t paraNum;
	DataPair para[FUNCTIONCALLPK_PARAMNUM];
	uint16_t functionResultFmt;
}FunctionCallPK;

int parse_frontEndPackage(void *data, int len);

int parse_sslRequestPK(PackageHeadPK* pHeadPK, SSLRequestPK* pSSLRequestPK, struct MBuf *buf);

int parse_startupMessagePK(PackageHeadPK* pHeadPK, StartupMessagePK* pStartUpMessagePK, struct MBuf *buf);

int parse_passwordMessagePK(PackageHeadPK* pHeadPK, PasswordMessagePK* pPasswordMessagePK, struct MBuf *buf);

int parse_terminatePK(PackageHeadPK* pHeadPK, TerminatePK* pTerminalMessagePK, struct MBuf *buf);

int parse_syncPK(PackageHeadPK* pHeadPK, SyncPK* pSyncMessagePK, struct MBuf *buf);

int parse_queryPK(PackageHeadPK* pHeadPK, QueryPK* pQueryPK, struct MBuf *buf);

int parse_parsePK(PackageHeadPK* pHeadPK, ParsePK* pParsePK, struct MBuf *buf);

int parse_flushPK(PackageHeadPK* pHeadPK, FlushPK* pFlushPK, struct MBuf* buf);

int parse_executePK(PackageHeadPK* pHeadPK, ExecutePK* pExecutePK, struct MBuf* buf);

int parse_describePK(PackageHeadPK* pHeadPK, DescribePK* pDescribePK, struct MBuf* buf);

int parse_bindPK(PackageHeadPK* pHeadPK, BindPK* pBindPK, struct MBuf* buf);

int parse_cancelRequestPK(PackageHeadPK* pHeadPK, CancelRequestPK* pCancelRequestPK, struct MBuf* buf);

int parse_closePK(PackageHeadPK* pHeadPK, ClosePK* pClosePK, struct MBuf* buf);

int parse_copyFailPK(PackageHeadPK* pHeadPK, CopyFailPK* pCopyFailPK, struct MBuf* buf);

int parse_functionCallPK(PackageHeadPK* pHeadPK, FunctionCallPK* pFunctionCallPK, struct MBuf* buf);
#endif
