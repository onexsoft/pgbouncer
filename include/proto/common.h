/*
 * common.h
 *
 *  Created on: 201579
 *      Author: April
 */

#ifndef INCLUDE_PROTO_COMMON_H_
#define INCLUDE_PROTO_COMMON_H_

#define NULL_VAL NULL

enum {
	skip_pacakge_length = -1,
	skip_pacakge_type_length = 0,
	skip_pacakge_length_requestcode = 1
};

typedef struct PackageHeadPK{
	uint32_t type; //package type
	uint32_t length; //package length,but not include type length
	bool     is_new; //true: new header format, false: old header format
}PackageHeadPK;

typedef struct NoticeData{
	uint8_t messageType;
#define NOTICEDATA_MESSAGELENGTH 1024
	char message[NOTICEDATA_MESSAGELENGTH];
}NoticeData;

typedef struct DataPair{
	uint32_t dataLen;
#define DATAPAIR_DATALENGTH 1024
	uint8_t data[DATAPAIR_DATALENGTH];
}DataPair;

//CopyData
typedef struct CopyDataPK{
	PackageHeadPK packageHead;
#define COPYDATA_DATALENGTH 2048
	uint8_t data[COPYDATA_DATALENGTH];
}CopyDataPK;

typedef struct CopyDonepK{
	PackageHeadPK packageHead;
}CopyDonePK;

int parse_pktHeader(const struct MBuf *pktBuf, PackageHeadPK *pkt);
int parse_onlyPackageHeadPK(PackageHeadPK* pDstHeadPK, PackageHeadPK* pSrcHeadPK,
		uint32_t commandSymbol);
int valid_inputParameter(PackageHeadPK* pHeadPK, void * pDstPackagePK,
		struct MBuf *mbuf, uint32_t commandSymbol);
int skipPackageHeader(struct MBuf *buf, int headType);
int parse_copyDataPK(PackageHeadPK* pHeadPK, CopyDataPK* pCopyDataPK, struct MBuf* buf);
int parse_copyDonePK(PackageHeadPK* pHeadPK, CopyDonePK* pCopyDonePK, struct MBuf* buf);

//copy package header
static inline void copy_packageHeader(PackageHeadPK *des, PackageHeadPK *src)
{
	des->is_new = src->is_new;
	des->length = src->length;
	des->type = src->type;
}

#endif /* INCLUDE_PROTO_COMMON_H_ */
