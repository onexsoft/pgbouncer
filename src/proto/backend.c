/*
 * protobackend.c
 *
 *  Created on: 201579
 *      Author: April
 */

#include "bouncer.h"

int parse_authPK(PackageHeadPK* pHeadPK, AuthPK* pAuthPK, struct MBuf *buf)
{
	
	uint32_t packageType32;
	uint16_t ext16Data = 0;
	uint32_t ext32Data = 0;

	if (valid_inputParameter(pHeadPK, pAuthPK, buf, 'R'))
	{
		log_error("input parameter have errors\n");
		return -1;
	}

	if (skipPackageHeader(buf,skip_pacakge_type_length))
	{
		log_error("skip package header error\n");
		return -1;
	}

	if (!mbuf_get_uint32be(buf, &packageType32))
	{
		log_debug("call mbuf_get_uint32be error\n");
		return -1;
	}

	if (packageType32 == PackageType_CRYPT && !mbuf_get_uint16be(buf, &ext16Data))
	{
		log_debug("parse authentication crypt password salt error\n");
		return -1;
	}

	if ((packageType32 == PackageType_MD5 || packageType32 == PackageType_SCMC)
			&& !mbuf_get_uint32be(buf, &ext32Data))
	{
		log_debug("parse AuthenticationMD5Password or AuthenticationSCMCredential error\n");
		return -1;
	}

	copy_packageHeader(&(pAuthPK->packageHead), pHeadPK);
	pAuthPK->packageType        = packageType32;
	pAuthPK->packageExtPara     = 0;
	if (packageType32 == PackageType_CRYPT) {
		pAuthPK->packageExtPara = ext16Data;
	} else if (packageType32 == PackageType_MD5 || packageType32 == PackageType_SCMC) {
		pAuthPK->packageExtPara = ext32Data;
	}

	return 0;
}

int parse_sslResponsePK(struct MBuf *buf, SSLResponsePK* pResponsePK)
{
	uint8_t byte;

	if (!buf || !pResponsePK)
	{
		log_error("buf is null or pResponsePK is null\n");
		return -1;
	}

	if (mbuf_avail_for_read(buf) == 1)
	{
		if (!mbuf_get_byte(buf, &byte))
		{
			log_error("mbuf_get_byte error\n");
			return -1;
		}

		if (byte == 'N' || byte == 'S')
		{
			pResponsePK->byte = byte;
			log_debug("get sslResponse package, byte: %c\n", pResponsePK->byte);
			return 0;
		}
	}
	return -1;
}

int parse_backendKeyDataPK(PackageHeadPK* pHeadPK, BackendKeyDataPK* pBackendKeyDataPK, struct MBuf *buf)
{
	
	uint32_t data32;

	if (valid_inputParameter(pHeadPK, pBackendKeyDataPK, buf, 'K'))
	{
		log_error("input parameter have errors\n");
		return -1;
	}

	if (skipPackageHeader(buf,skip_pacakge_type_length))
	{
		log_error("skip package header error\n");
		return -1;
	}

	copy_packageHeader(&(pBackendKeyDataPK->packageHead), pHeadPK);

	if (!mbuf_get_uint32be(buf, &data32))
	{
		log_error("read pid error\n");
		return -1;
	}
	pBackendKeyDataPK->pid = data32;

	if (!mbuf_get_uint32be(buf, &data32))
	{
		log_error("read secket key error\n");
		return -1;
	}
	pBackendKeyDataPK->secketKey = data32;

	return 0;
}


int parse_rowDescriptionPK(PackageHeadPK* pHeadPK, RowDescriptionPK* pRowDescriptionPK, struct MBuf *buf)
{
	
	uint32_t data32;
	uint16_t data16;
	uint32_t currRow;
	const char *rowName;
	uint32_t rowNameLen;

	if (valid_inputParameter(pHeadPK, pRowDescriptionPK, buf, 'T'))
	{
		log_error("input parameter have errors\n");
		return -1;
	}

	if (skipPackageHeader(buf,skip_pacakge_type_length))
	{
		log_error("skip package header error\n");
		return -1;
	}

	copy_packageHeader(&(pRowDescriptionPK->packageHead), pHeadPK);

	if (!mbuf_get_uint16be(buf, &data16))
	{
		log_error("read the number of row error\n");
		return -1;
	}
	pRowDescriptionPK->rowNum = data16;
	if (pRowDescriptionPK->rowNum > ROWNUM)
	{
		log_error("no more memory to save row comment, rowNum: %d, ROWNUM: %d\n", pRowDescriptionPK->rowNum, ROWNUM);
		return -1;
	}

	currRow = 0;
	rowName = NULL;
	while(currRow < pRowDescriptionPK->rowNum)
	{
		if(!mbuf_get_string(buf, &rowName) && *rowName == 0)
		{
			log_error("get row name error\n");
			return -1;
		}
		rowNameLen = (strlen(rowName) + 1) > ROWNAMELENGTH ? ROWNAMELENGTH : strlen(rowName) + 1;
		memcpy(pRowDescriptionPK->rowDescription[currRow].rowName, rowName, rowNameLen);

		if(!(mbuf_get_uint32be(buf, &data32)))
		{
			log_error("get table id error\n");
			return -1;
		}
		pRowDescriptionPK->rowDescription[currRow].tableId = data32;

		if (!(mbuf_get_uint16be(buf, &data16)))
		{
			log_error("get row attribute\n");
			return -1;
		}
		pRowDescriptionPK->rowDescription[currRow].rowId = data16;

		if (!(mbuf_get_uint32be(buf, &data32)))
		{
			log_error("get row object id\n");
			return -1;
		}
		pRowDescriptionPK->rowDescription[currRow].objectId = data32;

		if (!(mbuf_get_uint16be(buf, &data16)))
		{
			log_error("get data type length error\n");
			return -1;
		}
		pRowDescriptionPK->rowDescription[currRow].rowLength = data16;

		if (!(mbuf_get_uint32be(buf, &data32)))
		{
			log_error("get row attribute error\n");
			return -1;
		}
		pRowDescriptionPK->rowDescription[currRow].typeAttribut = data32;

		if (!(mbuf_get_uint16be(buf, &data16)))
		{
			log_error("get data type length error\n");
			return -1;
		}
		pRowDescriptionPK->rowDescription[currRow].format = data16;
		currRow ++;
	}

	return 0;
}

int parse_readyForQueryPK(PackageHeadPK* pHeadPK, ReadyForQueryPK* pReadyForQueryPK, struct MBuf *buf)
{
	
	uint8_t  data8;

	if (valid_inputParameter(pHeadPK, pReadyForQueryPK, buf, 'Z'))
	{
		log_error("input parameter have errors\n");
		return -1;
	}

	if (skipPackageHeader(buf,skip_pacakge_type_length))
	{
		log_error("skip package header error\n");
		return -1;
	}

	copy_packageHeader(&(pReadyForQueryPK->packageHead), pHeadPK);

	if (!mbuf_get_byte(buf, &data8))
	{
		log_error("read pid error\n");
		return -1;
	}
	pReadyForQueryPK->backendStatus = data8;

	return 0;
}

int parse_portalSuspendedPK(PackageHeadPK* pHeadPK, PortalSuspendedPK* pPortalSuspendedPK, struct MBuf *buf)
{
	
	return pPortalSuspendedPK == NULL ? -1 :
			parse_onlyPackageHeadPK(&(pPortalSuspendedPK->packageHead), pHeadPK, 's');
}

int parse_parseCompletePK(PackageHeadPK* pHeadPK, ParseCompletePK* pParseCompletePK, struct MBuf *buf)
{

	
	return pParseCompletePK == NULL ? -1 :
			parse_onlyPackageHeadPK(&(pParseCompletePK->packageHead), pHeadPK, 1);
}

int parse_parameterStatusPK(PackageHeadPK* pHeadPK, ParameterStatusPK* pParameterStatusPK, struct MBuf *buf)
{
	
	const char *str;

	if (valid_inputParameter(pHeadPK, pParameterStatusPK, buf, 'S'))
	{
		log_error("input parameter have errors\n");
		return -1;
	}

	if (skipPackageHeader(buf,skip_pacakge_type_length))
	{
		log_error("skip package header error\n");
		return -1;
	}

	copy_packageHeader(&(pParameterStatusPK->packageHead), pHeadPK);

	if (!mbuf_get_string(buf, &str) || *str == 0)
	{
		log_error("read param name error\n");
		return -1;
	}
	if (strlen(str) + 1 > PARAMETERSTATUS_PARAMLENGTH)
	{
		log_error("no more memeory to save param name\n");
		return -1;
	}
	memcpy(pParameterStatusPK->paraName, str, strlen(str) + 1);

	if (!mbuf_get_string(buf, &str))
	{
		log_error("read param value error\n");
		return -1;
	}
	if (*str == 0)
	{
		return 0;
	}

	if (strlen(str) + 1 > PARAMETERSTATUS_PARAMLENGTH)
	{
		log_error("no more memeory to save param value\n");
		return -1;
	}
	memcpy(pParameterStatusPK->paraValue, str, strlen(str) + 1);

	return 0;
}

int parse_parameterDescriptionPK(PackageHeadPK* pHeadPK, ParameterDescriptionPK* pParameterDescriptionPK, struct MBuf *buf)
{
	
	uint32_t data32;
	uint16_t data16;
	uint32_t loop = 0;

	if (valid_inputParameter(pHeadPK, pParameterDescriptionPK, buf, 't'))
	{
		log_error("input parameter have errors\n");
		return -1;
	}

	if (skipPackageHeader(buf,skip_pacakge_type_length))
	{
		log_error("skip package header error\n");
		return -1;
	}

	copy_packageHeader(&(pParameterDescriptionPK->packageHead), pHeadPK);

	if (!mbuf_get_uint16be(buf, &data16))
	{
		log_error("read param num error\n");
		return -1;
	}
	pParameterDescriptionPK->paramNum = data16;
	if (pParameterDescriptionPK->paramNum > ParameterDescriptionPK_PARAMNUM)
	{
		log_error("no more memory to save parameter type");
		return -1;
	}

	loop = 0;
	while(loop < pParameterDescriptionPK->paramNum)
	{
		if (!mbuf_get_uint32be(buf, &data32))
		{
			log_error("read param type error\n");
			return -1;
		}
		pParameterDescriptionPK->param[loop ++] = data32;
	}

	return 0;
}

int parse_notificationResponsePK(PackageHeadPK* pHeadPK, NotificationResponsePK* pNotificationResponsePK, struct MBuf *buf)
{
	
	uint32_t data32;
	const char *str;

	if (valid_inputParameter(pHeadPK, pNotificationResponsePK, buf, 'A'))
	{
		log_error("input parameter have errors\n");
		return -1;
	}

	if (skipPackageHeader(buf,skip_pacakge_type_length))
	{
		log_error("skip package header error\n");
		return -1;
	}

	copy_packageHeader(&(pNotificationResponsePK->packageHead), pHeadPK);

	if (!mbuf_get_uint32be(buf, &data32))
	{
		log_error("read pid error\n");
		return -1;
	}
	pNotificationResponsePK->pid = data32;

	if (!mbuf_get_string(buf, &str) || *str == 0)
	{
		log_error("read condition name error\n");
		return -1;
	}
	if (strlen(str) + 1 > NOTIFICATIONRESPONSEPK_STRINGLENGTH)
	{
		log_error("no more memeory to save condition name\n");
		return -1;
	}
	memcpy(pNotificationResponsePK->conditionName, str, strlen(str) + 1);

	if (!mbuf_get_string(buf, &str) || *str == 0)
	{
		log_error("read ext data error\n");
		return -1;
	}
	if (strlen(str) + 1 > NOTIFICATIONRESPONSEPK_STRINGLENGTH)
	{
		log_error("no more memeory to save ext data\n");
		return -1;
	}
	memcpy(pNotificationResponsePK->extMessage, str, strlen(str) + 1);

	return 0;
}

int parse_noticeResponsePK(PackageHeadPK* pHeadPK, NoticeResponsePK* pNoticeResponsePK, struct MBuf *buf)
{
	
	uint8_t  data8;
	const char *str;
	uint32_t loop = 0;

	if (valid_inputParameter(pHeadPK, pNoticeResponsePK, buf, 'N'))
	{
		log_error("input parameter have errors\n");
		return -1;
	}

	if (skipPackageHeader(buf,skip_pacakge_type_length))
	{
		log_error("skip package header error\n");
		return -1;
	}

	copy_packageHeader(&(pNoticeResponsePK->packageHead), pHeadPK);

	loop = 0;
	while(1)
	{
		if (loop >= NOTICERESPONSE_NUM)
		{
			log_error("no memeory to save message\n");
			return -1;
		}

		pNoticeResponsePK->noticeData[loop].messageType = 0;
		if (!mbuf_get_byte(buf, &data8))
		{
			log_error("read messageType error\n");
			return -1;
		}
		if (data8 == 0)
		{
			log_debug("finished parse message\n");
			return 0;
		}
		pNoticeResponsePK->noticeData[loop].messageType = data8;

		if(!mbuf_get_string(buf, &str))
		{
			log_error("read message error\n");
			return -1;
		}
		if (strlen(str) + 1 > NOTICEDATA_MESSAGELENGTH)
		{
			log_error("no memory to save message\n");
			return -1;
		}
		memcpy(pNoticeResponsePK->noticeData[loop ++].message, str, strlen(str) + 1);
	}

	return 0;
}

int parse_noDataPK(PackageHeadPK* pHeadPK, NoDataPK* pNoDataPK, struct MBuf *buf)
{
	
	return pNoDataPK == NULL ? -1 :
			parse_onlyPackageHeadPK(&(pNoDataPK->packageHead), pHeadPK, PKT_SSLREQ);
}

int parse_functionCallResponsePK(PackageHeadPK* pHeadPK, FunctionCallResponsePK* pFunctionCallResponsePK, struct MBuf *buf)
{
	
	uint32_t data32;
	const uint8_t* pData;

	if (valid_inputParameter(pHeadPK, pFunctionCallResponsePK, buf, 'V'))
	{
		log_error("input parameter have errors\n");
		return -1;
	}

	if (skipPackageHeader(buf,skip_pacakge_type_length))
	{
		log_error("skip package header error\n");
		return -1;
	}

	copy_packageHeader(&(pFunctionCallResponsePK->packageHead), pHeadPK);

	if(!mbuf_get_uint32be(buf, &data32))
	{
		log_error("read result error\n");
		return -1;
	}
	pFunctionCallResponsePK->resultLength = data32;

	if (pFunctionCallResponsePK->resultLength <= 0)
	{
		log_debug("finished read function result\n");
		return 0;
	}
	if (pFunctionCallResponsePK->resultLength > FUNCTIONCALLRESPONSEPK_RESULTLENGTH)
	{
		log_error("too more function result ,no memory to save\n");
		return -1;
	}

	if (!mbuf_get_bytes(buf, pFunctionCallResponsePK->resultLength, &pData))
	{
		log_error("read function result error\n");
		return -1;
	}
	memcpy(pFunctionCallResponsePK->resultValue, pData, pFunctionCallResponsePK->resultLength);

	return 0;
}

int parse_errorResponsePK(PackageHeadPK* pHeadPK, ErrorResponsePK* pErrorResponsePK, struct MBuf *buf)
{
	
	uint8_t  data8;
	const char *str;
	uint32_t loop = 0;

	if (valid_inputParameter(pHeadPK, pErrorResponsePK, buf, 'e'))
	{
		log_error("input parameter have errors\n");
		return -1;
	}

	if (skipPackageHeader(buf,skip_pacakge_type_length))
	{
		log_error("skip package header error\n");
		return -1;
	}

	copy_packageHeader(&(pErrorResponsePK->packageHead), pHeadPK);

	loop = 0;
	while(1)
	{
		if (loop >= NOTICERESPONSE_NUM)
		{
			log_error("no memeory to save message\n");
			return -1;
		}

		pErrorResponsePK->errorMsg[loop].messageType = 0;
		if (!mbuf_get_byte(buf, &data8))
		{
			log_error("read messageType error\n");
			return -1;
		}
		if (data8 == 0)
		{
			log_debug("finished parse message\n");
			return 0;
		}
		pErrorResponsePK->errorMsg[loop].messageType = data8;

		if(!mbuf_get_string(buf, &str))
		{
			log_error("read message error\n");
			return -1;
		}
		if (strlen(str) + 1 > NOTICEDATA_MESSAGELENGTH)
		{
			log_error("no memory to save message\n");
			return -1;
		}
		memcpy(pErrorResponsePK->errorMsg[loop ++].message, str, strlen(str) + 1);
	}

	return 0;
}

int parse_emptyQueryResponsePK(PackageHeadPK* pHeadPK, EmptyQueryResponsePK* pEmptyQueryResponsePK, struct MBuf *buf)
{
	
	return pEmptyQueryResponsePK == NULL ? -1 :
			parse_onlyPackageHeadPK(&(pEmptyQueryResponsePK->packageHead), pHeadPK, PKT_SSLREQ);
}

int parse_dataRowPK(PackageHeadPK* pHeadPK, DataRowPK* pDataRowPK, struct MBuf *buf)
{
	
	uint32_t data32;
	uint16_t data16;
	uint32_t loop = 0;
	const uint8_t* pData;

	if (valid_inputParameter(pHeadPK, pDataRowPK, buf, 'D'))
	{
		log_error("input parameter have errors\n");
		return -1;
	}

	if (skipPackageHeader(buf,skip_pacakge_type_length))
	{
		log_error("skip package header error\n");
		return -1;
	}

	copy_packageHeader(&(pDataRowPK->packageHead), pHeadPK);

	if (!mbuf_get_uint16be(buf, &data16))
	{
		log_error("read col num error\n");
		return -1;
	}
	pDataRowPK->colNum = data16;

	loop = 0;
	while(loop < pDataRowPK->colNum)
	{
		if (!mbuf_get_uint32be(buf, &data32))
		{
			log_error("read col length error\n");
			return -1;
		}
		pDataRowPK->colData[loop].valueLen = data32;
		if (data32 <= 0){
			loop ++;
			continue;
		}

		if (data32 > COLDATA_LENGTH)
		{
			log_error("no more memory to save col value\n");
			return -1;
		}

		pData = NULL;
		if ((mbuf_get_bytes(buf, data32, &pData)))
		{
			log_error("read col value error\n");
			return -1;
		}
		memcpy(pDataRowPK->colData[loop].data, pData, data32);
		++ loop;
	}

	return 0;
}

static int parse_copyResponsePK(PackageHeadPK* pHeadPK,
		CopyDescription* pCopyDescription, struct MBuf* buf, uint32_t commandSignal)
{
	
	uint8_t data8;
	uint16_t data16;
	int16_t count = 0;

	if (valid_inputParameter(pHeadPK, pCopyDescription, buf, commandSignal))
	{
		log_error("input parameter have error\n");
		return -1;
	}

	if (skipPackageHeader(buf,skip_pacakge_type_length))
	{
		log_error("skip package header error\n");
		return -1;
	}

	copy_packageHeader(&(pCopyDescription->packageHead), pHeadPK);

	if (!mbuf_get_byte(buf, &data8))
	{
		log_error("read copy data format error\n");
		return -1;
	}
	pCopyDescription->type = data8;

	if (!mbuf_get_uint16be(buf, &data16))
	{
		log_error("read copy data column num error\n");
		return -1;
	}
	pCopyDescription->colNum = data16;

	if(pCopyDescription->colNum > COPYDESCRIPTION_COLNUM)
	{
		log_error("read column format error\n");
		return -1;
	}
	count = 0;
	while(count < pCopyDescription->colNum)
	{
		if (!mbuf_get_uint16be(buf, &data16))
		{
			log_error("read column fmt error \n");
			return -1;
		}
		pCopyDescription->colFmt[count++] = data16;
	}

	return 0;

}
int parse_copyOutResponsePK(PackageHeadPK* pHeadPK, CopyOutResponsePK* pCopyOutResponsePK, struct MBuf* buf)
{
	
	return pCopyOutResponsePK == NULL_VAL ? -1 :
			parse_copyResponsePK(pHeadPK, &(pCopyOutResponsePK->copyDescription), buf, 'H');
}

int parse_copyInResponsePK(PackageHeadPK* pHeadPK, CopyInResponsePK* pCopyInResponsePK, struct MBuf* buf)
{
	
	return pCopyInResponsePK == NULL_VAL ? -1 :
			parse_copyResponsePK(pHeadPK, &(pCopyInResponsePK->copyDescription), buf, 'G');
}

int parse_commandCompletePK(PackageHeadPK* pHeadPK, CommandCompletePK* pCommandCompletePK, struct MBuf* buf)
{
	
	const char *src;

	if (valid_inputParameter(pHeadPK, pCommandCompletePK, buf, 'C'))
	{
		log_error("input parameter have error\n");
		return -1;
	}

	if (skipPackageHeader(buf,skip_pacakge_type_length))
	{
		log_error("skip package header error\n");
		return -1;
	}

	copy_packageHeader(&(pCommandCompletePK->packageHead), pHeadPK);

	if (!mbuf_get_string(buf, &src))
	{
		log_debug("finished read password \n");
		return -1;
	}
	if (strlen(src) + 1 > COMMANDCOMPLETEPK_COMANDLENGTH)
	{
		log_error("no more memory to save command mark\n");
		return -1;
	}
	memcpy(pCommandCompletePK->command, src, strlen(src) + 1);
	return 0;
}

int parse_closeCompletePK(PackageHeadPK* pHeadPK, CloseCompletePK* pCloseCompletePK, struct MBuf* buf)
{
	
	return pCloseCompletePK == NULL ? -1 :
			parse_onlyPackageHeadPK(&(pCloseCompletePK->packageHead), pHeadPK, PKT_SSLREQ);
}

int parse_bindCompletePK(PackageHeadPK* pHeadPK, BindCompletePK* pBindCompletePK, struct MBuf* buf)
{
	
	return pBindCompletePK == NULL ? -1 :
			parse_onlyPackageHeadPK(&(pBindCompletePK->packageHead), pHeadPK, 2);
}

int parse_backEndPackage(void *data, int len)
{	
	PackageHeadPK headPkt;
	struct MBuf buf;

	SSLResponsePK                           sslResponsePK;
	AuthPK                                  authPK;
	BackendKeyDataPK                        backendKeyDataPK;
	BindCompletePK                          bindCompletePK;
	CloseCompletePK                         closeCompletePK;
	CommandCompletePK                       commandCompletePK;
	CopyDataPK                              copyDataPK;
	CopyDonePK                              copyDonePK;
	CopyInResponsePK                        copyInResponsePK;
	CopyOutResponsePK                       copyOutResponsePK;
	DataRowPK                               dataRowPK;
	EmptyQueryResponsePK                    emptyQueryResponsePK;
	ErrorResponsePK                         errorResponsePK;
	FunctionCallResponsePK                  functionCallResponsePK;
	NoDataPK                                noDataPK;
	NoticeResponsePK                        noticeResponsePK;
	NotificationResponsePK                  notificationResponsePK;
	ParameterDescriptionPK                  parameterDescriptionPK;
	ParameterStatusPK                       parameterStatusPK;
	ParseCompletePK                         parseCompletePK;
	PortalSuspendedPK                       portalSuspendedPK;
	ReadyForQueryPK                         readyForQueryPK;
	RowDescriptionPK                        rowDescriptionPK;

	mbuf_init_fixed_reader(&buf, data, len);

	if(!parse_sslResponsePK(&buf, &sslResponsePK))
	{
		log_debug("sslResponsePK.type: %c\n",sslResponsePK.byte);
		return 0;
	}

	if(parse_pktHeader(&buf, &headPkt))
	{
		log_debug("parsePKTHeader error\n");
		return -1;
	}

	log_debug("type: %c , length: %d, is_new: %d\n", headPkt.type, headPkt.length, headPkt.is_new);
	switch(headPkt.type)
	{
		case 'R':
			log_debug("* start parse_authPK\n");
			if (parse_authPK(&headPkt, &authPK, &buf))
			{
				log_error("Err: parseAuthPk error\n");
				return -1;
			}
			print_authPK(authPK);
			break;

		case 'K':
			log_debug("* start parse_backendKeyDataPK\n");
			if (parse_backendKeyDataPK(&headPkt, &backendKeyDataPK, &buf))
			{
				log_error("Err: parse_backendKeyDataPk error\n");
				return -1;
			}
			print_backendKeyDataPK(backendKeyDataPK);
			break;
		case 2:
			log_debug("* start parse_bindCompletePK\n");
			if (parse_bindCompletePK(&headPkt, &bindCompletePK, &buf))
			{
				log_error("Err: parse_bindCompletePk error\n");
				return -1;
			}
			print_bindCompletePK(bindCompletePK);
			break;
		case 3:
			log_debug("* start parse_closeCompletePK\n");
			if (parse_closeCompletePK(&headPkt, &closeCompletePK, &buf))
			{
				log_error("Err: parse_closeCompletePk error\n");
				return -1;
			}
			print_closeCompletePK(closeCompletePK);
			break;
		case 'C':
			log_debug("* start parse_commandCompletePK\n");
			if (parse_commandCompletePK(&headPkt, &commandCompletePK, &buf))
			{
				log_error("Err: parse_commandCompletePk error\n");
				return -1;
			}
			print_commandCompletePK(commandCompletePK);
			break;
		case 'd':
			log_debug("* start parse_copyDataPK\n");
			if (parse_copyDataPK(&headPkt, &copyDataPK, &buf))
			{
				log_error("Err: parse_copyDataPk error\n");
				return -1;
			}
			print_copyDataPK(copyDataPK);
			break;
		case 'c':
			log_debug("* start parse_copyDonePK\n");
			if (parse_copyDonePK(&headPkt, &copyDonePK, &buf))
			{
				log_error("Err: parse_copyDonePk error\n");
				return -1;
			}
			print_copyDonePK(copyDonePK);
			break;
		case 'G':
			log_debug("* start parse_copyInResponsePK\n");
			if (parse_copyInResponsePK(&headPkt, &copyInResponsePK, &buf))
			{
				log_error("Err: parse_copyInResponsePk error\n");
				return -1;
			}
			print_copyInResponsePK(copyInResponsePK);
			break;
		case 'H':
			log_debug("* start parse_CopyOutResponsePK\n");
			if (parse_copyOutResponsePK(&headPkt, &copyOutResponsePK, &buf))
			{
				log_error("Err: parse_copyOutResponsePK error\n");
				return -1;
			}
			print_copyOutResponsePK(copyOutResponsePK);
			break;
		case 'D':
			log_debug("* start parse_dataRowPK\n");
			if (parse_dataRowPK(&headPkt, &dataRowPK, &buf))
			{
				log_error("Err: parse_dataRowPk error\n");
				return -1;
			}
			print_dataRowPK(dataRowPK);
			break;
		case 'I':
			log_debug("* start parse_emptyQueryResponsePK\n");
			if (parse_emptyQueryResponsePK(&headPkt, &emptyQueryResponsePK, &buf))
			{
				log_error("Err: parse_emptyQueryResponsePk error\n");
				return -1;
			}
			print_emptyQueryResponsePK(emptyQueryResponsePK);
			break;
		case 'E':
			log_debug("* start parse_errorResponsePK\n");
			if (parse_errorResponsePK(&headPkt, &errorResponsePK, &buf))
			{
				log_error("Err: parse_errorResponsePk error\n");
				return -1;
			}
			print_errorResponsePK(errorResponsePK);
			break;
		case 'V':
			log_debug("* start parse_functionCallResponsePK\n");
			if (parse_functionCallResponsePK(&headPkt, &functionCallResponsePK, &buf))
			{
				log_error("Err: parse_functionCallResponsePk error\n");
				return -1;
			}
			print_functionCallResponsePK(functionCallResponsePK);
			break;
		case 'n':
			log_debug("* start parse_noDataPK\n");
			if (parse_noDataPK(&headPkt, &noDataPK, &buf))
			{
				log_error("Err: parse_noDataPk error\n");
				return -1;
			}
			print_noDataPK(noDataPK);
			break;
		case 'N':
			log_debug("* start parse_noticeResponsePK\n");
			if (parse_noticeResponsePK(&headPkt, &noticeResponsePK, &buf))
			{
				log_error("Err: parse_noticeResponsePk error\n");
				return -1;
			}
			print_noticeResponsePK(noticeResponsePK);
			break;
		case 'A':
			log_debug("* start parse_notificationResponsePK\n");
			if (parse_notificationResponsePK(&headPkt, &notificationResponsePK, &buf))
			{
				log_error("Err: parse_notificationResponsePk error\n");
				return -1;
			}
			print_notificationResponsePK(notificationResponsePK);
			break;
		case 't':
			log_debug("* start parse_parameterDescriptionPK\n");
			if (parse_parameterDescriptionPK(&headPkt, &parameterDescriptionPK, &buf))
			{
				log_error("Err: parse_parameterDescriptionPk error\n");
				return -1;
			}
			print_parameterDescriptionPK(parameterDescriptionPK);
			break;
		case 'S':
			log_debug("* start parse_parameterStatusPK\n");
			if (parse_parameterStatusPK(&headPkt, &parameterStatusPK, &buf))
			{
				log_error("Err: parse_parameterStatusPk error\n");
				return -1;
			}
			print_parameterStatusPK(parameterStatusPK);
			break;
		case 1:
			log_debug("* start parse_parseCompletePK\n");
			if (parse_parseCompletePK(&headPkt, &parseCompletePK, &buf))
			{
				log_error("Err: parse_parseCompletePk error\n");
				return -1;
			}
			print_parseCompletePK(parseCompletePK);
			break;
		case 's':
			log_debug("* start parse_portalSuspendedPK\n");
			if (parse_portalSuspendedPK(&headPkt, &portalSuspendedPK, &buf))
			{
				log_error("Err: parse_portalSuspendedPk error\n");
				return -1;
			}
			print_portalSuspendedPK(portalSuspendedPK);
			break;
		case 'Z':
			log_debug("* start parse_readyForQueryPK\n");
			if (parse_readyForQueryPK(&headPkt, &readyForQueryPK, &buf))
			{
				log_error("Err: parse_readyForQueryPk error\n");
				return -1;
			}
			print_readyForQueryPK(readyForQueryPK);
			break;
		case 'T':
			log_debug("* start parse_rowDescriptionPK\n");
			if (parse_rowDescriptionPK(&headPkt, &rowDescriptionPK, &buf))
			{
				log_error("Err: parse_rowDescriptionPk error\n");
				return -1;
			}
			print_rowDescriptionPK(rowDescriptionPK);
			break;

		default:
			log_debug("the package is not sent from backend\n");
			break;
	}

	return 0;
}
