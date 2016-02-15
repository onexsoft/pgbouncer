/*
 * protofrontend.c
 *
 *  Created on: 20150709
 *      Author: April
 */

#include "bouncer.h"

int parse_sslRequestPK(PackageHeadPK* pHeadPK, SSLRequestPK* pSSLRequestPK, struct MBuf *buf)
{
	
	return pSSLRequestPK == NULL ? -1 :
			parse_onlyPackageHeadPK(&(pSSLRequestPK->packageHead), pHeadPK, PKT_SSLREQ);
}

int parse_startupMessagePK(PackageHeadPK* pHeadPK, StartupMessagePK* pStartUpMessagePK, struct MBuf *buf)
{
	
	uint32_t data32;
	const char *key, *value;
	ParameterPair* currParameterPair = NULL;
	int keyLen = 0, valueLen = 0;

	if (valid_inputParameter(pHeadPK, pStartUpMessagePK, buf, PKT_STARTUP))
	{
		log_error("input parameter have errors\n");
		return -1;
	}

	if (skipPackageHeader(buf, skip_pacakge_length))
	{
		log_error("skip package header error\n");
		return -1;
	}

	if (!mbuf_get_uint32be(buf, &data32))
	{
		log_error("get version error\n");
		return -1;
	}

	pStartUpMessagePK->version = data32;
	pStartUpMessagePK->length = pHeadPK->length;
	pStartUpMessagePK->head = NULL;

	log_debug("start parse parameter\n");
	while(1)
	{
		if (!mbuf_get_string(buf, &key) || *key == 0)
		{
			log_debug("finished read param \n");
			break;
		}
		if (!mbuf_get_string(buf, &value))
		{
			log_error("read param value error\n");
			return -1;
		}
		log_debug("key: %s, value: %s\n", key, value);
		keyLen = (strlen(key) + 1) > PARAMLENGTH ? PARAMLENGTH : (strlen(key) + 1);
		valueLen = (strlen(value) + 1) > PARAMLENGTH ? PARAMLENGTH : (strlen(value) + 1);

		if (currParameterPair == NULL)
		{
			currParameterPair = malloc(sizeof(ParameterPair));
			if (currParameterPair == NULL)
			{
				log_error("malloc ParameterPair error\n");
				return -1;
			}
			memcpy(currParameterPair->key, key, keyLen);
			memcpy(currParameterPair->val, value, valueLen);
			pStartUpMessagePK->head = currParameterPair;
		} else {
			currParameterPair->next = malloc(sizeof(ParameterPair));
			if (currParameterPair->next == NULL)
			{
				log_error("malloc ParameterPair next error\n");
				return -1;
			}
			currParameterPair = currParameterPair->next;
			memcpy(currParameterPair->key, key, keyLen);
			memcpy(currParameterPair->val, value, valueLen);
			currParameterPair->next = NULL;
		}
	}

	return 0;
}

int parse_passwordMessagePK(PackageHeadPK* pHeadPK, PasswordMessagePK* pPasswordMessagePK, struct MBuf *buf)
{
	
	const char *password;
	int passwordLen = 0;

	if (valid_inputParameter(pHeadPK, pPasswordMessagePK, buf, 'p'))
	{
		log_error("input parameter have error\n");
		return -1;
	}

	if (skipPackageHeader(buf,skip_pacakge_type_length))
	{
		log_error("skip package header error\n");
		return -1;
	}

	copy_packageHeader(&(pPasswordMessagePK->packageHeadPK), pHeadPK);

	if (!mbuf_get_string(buf, &password))
	{
		log_debug("finished read password \n");
		return -1;
	}
	passwordLen = (strlen(password) + 1) > PASSWORDLENGTH ? PASSWORDLENGTH : (strlen(password) + 1);
	memcpy(pPasswordMessagePK->password, password, passwordLen);
	return 0;
}

int parse_terminatePK(PackageHeadPK* pHeadPK, TerminatePK* pTerminalMessagePK, struct MBuf *buf)
{
	

	return pTerminalMessagePK == NULL_VAL ? -1 :
			parse_onlyPackageHeadPK(&(pTerminalMessagePK->packageHead), pHeadPK, 'X');
}

int parse_syncPK(PackageHeadPK* pHeadPK, SyncPK* pSyncMessagePK, struct MBuf *buf)
{
	

	return pSyncMessagePK == NULL_VAL ? -1 :
			parse_onlyPackageHeadPK(&(pSyncMessagePK->packageHead), pHeadPK, 'S');

}

int parse_queryPK(PackageHeadPK* pHeadPK, QueryPK* pQueryPK, struct MBuf *buf)
{
	
	const char *str;
	uint32_t strLen;

	if (valid_inputParameter(pHeadPK, pQueryPK, buf, 'Q'))
	{
		log_error("input parameter have error\n");
		return -1;
	}

	if (skipPackageHeader(buf,skip_pacakge_type_length))
	{
		log_error("skip package header error\n");
		return -1;
	}

	copy_packageHeader(&(pQueryPK->packageHead), pHeadPK);

	if (!mbuf_get_string(buf, &str))
	{
		log_error("read query string error\n");
		return -1;
	}
	strLen = (strlen(str) + 1) > QUERYSTRINGLENGTH ? QUERYSTRINGLENGTH : (strlen(str) + 1);
	memcpy(pQueryPK->queryStr, str, strLen);


	return 0;
}

int parse_parsePK(PackageHeadPK* pHeadPK, ParsePK* pParsePK, struct MBuf *buf)
{
	
	uint32_t data32;
	const char *str;
	uint16_t data16;
	uint32_t loop = 0;

	if (valid_inputParameter(pHeadPK, pParsePK, buf, 'P'))
	{
		log_error("input parameter have error\n");
		return -1;
	}

	if (skipPackageHeader(buf,skip_pacakge_type_length))
	{
		log_error("skip package header error\n");
		return -1;
	}

	copy_packageHeader(&(pParsePK->packageHead), pHeadPK);

	if (!mbuf_get_string(buf, &str) || *str == 0)
	{
		log_error("read prepare name error\n");
		return -1;
	}
	if (strlen(str) + 1 > PARSENAMELENGTH)
	{
		log_error("no memory to save prepare name error\n");
		return -1;
	}
	memcpy(pParsePK->name, str, strlen(str) + 1);

	if (!mbuf_get_string(buf, &str) || *str == 0)
	{
		log_error("read query string error\n");
		return -1;
	}
	if (strlen(str) + 1 > PARSESTRINGLENGTH)
	{
		log_error("no memory to save query string \n");
		return -1;
	}
	memcpy(pParsePK->queryStr, str, strlen(str) + 1);

	if (mbuf_avail_for_read(buf) < sizeof(uint16_t) || !mbuf_get_uint16be(buf, &data16))
	{
		log_error("read param num error\n");
		return -1;
	}
	pParsePK->paramNum = data16;
	if (pParsePK->paramNum > PARSEPARANUM)
	{
		log_error("no more memory to save parameter type");
		return -1;
	}

	loop = 0;
	while(loop < pParsePK->paramNum)
	{
		if (mbuf_avail_for_read(buf) < sizeof(uint32_t) || !mbuf_get_uint32be(buf, &data32))
		{
			log_error("read param type error\n");
			return -1;
		}
		pParsePK->paramId[loop++] = data32;
	}

	return 0;
}

int parse_flushPK(PackageHeadPK* pHeadPK, FlushPK* pFlushPK, struct MBuf *buf)
{
	

	return pFlushPK == NULL_VAL ? -1 :
				parse_onlyPackageHeadPK(&(pFlushPK->packageHead), pHeadPK, 'H');
}

int parse_executePK(PackageHeadPK* pHeadPK, ExecutePK* pExecutePK, struct MBuf *buf)
{
	
	const char *str;

	if (valid_inputParameter(pHeadPK, pExecutePK, buf, 'E'))
	{
		log_error("input parameter have error\n");
		return -1;
	}

	if (skipPackageHeader(buf,skip_pacakge_type_length))
	{
		log_error("skip package header error\n");
		return -1;
	}

	copy_packageHeader(&(pExecutePK->packageHead), pHeadPK);

	if (!mbuf_get_string(buf, &str))
	{
		log_error("no get string\n");
		return -1;
	}
	if (str != NULL && (strlen(str) + 1 > EXECUTEPK_NAMELENGTH))
	{
		log_error("no much memory to save entry name\n");
		return -1;
	}
	if (str != NULL)
	{
		memcpy(pExecutePK->entryName, str, strlen(str) + 1);
	}

	if (!mbuf_get_uint32be(buf, &(pExecutePK->maxRow)))
	{
		log_error("get max row error\n");
		return -1;
	}

	return 0;
}

int parse_describePK(PackageHeadPK* pHeadPK, DescribePK* pDescribePK, struct MBuf *buf)
{
	
	uint8_t  data8;
	const char *str = NULL;

	if (valid_inputParameter(pHeadPK, pDescribePK, buf, 'D'))
	{
		log_error("input parameter have error\n");
		return -1;
	}

	if (skipPackageHeader(buf,skip_pacakge_type_length))
	{
		log_error("skip package header error\n");
		return -1;
	}

	copy_packageHeader(&(pDescribePK->packageHead), pHeadPK);

	if (mbuf_avail_for_read(buf) < sizeof(uint8_t) || !mbuf_get_byte(buf, &data8))
	{
		log_error("read type error\n");
		return -1;
	}
	pDescribePK->type = data8;

	if(!mbuf_get_string(buf, &str))
	{
		log_error("get string fail\n");
	}
	if(*str != 0 && (strlen(str) + 1) > DESCRIBEPK_NAMELENGTH)
	{
		log_error("no memory to save describe name \n");
		return -1;
	}
	memcpy(pDescribePK->string, str, strlen(str) + 1);
	return 0;
}

int parse_bindPK(PackageHeadPK* pHeadPK, BindPK* pBindPK, struct MBuf* buf)
{
	
	const char *str;
	uint16_t data16;
	uint32_t data32;
	const uint8_t* pData;
	uint16_t count = 0;

	if (valid_inputParameter(pHeadPK, pBindPK, buf, 'B'))
	{
		log_error("input parameter have error\n");
		return -1;
	}

	if (skipPackageHeader(buf,skip_pacakge_type_length))
	{
		log_error("skip package header error\n");
		return -1;
	}

	copy_packageHeader(&(pBindPK->packageHead), pHeadPK);

	if (!mbuf_get_string(buf, &str) || *str == 0)
	{
		log_error("get entry name error\n");
		return -1;
	}
	if (strlen(str) + 1 > BINDPK_ENTRYLENGTH)
	{
		log_error("no more memory to save entry name error\n");
		return -1;
	}
	memcpy(pBindPK->dstEntry, str, strlen(str)+1);

	if (!mbuf_get_string(buf, &str) || *str == 0)
	{
		log_error("get prepare string error\n");
		return -1;
	}
	if (strlen(str) + 1 > BINDPK_PREPARESTRLENGTH)
	{
		log_error("no more memory to save prepare string error\n");
		return -1;
	}
	memcpy(pBindPK->prepareStr, str, strlen(str) + 1);

	if (!mbuf_get_uint16be(buf, &data16))
	{
		log_error("read the number of parameter format error\n");
		return -1;
	}
	pBindPK->fmtNum = data16;

	if (pBindPK->fmtNum > BINDPK_PARAMNUM)
	{
		log_error("no more memory to save format error\n");
		return -1;
	}

	count = 0;
	while(count < pBindPK->fmtNum)
	{
		if (!mbuf_get_uint16be(buf, &data16))
		{
			log_error("read parameter format value error");
			return -1;
		}
		pBindPK->paratFmt[count++] = data16;
	}

	if (!mbuf_get_uint16be(buf, &data16))
	{
		log_error("read parameter value num error\n");
		return -1;
	}
	pBindPK->paramValNum = data16;
	if (pBindPK->paramValNum > BINDPK_PARAMNUM)
	{
		log_error("no more memory to save parameter values\n");
		return -1;
	}

	count = 0;
	while(count < pBindPK->paramValNum)
	{
		if (!mbuf_get_uint32be(buf, &data32))
		{
			log_error("read parameter length error \n");
			return -1;
		}
		pBindPK->paramVal[count].dataLen = data32;

		if (data32 <= 0)
		{
			++count;
			continue;
		}

		if (data32 > DATAPAIR_DATALENGTH)
		{
			log_error("no more memory to save parameter values\n");
			return -1;
		}

		if (!mbuf_get_bytes(buf, data32, &pData))
		{
			log_error("read parameter value error\n");
			return -1;
		}
		memcpy(pBindPK->paramVal[count++].data, pData, sizeof(uint8_t) * data32);
	}

	if (!mbuf_get_uint16be(buf, &data16))
	{
		log_error("read the number of parameter format error\n");
		return -1;
	}
	pBindPK->resultFmtNum = data16;

	if (pBindPK->resultFmtNum > BINDPK_RESULTNUM)
	{
		log_error("no more memory to save result format error\n");
		return -1;
	}

	count = 0;
	while(count < pBindPK->resultFmtNum)
	{
		if (!mbuf_get_uint16be(buf, &data16))
		{
			log_error("read result format value error");
			return -1;
		}
		pBindPK->resultFmt[count++] = data16;
	}

	return 0;
}

int parse_cancelRequestPK(PackageHeadPK* pHeadPK, CancelRequestPK* pCancelRequestPK, struct MBuf* buf)
{
	
	uint32_t data32;

	if (valid_inputParameter(pHeadPK, pCancelRequestPK, buf, PKT_CANCEL))
	{
		log_error("input parameter have error\n");
		return -1;
	}

	if (skipPackageHeader(buf, skip_pacakge_length_requestcode))
	{
		log_error("skip package header error\n");
		return -1;
	}

	copy_packageHeader(&(pCancelRequestPK->packageHead), pHeadPK);

	if (mbuf_avail_for_read(buf) < sizeof(uint32_t) || !mbuf_get_uint32be(buf, &data32))
	{
		log_error("get cancel progess id error\n");
		return -1;
	}
	pCancelRequestPK->pid = data32;

	if (mbuf_avail_for_read(buf) < sizeof(uint32_t) || !mbuf_get_uint32be(buf, &data32))
	{
		log_error("get secret key error\n");
		return -1;
	}
	pCancelRequestPK->secketKey = data32;

	return 0;
}

int parse_closePK(PackageHeadPK* pHeadPK, ClosePK* pClosePK, struct MBuf* buf)
{

	

	return pClosePK == NULL_VAL ? -1 :
				parse_onlyPackageHeadPK(&(pClosePK->packageHead), pHeadPK, 'C');
}

int parse_copyFailPK(PackageHeadPK* pHeadPK, CopyFailPK* pCopyFailPK, struct MBuf* buf)
{
	
	const char *str;

	if (valid_inputParameter(pHeadPK, pCopyFailPK, buf, PKT_CANCEL))
	{
		log_error("input parameter have error\n");
		return -1;
	}

	if (skipPackageHeader(buf,skip_pacakge_type_length))
	{
		log_error("skip package header error\n");
		return -1;
	}

	copy_packageHeader(&(pCopyFailPK->packageHead), pHeadPK);

	if (mbuf_get_string(buf, &str))
	{
		if ((strlen(str) + 1) > COPYFAILPK_STRINGLENGTH)
		{
			log_error("no more memory to save the fail reason\n");
			return -1;
		}
		memcpy(pCopyFailPK->result, str, strlen(str) + 1);
	}
	return 0;
}

int parse_functionCallPK(PackageHeadPK* pHeadPK, FunctionCallPK* pFunctionCallPK, struct MBuf* buf)
{
	
	uint32_t data32;
	uint16_t data16;
	uint16_t count = 0;
	const uint8_t* pdata;

	if (valid_inputParameter(pHeadPK, pFunctionCallPK, buf, 'F'))
	{
		log_error("input parameter have error\n");
		return -1;
	}

	if (skipPackageHeader(buf,skip_pacakge_type_length))
	{
		log_error("skip package header error\n");
		return -1;
	}

	copy_packageHeader(&(pFunctionCallPK->packageHead), pHeadPK);

	if (!mbuf_get_uint32be(buf, &data32))
	{
		log_error("read call function object id error\n");
		return -1;
	}
	pFunctionCallPK->functionObjId = data32;

	if (!mbuf_get_uint16be(buf, &data16))
	{
		log_error("read function parameter error\n");
		return -1;
	}
	pFunctionCallPK->paraFmtNum = data16;

	count = 0;
	while(count < pFunctionCallPK->paraFmtNum)
	{
		if (!mbuf_get_uint16be(buf, &data16))
		{
			log_error("read function parameter format error\n");
			return -1;
		}
		pFunctionCallPK->paraFmt[count++] = data16;
	}

	if (!mbuf_get_uint16be(buf, &data16))
	{
		log_error("read the number of function parameter error\n");
		return -1;
	}
	pFunctionCallPK->paraNum = data16;

	count = 0;
	while(count < pFunctionCallPK->paraNum)
	{
		if (!mbuf_get_uint32be(buf, &data32))
		{
			log_error("read parameter length error \n");
			return -1;
		}
		pFunctionCallPK->para[count].dataLen = data32;

		if (data32 <= 0)
		{
			++count;
			continue;
		}

		if (data32 > DATAPAIR_DATALENGTH)
		{
			log_error("no more memory to save parameter values\n");
			return -1;
		}

		if (!mbuf_get_bytes(buf, data32, &pdata))
		{
			log_error("read parameter value error\n");
			return -1;
		}
		memcpy(pFunctionCallPK->para[count++].data, pdata, sizeof(uint8_t) * data32);
	}

	if (!mbuf_get_uint16be(buf, &data16))
	{
		log_error("read function result format error\n");
		return -1;
	}
	pFunctionCallPK->functionResultFmt = data16;

	return 0;
}

int parse_frontEndPackage(void *data, int len)
{	
	PackageHeadPK headPkt;
	struct MBuf buf;

	BindPK                      bindPK;
	CancelRequestPK             cancelRequestPK;
	ClosePK                     closePK;
	CopyDataPK                  copyDataPK;
	CopyDonePK                  copyDonePK;
	CopyFailPK                  copyFailPK;
	DescribePK                  describePK;
	ExecutePK                   executePK;
	FlushPK                     flushPK;
	FunctionCallPK              functionCallPK;
	ParsePK                     parsePK;
	PasswordMessagePK           passwordMessagePK;
	QueryPK                     queryPK;
	SSLRequestPK                sslRequestPK;
	StartupMessagePK            startupMessagePK;
	SyncPK                      syncPK;
	TerminatePK                 terminatePK;

	mbuf_init_fixed_reader(&buf, data, len);

	if(parse_pktHeader(&buf, &headPkt))
	{
		log_debug("parsePKTHeader error\n");
		return -1;
	}

	log_debug("type: %d, %c , length: %d, is_new: %d\n", headPkt.type, headPkt.type, headPkt.length, headPkt.is_new);
	switch(headPkt.type)
	{
		case 'B':
			log_debug("* start parse_bindPK\n");
			if (parse_bindPK(&headPkt, &bindPK, &buf))
			{
				log_error("parse_bindPK error\n");
				return -1;
			}
			print_bindPK(bindPK);
			break;

		case PKT_CANCEL:
			log_debug("* start parse_cancelRequestPK\n");
			if (parse_cancelRequestPK(&headPkt, &cancelRequestPK, &buf))
			{
				log_error("parse_cancelRequestPK error\n");
				return -1;
			}
			print_cancelRequestPK(cancelRequestPK);
			break;
		case 'C':
			log_debug("* start parse_closePK\n");
			if (parse_closePK(&headPkt, &closePK, &buf))
			{
				log_error("parse_closePK error\n");
				return -1;
			}
			print_closePK(closePK);
			break;

		case 'd':
			log_debug("* start parse_copyDataPK\n");
			if (parse_copyDataPK(&headPkt, &copyDataPK, &buf))
			{
				log_error("parse_copyDataPK error\n");
				return -1;
			}
			print_copyDataPK(copyDataPK);
			break;

		case 'c':
			log_debug("* start parse_copyDonePK\n");
			if (parse_copyDonePK(&headPkt, &copyDonePK, &buf))
			{
				log_error("parse_copyDonePK error\n");
				return -1;
			}
			print_copyDonePK(copyDonePK);
			break;

		case 'f':
			log_debug("* start parse_copyFailPK\n");
			if (parse_copyFailPK(&headPkt, &copyFailPK, &buf))
			{
				log_error("parse_copyFailPK error\n");
				return -1;
			}
			print_copyFailPK(copyFailPK);
			break;

		case 'D':
			log_debug("* start parse_describePK\n");
			if (parse_describePK(&headPkt, &describePK, &buf))
			{
				log_error("parse_describePK error\n");
				return -1;
			}
			print_describePK(describePK);
			break;

		case 'E':
			log_debug("* start parse_executePK\n");
			if (parse_executePK(&headPkt, &executePK, &buf))
			{
				log_error("parse_executePK error\n");
				return -1;
			}
			print_executePK(executePK);
			break;

		case 'H':
			log_debug("* start parse_flushPK\n");
			if (parse_flushPK(&headPkt, &flushPK, &buf))
			{
				log_error("parse_flushPK error\n");
				return -1;
			}
			print_flushPK(flushPK);
			break;

		case 'F':
			log_debug("* start parse_functionCallPK\n");
			if (parse_functionCallPK(&headPkt, &functionCallPK, &buf))
			{
				log_error("parse_functionCallPK error\n");
				return -1;
			}
			print_functionCallPK(functionCallPK);
			break;

		case 'P':
			log_debug("* start parse_parsePK\n");
			if (parse_parsePK(&headPkt, &parsePK, &buf))
			{
				log_error("parse_parsePK error\n");
				return -1;
			}
			print_parsePK(parsePK);
			break;

		case 'p':
			log_debug("* start parse_passwordMessagePK\n");
			if (parse_passwordMessagePK(&headPkt, &passwordMessagePK, &buf))
			{
				log_error("parse_passwordMessagePK error\n");
				return -1;
			}
			print_passwordMessagePK(passwordMessagePK);
			break;

		case 'Q':
			log_debug("* start parse_queryPK\n");
			if (parse_queryPK(&headPkt, &queryPK, &buf))
			{
				log_error("parse_queryPK error\n");
				return -1;
			}
			print_queryPK(queryPK);
			break;

		case PKT_SSLREQ:
			log_debug("* start parse_sslRequestPK\n");
			if (parse_sslRequestPK(&headPkt, &sslRequestPK, &buf))
			{
				log_error("parse_sslRequestPK error\n");
				return -1;
			}
			print_sslRequestPK(sslRequestPK);
			break;

		case PKT_STARTUP:
			log_debug("* start parse_startupMessagePK\n");
			if (parse_startupMessagePK(&headPkt, &startupMessagePK, &buf))
			{
				log_error("parse_startupMessagePK error\n");
				return -1;
			}
			print_startupMessagePK(startupMessagePK);
			break;

		case 'S':
			log_debug("* start parse_syncPK\n");
			if (parse_syncPK(&headPkt, &syncPK, &buf))
			{
				log_error("parse_syncPK error\n");
				return -1;
			}
			print_syncPK(syncPK);
			break;

		case 'X':
			log_debug("* start parse_terminatePK\n");
			if (parse_terminatePK(&headPkt, &terminatePK, &buf))
			{
				log_error("parse_terminatePK error\n");
				return -1;
			}
			print_terminatePK(terminatePK);
			break;

		default:
			log_debug("the package is not sent from frontend\n");
			break;
	}

	return 0;
}
