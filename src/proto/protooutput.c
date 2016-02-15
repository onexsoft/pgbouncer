/*
 * protooutput.c
 *
 *  Created on: 2015712
 *      Author: April
 */
#include "bouncer.h"

void print_functionCallPK(FunctionCallPK functionCallPK)
{
	print_pktHeader(functionCallPK.packageHead);
	log_debug("functionObjId: %d, functionResultFmt: %d, paraFmtNum: %d, paraNum: %d\n", functionCallPK.functionObjId,
			functionCallPK.functionResultFmt, functionCallPK.paraFmtNum, functionCallPK.paraNum);
	log_debug("----------paraFmt---------------\n");
	for (uint16_t i = 0; i < functionCallPK.paraFmtNum; ++i)
	{
		log_debug("%d ", functionCallPK.paraFmt[i]);
	}
	log_debug("\n");
	log_debug("--------------para----------------\n");
	for (uint16_t i = 0; i < functionCallPK.paraNum; ++i)
	{
		log_debug("dataLen: %d, data: %s\n", functionCallPK.para[i].dataLen, functionCallPK.para[i].data);
	}
}

void print_pktHeader(PackageHeadPK packageHead)
{
	log_debug("type: %c, length: %d, is_new: %d\n", packageHead.type,
			packageHead.length, packageHead.is_new);
}

void print_sslResponsePK(SSLResponsePK sslResponsePK)
{
	log_debug("sslResponsePK.type: %c\n", sslResponsePK.byte);
}

void print_authPK(AuthPK authPK)
{
	print_pktHeader(authPK.packageHead);
	log_debug("packageType: %d, packageExtPara: %d\n",authPK.packageType, authPK.packageExtPara);
}

void print_backendKeyDataPK(BackendKeyDataPK backendKeyDataPK)
{
	print_pktHeader(backendKeyDataPK.packageHead);
	log_debug("pid:%d, secketKey: %d\n", backendKeyDataPK.pid, backendKeyDataPK.secketKey);
}

void print_bindCompletePK(BindCompletePK bindCompletePK)
{
	print_pktHeader(bindCompletePK.packageHead);
}

void print_closeCompletePK(CloseCompletePK closeCompletePK)
{
	print_pktHeader(closeCompletePK.packageHead);
}

void print_commandCompletePK(CommandCompletePK commandCompletePK)
{
	print_pktHeader(commandCompletePK.packageHead);
	log_debug("command: %s\n", commandCompletePK.command);
}

void print_copyDataPK(CopyDataPK copyDataPK)
{
	print_pktHeader(copyDataPK.packageHead);
	for (unsigned int i = 0; i < copyDataPK.packageHead.length - 4; ++i)
	{
		log_debug("%d ", copyDataPK.data[i]);
	}
	log_debug("\n");
}

void print_copyDonePK(CopyDonePK copyDonePK)
{
	print_pktHeader(copyDonePK.packageHead);
}

void print_copyInResponsePK(CopyInResponsePK copyInResponsePK)
{
	print_pktHeader(copyInResponsePK.copyDescription.packageHead);
	log_debug("type: %d, colNum: %d\n", copyInResponsePK.copyDescription.type, copyInResponsePK.copyDescription.colNum);
	for (uint16_t i = 0; i < copyInResponsePK.copyDescription.colNum; ++i)
	{
		log_debug("%d ", copyInResponsePK.copyDescription.colFmt[i]);
	}
	log_debug("\n");
}

void print_copyOutResponsePK(CopyOutResponsePK copyOutResponsePK)
{
	print_pktHeader(copyOutResponsePK.copyDescription.packageHead);
	log_debug("type: %d, colNum: %d\n", copyOutResponsePK.copyDescription.type, copyOutResponsePK.copyDescription.colNum);
	for (uint16_t i = 0; i < copyOutResponsePK.copyDescription.colNum; ++i)
	{
		log_debug("%d ", copyOutResponsePK.copyDescription.colFmt[i]);
	}
	log_debug("\n");
}

void print_dataRowPK(DataRowPK dataRowPK)
{
	print_pktHeader(dataRowPK.packageHead);
	log_debug("colnum: %d\n", dataRowPK.colNum);
	for (uint16_t i = 0; i < dataRowPK.colNum; ++i)
	{
		log_debug("valueLen: %d, data: %s\n", dataRowPK.colData[i].valueLen, dataRowPK.colData[i].data);
	}
}

void print_emptyQueryResponsePK(EmptyQueryResponsePK emptyQueryResponsePK)
{
	print_pktHeader(emptyQueryResponsePK.packageHead);
}

void print_errorResponsePK(ErrorResponsePK errorResponsePK)
{
	int loop = 0;
	NoticeData* tmpData;
	print_pktHeader(errorResponsePK.packageHead);
	while(loop < ERRORRESPONSEPK_NUM && errorResponsePK.errorMsg[loop].messageType > 0){
		tmpData = &errorResponsePK.errorMsg[loop++];
		log_debug("messageType: %d, errorMsg: %s\n",
				tmpData->messageType, tmpData->message);
	}
}

void print_functionCallResponsePK(FunctionCallResponsePK functionCallResponsePK)
{
	print_pktHeader(functionCallResponsePK.packageHead);
	log_debug("resultLength: %d, resultValue: %s\n", functionCallResponsePK.resultLength, functionCallResponsePK.resultValue);
}
void print_noDataPK(NoDataPK noDataPK)
{
	print_pktHeader(noDataPK.packageHead);
}

void print_noticeResponsePK(NoticeResponsePK noticeResponsePK)
{
	int loop = 0;
	NoticeData* tmpData;

	print_pktHeader(noticeResponsePK.packageHead);
	while(loop < NOTICERESPONSE_NUM && noticeResponsePK.noticeData[loop].messageType > 0){
		tmpData = &noticeResponsePK.noticeData[loop++];
		log_debug("messageType: %d, message: %s\n", tmpData->messageType, tmpData->message);
	}
}

void print_notificationResponsePK(NotificationResponsePK notificationResponsePK)
{
	print_pktHeader(notificationResponsePK.packageHead);
	log_debug("pid: %d, extMessage: %s, conditionName: %s\n", notificationResponsePK.pid,
			notificationResponsePK.extMessage, notificationResponsePK.conditionName);
}

void print_parameterDescriptionPK(ParameterDescriptionPK parameterDescriptionPK)
{
	int loop = 0;
	uint32_t tmpdata;
	print_pktHeader(parameterDescriptionPK.packageHead);
	while(loop < parameterDescriptionPK.paramNum){
		tmpdata = parameterDescriptionPK.param[loop];
		log_debug("paramnum: %d, param[%d]: %d\n",
				parameterDescriptionPK.paramNum, loop,  tmpdata);
		++loop;
	}
}

void print_parameterStatusPK(ParameterStatusPK parameterStatusPK)
{
	print_pktHeader(parameterStatusPK.packageHead);
	log_debug("paraName: %s, paraValue: %s\n", parameterStatusPK.paraName, parameterStatusPK.paraValue);
}

void print_parseCompletePK(ParseCompletePK parseCompletePK)
{
	print_pktHeader(parseCompletePK.packageHead);
}

void print_portalSuspendedPK(PortalSuspendedPK portalSuspendedPK)
{
	print_pktHeader(portalSuspendedPK.packageHead);
}

void print_readyForQueryPK(ReadyForQueryPK readyForQueryPK)
{
	print_pktHeader(readyForQueryPK.packageHead);
	log_debug("status: %d\n", readyForQueryPK.backendStatus);
}

void print_rowDescriptionPK(RowDescriptionPK rowDescriptionPK)
{
	print_pktHeader(rowDescriptionPK.packageHead);
	log_debug("rownum: %d\n", rowDescriptionPK.rowNum);
	for (uint16_t i = 0; i < rowDescriptionPK.rowNum; ++i)
	{
		log_debug("format: %d, objectId: %d, rowId: %d, rowLength: %d, rowName: %s, tableId: %d, typeAttribut: %d\n",
				rowDescriptionPK.rowDescription[i].format, rowDescriptionPK.rowDescription[i].objectId,
				rowDescriptionPK.rowDescription[i].rowId, rowDescriptionPK.rowDescription[i].rowLength,
				rowDescriptionPK.rowDescription[i].rowName, rowDescriptionPK.rowDescription[i].tableId,
				rowDescriptionPK.rowDescription[i].typeAttribut);
	}
}
void print_bindPK(BindPK bindPK)
{
	print_pktHeader(bindPK.packageHead);
	log_debug("dstEntry: %s, prepareStr: %s\n", bindPK.dstEntry, bindPK.prepareStr);
}

void print_cancelRequestPK(CancelRequestPK cancelRequestPK)
{
	print_pktHeader(cancelRequestPK.packageHead);
	log_debug("pid: %d, secketKey: %d\n", cancelRequestPK.pid, cancelRequestPK.secketKey);
}

void print_closePK(ClosePK closePK)
{
	print_pktHeader(closePK.packageHead);
	log_debug("type: %d, prepareStr: %s\n",closePK.type, closePK.prepareStr);
}

void print_copyFailPK(CopyFailPK copyFailPK)
{
	print_pktHeader(copyFailPK.packageHead);
	log_debug("result: %s\n", copyFailPK.result);
}
void print_describePK(DescribePK describePK)
{
	print_pktHeader(describePK.packageHead);
	log_debug("type: %d, string: %s\n", describePK.type, describePK.string);
}

void print_executePK(ExecutePK executePK)
{
	print_pktHeader(executePK.packageHead);
	log_debug("maxRow: %d, entryName: %s\n", executePK.maxRow, executePK.entryName);
}

void print_flushPK(FlushPK flushPK)
{
	print_pktHeader(flushPK.packageHead);
}


void print_parsePK(ParsePK parsePK)
{
	print_pktHeader(parsePK.packageHead);
	log_debug("name: %s, paramNum: %d, queryStr: %s\n", parsePK.name, parsePK.paramNum, parsePK.queryStr);
	for (uint16_t i = 0; i < parsePK.paramNum; ++i)
	{
		log_debug("%d ", parsePK.paramId[i]);
	}
	log_debug("\n");
}

void print_passwordMessagePK(PasswordMessagePK passwordMessagePK)
{
	print_pktHeader(passwordMessagePK.packageHeadPK);
	log_debug("password: %s\n", passwordMessagePK.password);
}

void print_queryPK(QueryPK queryPK)
{
	print_pktHeader(queryPK.packageHead);
	log_debug("queryStr: %s\n", queryPK.queryStr);
}

void print_sslRequestPK(SSLRequestPK sslRequestPK)
{
	print_pktHeader(sslRequestPK.packageHead);
}

void print_startupMessagePK(StartupMessagePK startupMessagePK)
{
	ParameterPair *curr;
	log_debug("length: %d, version: %d\n", startupMessagePK.length, startupMessagePK.version);
	curr = startupMessagePK.head;
	while(curr != NULL)
	{
		log_debug("key: %s, val: %s\n", curr->key, curr->val);
		curr = curr->next;
	}
	LOG_TRACE_RUN_END
}

void print_syncPK(SyncPK syncPK)
{
	print_pktHeader(syncPK.packageHead);
}

void print_terminatePK(TerminatePK terminatePK)
{
	print_pktHeader(terminatePK.packageHead);
}
