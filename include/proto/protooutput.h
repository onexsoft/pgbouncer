/*
 * protooutput.h
 *
 *  Created on: 2015710
 *      Author: April
 */

#ifndef INCLUDE_PROTO_PROTOOUTPUT_H_
#define INCLUDE_PROTO_PROTOOUTPUT_H_

void print_pktHeader(PackageHeadPK packageHead);
void print_sslResponsePK(SSLResponsePK sslResponsePK);
void print_authPK(AuthPK authPK);
void print_backendKeyDataPK(BackendKeyDataPK backendKeyDataPK);
void print_bindCompletePK(BindCompletePK bindCompletePK);
void print_closeCompletePK(CloseCompletePK closeCompletePK);
void print_commandCompletePK(CommandCompletePK commandCompletePK);
void print_copyDataPK(CopyDataPK copyDataPK);
void print_copyDonePK(CopyDonePK copyDonePK);
void print_copyInResponsePK(CopyInResponsePK copyInResponsePK);
void print_copyOutResponsePK(CopyOutResponsePK copyOutResponsePK);
void print_dataRowPK(DataRowPK dataRowPK);
void print_emptyQueryResponsePK(EmptyQueryResponsePK emptyQueryResponsePK);
void print_errorResponsePK(ErrorResponsePK errorResponsePK);
void print_functionCallResponsePK(FunctionCallResponsePK functionCallResponsePK);
void print_noDataPK(NoDataPK noDataPK);
void print_noticeResponsePK(NoticeResponsePK noticeResponsePK);
void print_notificationResponsePK(NotificationResponsePK notificationResponsePK);
void print_parameterDescriptionPK(ParameterDescriptionPK parameterDescriptionPK);
void print_parameterStatusPK(ParameterStatusPK parameterStatusPK);
void print_parseCompletePK(ParseCompletePK parseCompletePK);
void print_portalSuspendedPK(PortalSuspendedPK portalSuspendedPK);
void print_readyForQueryPK(ReadyForQueryPK readyForQueryPK);
void print_rowDescriptionPK(RowDescriptionPK rowDescriptionPK);
void print_bindPK(BindPK bindPK);
void print_cancelRequestPK(CancelRequestPK cancelRequestPK);
void print_closePK(ClosePK closePK);
void print_copyFailPK(CopyFailPK copyFailPK);
void print_describePK(DescribePK describePK);
void print_executePK(ExecutePK executePK);
void print_flushPK(FlushPK flushPK);
void print_parsePK(ParsePK parsePK);
void print_passwordMessagePK(PasswordMessagePK passwordMessagePK);
void print_queryPK(QueryPK queryPK);
void print_sslRequestPK(SSLRequestPK sslRequestPK);
void print_startupMessagePK(StartupMessagePK startupMessagePK);
void print_syncPK(SyncPK syncPK);
void print_terminatePK(TerminatePK terminatePK);

void print_functionCallPK(FunctionCallPK functionCallPK);

#endif /* INCLUDE_PROTO_PROTOOUTPUT_H_ */
