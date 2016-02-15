/*
 * common.c
 *
 *  Created on: 201579
 *      Author: April
 */

#include "bouncer.h"

int valid_inputParameter(PackageHeadPK* pHeadPK, void * pDstPackagePK, struct MBuf *buf, uint32_t commandSymbol)
{
	if (!pHeadPK || !buf)
	{
		log_error("pHeadPk is null or buf is null\n");
		return -1;
	}
	log_debug("pHeadPk->type: %d, pHeadPk->length: %d, pHeadPk->is_new: %d\n",
				pHeadPK->type, pHeadPK->length, pHeadPK->is_new);

	if (!pDstPackagePK)
	{
		log_error("pDstPackagePK no memory\n");
		return -1;
	}

	if (pHeadPK->type != commandSymbol)
	{
		log_error("pHeadPk->type(%d) != \'%d\'",pHeadPK->type, commandSymbol);
		return -1;
	}
	return 0;
}

int skipPackageHeader(struct MBuf *buf, int headType)
{
	

	uint32_t data32;
	uint8_t  data8;

	if (buf == NULL)
	{
		log_error("buf == NULL\n");
		return -1;
	}

	if (headType == skip_pacakge_type_length)
	{
		if (!mbuf_get_byte(buf, &data8))
		{
			log_error("skip package type error\n");
			return -1;
		}
	}
	else if (headType == skip_pacakge_length_requestcode)
	{
		if (!mbuf_get_uint32be(buf, &data32))
		{
			log_error("skip package length error\n");
			return -1;
		}
	}

	if (!mbuf_get_uint32be(buf, &data32))
	{
		log_error("skip package length or package request code error\n");
		return -1;
	}
	log_debug("finished skipPackageHeader\n");
	return 0;
}

int parse_pktHeader(const struct MBuf *pktBuf, PackageHeadPK *pkt)
{
	

	uint8_t type8;
	int pktLen = 0;
	struct MBuf data;
	int bufLen = 0;
    int got = 0;
	uint16_t len16 = 0;
	uint32_t code = 0;
	uint32_t pktType = 0;
	uint32_t len32 = 0;

	mbuf_copy(pktBuf, &data);

	bufLen = mbuf_avail_for_read(&data);
	if (bufLen < NEW_HEADER_LEN)
	{
		log_error("data len (%d) too short\n", bufLen);
		return -1;
	}

	if (!mbuf_get_byte(&data, &type8))
	{
		log_error("call mbuf_get_byte error\n");
		return -1;
	}

	if (0 != type8)
	{
		if (!mbuf_get_uint32be(&data, &len32))
		{
			log_error("call mbuf_get_uint32be error\n");
			return -1;
		}
		pktType = type8;
		pktLen = len32;
		got = NEW_HEADER_LEN;
		log_debug("type8: %d, len32: %d\n",type8, len32);
	} else {
		if (!mbuf_get_byte(&data, &type8)) {
			return -1;
		}
		if (type8 != 0) {
			log_error("get_header: unknown special pkt");
			return -1;
		}

		if (mbuf_avail_for_read(&data) < OLD_HEADER_LEN - 2) {
			log_error("get_header: less than 8 bytes for special pkt");
			return -1;
		}

		if (!mbuf_get_uint16be(&data, &len16)){
			log_error("mbuf_get_uint16be error\n");
			return -1;
		}
		pktLen = len16;

		if (!mbuf_get_uint32be(&data, &code)) {
			log_error("mbuf_get_uint32be error\n");
			return -1;
		}
		log_debug("code: %d\n", code);

		if (code == PKT_CANCEL)
			pktType = PKT_CANCEL;
		else if (code == PKT_SSLREQ)
			pktType = PKT_SSLREQ;
		else if ((code >> 16) == 3 && (code & 0xFFFF) < 2)
			pktType = PKT_STARTUP;
		else if (code == PKT_STARTUP_V2)
			pktType = PKT_STARTUP_V2;
		else {
			log_error("get_header: unknown special pkt: len=%u code=%u", pktLen, code);
			return -1;
		}
		got = OLD_HEADER_LEN;
	}

	if ((pktLen + 1) < got || pktLen > (int)cf_max_packet_size)
	{
		log_debug("pkt is illege\n");
		return -1;
	}

	pkt->length = pktLen;
	pkt->type = pktType;
	if (got == OLD_HEADER_LEN)
	{
		pkt->is_new = false;
	} else {
		pkt->is_new = true;
	}

	return 0;
}

int parse_onlyPackageHeadPK(PackageHeadPK* pDstHeadPK, PackageHeadPK* pSrcHeadPK, uint32_t commandSymbol)
{
	if (!pSrcHeadPK)
	{
		log_debug("pHeadPk is null or buf is null\n");
		return -1;
	}
	log_debug("pHeadPk->type: %d, pHeadPk->length: %d, pHeadPk->is_new: %d\n",
			pSrcHeadPK->type, pSrcHeadPK->length, pSrcHeadPK->is_new);

	if (!pDstHeadPK)
	{
		log_debug("pDstHeadPK no memory\n");
		return -1;
	}

	if (pSrcHeadPK->type != commandSymbol)
	{
		log_debug("pHeadPk->type(%d) != \'%d\'",pSrcHeadPK->type, commandSymbol);
		return -1;
	}

	copy_packageHeader(pDstHeadPK, pSrcHeadPK);

	return 0;
}

int parse_copyDataPK(PackageHeadPK* pHeadPK, CopyDataPK* pCopyDataPK, struct MBuf* buf)
{
	
	const uint8_t* pData;

	if (valid_inputParameter(pHeadPK, pCopyDataPK, buf, 'd'))
	{
		log_error("input parameter have error\n");
		return -1;
	}

	if (skipPackageHeader(buf,skip_pacakge_type_length))
	{
		log_error("skip package header error\n");
		return -1;
	}

	copy_packageHeader(&(pCopyDataPK->packageHead), pHeadPK);

	if (pHeadPK->length - 4 > COPYDATA_DATALENGTH)
	{
		log_error("no more memory to save copy data\n");
		return -1;
	}
	if (!mbuf_get_bytes(buf, pHeadPK->length - 4, &pData))
	{
		log_error("read data error\n");
		return -1;
	}
	memcpy(pCopyDataPK->data, pData, (sizeof(uint8_t) * (pHeadPK->length - 4)));
	return 0;
}

int parse_copyDonePK(PackageHeadPK* pHeadPK, CopyDonePK* pCopyDonePK, struct MBuf* buf)
{
	
	return pCopyDonePK == NULL ? -1 :
			parse_onlyPackageHeadPK(&(pCopyDonePK->packageHead), pHeadPK, PKT_SSLREQ);
}
