/*
 * vipthread.c
 *
 *  Created on: 2015Äê8ÔÂ31ÈÕ
 *      Author: hui
 */

#include "bouncer.h"
#include <net/if.h>
#include <linux/sockios.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include <errno.h>

typedef struct InterfaceNameNode InterfaceNameNode;
static PgThread *vipThread = NULL;

struct InterfaceNameNode
{
	struct InterfaceNameNode *next;
	char name[IFNAMSIZ];
};

static void *start_work(void* arg);

//check ip used or not
static bool check_vipIsUsed(const char *ifname, const char *vip) _UNUSED;
static bool check_vipIsUsedByPing(const char *vip);

//delete virtual ip
static void delete_vip(const char *ifname);

//set virtual ip, 0 add vip success, -1 add vip failed.
static int set_vip(const char *ifname, const char *vip);

static int send_arp_packet(const char *ifname, const char *vip);
static int update_route_byArpping(const char* ifname, const char *vip);

//get all interface name, failed return NULL, or return interface name list head
static InterfaceNameNode* get_allInterfaceName(void);
static char* get_validInterfaceName(void);
static char* get_virtualInterfaceName(void);
static bool  is_realInterfaceName(const char *ifname);
static char* get_realInterfaceName(void);

//init
int init_vipThread(void)
{
	int err;
	vipThread = new_pgThread("vip thread");
	if (vipThread == NULL) {
		log_error("init acceptThread fail");
		return -1;
	}

	err = pthread_create(&vipThread->tid, NULL, start_work ,vipThread);
	if (err) {
		log_error("create thread error\n");
		return -1;
	}
	return 0;
}

//destory thread
void destory_vipThread(void)
{
	if (vipThread == NULL)
		return;

	pthread_join(vipThread->tid, NULL);
	destroy_pgThread(vipThread);
}

static void *start_work(void* arg)
{
	int sendArpNum = 0;
	int send_arp_rate = 0.5; //second
	int ha_check_rate = 0.5; //second

	if (!cf_ha_interface_name || strlen(cf_ha_interface_name) <= 0)
	{
		cf_ha_interface_name = get_virtualInterfaceName();
	}

	if (!cf_ha_interface_name || !cf_ha_interface_vip
			|| strlen(cf_ha_interface_name) <= 0
			|| strlen(cf_ha_interface_name) <= 0) {
		log_error("cf_ha_interface_name or cf_ha_interface_vip is null");
		return (void*)-1;
	}

	while(cf_shutdown < 2) {

		//check vip
		if (!check_vipIsUsedByPing(cf_ha_interface_vip)) {//not use vip
			//set vip
			if(set_vip(cf_ha_interface_name, cf_ha_interface_vip) < 0) {
				log_error("set vip error");
				continue;
			}

			//set arp package
			while(sendArpNum ++ < 10 && send_arp_packet(cf_ha_interface_name, cf_ha_interface_vip) < 0){
				sleep(send_arp_rate);
			}
			//update_route_byArpping(cf_ha_interface_name, cf_ha_interface_vip);
		}
		sleep(ha_check_rate);
	}

	//delete vip
	delete_vip(cf_ha_interface_name);

	return (void*) 0;
}

static bool check_vipIsUsed(const char *ifname, const char *vip)
{
	char buf[1024];
	char realInterfaceName[IFNAMSIZ];
	unsigned int i = 0;
	FILE *stream;
	char recvBuf[16] = {0};

	while(ifname[i] && ifname[i++] != ':');
	memset(realInterfaceName, 0, 125);
	memcpy(realInterfaceName, ifname, i - 1);
	realInterfaceName[i] = '\0';

	memset(buf, 0, 1024);
	snprintf(buf, 1024, "/sbin/arping -I %s -D %s -w 5 | grep \"Received 0 response\" | wc -l",
			realInterfaceName, vip);
	stream = popen(buf, "r");
	fread(recvBuf, sizeof(char), sizeof(recvBuf)-1, stream);
	pclose(stream);

	if (atoi(recvBuf) > 0)
		return false;
	return true;

//	err = system(buf);
//	log_error("buf: %s, err: %d", buf, err);

//	return err == 0 ? false : true;
}

static bool check_vipIsUsedByPing(const char *vip)
{
	FILE *stream;
	char recvBuf[16] = {0};
	char cmdBuf[256] = {0};

	sprintf(cmdBuf, "ping %s -c 3 -i 0.2 | grep ttl= | wc -l", vip);
	stream = popen(cmdBuf, "r");
	fread(recvBuf, sizeof(char), sizeof(recvBuf)-1, stream);
	pclose(stream);

	if (atoi(recvBuf) > 0)
	return true;

	return false;
}

static void delete_vip(const char *ifname)
{
	int sock = 0;
	struct ifreq ifr;

	log_error("start delete vip");
	sock = socket (AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		log_error("delete failed");
		return;
	}

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	ifr.ifr_name[IFNAMSIZ - 1] = '\0';

	if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0){
		log_error("ioctl error");
		close(sock);
		return;
	}

	close(sock);
	return;
}

static int set_vip(const char *ifname, const char *vip)
{
	struct ifreq ifr;

	struct sockaddr_in brdaddr;
    struct sockaddr_in netmask;
    int    sock = 0;
    int    addr_mask = 0;
    int    err  = 0;

	Assert(ifname != NULL);
	Assert(vip != NULL);

	//get real interface name
	{
		unsigned int i = 0;
		while(ifname[i] && ifname[i++] != ':');

		if (i >= strlen(ifname)) {
			log_error("ifname(%s) format is error, for example: eth0:0", ifname);
			return -1;
		}

		memset(&ifr, 0, sizeof(ifr));
		memcpy(ifr.ifr_name, ifname, i - 1);
		ifr.ifr_name[IFNAMSIZ-1] = '\0';
	}

	 sock = socket (AF_INET, SOCK_STREAM, 0);
	 if (sock < 0) {
		 log_error("create sock error\n");
		 return -1;
	 }

	//get real interface netmask, mac, boradip, interface index
	{
		//board address
		memset(&ifr.ifr_ifru, 0, sizeof(ifr.ifr_ifru));
		if (ioctl (sock, SIOCGIFBRDADDR, &ifr) >= 0)
		{
			memcpy(&brdaddr, &ifr.ifr_broadaddr, sizeof(struct sockaddr_in));
			addr_mask = addr_mask | 0x01;
		}

		//net mask
		memset(&ifr.ifr_ifru, 0, sizeof(ifr.ifr_ifru));
		if (ioctl (sock, SIOCGIFNETMASK, &ifr) >= 0)
		{
			memcpy(&netmask, &ifr.ifr_netmask, sizeof(struct sockaddr_in));
			addr_mask = addr_mask | 0x02;
		}
	}

	//add virtual vip
	{
		//set interface name
		struct sockaddr_in *sin = NULL;

		memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

	    memset(&ifr.ifr_ifru, 0, sizeof(ifr.ifr_ifru));
	    sin = (struct sockaddr_in *) &ifr.ifr_addr;
	    sin->sin_family = AF_INET;
	    err = inet_aton(vip, &sin->sin_addr);
	    if (!err) {
	    	log_error("vip is invalid");
	    	close(sock);
	    	return -1;
	    }

	    //set ip address
		 err = ioctl (sock, SIOCSIFADDR, &ifr);
		 if (err < 0)
		 {
			log_error("set vip address error, errstr: %s", strerror(errno));
			close(sock);
			return -1;
		 }

		 //set board address
		 if (addr_mask & 0x1)
		 {
			memset(&ifr.ifr_ifru, 0, sizeof(ifr.ifr_ifru));
			memcpy(&ifr.ifr_broadaddr, &brdaddr, sizeof(struct sockaddr_in));
			ioctl (sock, SIOCSIFBRDADDR, &ifr);
		 }

		 //set netmask
		 if (addr_mask & 0x2)
		 {
			memset(&ifr.ifr_ifru, 0, sizeof(ifr.ifr_ifru));
			memcpy(&ifr.ifr_netmask, &netmask, sizeof(struct sockaddr_in));
			ioctl (sock, SIOCSIFNETMASK, &ifr);
		 }
		 close(sock);
	}
	return 0;
}

static int send_arp_packet(const char *ifname, const char *vip)
{
	int    sock = 0;
	int    ifindex = 0;
	struct sockaddr macaddr;

	struct ifreq ifr;

	if (!ifname || !vip) {
		log_error("ifname or vip is null");
		return -1;
	}

	sock = socket (AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
	 log_error("create sock error\n");
	 return -1;
	}

	//get mac and ifindex
	{
		memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
		ifr.ifr_name[IFNAMSIZ - 1] = '\0';

		//get mac
		memset(&ifr.ifr_ifru, 0, sizeof(ifr.ifr_ifru));
		if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0)
		{
			log_error("get mac error\n");
			close(sock);
			return -1;
		}
		memcpy(&macaddr, &ifr.ifr_hwaddr, sizeof(struct sockaddr_in));

		//get ifindex
		memset(&ifr.ifr_ifru, 0, sizeof(ifr.ifr_ifru));
		if (ioctl (sock, SIOCGIFINDEX, &ifr) < 0)
		{
			log_error("get ifindex error");
			close(sock);
			return -1;
		}
		ifindex = ifr.ifr_ifindex;
	}
	close(sock);

	//set arp
	{
		typedef struct ARP_PACKET
		{
		 unsigned char dest_mac[6];
		 unsigned char src_mac[6];
		 unsigned short type;
		 unsigned short hw_type;
		 unsigned short pro_type;
		 unsigned char hw_len;
		 unsigned char pro_len;
		 unsigned short op;
		 unsigned char from_mac[6];
		 unsigned char from_ip[4];
		 unsigned char to_mac[6];
		 unsigned char to_ip[4];
		}ARP_PACKET;

		ARP_PACKET arpPacket;
		struct sockaddr_ll dest;
		struct sockaddr_in ip;

		sock = socket(PF_PACKET,SOCK_RAW, htons(ETH_P_RARP));
		if (sock < 0) {
			log_error("create socket error");
			return -1;
		}

		//set ip address
		{
			ip.sin_family = AF_INET;
			if(!inet_aton(vip, &ip.sin_addr))
			{
				log_error("vip error\n");
				close(sock);
				return -1;
			}
		}

		memset(&dest, 0, sizeof(struct sockaddr_ll));
		dest.sll_family = AF_PACKET;
		dest.sll_halen =  ETH_ALEN;
		dest.sll_ifindex = ifindex;
		memcpy(dest.sll_addr, macaddr.sa_data, ETH_ALEN);

		arpPacket.type     = htons(ETHERTYPE_ARP);
		memset(arpPacket.dest_mac, 0xff, 6);
		memcpy(arpPacket.src_mac, macaddr.sa_data, 6);
		arpPacket.hw_type  = htons(ARPHRD_ETHER);
		arpPacket.pro_type = htons(ETH_P_IP);
		arpPacket.hw_len   = ETH_ALEN;
		arpPacket.pro_len  = 4;
		arpPacket.op       = htons(ARPOP_REPLY);
		memcpy(arpPacket.from_mac, macaddr.sa_data, 6);
		memcpy(arpPacket.from_ip, &ip.sin_addr.s_addr, 4);
		memset(arpPacket.to_ip, 0x00, 4);
		memset(arpPacket.to_mac, 0xff, 6);
		if(sendto(sock, &arpPacket, sizeof(arpPacket), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0)
		{
			log_error("send packet error");
			close(sock);
			return -1;
		}
		close(sock);
	}

	return 0;
}

static int update_route_byArpping(const char* ifname, const char *vip)
{
	char arpcmd[512];
	struct ifreq ifr;
	unsigned int i = 0;

	while(ifname[i] && ifname[i++] != ':');
	memset(&ifr, 0, sizeof(ifr));
	memcpy(ifr.ifr_name, ifname, i - 1);
	ifr.ifr_name[IFNAMSIZ - 1] = '\0';

	memset(arpcmd, 0, 512);
	snprintf(arpcmd, 512, "/sbin/arping -A -c 1 -I %s %s > /dev/null 2>&1", (char*)ifr.ifr_name, vip);
	system(arpcmd);

	return 0;
}

static const char *get_name(char *name, const char *p)
{
    while (isspace(*p))
	p++;
    while (*p) {
	if (isspace(*p))
	    break;
	if (*p == ':') {	/* could be an alias */
		const char *dot = p++;
 		while (*p && isdigit(*p)) p++;
		if (*p == ':') {
			/* Yes it is, backup and copy it. */
			p = dot;
			*name++ = *p++;
			while (*p && isdigit(*p)) {
				*name++ = *p++;
			}
		} else {
			/* No, it isn't */
			p = dot;
	    }
	    p++;
	    break;
	}
	*name++ = *p++;
    }
    *name++ = '\0';
    return p;
}

static InterfaceNameNode* get_allInterfaceName(void)
{
	FILE *fh;
	char buf[512];
	InterfaceNameNode *node = NULL, *head = NULL;
	char *_PATH_PROCNET_DEV = "/proc/net/dev";

	fh = fopen(_PATH_PROCNET_DEV, "r");
	if (!fh) {
		log_error("fopen file: %s failed.", _PATH_PROCNET_DEV);
		return head;
	}

	if (fgets(buf, sizeof buf, fh)){}
		/* eat line */
	if (fgets(buf, sizeof buf, fh)){}
		/* eat line */

	while (fgets(buf, sizeof buf, fh)) {
		node = malloc(sizeof(InterfaceNameNode));
		if (!node) {
			log_error("malloc InterfaceName failed.");
			fclose(fh);
			return head;
		}

		//get interface name
		get_name(node->name, buf);

		//add node to list
		if (!head)
			head = node;
		else
			head->next = node;
		node->next = NULL;
	}
	fclose(fh);
	return head;
}

static char* get_validInterfaceName(void)
{
	int i;
	char *ifname = NULL;
	struct InterfaceNameNode *head = NULL, *tmp;

	//get all interface name
	if ((head = get_allInterfaceName()) == NULL){
		log_error("get all interface name error");
		return ifname;
	}

	//get real interface name,except lo
	tmp = head;
	while(tmp) {
		//virtual interface name
		i = 0;
		while(tmp->name[i] && tmp->name[i++] != ':');
		if (tmp->name[i-1] && tmp->name[i-1] == ':')
			continue;

		//lo
		if (strcmp(tmp->name, "lo")){
			ifname = malloc(sizeof(IFNAMSIZ));
			if (ifname) {
				strncpy(ifname, tmp->name, IFNAMSIZ);
			}
			break;
		}
		tmp = tmp->next;
	}

	//free
	while(head){
		tmp = head;
		head = head->next;
		free(tmp);
	}

	return ifname;
}

static char* get_virtualInterfaceName(void)
{
	char *realIfName = NULL;
	char *vIfName = NULL;

	realIfName = get_realInterfaceName();
	if (!realIfName) {
		log_error("get_validInterfaceName error");
		return vIfName;
	}

	vIfName = malloc(sizeof(IFNAMSIZ));
	if(!vIfName) {
		log_error("malloc error");
		return vIfName;
	}
	memset(vIfName, 0, IFNAMSIZ);
	snprintf(vIfName, IFNAMSIZ, "%s:0", realIfName);

	free(realIfName);

	return vIfName;
}

static bool  is_realInterfaceName(const char *ifname)
{
	unsigned int i = 0;

	//filter virtual interface name
	while(ifname[i] && ifname[i++] != ':');
	if (i < strlen(ifname))
		return false;

	//filter lo interface name
	if (strcmp(ifname, "lo")) {
		return true;
	}
	return false;
}

static char* get_realInterfaceName(void)
{
	FILE *fh;
	char buf[512];
	char * ifname = NULL;
	char *_PATH_PROCNET_DEV = "/proc/net/dev";

	fh = fopen(_PATH_PROCNET_DEV, "r");
	if (!fh) {
		log_error("fopen file: %s failed.", _PATH_PROCNET_DEV);
		return ifname;
	}

	if (fgets(buf, sizeof buf, fh)){}
		/* eat line */
	if (fgets(buf, sizeof buf, fh)){}
		/* eat line */

	while (fgets(buf, sizeof buf, fh)) {
		char name[IFNAMSIZ];
		//get interface name
		memset(name, 0, IFNAMSIZ);
		get_name(name, buf);

		//judge interface name
		if (is_realInterfaceName(name)){
			ifname = malloc(IFNAMSIZ);
			if(!ifname) {
				return ifname;
			}
			memset(ifname, 0, IFNAMSIZ);
			memcpy(ifname, name, IFNAMSIZ);
			ifname[IFNAMSIZ] = '\0';
			break;
		}
	}
	fclose(fh);
	return ifname;
}
