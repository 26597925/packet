#include "selfdefine.h"
#include "arp.h"
#include "unpifi.h"
#include "jhash.h"

/*命令行中所对应的长选项*/
static struct	option	longopts[]=
{
	{"type", required_argument, NULL, 't'},
	{"interface", required_argument, NULL, 'i'},
	{0, 0, 0, 0}
};

static	struct ipmac **hashtable;
static int bigendian=0;
static unsigned int hashsize=0;
struct in_addr localaddr;
char haddr[IFI_HADDR];

unsigned int hash_size(unsigned int number){
	unsigned int a;

	a=number/256;
	if(!a)/*number<256*/
		return(number);
	if(a>4096)
		return(4096);
	return(a);
}

void create_hashtable(unsigned int hashsize)
{
	if(!hashsize)
		err_quit("the hash size you specified is zero!");
	hashtable=(struct ipmac **)Malloc(hashsize*sizeof(struct ipmac *));
	memset(hashtable,0,hashsize*sizeof(struct ipmac *));
}

u_int32_t get_hashvalue(u_int32_t ip)
{
	if(hashsize)
		return jhash_1word(ip,0)%hashsize;
	err_quit("You didn't alloc the hashtable!");
	return -1;
}

static int parsetype(char *str)
{
	if(!strcmp(str,"scan"))
		return(TYPE_SCAN);
	return(-1);
}

static inline void isbigendian()
{
	int	a=1;
	if(*((char *)&a)!=1)
		bigendian=1;
}

/*将二进制IP地址高低位对换*/
static void	swap(u_int32_t *ipaddr)
{
	if(!bigendian)
		*ipaddr=htonl(*ipaddr);
	return;
}

/*
	给定ip地址及其掩码，计算出ip地址范围，这里没有ip地址及其
	掩码的错误检验机制。计算出的ip地址范围不包含网络地址与
	广播地址，所以startip应为网络地址加1，startip+incre+1为其网络广播地址。
*/
static void	cmpipaddr(u_int32_t ipaddr, u_int32_t netmask, u_int32_t *startip, u_int32_t *incre)
{
	u_int32_t	i=0,j;

	swap(&ipaddr);
	swap(&netmask);

	j=netmask;
	if(netmask==IN_ADDR_BROADCAST)
	{
		*startip=ipaddr;
		*incre=0;
		swap(&ipaddr);
		swap(startip);
		return;
	}	
	
	while((netmask&1)==0)
	{	
		netmask>>=1;
		i++;
	}
	netmask=j;
	*startip=(ipaddr&netmask);
	*incre=(1<<i)-2;

	swap(&ipaddr);
	swap(&netmask);
	swap(startip);
}

static void cmpipaddr2(u_int32_t ipaddr, u_int32_t netmask, u_int32_t *startip, u_int32_t *endip)
{
	u_int32_t incre;

	cmpipaddr(ipaddr,netmask,startip,&incre);
	swap(startip);
	*endip=*startip+incre;
	swap(startip);
	swap(endip);
}

static struct in_addr get_interface_info(char *ifname,char *haddr,int *hlen,
										struct in_addr *netmask,int *ifindex)
{
		struct ifi_info *ifi, *ifihead;
		int 			i;
	
		for (ifihead = ifi = Get_ifi_info(AF_INET, 0);
			 ifi != NULL; ifi = ifi->ifi_next) {
#ifdef DEBUG
			fprintf(stdout,"interface=%s\n",ifi->ifi_name);
			fprintf(stdout,"mtu=%d\n",ifi->ifi_mtu);
			fprintf(stdout,"hardware type=%u\n",ifi->ifi_hatype);
			fprintf(stdout,"hardware address=");
			for(i=0;i<ifi->ifi_hlen;i++)
				fprintf(stdout,"%x:",*(ifi->ifi_haddr+i));
			fprintf(stdout,"\n");
			fprintf(stdout,"header len=%u\n",ifi->ifi_hlen);
			if(ifi->ifi_addr)
				fprintf(stdout,"ip address=%s\n",inet_ntoa(((struct sockaddr_in *)(ifi->ifi_addr))->sin_addr)); 
			if(ifi->ifi_netmask)
				fprintf(stdout,"netmask=%s\n",inet_ntoa(((struct sockaddr_in *)(ifi->ifi_netmask))->sin_addr));
			if(ifi->ifi_brdaddr)
				fprintf(stdout,"broad address=%s\n",inet_ntoa(((struct sockaddr_in *)(ifi->ifi_brdaddr))->sin_addr));
			if(ifi->ifi_dstaddr)
				fprintf(stdout,"dst address=%s\n",inet_ntoa(((struct sockaddr_in *)(ifi->ifi_dstaddr))->sin_addr));
			fprintf(stdout,"interface index=%d\n",ifi->ifi_index);	
			fprintf(stdout,"\n");
#endif
			if(!ifname||strcmp(ifname,ifi->ifi_name))
				continue;
			if ( (i = ifi->ifi_hlen) > 0) {
				if(hlen)
					*hlen=ifi->ifi_hlen;
				if(haddr)
					memcpy(haddr,ifi->ifi_haddr,ifi->ifi_hlen);
				if(netmask)
					*netmask=((struct sockaddr_in *)(ifi->ifi_netmask))->sin_addr;
				if(ifindex)
					*ifindex=ifi->ifi_index;
				return(((struct sockaddr_in *)(ifi->ifi_addr))->sin_addr);
			}
		}
		fprintf(stdout,"success");
		free_ifi_info(ifihead);
		return((struct in_addr){0});
	}

void send_arppacket(unsigned char hlen, unsigned short arpop,char *sha,char *dha,
                         u_int32_t sip,u_int32_t dip,int ifindex,unsigned char broadcast)
{
		int sockfd;
		struct sockaddr_ll shaddr,dhaddr;
		struct arphdr *arpheader;
		struct ethhdr *ethheader;/*以太网首部*/
		char dha2[IFI_HADDR]={0xff,0xff,0xff,0xff,0xff,0xff,'\0'};
	
		sockfd=Socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	
		memset(&shaddr,0,sizeof(struct sockaddr_ll));
		shaddr.sll_family=AF_PACKET;
		shaddr.sll_protocol=htons(ETH_P_ARP);
		shaddr.sll_ifindex=ifindex;
		shaddr.sll_hatype=ARPHRD_ETHER;/*以太网*/
	
		Bind(sockfd,(struct sockaddr *)&shaddr,sizeof(struct sockaddr_ll));
	
		memset(&dhaddr,0,sizeof(struct sockaddr_ll));
		dhaddr.sll_family=AF_PACKET;
		dhaddr.sll_protocol=htons(ETH_P_ARP);
		dhaddr.sll_ifindex=ifindex;
		dhaddr.sll_hatype=ARPHRD_ETHER;
		/*下面构造链路层首部,目前只支持IEEE 802.3以太网*/
		ethheader=(struct ethhdr *)malloc(sizeof(struct ethhdr)+sizeof(struct arphdr)+2*(hlen+4));
		if(broadcast)
			memcpy(ethheader->h_dest,dha2,hlen);
		else
			memcpy(ethheader->h_dest,dha,hlen);		
		memcpy(ethheader->h_source,sha,hlen);
		ethheader->h_proto=htons(ETH_P_ARP);
		
		arpheader=(struct arphdr *)(ethheader+1);
		arpheader->ar_hrd=htons(ARPHRD_ETHER);
		arpheader->ar_pro=htons(ETH_P_IP);
		arpheader->ar_hln=hlen;
		arpheader->ar_pln=4;
		arpheader->ar_op=htons(arpop);
	//#ifdef DEBUG
	//	print(sip);
	//	print(dip);
	//#endif
		memcpy(arpheader+1, sha, hlen);
		memcpy((char *)(arpheader+1)+hlen, (char *)&sip, 4);
		if(arpop==ARPOP_REQUEST)
			memset((char *)(arpheader+1)+hlen+4, 0, hlen);
		if(arpop==ARPOP_REPLY)
			memcpy((char *)(arpheader+1)+hlen+4, dha, hlen);		
		memcpy((char *)(arpheader+1)+2*hlen+4, (char *)&dip, 4);
	//#ifdef DEBUG
	//	print((u_int32_t *)((char *)(arpheader+1)+hlen));
	//#endif
		Sendto(sockfd, ethheader, sizeof(struct ethhdr)+sizeof(struct arphdr)+2*(hlen+4), 0, 
				(struct sockaddr *)&dhaddr, sizeof(struct sockaddr_ll));
		Close(sockfd);
}

static inline int in_exclusive(u_int32_t host, u_int32_t ehoststart, u_int32_t ehostend,
									u_int32_t *ehosts, int ehosts_number)
{
	int i;
	
	if(!ehosts_number)
		return(host>=ehoststart&&host<=ehostend);

	swap(&host);
	for(i=0;i<ehosts_number;i++){
		if(host<*(ehosts+i))
			return 0;
		if(host==*(ehosts+i))
			return 1;
	}
	return 0;
}

static int 
find_hashnode(struct ipmac *ipmac,int hlen)
{
	struct ipmac **tmp;	
	struct ipmac *a;
	u_int32_t n;
		
	n=get_hashvalue(ipmac->ipaddr.s_addr);
	tmp=hashtable+n;
	while(*tmp){
		struct ipmac *t;
	
		t=*tmp;
		if((t->ipaddr.s_addr==ipmac->ipaddr.s_addr))
			return(1);		
		tmp=&(t->next);
	}
//	printf("%s:%d\n",inet_ntoa(*((struct in_addr *)&ip)),ntohs(port));	
//	fflush(stdout);
	a=(struct ipmac *)Malloc(sizeof(struct ipmac));
	a->ipaddr=ipmac->ipaddr;
	memcpy(a->haddr,ipmac->haddr,hlen);
	a->next=NULL;
	(*tmp)=a;
	return(0);
}

/*根据ip地址在ip-mac映射表中寻找其对应的mac地址,
   若未找到返回-1,否则返回1*/
static int
getmac(u_int32_t ipaddr, char *haddr, int hlen)
{
	u_int32_t n;
		
	n=get_hashvalue(ipaddr);
	struct ipmac *listhead=*(hashtable+n);

	while(listhead){
		if(listhead->ipaddr.s_addr==ipaddr){
			memcpy(haddr,listhead->haddr,hlen);
			return(1);
		}			
		listhead=listhead->next;
	}
	return(-1);
}

static void 
getipmac(void *ifindex)
{
	struct sockaddr_ll shaddr;
	char buff[100];	
	int sockfd,len;
	
	sockfd=Socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_ARP));
	
	memset(&shaddr,0,sizeof(struct sockaddr_ll));
	shaddr.sll_family=AF_PACKET;
	shaddr.sll_protocol=htons(ETH_P_ARP);
	shaddr.sll_ifindex=*((int *)ifindex);
	shaddr.sll_hatype=ARPHRD_ETHER;/*以太网*/
	shaddr.sll_pkttype=PACKET_HOST;
	Bind(sockfd,(struct sockaddr *)&shaddr,sizeof(struct sockaddr_ll));

	while((len=Recvfrom(sockfd,buff,sizeof(buff),0,NULL,0))>0){
		struct arphdr *arpheader;
		int hlen;
		unsigned short op;
		struct ipmac ipmac;
			
		if(len<sizeof(struct arphdr))
			continue;
		arpheader=(struct arphdr *)buff;
		op=ntohs(arpheader->ar_op);
		if(op!=ARPOP_REPLY)
			continue;
		hlen=arpheader->ar_hln;
		if(len<sizeof(struct arphdr)+2*(hlen+4))
			continue;
		memcpy(ipmac.haddr,arpheader+1, hlen);
		ipmac.ipaddr=*((struct in_addr *)((char *)(arpheader+1)+hlen));
		find_hashnode(&ipmac,hlen);
	}
}

static void 
printipmac(int hlen)
{
	int i;
	char macstr[50];
	
	for(i=0;i<hashsize;i++){
		struct ipmac *listhead=*(hashtable+i);
#ifdef HASHCONFLICT
		if(listhead)
			fprintf(stdout,"%d	",i);
#endif
		while(listhead){
			fprintf(stdout,"%-20s:",inet_ntoa(listhead->ipaddr));
			printMAC(macstr,listhead->haddr,hlen);
			fprintf(stdout,"%s\n",macstr);
			listhead=listhead->next;
		}
	}
}

static void hostscan(u_int32_t hoststart, u_int32_t hostend, u_int32_t *hosts, int hosts_number,
                       u_int32_t ehoststart, u_int32_t ehostend, u_int32_t *ehosts, int ehosts_number,
                       unsigned char hlen, char *haddr,u_int32_t localaddr,int ifindex)
{
	int count,size;
	pthread_t tid;

	if(hosts_number)
		size=hosts_number;
	else{
		swap(&hoststart);
		swap(&hostend);
		size=hostend-hoststart+1;
	}
	hashsize=hash_size(size);
	create_hashtable(hashsize);
	if(pthread_create(&tid,NULL,getipmac,&ifindex))
		err_quit("pthread_create error!");
	sleep(1);
	for(count=1;count<2;count++){
		swap(&ehostend);	
		swap(&ehoststart);
		if(hoststart){
			for(;hoststart<=hostend;hoststart++){
				if(in_exclusive(hoststart, ehoststart, ehostend, ehosts, ehosts_number))
					continue;
				swap(&hoststart);
#ifdef DEBUG
				fprintf(stdout,"%s,",inet_ntoa(*((struct in_addr *)&hoststart)));
#endif		
				send_arppacket(hlen, ARPOP_REQUEST, haddr, NULL, localaddr, hoststart, ifindex, 1);
				swap(&hoststart);
			}
		}
		else{
			int i;

			for(i=0;i<hosts_number;i++){
				hoststart=*(hosts+i);
				swap(&hoststart);
				if(in_exclusive(hoststart, ehoststart, ehostend, ehosts, ehosts_number))
					continue;
				swap(&hoststart);
#ifdef DEBUG
				fprintf(stdout,"%s,",inet_ntoa(*((struct in_addr *)&hoststart)));
#endif	
				send_arppacket(hlen, ARPOP_REQUEST, haddr, NULL, localaddr, hoststart, ifindex, 1);
			}
		}
		sleep(2);
	}
}

int
main(int argc, char *argv[])
{
	int type=0,options=0,number=0,ifindex,hlen;
	u_int32_t hosts[HOSTS_NUMBER],hosts_number=0,ehosts[HOSTS_NUMBER],ehosts_number=0;
	char ifi_name[IFI_NAME] = "eth0";
	int c;
	struct in_addr hoststart,hostend,ehoststart,ehostend;
	struct in_addr netmask;
	struct sockaddr_in gateway;
	hoststart.s_addr=0;
	hostend.s_addr=0;
	ehoststart.s_addr=0;
	ehostend.s_addr=0;	

	isbigendian();/*检验系统是bigendian还是littleendian*/
	opterr = 0;
	while((c=getopt_long(argc,argv,"t:i:",longopts,NULL))!=-1)
	{
		switch(c)
		{
			case 't':
				if(type)
					printf("you can specify only one arpattack type!");
				type=parsetype(optarg);
				if(type<0)
					printf("the arpattack type you specified doesn't exit!");
				break;
			case 'i':
				//fprintf(stdout,"optarg=%s\n",optarg);
				//strcpy(ifi_name,optarg);
				options|=OPT_INTERFACE;
				break;
		}
	}
	if(argc==1){
		exit(0);
	}	
	if(!type)
		err_quit("you must specify an arpattack type!");

	localaddr=get_interface_info(ifi_name, haddr, &hlen,&netmask,&ifindex);

	if(!localaddr.s_addr)
		err_quit("can't get the local ip addr on the interface %s!",ifi_name);
		
	if(!hoststart.s_addr)
		cmpipaddr2(localaddr.s_addr,netmask.s_addr,&hoststart.s_addr,&hostend.s_addr);
	
	//初始化
	fprintf(stdout,"正在初始化ip-mac映射表......\n");
	hostscan(hoststart.s_addr,hostend.s_addr,hosts,hosts_number,ehoststart.s_addr,ehostend.s_addr,
						ehosts,ehosts_number,hlen,haddr,localaddr.s_addr,ifindex);
	printipmac(hlen);
	fprintf(stdout,"初始化完毕\n");
	return(0);
}

