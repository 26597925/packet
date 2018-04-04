#include <pcap.h>
#include <jni.h>
#include <zlib.h>
#include <iconv.h>
#include <errno.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <pthread.h>
#include <android/log.h>
#include <curl/curl.h>

#include "Base64.h"

#define LOG_TAG "URL"
#define MAXSIZE 15500
#define CONTENT_TYPE "Content-Type: application/octet-stream"
#define CONTENT_ENCODING "Content-Encoding: gzip"
#define CONTENT_ENCODING2 "Content-Encoding: deflate"
#define TRANSFER_ENCODING "Transfer-Encoding: chunked"
#define CONTENT_LENGTH "Content-Length: "
#define HOST "Host: "
#define AKLOGE(fmt, ...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, fmt, ##__VA_ARGS__)
#define AKLOGI(fmt, ...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, fmt, ##__VA_ARGS__)


typedef struct Port_info {
	unsigned int src_port;
	unsigned int dst_port;
	unsigned int seq;
	unsigned int ack;
	unsigned int tcp_data_len;
}Port;

/*request packet info*/
typedef struct http_req_data {
	struct Port_info port;
	u_char url[0];
}req_data;


/*answer packet info*/
typedef struct http_ans_data {
	unsigned int seq;
	unsigned int ack;
	unsigned int tcp_data_len;
	struct http_ans_data *pdu;
	u_char packet[0];
}ans_data;


/*packet node*/
typedef struct http_packet_node {
	int deal_count;
	int counter;
	int flag;
	int first_size;
	int chunk;
	int gzip;
		
	struct http_req_data *req_packet;
	struct http_ans_data *ans_packet;
	struct http_packet_node *next;
}packet_node;

typedef struct cap_packet_info {
	pcap_t *device;
	struct pcap_pkthdr *pkthdr;
    const u_char *pkt_data;
}packet_info;


packet_node *list;

Port port;

int size;
int c_length;
int sequence = 0;

u_char *ungzipTemp; //解压缩数据缓存空间
u_char *gzipTemp; //压缩数据空间


unsigned char * print_tcp_packet(const char *packet);
void print_http_ans_packet(u_char  *data);
void get_http_data(u_char* data);


void print_http_req_packet(u_char *data);

void print_req_head(u_char *data, int size);
void print_ans_head(u_char *data, int size, packet_node * p);

void getPacket(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char * packet);

void get_tcphdr(u_char *packet);
int  get_chunk_data(u_char *dst, u_char *src, int data_len);
int  get_chunk_head(u_char *src, int *chunk_head_size);
int httpgzdecompress(Byte *zdata , uLong nzdata , Byte * data, uLong * ndata, int flag);

void Init();
void insert_node(packet_node *p);
void delete_node(packet_node *p);
void delete_ans_packet (ans_data *p);

int complete_packet(packet_node *p);
void* deal_anspacket(void *arg);
int print_http_data(packet_node* p,int data_len,  u_char* gzipTemp, u_char* ungzipTemp);
packet_node * judge_html(Port port);

int  print_content(u_char url[0], u_char *data);
void get_line(unsigned char *data, unsigned char *buff, int length);


int main(int argc, char *argv[])
{
	char errBuf[PCAP_ERRBUF_SIZE];
	char *devStr;

	packet_info arg1;

	devStr = pcap_lookupdev(errBuf);

	if (devStr)
	{
		printf ("Success: device: %s\n",devStr);
	}

	else
	{
		printf("error: %s\n", errBuf);
		exit(1);
	}

	pcap_t *device = pcap_open_live(devStr, 65535, 1, 1000, errBuf);

	if (!device)
	{
		printf ("error: pcap_open_live(): %s\n", errBuf);
		exit(1);
	}


	Init();

	pcap_loop(device, -1, getPacket, NULL);

	pcap_close(device);


	free (ungzipTemp);
	free (gzipTemp);
	return 0;
}

void Init()
{
	ungzipTemp =(Byte *)malloc(sizeof(Byte)*1024*512);
	gzipTemp =(Byte *)malloc(sizeof(Byte)*1024*128);

	if ( ungzipTemp == NULL || gzipTemp == NULL) {
		printf ("gzipTemp, ungzipTemp malloc error\n");
		exit (1);
	}

	memset(gzipTemp,'\0',1024*128);
	memset(ungzipTemp,'\0',1024*512);
	list = (packet_node *)malloc(sizeof(packet_node));
	list->deal_count = 0;
	list->counter = 0;
	list->flag = 0;
	list->first_size = 0;
	list->chunk = -1;
	list->gzip = -1;
	list->req_packet = NULL;
	list->ans_packet = NULL;
	list->next = NULL;
	
}

void insert_node(packet_node *p)
{
	p->next = list->next;
	list->next = p;
}

void delete_node(packet_node *p)
{
	packet_node *s = list->next;
	packet_node *t = list;
	for ( ; s != NULL; t = s, s = s->next) {
		if (p == s) {
	        t->next = s->next;

			delete_ans_packet(p->ans_packet);
			p->ans_packet = NULL;

			free(p->req_packet);
			p->req_packet = NULL;

			free (p);
			p = NULL;
		}
	}
}

void delete_ans_packet (ans_data *p)

{
	ans_data *s = p;
	ans_data *t = p;
	for ( ; s != NULL; s = t) {
	
		t = s->pdu;
		free (s);
	}
}


packet_node * judge_html(Port port)
{
	if (port.tcp_data_len <= 6)
	  return NULL;

	packet_node *p = list->next;
	for ( ; p != NULL; p = p->next) {
		if (p->req_packet->port.src_port == port.dst_port && 
					p->req_packet->port.seq + p->req_packet->port.tcp_data_len <= port.ack)
		  return p;
	}

	return NULL;
}


void* deal_anspacket(void *arg)
{
	packet_node * p = (packet_node *)arg;
	packet_node *s = list->next;
	packet_node *t = list;
	int flag = 0;

	for ( ; s != NULL; t = s, s = s->next) {
		if (s == p) {
			flag = 1;
			break;
		}
	}

	if (flag) {
		int rct = complete_packet(p);
		if (rct == 1) {
			t->next = s->next;
			delete_node (p);
			//free(p);
		}
	}
	return p;
}

int complete_packet(packet_node *p)
{
	memset(gzipTemp, '\0', sizeof(u_char)*128*1024);
	u_char *data = gzipTemp;
	ans_data *q = p->ans_packet;

	if ( q == NULL || p->flag == 0)
	  return 0;
	memcpy (data, q->packet, p->first_size);
	int data_len = 0;
	data_len += p->first_size;
	data +=p->first_size;

	ans_data *temp = q;
	ans_data *s;
	int flag = 0;
	p->deal_count++;
	int i = 0;
	
	for ( ; i < p->counter; i++) {
		flag = 0;
		s = q->pdu;
		
		for ( ; s != NULL; s = s->pdu) {
			if (temp->seq + temp->tcp_data_len == s->seq) {
				memcpy(data, s->packet, s->tcp_data_len);
				data += s->tcp_data_len;
				data_len += s->tcp_data_len;
				temp = s;
			}

			if (data_len >= c_length) {
				flag = 1;
				break;
			}
		}

		if (flag) 
		  break;
	}

	if (flag) {
		print_http_data(p, data_len,  gzipTemp, ungzipTemp);
	}

_end:
	return flag;

}

int  print_http_data(packet_node *p, int data_len,  u_char* gzipTemp, u_char* ungzipTemp)
{
	memset(ungzipTemp, '\0',sizeof(u_char)*512*1024);
	
	int rct = 0;
	uLong data_length = 512*1024;	
	if (p->gzip >= 1 && p->chunk == 1) {

		u_char *temp = (u_char *)malloc(sizeof(u_char)*128*1024);
		if (temp == NULL) {
			printf ("print_http_data(): temp malloc error\n");
			exit (1);
		}

		memset (temp, '\0', sizeof (u_char)*128*1024);
		int gzip_length = get_chunk_data(temp, gzipTemp, data_len);
		if (gzip_length == 0) {
			printf("get chunk data faile!\n");
		}
		else {
			if (httpgzdecompress(temp, gzip_length, ungzipTemp, &data_length, p->gzip) == 0 ||*ungzipTemp != '\0') {
				rct = print_content(p->req_packet->url, ungzipTemp);
			}

		}

		free(temp);
		temp = NULL;
	}
	else if (p->gzip >= 1 && p->chunk == 0) {
		if (httpgzdecompress(gzipTemp, data_len, ungzipTemp, &data_length, p->gzip) == 0 || *ungzipTemp != '\0') {
			rct = print_content(p->req_packet->url, ungzipTemp);
		}
	}
	else if (p->gzip == 0 && p->chunk == 1) {
		int length = get_chunk_data(ungzipTemp, gzipTemp, data_len);
		if (length == 0) {
			printf("!gzip-get chunk data failue!\n");

		}

		else {
			rct = print_content(p->req_packet->url, ungzipTemp);
		}
	}
	else if (p->gzip == 0 && p->chunk == 0) {
		rct = print_content(p->req_packet->url, gzipTemp);
	}

	return rct;
}


/*libpcap回调函数，处理获得数据包*/
void getPacket(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
	size = pkthdr->len;

	struct iphdr *iph = (struct iphdr*)(packet + sizeof(struct ethhdr));



	switch (iph->protocol) {
		case 6: {
					unsigned char *data = print_tcp_packet((char*)packet);

					if (size <= 0)
					  break;
					  print_http_ans_packet(data);
					  print_http_req_packet(data);
					break;
				}
	}
}


/*获得http协议头*/
unsigned char * print_tcp_packet(const char *packet)
{
	struct iphdr *iph = (struct iphdr*)(packet + sizeof(struct ethhdr));
	unsigned int ip = iph->ihl * 4; 

	struct tcphdr *tcph = (struct tcphdr*)(packet + ip + sizeof(struct ethhdr));
	int header_size = sizeof(struct ethhdr) + ip + tcph->doff*4;
	size = size - header_size;

	port.src_port = ntohs(tcph->source);
	port.dst_port = ntohs(tcph->dest);
	port.seq = ntohl(tcph->seq);
	port.ack = ntohl(tcph->ack_seq);
	port.tcp_data_len = size;

	return (unsigned char*)(packet + header_size);
}


/*获得http应答包，并分析*/
void print_http_ans_packet(u_char *data)
{
	packet_node *p  = NULL;
	p = judge_html(port);
	if ( p == NULL)
	  return;

	if (strncasecmp((const char*)data, "HTTP/1.1 200 OK", strlen ("HTTP/1.1 200 OK")) == 0 ||
				strncasecmp((const char*)data, "HTTP/1.0 200 OK", strlen("HTTP/1.0 200 OK")) == 0){
	  print_ans_head(data, size, p);
	}else {
		if (strncasecmp((const char*)data, "HTTP/1.1", strlen("HTTP/1.1")) == 0 
					|| strncasecmp((const char*)data, "HTTP/1.0", strlen("HTTP/1.0")) == 0) {
			delete_node (p);
			//free(p);
			return ;
		}

		if (p->counter >= 15) 
		  return;

		p->counter++;
		
		ans_data *q = (ans_data *)malloc(sizeof (ans_data) + MAXSIZE + 1);
		if ( q == NULL) {
			printf ("print_http_ans_packet():q malloc err \n");
			exit(1);
		}

		q->seq = port.seq;
		q->ack = port.ack;
		q->tcp_data_len = port.tcp_data_len;
		q->pdu = NULL;
		
		memcpy(q->packet, data, port.tcp_data_len);

		ans_data *s = p->ans_packet;
		ans_data *t = s;

		for ( ; s != NULL; t = s,s = s->pdu) {
		}
		if (p->ans_packet == NULL)
		  p->ans_packet = q;

		else
			t->pdu = q;
	}

	if (p->counter < 2)
	  return;
	pthread_t ntid;
	void *status;
	pthread_create (&ntid, NULL, deal_anspacket, (void *)p);
	pthread_join (ntid, &status);
}


void print_http_req_packet(u_char *data)
{
	if (strncasecmp((const char*)data, "GET ",strlen("GET ")) == 0)
	  print_req_head(data, size);

}


void print_req_head(u_char *data, int size)
{
	if (size == 0)
	  return;
	
	char host_name[100];
	char relpath[1400];
	memset(host_name, '\0', 100);
	memset(relpath,  '\0', 1400);

	char buff[MAXSIZE];
	memset(buff, '\0', MAXSIZE);
	get_line((unsigned char*)data, (unsigned char*)buff, size);
	unsigned int off = strlen(buff);
	size = size - off;
	int flag = 1;
	int  i = 0;


	if ( strstr(buff,".js") || strstr(buff, ".flv") || strstr(buff, ".swf") ||
				strstr(buff, ".mp4") ||strstr(buff, ".mp3") ||strstr(buff, ".ts") ||strstr(buff, ".apk") )
	  return;
	if(!strstr(buff,".m3u8")){
		return;
	}
	
	if (strncmp (buff, "GET / HTTP/1.0", strlen("GET / HTTP/1.0"))!=0 && strncmp(buff, "GET / HTTP/1.1", strlen("GET / HTTP/1.1")) != 0)
	strncpy (relpath, buff + strlen ("GET "), strlen(buff) - strlen( "HTTP/1.1\r\n") - strlen ("GET "));

	while (strcmp(buff,"\r\n") != 0 && i < 15) {
		memset(buff, '\0', sizeof(buff));
		get_line((unsigned char*)data+off, (unsigned char*)buff, size);

		if (strncasecmp (buff, HOST, strlen(HOST)) == 0) {
			strncpy (host_name, buff + strlen(HOST), strlen(buff) - strlen(HOST) -2);
		}
		
		off = off + strlen(buff);
		size = size - strlen(buff);
		i++;
	}

	if (flag) {
		packet_node *s = list->next;
		for ( ; s != NULL; s = s->next) {
			if (port.src_port == s->req_packet->port.src_port 
						&& port.seq == s->req_packet->port.seq)
			  return;
		}

		packet_node *p = (packet_node *)malloc(sizeof (packet_node));

		if ( p == NULL) {
			printf ("print_req_head():p malloc err\n");
			exit (1);
		}

		p->deal_count = 0;
		p->counter = 1;
		p->flag = 0;
		p->chunk = -1;
		p->gzip = -1;
		p->first_size = 0;
		p->req_packet = (req_data *) malloc(sizeof(req_data) + MAXSIZE + 1);

		if (p->req_packet == NULL) {
			printf ("print_req_head():p->req_packet malloc err\n");
			exit (1);
		}
		p->ans_packet = NULL;
		p->next = NULL;

		req_data *q = p->req_packet;

		q->port.src_port = port.src_port;
		q->port.dst_port = port.dst_port;
		q->port.seq = port.seq;
		q->port.ack = port.ack;
		q->port.tcp_data_len = port.tcp_data_len;
		memset(q->url, '\0', MAXSIZE+1);
		strncpy ((char*)q->url, "http://", strlen("http://"));
		strncpy ((char*)q->url + strlen("http://"), (char const*)host_name, strlen(host_name));
		strncpy ((char*)q->url + strlen("http://") + strlen(host_name), (char const*)relpath, strlen(relpath));
		insert_node(p);

		}

}


void print_ans_head(u_char *data, int size, packet_node *p)
{
	if (size == 0) 
	  return;

	int html_flag = 0;
	int gzip_flag = 0;
	int chunk_flag = 0;

	int dataSize=size;
	char buff[MAXSIZE] = {'\0'};
	char content_len[10];
	get_line((unsigned char*)data, (unsigned char*)buff, size);

	unsigned int off = strlen(buff);
	size = size - off;     
	while (strcmp(buff,"\r\n") != 0 && size >= 0) {
		memset(buff, '\0',sizeof(buff));
		get_line((unsigned char*)data+off, (unsigned char*)buff,size);
		
		if (strncasecmp(buff, CONTENT_TYPE, strlen(CONTENT_TYPE)) == 0) {
			html_flag = 1;

		}
		

		if (strncasecmp(buff, CONTENT_LENGTH, strlen(CONTENT_LENGTH)) == 0) {
			c_length = atoi(buff + strlen(CONTENT_LENGTH));
		}

		if (strncasecmp(buff, CONTENT_ENCODING, strlen(CONTENT_ENCODING)) == 0)	{
			gzip_flag = 1;
			//	  printf("%s", buff);
		}

		if (strncasecmp(buff, CONTENT_ENCODING2, strlen(CONTENT_ENCODING2)) == 0) {
			gzip_flag = 2;
		}

		if (strncasecmp(buff, TRANSFER_ENCODING, strlen(TRANSFER_ENCODING)) == 0) {
			chunk_flag = 1 ;
		}

		off = off + strlen(buff);
		size = size -strlen(buff);
	}

	if (!html_flag)	{
		return;
	}

	if (port.tcp_data_len == 159)
	  return;

	if (p->ans_packet != NULL && p->ans_packet->seq == port.seq)
	  return;

	ans_data *q  =(ans_data *) malloc(sizeof(ans_data) +MAXSIZE+1);
	p->counter++;
	p->flag = 1;
	p->chunk = chunk_flag;
	p->gzip = gzip_flag;
	p->first_size = size;

	q->seq = port.seq;
	q->ack = port.ack;
	q->tcp_data_len = port.tcp_data_len;
	memcpy(q->packet, data + off, size);
	q->pdu = NULL;

	if (p->ans_packet != NULL) {
	  q->pdu = p->ans_packet;
	  p->ans_packet = q;
	}
	else
	  p->ans_packet = q;

}

/*http协议头内容获取*/
void get_line(unsigned char *data,unsigned  char *buff, int length)
{
	int i = 0;
	char ch;

	for(; i < length; ++i) {
		ch = *(data + i);
		*(buff + i) = ch;	
		if (ch == '\n')
		  break;
	}
}

/*解http gzip压缩*/
int httpgzdecompress(Byte *zdata , uLong nzdata ,
			Byte * data, uLong * ndata, int flag)
{
	int err = 0;
	z_stream d_stream = {0}; /* decompression stream */
	static char dummy_head[2] = {
		0x8 + 0x7 * 0x10,
		(((0x8 + 0x7 * 0x10) * 0x100 + 30) / 31 * 31) & 0xFF,
	};

	d_stream.zalloc = ( alloc_func)0;
	d_stream.zfree = ( free_func)0;
	d_stream.opaque = ( voidpf)0;
	d_stream.next_in = zdata;
	d_stream.avail_in = 0;
	d_stream.next_out = data;
	if (flag == 1) {
		if( inflateInit2(&d_stream, 47) != Z_OK ) 
		  return -1;
	}
	else if (flag == 2) {
		if (inflateInit(&d_stream) != Z_OK)
		  return -1;
	}

	while (d_stream.total_out < * ndata && d_stream.total_in < nzdata) {
		d_stream.avail_in = d_stream.avail_out = 100; /* force small buffers */
		if((err = inflate(&d_stream, Z_NO_FLUSH)) == Z_STREAM_END ) break ;
		if(err != Z_OK ) {
			if(err == Z_DATA_ERROR) {
				if (flag == 2)
				  inflateReset(&d_stream);  

				d_stream.next_in = ( Bytef*) dummy_head;
				d_stream.avail_in = sizeof(dummy_head);
				if((err = inflate(&d_stream, Z_NO_FLUSH)) != Z_OK ) {
					return -1;
				}

				if (flag == 2)
				  d_stream.next_in = zdata;
			}
			else return -1;
		}
	}

	if(inflateEnd(&d_stream) != Z_OK) 
	  return -1;

	*ndata = d_stream.total_out;
	return 0;
}

char *str_split(char **stringp, const char *delim)
{
    char *s;
    const char *spanp;
    int c, sc;
    char *tok;
    if ((s = *stringp)== NULL)
        return (NULL);
    for (tok = s;;) {
        c = *s++;
        spanp = delim;
        do {
            if ((sc =*spanp++) == c) {
                if (c == 0)
                    s = NULL;
                else
                    s[-1] = 0;
                *stringp = s;
                return (tok);
            }
        } while (sc != 0);
    }
}

static char* parse_url(u_char url[0]){
	char *key = "stream_id=";
	char *keys,*value;
	char *uri = strstr((const char*)url, "?");
	char *temp = strtok( uri, "?");
    while( temp != NULL )
    {
		uri = temp;
        temp = strtok( NULL, "?");
    }
	while((keys = str_split( &uri, "&")))
	{
		if(!strncasecmp(keys, key, strlen(key))){
			value = keys;
		}
	}
	while((keys = str_split( &value, "=")))
	{
		if(strncasecmp(keys, key, strlen(key)-1) < 0){
			key = keys;
		}
	}
	return key;
}

char * str_contact(const char *str1,const char *str2)
{
     char * result;
     result = (char*)malloc(strlen(str1) + strlen(str2) + 1); //str1的长度 + str2的长度 + \0;
     if(!result){ //如果内存动态分配失败
        printf("Error: malloc failed in concat! \n");
        return NULL;
     }
     strcpy(result,str1); 
     strcat(result,str2); //字符串拼接
    return result;
}

static void send_data(char *key, char *data){
	int size = strlen("letv")+strlen(key)+strlen(data)+32;
	char uri[size];
	sprintf(uri, "type=%s&name=%s&data=%s", "letv", key, data);
	//printf("%s\n", uri);
	AKLOGE("%s\n", uri);
	/*time_t t;
    int j;
    j = time(&t);
    printf("j=%d \n", j);*/
	CURL *curl;
	CURLcode res;
	curl_global_init(CURL_GLOBAL_ALL);
	curl = curl_easy_init();
	if(curl) {
		//"http://mng.on-best.com/index.php/index/addTv"
		curl_easy_setopt(curl, CURLOPT_URL, "http://api.digomate.com/proxy/addTv");
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, uri);
		res = curl_easy_perform(curl);
		if(res != CURLE_OK)
		  fprintf(stderr, "curl_easy_perform() failed: %s\n",
				  curl_easy_strerror(res));
		curl_easy_cleanup(curl);
	}
	curl_global_cleanup();
}

/*打印内容*/
int print_content(u_char url[0], u_char *data)
{
	char *line;
	char *result = "";
	int  temp = 0;
	bool is_send = false;
	while((line = str_split( (char**)&data, "\n")))
	{
		if(!(strstr(line,"#EXT-LETV")
			||strstr(line,"#EXT-X-PROGRAM-DATE-TIME")
			||strstr(line,"#EXT-X-ALLOW-CACHE"))){
			line = str_contact(line, "\n");
			result = str_contact(result, line);
		}
		if (strncasecmp (line, "#EXT-X-MEDIA-SEQUENCE:", strlen("#EXT-X-MEDIA-SEQUENCE:")) == 0) {
			temp = atoi(line + strlen("#EXT-X-MEDIA-SEQUENCE:"));
			if(sequence == 0){
				sequence = temp;
			}else{
				if(sequence != temp){
					is_send = true;
					sequence = temp;
				}
			}
		}
	}
	if(is_send){
		AKLOGE("%s\n", result);
		printf("%s\n", result);
		int len = strlen(result);
		char *enc = base64_encode((const char*)result, len);
		send_data(parse_url(url), enc);
	}
	return 0;
}

/*将压缩后，chunk的gzip数据还原*/
int get_chunk_data(u_char *dst, u_char *src, int data_len)
{
	int chunk_data_size = 0;
	int chunk_head_size = 0;

	int gzip_length = 0;
	int data_odd = 0;

	u_char *p = src;
	u_char *q = dst;

	chunk_data_size = get_chunk_head(p, &chunk_head_size);
	if (chunk_data_size == 0)
	  return 0;

	p = p + chunk_head_size + 2;
	gzip_length =  data_len - chunk_head_size -2;
	data_odd = gzip_length;

	
	while (1) {

			//chunk的数据大于捕获的包的总长度
			if (data_odd <= chunk_data_size) {
			memcpy(q, p, data_odd);
			break;
		}

		memcpy (q, p, chunk_data_size);
		data_odd = data_odd - chunk_data_size;
		p = p + chunk_data_size;
		q = q + chunk_data_size;

		chunk_data_size = get_chunk_head(p, &chunk_head_size);
		if (chunk_data_size == 0)
		  return gzip_length;

		p = p + chunk_head_size + 2;
		gzip_length = gzip_length -chunk_head_size -2;
		data_odd = data_odd - chunk_head_size- 2;

	}

	return gzip_length;
}

/*获取每个chunk的大小，及表示chunk长度的字节数*/
int get_chunk_head(u_char *src, int *chunk_head_size)
{
	int size = 0;
	u_char *p = src;
	u_char chunk_head[10];
	memset(chunk_head, '\0', sizeof(u_char)*10);

	while ( *p!='\r'&& *(p+1)!='\n') {
		(*chunk_head_size)++;
		p++;
		if (*chunk_head_size >= 8) {
			*chunk_head_size = -1;
			return 0;
		}
	}

	strncpy((char*)chunk_head, "0x", 2);
	strncpy((char*)chunk_head + 2, (char*)src, *chunk_head_size);

	size = strtol((char*)chunk_head, NULL, 16);
	return size;
}
