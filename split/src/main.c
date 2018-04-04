#include "hlsenc.h"

int main(int argc ,char ** argv)
{
	av_register_all();
	avformat_network_init();

	/*init_demux(INPUTURL,&icodec);
	printf("--------程序运行开始----------\n");
	//////////////////////////////////////////////////////////////////////////
	slice_up();
	//////////////////////////////////////////////////////////////////////////
	uinit_demux();
	printf("--------程序运行结束----------\n");
	printf("-------请按任意键退出---------\n");*/
	
	//char *url = "http://rrsm.iptv.gd.cn:30001/PLTV/88888905/224/3221227511/1.m3u8";
	char *url = "http://weblive.hebtv.com/live/hbws_bq/index.m3u8";
	//char *url = "rtmp://livetv.dhtv.cn/live/financial";
	//char *url = "http://cctv1.vtime.cntv.wscdns.com/live/cctv1hls_/index.m3u8?ptype=1&amode=1&AUTH=2cn/eV4wKrhD8SYUE56ehAEvx2hpX6Hq7wBDdQwYDW1ph3EKpTzJz4o9tdERbWyy+mWlJF43B3oZ0gLpu5csqQ==";
	//char *url = "rtmp://124.132.96.20/live/ltv2";
	
	HLSContext *hlscontext = init_hlscontex(url);
	
	start_slice(hlscontext);
	
	return getchar();
}