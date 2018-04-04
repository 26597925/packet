#ifndef __HLSSENC_H__
#define __HLSSENC_H__

#include <float.h>
#include <stdint.h>

#include "libavutil/mathematics.h"
#include "libavutil/parseutils.h"
#include "libavutil/avstring.h"
#include "libavutil/opt.h"
#include "libavutil/log.h"

#include "libavformat/avformat.h"
#define IO_BUFFER_SIZE      32768

typedef struct ListEntry {
    char  name[1024];
    double   duration;
    struct ListEntry *next;
} ListEntry;

typedef struct HLSContext {
	char *input_url;
	char *ouput_url;
	AVFormatContext *input_avf;
    unsigned number;
	float time;
    int  size;
    int  wrap;
	
    int64_t sequence;
    int64_t start_sequence;
    AVOutputFormat *oformat;
    AVFormatContext *avf;
    int64_t recording_time;
    int has_video;
    int64_t start_pts;
    int64_t end_pts;
    double duration;      // last segment duration computed so far, in seconds
    int nb_entries;
    ListEntry *list;
    ListEntry *end_list;
    char *basename;
    AVIOContext *pb;
} HLSContext;

typedef struct ts_buffer{
	uint8_t *ptr;
	size_t len;
} ts_buffer_t;

HLSContext *init_hlscontex(char *url);

void start_slice(HLSContext *hls);

void stop_slice(HLSContext *hls);

#endif
