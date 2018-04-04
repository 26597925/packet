#include "hlsenc.h"

//http://blog.csdn.net/wishfly/article/details/51821731
static int write_buffer(void *opaque, uint8_t *buf, int buf_size)
{  
	ts_buffer_t *ts_buffer = (ts_buffer_t *)opaque;
	ts_buffer->ptr = realloc(ts_buffer->ptr, ts_buffer->len + buf_size + 1);
	memcpy(&(ts_buffer->ptr[ts_buffer->len]), buf, buf_size);
	ts_buffer->len += buf_size;
	ts_buffer->ptr[ts_buffer->len] = 0;
	//printf("call %s %s %d %d\n",__FILE__,__FUNCTION__,__LINE__, buf_size);
	return 0;
}

static int append_entry(HLSContext *hls, double duration)
{
    ListEntry *en = av_malloc(sizeof(*en));

    if (!en)
        return AVERROR(ENOMEM);

    av_strlcpy(en->name, av_basename(hls->avf->filename), sizeof(en->name));

    en->duration = duration;
    en->next     = NULL;

    if (!hls->list)
        hls->list = en;
    else
        hls->end_list->next = en;

    hls->end_list = en;

    if (hls->size && hls->nb_entries >= hls->size) {
        en = hls->list;
        hls->list = en->next;
        av_free(en);
    } else
        hls->nb_entries++;

    hls->sequence++;

    return 0;
}

static void free_entries(HLSContext *hls)
{
    ListEntry *p = hls->list, *en;

    while(p) {
        en = p;
        p = p->next;
        av_free(en);
    }
}

static int hls_window(HLSContext *hls, int last)
{
	char *write_buf = NULL;
    AVFormatContext *s = hls->input_avf;
    ListEntry *en;
    int target_duration = 0;
    int ret = 0;
    int64_t sequence = FFMAX(hls->start_sequence, hls->sequence - hls->nb_entries);

	write_buf = (char *)malloc(sizeof(char) * 1024);
	
	if (!write_buf) 
	{
		return -1;
	}
	
	for (en = hls->list; en; en = en->next) {
        if (target_duration < en->duration)
            target_duration = ceil(en->duration);
    }
	
	sprintf(write_buf, "#EXTM3U\n");
    sprintf(write_buf, "%s#EXT-X-VERSION:3\n", write_buf);
    sprintf(write_buf, "%s#EXT-X-TARGETDURATION:%d\n", write_buf, target_duration);
    sprintf(write_buf, "%s#EXT-X-MEDIA-SEQUENCE:%"PRId64"\n", write_buf, sequence);
	
	for (en = hls->list; en; en = en->next) {
        sprintf(write_buf, "%s#EXTINF:%f,\n", write_buf, en->duration);

        sprintf(write_buf, "%s%s\n", write_buf, en->name);
    }

    if (last)
        sprintf(write_buf, "%s#EXT-X-ENDLIST\n", write_buf);
	
	printf("call %s %s %d %s\n",__FILE__,__FUNCTION__,__LINE__, write_buf);

    return ret;
}

static int hls_mux_init(HLSContext *hls)
{
	AVFormatContext *s = hls->input_avf;
    AVFormatContext *oc;
    int i;

    hls->avf = oc = avformat_alloc_context();
    if (!oc)
        return AVERROR(ENOMEM);

    oc->oformat            = hls->oformat;
    oc->interrupt_callback = s->interrupt_callback;

    for (i = 0; i < s->nb_streams; i++) {
        AVStream *st;
        if (!(st = avformat_new_stream(oc, NULL)))
            return AVERROR(ENOMEM);
        avcodec_copy_context(st->codec, s->streams[i]->codec);
        st->sample_aspect_ratio = s->streams[i]->sample_aspect_ratio;
    }

    return 0;
}

static int hls_start(HLSContext *hls)
{
   AVFormatContext *s = hls->input_avf;
    AVFormatContext *oc = hls->avf;
    int err = 0;

    if (av_get_frame_filename(oc->filename, sizeof(oc->filename),
                              hls->basename, hls->wrap ? hls->sequence % hls->wrap : hls->sequence) < 0) {
        av_log(oc, AV_LOG_ERROR, "Invalid segment filename template '%s'\n", hls->basename);
        return AVERROR(EINVAL);
    }
    hls->number++;

	printf("call %s %s %d %s\n",__FILE__,__FUNCTION__,__LINE__, oc->filename);
	
	unsigned char *buffer = (unsigned char *)av_malloc(IO_BUFFER_SIZE);
	ts_buffer_t *ts_buffer = av_mallocz(sizeof(ts_buffer_t) + IO_BUFFER_SIZE);
	AVIOContext *avio_out = avio_alloc_context(buffer, IO_BUFFER_SIZE, AVIO_FLAG_WRITE, ts_buffer, NULL, &write_buffer, NULL);
	oc->pb = avio_out;
	oc->flags = AVFMT_FLAG_CUSTOM_IO;

    if (oc->oformat->priv_class && oc->priv_data)
        av_opt_set(oc->priv_data, "mpegts_flags", "resend_headers", 0);

    return 0;
}

static int hls_write_header(HLSContext *hls)
{
	AVFormatContext *s = hls->input_avf;
    int ret, i;
    char *p;
    const char *pattern = "%d.ts";
    int basename_size = strlen(hls->ouput_url) + strlen(pattern) + 1;

    hls->sequence       = hls->start_sequence;
    hls->recording_time = hls->time * AV_TIME_BASE;
    hls->start_pts      = AV_NOPTS_VALUE;

    for (i = 0; i < s->nb_streams; i++)
        hls->has_video +=
            s->streams[i]->codec->codec_type == AVMEDIA_TYPE_VIDEO;

    if (hls->has_video > 1)
        av_log(s, AV_LOG_WARNING,
               "More than a single video stream present, "
               "expect issues decoding it.\n");

    hls->oformat = av_guess_format("mpegts", NULL, NULL);

    if (!hls->oformat) {
        ret = AVERROR_MUXER_NOT_FOUND;
        goto fail;
    }

    hls->basename = av_malloc(basename_size);

    if (!hls->basename) {
        ret = AVERROR(ENOMEM);
        goto fail;
    }

    strcpy(hls->basename, hls->ouput_url);

    p = strrchr(hls->basename, '.');

    if (p)
        *p = '\0';

    av_strlcat(hls->basename, pattern, basename_size);

    if ((ret = hls_mux_init(hls)) < 0)
        goto fail;

    if ((ret = hls_start(hls)) < 0)
        goto fail;

    if ((ret = avformat_write_header(hls->avf, NULL)) < 0)
        return ret;


fail:
    if (ret) {
        av_free(hls->basename);
        if (hls->avf)
            avformat_free_context(hls->avf);
    }
    return ret;
}

static int write_tsbuffer(HLSContext *hls)
{
	AVFormatContext *oc = hls->avf;
	AVIOContext *avio_out = oc->pb;
	if(avio_out->opaque != NULL)
	{
		avio_flush(avio_out);
		ts_buffer_t *ts_buffer = (ts_buffer_t *) avio_out->opaque;
		printf("call %s %s %d %s\n",__FILE__,__FUNCTION__,__LINE__, oc->filename);
		printf("call %s %s %d %d\n",__FILE__,__FUNCTION__,__LINE__, ts_buffer->len);
		if(ts_buffer->len == 0)
		{
			av_free(ts_buffer);
			return 0;
		}
		av_freep(&avio_out->buffer);
		av_free(avio_out);
		return 1;
	}
	return 0;
}


static int hls_write_packet(HLSContext *hls, AVPacket *pkt)
{
    AVFormatContext *s = hls->input_avf;
    AVFormatContext *oc = hls->avf;
    AVStream *st = s->streams[pkt->stream_index];
    int64_t end_pts = hls->recording_time * hls->number;
    int is_ref_pkt = 1;
    int ret, can_split = 1;

    if (hls->start_pts == AV_NOPTS_VALUE) {
        hls->start_pts = pkt->pts;
        hls->end_pts   = pkt->pts;
    }

    if (hls->has_video) {
        can_split = st->codec->codec_type == AVMEDIA_TYPE_VIDEO &&
                    pkt->flags & AV_PKT_FLAG_KEY;
        is_ref_pkt = st->codec->codec_type == AVMEDIA_TYPE_VIDEO;
    }
    if (pkt->pts == AV_NOPTS_VALUE)
        is_ref_pkt = can_split = 0;

    if (is_ref_pkt)
        hls->duration = (double)(pkt->pts - hls->end_pts)
                                   * st->time_base.num / st->time_base.den;

    if (can_split && av_compare_ts(pkt->pts - hls->start_pts, st->time_base,
                                   end_pts, AV_TIME_BASE_Q) >= 0) {
        ret = append_entry(hls, hls->duration);
        if (ret)
            return ret;

        hls->end_pts = pkt->pts;
        hls->duration = 0;

        av_write_frame(oc, NULL); /* Flush any buffered data */
		write_tsbuffer(hls);

        ret = hls_start(hls);

        if (ret)
            return ret;

        oc = hls->avf;

        if ((ret = hls_window(hls, 0)) < 0)
            return ret;
    }

    ret = ff_write_chained(oc, pkt->stream_index, pkt, s);

    return ret;
}

static int hls_write_trailer(HLSContext *hls)
{
	AVFormatContext *s = hls->input_avf;
    AVFormatContext *oc = hls->avf;

    av_write_trailer(oc);
    avio_closep(&oc->pb);
    av_free(hls->basename);
    append_entry(hls, hls->duration);
    avformat_free_context(oc);
    hls->avf = NULL;
    hls_window(hls, 1);

    free_entries(hls);
    avio_close(hls->pb);
    return 0;
}

static int init_demux(HLSContext *hls)
{
	AVFormatContext *input_avf = NULL;
	if (avformat_open_input(&input_avf, hls->input_url,NULL, NULL) != 0)
	{
		return -1;
	}
	
	if(avformat_find_stream_info(input_avf, NULL) < 0)
	{
		return -1;
	}
	
	printf("call %s %s %d %s\n",__FILE__,__FUNCTION__,__LINE__, hls->input_url);
	
	av_dump_format(input_avf, -1, hls->input_url, 0);
	
	/*for (int i = 0; i < input_avf->nb_streams; i++)
	{
		if (input_avf->streams[i]->codec->codec_type == AVMEDIA_TYPE_VIDEO)
		{
			tscontext->video_stream_idx = i;
		}
		else if (tscontext->icodec->streams[i]->codec->codec_type == AVMEDIA_TYPE_AUDIO)
		{
			tscontext->audio_stream_idx = i;
		}
	}
	
	if ((strstr(tscontext->icodec->iformat->name, "flv") != NULL) || 
		(strstr(tscontext->icodec->iformat->name, "mp4") != NULL) || 
		(strstr(tscontext->icodec->iformat->name, "mov") != NULL))    
	{
		if (tscontext->icodec->streams[tscontext->video_stream_idx]->codec->codec_id == AV_CODEC_ID_H264)  //AV_CODEC_ID_H264
		{
			tscontext->vbsf_h264_toannexb = av_bitstream_filter_init("h264_mp4toannexb"); 
		}
		if (tscontext->icodec->streams[tscontext->audio_stream_idx]->codec->codec_id == AV_CODEC_ID_AAC) //AV_CODEC_ID_AAC
		{
			tscontext->vbsf_aac_adtstoasc = av_bitstream_filter_init("aac_adtstoasc");
		}
	} */
	
	hls->input_avf = input_avf;

	return 0;
}

HLSContext *init_hlscontex(char *url)
{
	HLSContext *hls = (HLSContext *)malloc(sizeof(HLSContext));
	hls->input_url = url;
	hls->ouput_url = "/data/local/output/xmts.m3u8";
	hls->input_avf = NULL;
	hls->start_sequence = 0;
	hls->time = 1.0f;
	hls->size = 3;
	hls->wrap = 0;
	return hls;
}

void start_slice(HLSContext *hls)
{
	int ret;
	
	ret = init_demux(hls);
	
	printf("call %s %s %d %d\n",__FILE__,__FUNCTION__,__LINE__, ret);
	
	ret = hls_write_header(hls);
	
	printf("call %s %s %d %d\n",__FILE__,__FUNCTION__,__LINE__, ret);
	
	int decode_done = 0;
	
	do 
	{
		AVPacket packet;
		av_init_packet(&packet);
		
		decode_done = av_read_frame(hls->input_avf, &packet);
		
		if (decode_done < 0) 
		{
			break;
		}

		if (av_dup_packet(&packet) < 0) 
		{
			av_free_packet(&packet);
			break;
		}
		
		if (packet.pts < packet.dts)
		{
			packet.pts = packet.dts;
		}
		
		hls_write_packet(hls, &packet);
		
		av_free_packet(&packet);
		
	} while (!decode_done);
	
	hls_write_trailer(hls);
	
}

void stop_slice(HLSContext *hls)
{
	
}