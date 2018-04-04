LOCAL_PATH := $(call my-dir)
MY_LOCAL_PATH := $(LOCAL_PATH)
include $(CLEAR_VARS)

LOCAL_MODULE := iplist

LOCAL_SRC_FILES := arp/arp.c  \
				   arp/parse_hostnetworkmask.c \
				   arp/wrapsock.c \
                   arp/get_ifi_info.c \
				   arp/get_printMAC.c \
				   arp/getgateway.c \
				   arp/error.c \
				   arp/wrapunix.c
APP_OPTIM := release
LOCAL_C_INCLUDES := libpcap
LOCAL_STATIC_LIBRARIES := libpcap
include $(BUILD_EXECUTABLE)
include $(MY_LOCAL_PATH)/libpcap/Android.mk
