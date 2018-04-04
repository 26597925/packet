LOCAL_PATH := $(call my-dir)
MY_LOCAL_PATH := $(LOCAL_PATH)

include $(CLEAR_VARS)
LOCAL_MODULE    := libpcap
LOCAL_SRC_FILES := libpcap.cpp Base64.cpp

LOCAL_C_INCLUDES := $(MY_LOCAL_PATH)/libpcap $(MY_LOCAL_PATH)/libiconv/include $(MY_LOCAL_PATH)/libcurl/include external/zlib

LOCAL_STATIC_LIBRARIES := libpcap libiconv libz 

LOCAL_SHARED_LIBRARIES += liblog libcurl

LOCAL_LDLIBS := -ldl

#include $(BUILD_SHARED_LIBRARY) 
include $(BUILD_EXECUTABLE)

include $(MY_LOCAL_PATH)/libpcap/Android.mk
include $(MY_LOCAL_PATH)/libiconv/Android.mk
include $(MY_LOCAL_PATH)/libcurl/Android.mk


