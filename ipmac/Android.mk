LOCAL_PATH := $(call my-dir)  
include $(CLEAR_VARS)  
  
LOCAL_ARM_MODE := arm  

LOCAL_MODULE:= ipmac  
  
LOCAL_SRC_FILES := ipmac.c  
  

  
LOCAL_PRELINK_MODULE := false  
  
  
  
include $(BUILD_EXECUTABLE)