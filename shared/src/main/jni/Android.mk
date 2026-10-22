LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := xcertplay_i2c
LOCAL_SRC_FILES := linux_i2c_jni.c
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := local_hotspot_radio
LOCAL_SRC_FILES := local_hotspot_radio.c
LOCAL_CFLAGS := -Wall -Wextra -Werror
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := speex_echo
LOCAL_SRC_FILES := speex_echo_jni.c \
    speexdsp/mdf.c speexdsp/preprocess.c speexdsp/fftwrap.c \
    speexdsp/kiss_fft.c speexdsp/kiss_fftr.c speexdsp/filterbank.c
LOCAL_C_INCLUDES := $(LOCAL_PATH)/speexdsp $(LOCAL_PATH)/speexdsp/include
LOCAL_CFLAGS := -O2 -DFLOATING_POINT -DUSE_KISS_FFT -DEXPORT= -Wno-unused-parameter
LOCAL_LDLIBS := -lm
include $(BUILD_SHARED_LIBRARY)

# 用户态 lwIP TCP/IP 协议栈，用于 NCM 以太网中继，无需 VpnService/TUN
# 源码由 scripts/prepare-lwip.py 以固定 commit 拉取到 shared/src/main/jni/lwip
ifeq ($(wildcard $(LOCAL_PATH)/lwip/src/include/lwip/opt.h),)
$(error lwip sources missing: run scripts/prepare-lwip.py)
endif

include $(CLEAR_VARS)
LOCAL_MODULE := lwip_ncm_relay
LOCAL_SRC_FILES := lwip_ncm_relay.c \
    lwip/src/core/init.c \
    lwip/src/core/def.c \
    lwip/src/core/inet_chksum.c \
    lwip/src/core/ip.c \
    lwip/src/core/mem.c \
    lwip/src/core/memp.c \
    lwip/src/core/netif.c \
    lwip/src/core/pbuf.c \
    lwip/src/core/raw.c \
    lwip/src/core/sys.c \
    lwip/src/core/tcp.c \
    lwip/src/core/tcp_in.c \
    lwip/src/core/tcp_out.c \
    lwip/src/core/timeouts.c \
    lwip/src/core/udp.c \
    lwip/src/core/ipv4/etharp.c \
    lwip/src/core/ipv4/icmp.c \
    lwip/src/core/ipv4/ip4.c \
    lwip/src/core/ipv4/ip4_addr.c \
    lwip/src/core/ipv4/ip4_frag.c \
    lwip/src/core/ipv6/ethip6.c \
    lwip/src/core/ipv6/icmp6.c \
    lwip/src/core/ipv6/inet6.c \
    lwip/src/core/ipv6/ip6.c \
    lwip/src/core/ipv6/ip6_addr.c \
    lwip/src/core/ipv6/mld6.c \
    lwip/src/core/ipv6/nd6.c \
    lwip/src/netif/ethernet.c

LOCAL_C_INCLUDES := $(LOCAL_PATH)/lwip_port \
    $(LOCAL_PATH)/lwip/src/include

LOCAL_CFLAGS := -O2 -Wno-unused-parameter -Wno-sign-compare
LOCAL_LDLIBS := -llog
include $(BUILD_SHARED_LIBRARY)
