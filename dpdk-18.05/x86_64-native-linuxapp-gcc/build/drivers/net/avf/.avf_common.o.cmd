cmd_avf_common.o = gcc -Wp,-MD,./.avf_common.o.d.tmp  -m64 -pthread  -march=native -DRTE_MACHINE_CPUFLAG_SSE -DRTE_MACHINE_CPUFLAG_SSE2 -DRTE_MACHINE_CPUFLAG_SSE3 -DRTE_MACHINE_CPUFLAG_SSSE3 -DRTE_MACHINE_CPUFLAG_SSE4_1 -DRTE_MACHINE_CPUFLAG_SSE4_2 -DRTE_MACHINE_CPUFLAG_AES -DRTE_MACHINE_CPUFLAG_PCLMULQDQ -DRTE_MACHINE_CPUFLAG_AVX -DRTE_MACHINE_CPUFLAG_RDRAND -DRTE_MACHINE_CPUFLAG_FSGSBASE -DRTE_MACHINE_CPUFLAG_F16C -DRTE_MACHINE_CPUFLAG_AVX2  -I/home/kang/dpdk-18.05/x86_64-native-linuxapp-gcc/include -include /home/kang/dpdk-18.05/x86_64-native-linuxapp-gcc/include/rte_config.h -O3 -Wno-pointer-to-int-cast   -o avf_common.o -c /home/kang/dpdk-18.05/drivers/net/avf/base/avf_common.c 
