cmd_dpaa_rxtx.o = gcc -Wp,-MD,./.dpaa_rxtx.o.d.tmp  -I/home/kang/dpdk-18.05/drivers/net/dpaa -m64 -pthread  -march=native -DRTE_MACHINE_CPUFLAG_SSE -DRTE_MACHINE_CPUFLAG_SSE2 -DRTE_MACHINE_CPUFLAG_SSE3 -DRTE_MACHINE_CPUFLAG_SSSE3 -DRTE_MACHINE_CPUFLAG_SSE4_1 -DRTE_MACHINE_CPUFLAG_SSE4_2 -DRTE_MACHINE_CPUFLAG_AES -DRTE_MACHINE_CPUFLAG_PCLMULQDQ -DRTE_MACHINE_CPUFLAG_AVX -DRTE_MACHINE_CPUFLAG_RDRAND -DRTE_MACHINE_CPUFLAG_FSGSBASE -DRTE_MACHINE_CPUFLAG_F16C -DRTE_MACHINE_CPUFLAG_AVX2  -I/home/kang/dpdk-18.05/build/include -include /home/kang/dpdk-18.05/build/include/rte_config.h -O3 -W -Wall -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wold-style-definition -Wpointer-arith -Wcast-align -Wnested-externs -Wcast-qual -Wformat-nonliteral -Wformat-security -Wundef -Wwrite-strings -Wdeprecated -Wno-pointer-arith -I/home/kang/dpdk-18.05/drivers/net/dpaa/ -I/home/kang/dpdk-18.05/drivers/net/dpaa/include -I/home/kang/dpdk-18.05/drivers/bus/dpaa -I/home/kang/dpdk-18.05/drivers/bus/dpaa/include/ -I/home/kang/dpdk-18.05/drivers/bus/dpaa/base/qbman -I/home/kang/dpdk-18.05/drivers/mempool/dpaa -I/home/kang/dpdk-18.05/drivers/event/dpaa -I/home/kang/dpdk-18.05/lib/librte_eal/common/include -I/home/kang/dpdk-18.05/lib/librte_eal/linuxapp/eal/include -DALLOW_EXPERIMENTAL_API    -o dpaa_rxtx.o -c /home/kang/dpdk-18.05/drivers/net/dpaa/dpaa_rxtx.c 
