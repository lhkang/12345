cmd_qbman/qbman_debug.o = gcc -Wp,-MD,qbman/.qbman_debug.o.d.tmp  -m64 -pthread  -march=native -DRTE_MACHINE_CPUFLAG_SSE -DRTE_MACHINE_CPUFLAG_SSE2 -DRTE_MACHINE_CPUFLAG_SSE3 -DRTE_MACHINE_CPUFLAG_SSSE3 -DRTE_MACHINE_CPUFLAG_SSE4_1 -DRTE_MACHINE_CPUFLAG_SSE4_2 -DRTE_MACHINE_CPUFLAG_AES -DRTE_MACHINE_CPUFLAG_PCLMULQDQ -DRTE_MACHINE_CPUFLAG_AVX -DRTE_MACHINE_CPUFLAG_RDRAND -DRTE_MACHINE_CPUFLAG_FSGSBASE -DRTE_MACHINE_CPUFLAG_F16C -DRTE_MACHINE_CPUFLAG_AVX2  -I/home/kang/dpdk-18.05/build/include -include /home/kang/dpdk-18.05/build/include/rte_config.h -DALLOW_EXPERIMENTAL_API -O3 -W -Wall -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wold-style-definition -Wpointer-arith -Wcast-align -Wnested-externs -Wcast-qual -Wformat-nonliteral -Wformat-security -Wundef -Wwrite-strings -Wdeprecated -I/home/kang/dpdk-18.05/drivers/bus/fslmc -I/home/kang/dpdk-18.05/drivers/bus/fslmc/mc -I/home/kang/dpdk-18.05/drivers/bus/fslmc/qbman/include -I/home/kang/dpdk-18.05/lib/librte_eal/common    -o qbman/qbman_debug.o -c /home/kang/dpdk-18.05/drivers/bus/fslmc/qbman/qbman_debug.c 
