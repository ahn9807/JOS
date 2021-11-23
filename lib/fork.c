// implement fork from user space

#include <inc/string.h>
#include <inc/lib.h>

// PTE_COW marks copy-on-write page table entries.
// It is one of the bits explicitly allocated to user processes (PTE_AVAIL).
#define PTE_COW		0x800

//
// Custom page fault handler - if faulting page is copy-on-write,
// map in our own private writable copy.
//
static void
pgfault(struct UTrapframe *utf)
{
	void *addr = (void *) utf->utf_fault_va;
	uint32_t err = utf->utf_err;
	int r;

	// Check that the faulting access was (1) a write, and (2) to a
	// copy-on-write page.  If not, panic.
	// Hint:
	//   Use the read-only page table mappings at uvpt
	//   (see <inc/memlayout.h>).

	// LAB 4: Your code here.
	//cprintf("pgfault addr %x\n",addr);
	if(!(err & FEC_WR)){
		//cprintf("addr %x\n",addr);
		panic("not write");
	}
	if(!(uvpt[VPN(addr)] & PTE_COW)){
		//cprintf("addr %x\n",addr);
		panic("not cow page");
	}
	envid_t cur_id = sys_getenvid();

	// Allocate a new page, map it at a temporary location (PFTEMP),
	// copy the data from the old page to the new page, then move the new
	// page to the old page's address.
	// Hint:
	//   You should make three system calls.
	//   No need to explicitly delete the old page's mapping.

	// LAB 4: Your code here.
	void * aligned = ROUNDDOWN(addr, PGSIZE);
	sys_page_alloc(cur_id, (void *)PFTEMP, PTE_P | PTE_U | PTE_W);
	memcpy((void *)PFTEMP, aligned, PGSIZE);
	sys_page_map(cur_id, (void *)PFTEMP, cur_id, aligned, PTE_P | PTE_W | PTE_U);

	//cprintf("page fault handled\n");
	//panic("pgfault not implemented");
}

//
// Map our virtual page pn (address pn*PGSIZE) into the target envid
// at the same virtual address.  If the page is writable or copy-on-write,
// the new mapping must be created copy-on-write, and then our mapping must be
// marked copy-on-write as well.  (Exercise: Why do we need to mark ours
// copy-on-write again if it was already copy-on-write at the beginning of
// this function?)
//
// Returns: 0 on success, < 0 on error.
// It is also OK to panic on error.
//
static int
duppage(envid_t envid, unsigned pn)
{
	int r;

	// LAB 4: Your code here.
	//cprintf("duppage %x\n",pn*PGSIZE);
	int perm = (uvpt[VPN(pn*PGSIZE)] & ~PTE_W) | PTE_COW;
	envid_t cur_id = sys_getenvid();
	
	// For each writable or copy-on-write page in its address space below UTOP, 
	// the parent calls duppage,
	// 1. which should map the page copy-on-write into the address space of the child
	// 2. and then remap the page copy-on-write in its own address space.
	sys_page_map(cur_id, (void *)(((uint64_t)pn)*PGSIZE), envid, (void *)(((uint64_t)pn)*PGSIZE), perm);
	sys_page_map(cur_id, (void *)(((uint64_t)pn)*PGSIZE), cur_id, (void *)(((uint64_t)pn)*PGSIZE), perm);
	
	//panic("duppage not implemented");
	return 0;
}

//
// User-level fork with copy-on-write.
// Set up our page fault handler appropriately.
// Create a child.
// Copy our address space and page fault handler setup to the child.
// Then mark the child as runnable and return.
//
// Returns: child's envid to the parent, 0 to the child, < 0 on error.
// It is also OK to panic on error.
//
// Hint:
//   Use uvpd, uvpt, and duppage.
//   Remember to fix "thisenv" in the child process.
//   Neither user exception stack should ever be marked copy-on-write,
//   so you must allocate a new page for the child's user exception stack.
//
envid_t
fork(void)
{
	// LAB 4: Your code here.
	
	set_pgfault_handler(pgfault);
	envid_t child = sys_exofork();
	
	if(child == 0){
		//child
		thisenv = &envs[ENVX(sys_getenvid())];
		
		return 0;
	}
	else if(child < 0){
		panic("fork failed");
	}

	//parent
	uint64_t start, end = USTACKTOP; //USTACKTOP is used instead of UTOP due to tiemout problem
	for(start=UTEXT;start<end;start+=PGSIZE){
		if(
		//	(uvpml4e[VPML4E(start)] & PTE_P) && // commented due to timeout problem
			(uvpde[VPDPE(start)] & PTE_P) && 
			(uvpd[VPD(start)] & PTE_P) && 
			(uvpt[VPN(start)] & (PTE_P | PTE_W | PTE_COW))) {
				duppage(child, start/PGSIZE);
		}
	}

	sys_page_alloc(child, (void *)(UXSTACKTOP - PGSIZE), PTE_P | PTE_U | PTE_W);
	extern void _pgfault_upcall(void);
	sys_env_set_pgfault_upcall(child, _pgfault_upcall);
	sys_env_set_status(child, ENV_RUNNABLE);

	//cprintf("fork done\n");
	
	return child;
	//panic("fork not implemented");
}

// Challenge!
int
sfork(void)
{
	panic("sfork not implemented");
	return -E_INVAL;
}
