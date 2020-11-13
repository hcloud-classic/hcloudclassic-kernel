#ifndef __HCCSYMS__
#define __HCCSYMS__

#ifndef __ASSEMBLY__

typedef enum hccsyms_val {
	HCCSYMS_UNDEF, // Must be the first one
	HCCSYMS_VM_OPS_NULL,
	HCCSYMS_VM_OPS_SHM,
	HCCSYMS_VM_OPS_SHMEM,
	HCCSYMS_VM_OPS_FILE_GENERIC,
	HCCSYMS_VM_OPS_FILE_EXT4,

} hccsyms_val_t;

int hccsyms_register(enum hccsyms_val v, void* p);
int hccsyms_unregister(enum hccsyms_val v);

enum hccsyms_val hccsyms_export(void* p);
void* hccsyms_import(enum hccsyms_val v);

extern int init_hccsyms(void);

#endif /* __ASSEMBLY__ */

#endif /* __HCCSYMS__ */
