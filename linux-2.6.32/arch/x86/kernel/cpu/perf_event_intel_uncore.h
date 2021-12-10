#include <linux/module.h>
#include <linux/slab.h>
#include <linux/pci.h>
#include <linux/perf_event.h>
#include "perf_event.h"

#define UNCORE_PMU_NAME_LEN		32
#define UNCORE_PMU_HRTIMER_INTERVAL	(60LL * NSEC_PER_SEC)
#define UNCORE_SNB_IMC_HRTIMER_INTERVAL (5ULL * NSEC_PER_SEC)

#define UNCORE_FIXED_EVENT		0xff
#define UNCORE_PMC_IDX_MAX_GENERIC	8
#define UNCORE_PMC_IDX_FIXED		UNCORE_PMC_IDX_MAX_GENERIC
#define UNCORE_PMC_IDX_MAX		(UNCORE_PMC_IDX_FIXED + 1)

#define UNCORE_PCI_DEV_DATA(type, idx)	((type << 8) | idx)
#define UNCORE_PCI_DEV_TYPE(data)	((data >> 8) & 0xff)
#define UNCORE_PCI_DEV_IDX(data)	(data & 0xff)
#define UNCORE_EXTRA_PCI_DEV		0xff
#define UNCORE_EXTRA_PCI_DEV_MAX	3

/* support up to 8 sockets */
#define UNCORE_SOCKET_MAX		8

#define UNCORE_EVENT_CONSTRAINT(c, n) EVENT_CONSTRAINT(c, n, 0xff)

/* NHM-EX event control */
#define NHMEX_PMON_CTL_EV_SEL_MASK	0x000000ff
#define NHMEX_PMON_CTL_UMASK_MASK	0x0000ff00
#define NHMEX_PMON_CTL_EN_BIT0		(1 << 0)
#define NHMEX_PMON_CTL_EDGE_DET		(1 << 18)
#define NHMEX_PMON_CTL_PMI_EN		(1 << 20)
#define NHMEX_PMON_CTL_EN_BIT22		(1 << 22)
#define NHMEX_PMON_CTL_INVERT		(1 << 23)
#define NHMEX_PMON_CTL_TRESH_MASK	0xff000000
#define NHMEX_PMON_RAW_EVENT_MASK	(NHMEX_PMON_CTL_EV_SEL_MASK | \
					 NHMEX_PMON_CTL_UMASK_MASK | \
					 NHMEX_PMON_CTL_EDGE_DET | \
					 NHMEX_PMON_CTL_INVERT | \
					 NHMEX_PMON_CTL_TRESH_MASK)

/* NHM-EX Ubox */
#define NHMEX_U_MSR_PMON_GLOBAL_CTL		0xc00
#define NHMEX_U_MSR_PMON_CTR			0xc11
#define NHMEX_U_MSR_PMON_EV_SEL			0xc10

#define NHMEX_U_PMON_GLOBAL_EN			(1 << 0)
#define NHMEX_U_PMON_GLOBAL_PMI_CORE_SEL	0x0000001e
#define NHMEX_U_PMON_GLOBAL_EN_ALL		(1 << 28)
#define NHMEX_U_PMON_GLOBAL_RST_ALL		(1 << 29)
#define NHMEX_U_PMON_GLOBAL_FRZ_ALL		(1 << 31)

#define NHMEX_U_PMON_RAW_EVENT_MASK		\
		(NHMEX_PMON_CTL_EV_SEL_MASK |	\
		 NHMEX_PMON_CTL_EDGE_DET)

/* NHM-EX Cbox */
#define NHMEX_C0_MSR_PMON_GLOBAL_CTL		0xd00
#define NHMEX_C0_MSR_PMON_CTR0			0xd11
#define NHMEX_C0_MSR_PMON_EV_SEL0		0xd10
#define NHMEX_C_MSR_OFFSET			0x20

/* NHM-EX Bbox */
#define NHMEX_B0_MSR_PMON_GLOBAL_CTL		0xc20
#define NHMEX_B0_MSR_PMON_CTR0			0xc31
#define NHMEX_B0_MSR_PMON_CTL0			0xc30
#define NHMEX_B_MSR_OFFSET			0x40
#define NHMEX_B0_MSR_MATCH			0xe45
#define NHMEX_B0_MSR_MASK			0xe46
#define NHMEX_B1_MSR_MATCH			0xe4d
#define NHMEX_B1_MSR_MASK			0xe4e

#define NHMEX_B_PMON_CTL_EN			(1 << 0)
#define NHMEX_B_PMON_CTL_EV_SEL_SHIFT		1
#define NHMEX_B_PMON_CTL_EV_SEL_MASK		\
		(0x1f << NHMEX_B_PMON_CTL_EV_SEL_SHIFT)
#define NHMEX_B_PMON_CTR_SHIFT		6
#define NHMEX_B_PMON_CTR_MASK		\
		(0x3 << NHMEX_B_PMON_CTR_SHIFT)
#define NHMEX_B_PMON_RAW_EVENT_MASK		\
		(NHMEX_B_PMON_CTL_EV_SEL_MASK | \
		 NHMEX_B_PMON_CTR_MASK)

/* NHM-EX Sbox */
#define NHMEX_S0_MSR_PMON_GLOBAL_CTL		0xc40
#define NHMEX_S0_MSR_PMON_CTR0			0xc51
#define NHMEX_S0_MSR_PMON_CTL0			0xc50
#define NHMEX_S_MSR_OFFSET			0x80
#define NHMEX_S0_MSR_MM_CFG			0xe48
#define NHMEX_S0_MSR_MATCH			0xe49
#define NHMEX_S0_MSR_MASK			0xe4a
#define NHMEX_S1_MSR_MM_CFG			0xe58
#define NHMEX_S1_MSR_MATCH			0xe59
#define NHMEX_S1_MSR_MASK			0xe5a

#define NHMEX_S_PMON_MM_CFG_EN			(0x1ULL << 63)
#define NHMEX_S_EVENT_TO_R_PROG_EV		0

/* NHM-EX Mbox */
#define NHMEX_M0_MSR_GLOBAL_CTL			0xca0
#define NHMEX_M0_MSR_PMU_DSP			0xca5
#define NHMEX_M0_MSR_PMU_ISS			0xca6
#define NHMEX_M0_MSR_PMU_MAP			0xca7
#define NHMEX_M0_MSR_PMU_MSC_THR		0xca8
#define NHMEX_M0_MSR_PMU_PGT			0xca9
#define NHMEX_M0_MSR_PMU_PLD			0xcaa
#define NHMEX_M0_MSR_PMU_ZDP_CTL_FVC		0xcab
#define NHMEX_M0_MSR_PMU_CTL0			0xcb0
#define NHMEX_M0_MSR_PMU_CNT0			0xcb1
#define NHMEX_M_MSR_OFFSET			0x40
#define NHMEX_M0_MSR_PMU_MM_CFG			0xe54
#define NHMEX_M1_MSR_PMU_MM_CFG			0xe5c

#define NHMEX_M_PMON_MM_CFG_EN			(1ULL << 63)
#define NHMEX_M_PMON_ADDR_MATCH_MASK		0x3ffffffffULL
#define NHMEX_M_PMON_ADDR_MASK_MASK		0x7ffffffULL
#define NHMEX_M_PMON_ADDR_MASK_SHIFT		34

#define NHMEX_M_PMON_CTL_EN			(1 << 0)
#define NHMEX_M_PMON_CTL_PMI_EN			(1 << 1)
#define NHMEX_M_PMON_CTL_COUNT_MODE_SHIFT	2
#define NHMEX_M_PMON_CTL_COUNT_MODE_MASK	\
	(0x3 << NHMEX_M_PMON_CTL_COUNT_MODE_SHIFT)
#define NHMEX_M_PMON_CTL_STORAGE_MODE_SHIFT	4
#define NHMEX_M_PMON_CTL_STORAGE_MODE_MASK	\
	(0x3 << NHMEX_M_PMON_CTL_STORAGE_MODE_SHIFT)
#define NHMEX_M_PMON_CTL_WRAP_MODE		(1 << 6)
#define NHMEX_M_PMON_CTL_FLAG_MODE		(1 << 7)
#define NHMEX_M_PMON_CTL_INC_SEL_SHIFT		9
#define NHMEX_M_PMON_CTL_INC_SEL_MASK		\
	(0x1f << NHMEX_M_PMON_CTL_INC_SEL_SHIFT)
#define NHMEX_M_PMON_CTL_SET_FLAG_SEL_SHIFT	19
#define NHMEX_M_PMON_CTL_SET_FLAG_SEL_MASK	\
	(0x7 << NHMEX_M_PMON_CTL_SET_FLAG_SEL_SHIFT)
#define NHMEX_M_PMON_RAW_EVENT_MASK			\
		(NHMEX_M_PMON_CTL_COUNT_MODE_MASK |	\
		 NHMEX_M_PMON_CTL_STORAGE_MODE_MASK |	\
		 NHMEX_M_PMON_CTL_WRAP_MODE |		\
		 NHMEX_M_PMON_CTL_FLAG_MODE |		\
		 NHMEX_M_PMON_CTL_INC_SEL_MASK |	\
		 NHMEX_M_PMON_CTL_SET_FLAG_SEL_MASK)

#define NHMEX_M_PMON_ZDP_CTL_FVC_MASK		(((1 << 11) - 1) | (1 << 23))
#define NHMEX_M_PMON_ZDP_CTL_FVC_EVENT_MASK(n)	(0x7ULL << (11 + 3 * (n)))

#define WSMEX_M_PMON_ZDP_CTL_FVC_MASK		(((1 << 12) - 1) | (1 << 24))
#define WSMEX_M_PMON_ZDP_CTL_FVC_EVENT_MASK(n)	(0x7ULL << (12 + 3 * (n)))

/*
 * use the 9~13 bits to select event If the 7th bit is not set,
 * otherwise use the 19~21 bits to select event.
 */
#define MBOX_INC_SEL(x) ((x) << NHMEX_M_PMON_CTL_INC_SEL_SHIFT)
#define MBOX_SET_FLAG_SEL(x) (((x) << NHMEX_M_PMON_CTL_SET_FLAG_SEL_SHIFT) | \
				NHMEX_M_PMON_CTL_FLAG_MODE)
#define MBOX_INC_SEL_MASK (NHMEX_M_PMON_CTL_INC_SEL_MASK | \
			   NHMEX_M_PMON_CTL_FLAG_MODE)
#define MBOX_SET_FLAG_SEL_MASK (NHMEX_M_PMON_CTL_SET_FLAG_SEL_MASK | \
				NHMEX_M_PMON_CTL_FLAG_MODE)
#define MBOX_INC_SEL_EXTAR_REG(c, r) \
		EVENT_EXTRA_REG(MBOX_INC_SEL(c), NHMEX_M0_MSR_PMU_##r, \
				MBOX_INC_SEL_MASK, (u64)-1, NHMEX_M_##r)
#define MBOX_SET_FLAG_SEL_EXTRA_REG(c, r) \
		EVENT_EXTRA_REG(MBOX_SET_FLAG_SEL(c), NHMEX_M0_MSR_PMU_##r, \
				MBOX_SET_FLAG_SEL_MASK, \
				(u64)-1, NHMEX_M_##r)

/* NHM-EX Rbox */
#define NHMEX_R_MSR_GLOBAL_CTL			0xe00
#define NHMEX_R_MSR_PMON_CTL0			0xe10
#define NHMEX_R_MSR_PMON_CNT0			0xe11
#define NHMEX_R_MSR_OFFSET			0x20

#define NHMEX_R_MSR_PORTN_QLX_CFG(n)		\
		((n) < 4 ? (0xe0c + (n)) : (0xe2c + (n) - 4))
#define NHMEX_R_MSR_PORTN_IPERF_CFG0(n)		(0xe04 + (n))
#define NHMEX_R_MSR_PORTN_IPERF_CFG1(n)		(0xe24 + (n))
#define NHMEX_R_MSR_PORTN_XBR_OFFSET(n)		\
		(((n) < 4 ? 0 : 0x10) + (n) * 4)
#define NHMEX_R_MSR_PORTN_XBR_SET1_MM_CFG(n)	\
		(0xe60 + NHMEX_R_MSR_PORTN_XBR_OFFSET(n))
#define NHMEX_R_MSR_PORTN_XBR_SET1_MATCH(n)	\
		(NHMEX_R_MSR_PORTN_XBR_SET1_MM_CFG(n) + 1)
#define NHMEX_R_MSR_PORTN_XBR_SET1_MASK(n)	\
		(NHMEX_R_MSR_PORTN_XBR_SET1_MM_CFG(n) + 2)
#define NHMEX_R_MSR_PORTN_XBR_SET2_MM_CFG(n)	\
		(0xe70 + NHMEX_R_MSR_PORTN_XBR_OFFSET(n))
#define NHMEX_R_MSR_PORTN_XBR_SET2_MATCH(n)	\
		(NHMEX_R_MSR_PORTN_XBR_SET2_MM_CFG(n) + 1)
#define NHMEX_R_MSR_PORTN_XBR_SET2_MASK(n)	\
		(NHMEX_R_MSR_PORTN_XBR_SET2_MM_CFG(n) + 2)

#define NHMEX_R_PMON_CTL_EN			(1 << 0)
#define NHMEX_R_PMON_CTL_EV_SEL_SHIFT		1
#define NHMEX_R_PMON_CTL_EV_SEL_MASK		\
		(0x1f << NHMEX_R_PMON_CTL_EV_SEL_SHIFT)
#define NHMEX_R_PMON_CTL_PMI_EN			(1 << 6)
#define NHMEX_R_PMON_RAW_EVENT_MASK		NHMEX_R_PMON_CTL_EV_SEL_MASK

/* NHM-EX Wbox */
#define NHMEX_W_MSR_GLOBAL_CTL			0xc80
#define NHMEX_W_MSR_PMON_CNT0			0xc90
#define NHMEX_W_MSR_PMON_EVT_SEL0		0xc91
#define NHMEX_W_MSR_PMON_FIXED_CTR		0x394
#define NHMEX_W_MSR_PMON_FIXED_CTL		0x395

#define NHMEX_W_PMON_GLOBAL_FIXED_EN		(1ULL << 31)

struct intel_uncore_ops;
struct intel_uncore_pmu;
struct intel_uncore_box;
struct uncore_event_desc;

struct intel_uncore_type {
	const char *name;
	int num_counters;
	int num_boxes;
	int perf_ctr_bits;
	int fixed_ctr_bits;
	unsigned perf_ctr;
	unsigned event_ctl;
	unsigned event_mask;
	unsigned fixed_ctr;
	unsigned fixed_ctl;
	unsigned box_ctl;
	unsigned msr_offset;
	unsigned num_shared_regs:8;
	unsigned single_fixed:1;
	unsigned pair_ctr_ctl:1;
	unsigned *msr_offsets;
	struct event_constraint unconstrainted;
	struct event_constraint *constraints;
	struct intel_uncore_pmu *pmus;
	struct intel_uncore_ops *ops;
	struct uncore_event_desc *event_descs;
	const struct attribute_group *attr_groups[4];
	struct pmu *pmu; /* for custom pmu ops */
};

#define pmu_group attr_groups[0]
#define format_group attr_groups[1]
#define events_group attr_groups[2]

struct intel_uncore_ops {
	void (*init_box)(struct intel_uncore_box *);
	void (*disable_box)(struct intel_uncore_box *);
	void (*enable_box)(struct intel_uncore_box *);
	void (*disable_event)(struct intel_uncore_box *, struct perf_event *);
	void (*enable_event)(struct intel_uncore_box *, struct perf_event *);
	u64 (*read_counter)(struct intel_uncore_box *, struct perf_event *);
	int (*hw_config)(struct intel_uncore_box *, struct perf_event *);
	struct event_constraint *(*get_constraint)(struct intel_uncore_box *,
						   struct perf_event *);
	void (*put_constraint)(struct intel_uncore_box *, struct perf_event *);
};

struct intel_uncore_pmu {
	struct pmu pmu;
	char name[UNCORE_PMU_NAME_LEN];
	int pmu_idx;
	int func_id;
	struct intel_uncore_type *type;
	struct intel_uncore_box ** __percpu box;
	struct list_head box_list;
};

struct intel_uncore_extra_reg {
	spinlock_t lock;
	u64 config, config1, config2;
	atomic_t ref;
};

struct intel_uncore_box {
	int phys_id;
	int n_active;	/* number of active events */
	int n_events;
	int cpu;	/* cpu to collect events */
	unsigned long flags;
	atomic_t refcnt;
	struct perf_event *events[UNCORE_PMC_IDX_MAX];
	struct perf_event *event_list[UNCORE_PMC_IDX_MAX];
	struct event_constraint *event_constraint[UNCORE_PMC_IDX_MAX];
	unsigned long active_mask[BITS_TO_LONGS(UNCORE_PMC_IDX_MAX)];
	u64 tags[UNCORE_PMC_IDX_MAX];
	struct pci_dev *pci_dev;
	struct intel_uncore_pmu *pmu;
	u64 hrtimer_duration; /* hrtimer timeout for this box */
	struct hrtimer hrtimer;
	struct list_head list;
	struct list_head active_list;
	void *io_addr;
	struct intel_uncore_extra_reg shared_regs[0];
};

#define UNCORE_BOX_FLAG_INITIATED	0

struct uncore_event_desc {
	struct kobj_attribute attr;
	const char *config;
};

ssize_t uncore_event_show(struct kobject *kobj,
			  struct kobj_attribute *attr, char *buf);

#define INTEL_UNCORE_EVENT_DESC(_name, _config)			\
{								\
	.attr	= __ATTR(_name, 0444, uncore_event_show, NULL),	\
	.config	= _config,					\
}

#define DEFINE_UNCORE_FORMAT_ATTR(_var, _name, _format)			\
static ssize_t __uncore_##_var##_show(struct kobject *kobj,		\
				struct kobj_attribute *attr,		\
				char *page)				\
{									\
	BUILD_BUG_ON(sizeof(_format) >= PAGE_SIZE);			\
	return sprintf(page, _format "\n");				\
}									\
static struct kobj_attribute format_attr_##_var =			\
	__ATTR(_name, 0444, __uncore_##_var##_show, NULL)

static inline unsigned uncore_pci_box_ctl(struct intel_uncore_box *box)
{
	return box->pmu->type->box_ctl;
}

static inline unsigned uncore_pci_fixed_ctl(struct intel_uncore_box *box)
{
	return box->pmu->type->fixed_ctl;
}

static inline unsigned uncore_pci_fixed_ctr(struct intel_uncore_box *box)
{
	return box->pmu->type->fixed_ctr;
}

static inline
unsigned uncore_pci_event_ctl(struct intel_uncore_box *box, int idx)
{
	return idx * 4 + box->pmu->type->event_ctl;
}

static inline
unsigned uncore_pci_perf_ctr(struct intel_uncore_box *box, int idx)
{
	return idx * 8 + box->pmu->type->perf_ctr;
}

static inline unsigned uncore_msr_box_offset(struct intel_uncore_box *box)
{
	struct intel_uncore_pmu *pmu = box->pmu;
	return pmu->type->msr_offsets ?
		pmu->type->msr_offsets[pmu->pmu_idx] :
		pmu->type->msr_offset * pmu->pmu_idx;
}

static inline unsigned uncore_msr_box_ctl(struct intel_uncore_box *box)
{
	if (!box->pmu->type->box_ctl)
		return 0;
	return box->pmu->type->box_ctl + uncore_msr_box_offset(box);
}

static inline unsigned uncore_msr_fixed_ctl(struct intel_uncore_box *box)
{
	if (!box->pmu->type->fixed_ctl)
		return 0;
	return box->pmu->type->fixed_ctl + uncore_msr_box_offset(box);
}

static inline unsigned uncore_msr_fixed_ctr(struct intel_uncore_box *box)
{
	return box->pmu->type->fixed_ctr + uncore_msr_box_offset(box);
}

static inline
unsigned uncore_msr_event_ctl(struct intel_uncore_box *box, int idx)
{
	return box->pmu->type->event_ctl +
		(box->pmu->type->pair_ctr_ctl ? 2 * idx : idx) +
		uncore_msr_box_offset(box);
}

static inline
unsigned uncore_msr_perf_ctr(struct intel_uncore_box *box, int idx)
{
	return box->pmu->type->perf_ctr +
		(box->pmu->type->pair_ctr_ctl ? 2 * idx : idx) +
		uncore_msr_box_offset(box);
}

static inline
unsigned uncore_fixed_ctl(struct intel_uncore_box *box)
{
	if (box->pci_dev)
		return uncore_pci_fixed_ctl(box);
	else
		return uncore_msr_fixed_ctl(box);
}

static inline
unsigned uncore_fixed_ctr(struct intel_uncore_box *box)
{
	if (box->pci_dev)
		return uncore_pci_fixed_ctr(box);
	else
		return uncore_msr_fixed_ctr(box);
}

static inline
unsigned uncore_event_ctl(struct intel_uncore_box *box, int idx)
{
	if (box->pci_dev)
		return uncore_pci_event_ctl(box, idx);
	else
		return uncore_msr_event_ctl(box, idx);
}

static inline
unsigned uncore_perf_ctr(struct intel_uncore_box *box, int idx)
{
	if (box->pci_dev)
		return uncore_pci_perf_ctr(box, idx);
	else
		return uncore_msr_perf_ctr(box, idx);
}

static inline int uncore_perf_ctr_bits(struct intel_uncore_box *box)
{
	return box->pmu->type->perf_ctr_bits;
}

static inline int uncore_fixed_ctr_bits(struct intel_uncore_box *box)
{
	return box->pmu->type->fixed_ctr_bits;
}

static inline int uncore_num_counters(struct intel_uncore_box *box)
{
	return box->pmu->type->num_counters;
}

static inline void uncore_disable_box(struct intel_uncore_box *box)
{
	if (box->pmu->type->ops->disable_box)
		box->pmu->type->ops->disable_box(box);
}

static inline void uncore_enable_box(struct intel_uncore_box *box)
{
	if (box->pmu->type->ops->enable_box)
		box->pmu->type->ops->enable_box(box);
}

static inline void uncore_disable_event(struct intel_uncore_box *box,
				struct perf_event *event)
{
	box->pmu->type->ops->disable_event(box, event);
}

static inline void uncore_enable_event(struct intel_uncore_box *box,
				struct perf_event *event)
{
	box->pmu->type->ops->enable_event(box, event);
}

static inline u64 uncore_read_counter(struct intel_uncore_box *box,
				struct perf_event *event)
{
	return box->pmu->type->ops->read_counter(box, event);
}

static inline void uncore_box_init(struct intel_uncore_box *box)
{
	if (!test_and_set_bit(UNCORE_BOX_FLAG_INITIATED, &box->flags)) {
		if (box->pmu->type->ops->init_box)
			box->pmu->type->ops->init_box(box);
	}
}

static inline bool uncore_box_is_fake(struct intel_uncore_box *box)
{
	return (box->phys_id < 0);
}

struct intel_uncore_pmu *uncore_event_to_pmu(struct perf_event *event);
struct intel_uncore_box *uncore_pmu_to_box(struct intel_uncore_pmu *pmu, int cpu);
struct intel_uncore_box *uncore_event_to_box(struct perf_event *event);
u64 uncore_msr_read_counter(struct intel_uncore_box *box, struct perf_event *event);
void uncore_pmu_start_hrtimer(struct intel_uncore_box *box);
void uncore_pmu_cancel_hrtimer(struct intel_uncore_box *box);
void uncore_pmu_event_read(struct perf_event *event);
void uncore_perf_event_update(struct intel_uncore_box *box, struct perf_event *event);
struct event_constraint *
uncore_get_constraint(struct intel_uncore_box *box, struct perf_event *event);
void uncore_put_constraint(struct intel_uncore_box *box, struct perf_event *event);
u64 uncore_shared_reg_config(struct intel_uncore_box *box, int idx);

extern struct intel_uncore_type **uncore_msr_uncores;
extern struct intel_uncore_type **uncore_pci_uncores;
extern struct pci_driver *uncore_pci_driver;
extern int uncore_pcibus_to_physid[256];
extern struct pci_dev *uncore_extra_pci_dev[UNCORE_SOCKET_MAX][UNCORE_EXTRA_PCI_DEV_MAX];
extern struct event_constraint uncore_constraint_empty;

/* perf_event_intel_uncore_snb.c */
int snb_uncore_pci_init(void);
int ivb_uncore_pci_init(void);
int hsw_uncore_pci_init(void);
int bdw_uncore_pci_init(void);
void snb_uncore_cpu_init(void);
void nhm_uncore_cpu_init(void);

/* perf_event_intel_uncore_snbep.c */
int snbep_uncore_pci_init(void);
void snbep_uncore_cpu_init(void);
int ivbep_uncore_pci_init(void);
void ivbep_uncore_cpu_init(void);
int hswep_uncore_pci_init(void);
void hswep_uncore_cpu_init(void);
int bdx_uncore_pci_init(void);
void bdx_uncore_cpu_init(void);
