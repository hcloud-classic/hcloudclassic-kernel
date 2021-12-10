#include "perf_event_intel_uncore.h"

static struct intel_uncore_type *empty_uncore[] = { NULL, };
struct intel_uncore_type **uncore_msr_uncores = empty_uncore;
struct intel_uncore_type **uncore_pci_uncores = empty_uncore;

static bool pcidrv_registered;
struct pci_driver *uncore_pci_driver;
/* pci bus to socket mapping */
int uncore_pcibus_to_physid[256] = { [0 ... 255] = -1, };
struct pci_dev *uncore_extra_pci_dev[UNCORE_SOCKET_MAX][UNCORE_EXTRA_PCI_DEV_MAX];

static DEFINE_SPINLOCK(uncore_box_lock);
/* mask of cpus that collect uncore events */
static cpumask_t uncore_cpu_mask;

/* constraint for the fixed counter */
static struct event_constraint uncore_constraint_fixed =
	EVENT_CONSTRAINT(~0ULL, 1 << UNCORE_PMC_IDX_FIXED, ~0ULL);
struct event_constraint uncore_constraint_empty =
	EVENT_CONSTRAINT(0, 0, 0);

ssize_t uncore_event_show(struct kobject *kobj,
			  struct kobj_attribute *attr, char *buf)
{
	struct uncore_event_desc *event =
		container_of(attr, struct uncore_event_desc, attr);
	return sprintf(buf, "%s", event->config);
}

#define __BITS_VALUE(x, i, n)  ((typeof(x))(((x) >> ((i) * (n))) & \
				((1ULL << (n)) - 1)))

DEFINE_UNCORE_FORMAT_ATTR(event, event, "config:0-7");
DEFINE_UNCORE_FORMAT_ATTR(umask, umask, "config:8-15");
DEFINE_UNCORE_FORMAT_ATTR(edge, edge, "config:18");
DEFINE_UNCORE_FORMAT_ATTR(inv, inv, "config:23");
DEFINE_UNCORE_FORMAT_ATTR(thresh8, thresh, "config:24-31");

struct intel_uncore_pmu *uncore_event_to_pmu(struct perf_event *event)
{
	return container_of(event->pmu, struct intel_uncore_pmu, pmu);
}

struct intel_uncore_box *uncore_pmu_to_box(struct intel_uncore_pmu *pmu, int cpu)
{
	struct intel_uncore_box *box;

	box = *per_cpu_ptr(pmu->box, cpu);
	if (box)
		return box;

	spin_lock(&uncore_box_lock);
	list_for_each_entry(box, &pmu->box_list, list) {
		if (box->phys_id == topology_physical_package_id(cpu)) {
			atomic_inc(&box->refcnt);
			*per_cpu_ptr(pmu->box, cpu) = box;
			break;
		}
	}
	spin_unlock(&uncore_box_lock);

	return *per_cpu_ptr(pmu->box, cpu);
}

struct intel_uncore_box *uncore_event_to_box(struct perf_event *event)
{
	/*
	 * perf core schedules event on the basis of cpu, uncore events are
	 * collected by one of the cpus inside a physical package.
	 */
	return uncore_pmu_to_box(uncore_event_to_pmu(event), smp_processor_id());
}

u64 uncore_msr_read_counter(struct intel_uncore_box *box, struct perf_event *event)
{
	u64 count;

	rdmsrl(event->hw.event_base, count);

	return count;
}

/*
 * generic get constraint function for shared match/mask registers.
 */
struct event_constraint *
uncore_get_constraint(struct intel_uncore_box *box, struct perf_event *event)
{
	struct intel_uncore_extra_reg *er;
	struct hw_perf_event_extra *reg1 = &event->hw.extra_reg;
	struct hw_perf_event_extra *reg2 = &event->hw.branch_reg;
	unsigned long flags;
	bool ok = false;

	/*
	 * reg->alloc can be set due to existing state, so for fake box we
	 * need to ignore this, otherwise we might fail to allocate proper
	 * fake state for this extra reg constraint.
	 */
	if (reg1->idx == EXTRA_REG_NONE ||
	    (!uncore_box_is_fake(box) && reg1->alloc))
		return NULL;

	er = &box->shared_regs[reg1->idx];
	spin_lock_irqsave(&er->lock, flags);
	if (!atomic_read(&er->ref) ||
	    (er->config1 == reg1->config && er->config2 == reg2->config)) {
		atomic_inc(&er->ref);
		er->config1 = reg1->config;
		er->config2 = reg2->config;
		ok = true;
	}
	spin_unlock_irqrestore(&er->lock, flags);

	if (ok) {
		if (!uncore_box_is_fake(box))
			reg1->alloc = 1;
		return NULL;
	}

	return &uncore_constraint_empty;
}

void uncore_put_constraint(struct intel_uncore_box *box, struct perf_event *event)
{
	struct intel_uncore_extra_reg *er;
	struct hw_perf_event_extra *reg1 = &event->hw.extra_reg;

	/*
	 * Only put constraint if extra reg was actually allocated. Also
	 * takes care of event which do not use an extra shared reg.
	 *
	 * Also, if this is a fake box we shouldn't touch any event state
	 * (reg->alloc) and we don't care about leaving inconsistent box
	 * state either since it will be thrown out.
	 */
	if (uncore_box_is_fake(box) || !reg1->alloc)
		return;

	er = &box->shared_regs[reg1->idx];
	atomic_dec(&er->ref);
	reg1->alloc = 0;
}

u64 uncore_shared_reg_config(struct intel_uncore_box *box, int idx)
{
	struct intel_uncore_extra_reg *er;
	unsigned long flags;
	u64 config;

	er = &box->shared_regs[idx];

	spin_lock_irqsave(&er->lock, flags);
	config = er->config;
	spin_unlock_irqrestore(&er->lock, flags);

	return config;
}

/* Nehalem-EX uncore support */
DEFINE_UNCORE_FORMAT_ATTR(event5, event, "config:1-5");
DEFINE_UNCORE_FORMAT_ATTR(counter, counter, "config:6-7");
DEFINE_UNCORE_FORMAT_ATTR(match, match, "config1:0-63");
DEFINE_UNCORE_FORMAT_ATTR(mask, mask, "config2:0-63");

static void nhmex_uncore_msr_init_box(struct intel_uncore_box *box)
{
	wrmsrl(NHMEX_U_MSR_PMON_GLOBAL_CTL, NHMEX_U_PMON_GLOBAL_EN_ALL);
}

static void nhmex_uncore_msr_disable_box(struct intel_uncore_box *box)
{
	unsigned msr = uncore_msr_box_ctl(box);
	u64 config;

	if (msr) {
		rdmsrl(msr, config);
		config &= ~((1ULL << uncore_num_counters(box)) - 1);
		/* WBox has a fixed counter */
		if (uncore_msr_fixed_ctl(box))
			config &= ~NHMEX_W_PMON_GLOBAL_FIXED_EN;
		wrmsrl(msr, config);
	}
}

static void nhmex_uncore_msr_enable_box(struct intel_uncore_box *box)
{
	unsigned msr = uncore_msr_box_ctl(box);
	u64 config;

	if (msr) {
		rdmsrl(msr, config);
		config |= (1ULL << uncore_num_counters(box)) - 1;
		/* WBox has a fixed counter */
		if (uncore_msr_fixed_ctl(box))
			config |= NHMEX_W_PMON_GLOBAL_FIXED_EN;
		wrmsrl(msr, config);
	}
}

static void nhmex_uncore_msr_disable_event(struct intel_uncore_box *box, struct perf_event *event)
{
	wrmsrl(event->hw.config_base, 0);
}

static void nhmex_uncore_msr_enable_event(struct intel_uncore_box *box, struct perf_event *event)
{
	struct hw_perf_event *hwc = &event->hw;

	if (hwc->idx >= UNCORE_PMC_IDX_FIXED)
		wrmsrl(hwc->config_base, NHMEX_PMON_CTL_EN_BIT0);
	else if (box->pmu->type->event_mask & NHMEX_PMON_CTL_EN_BIT0)
		wrmsrl(hwc->config_base, hwc->config | NHMEX_PMON_CTL_EN_BIT22);
	else
		wrmsrl(hwc->config_base, hwc->config | NHMEX_PMON_CTL_EN_BIT0);
}

#define NHMEX_UNCORE_OPS_COMMON_INIT()				\
	.init_box	= nhmex_uncore_msr_init_box,		\
	.disable_box	= nhmex_uncore_msr_disable_box,		\
	.enable_box	= nhmex_uncore_msr_enable_box,		\
	.disable_event	= nhmex_uncore_msr_disable_event,	\
	.read_counter	= uncore_msr_read_counter

static struct intel_uncore_ops nhmex_uncore_ops = {
	NHMEX_UNCORE_OPS_COMMON_INIT(),
	.enable_event	= nhmex_uncore_msr_enable_event,
};

static struct attribute *nhmex_uncore_ubox_formats_attr[] = {
	&format_attr_event.attr,
	&format_attr_edge.attr,
	NULL,
};

static struct attribute_group nhmex_uncore_ubox_format_group = {
	.name		= "format",
	.attrs		= nhmex_uncore_ubox_formats_attr,
};

static struct intel_uncore_type nhmex_uncore_ubox = {
	.name		= "ubox",
	.num_counters	= 1,
	.num_boxes	= 1,
	.perf_ctr_bits	= 48,
	.event_ctl	= NHMEX_U_MSR_PMON_EV_SEL,
	.perf_ctr	= NHMEX_U_MSR_PMON_CTR,
	.event_mask	= NHMEX_U_PMON_RAW_EVENT_MASK,
	.box_ctl	= NHMEX_U_MSR_PMON_GLOBAL_CTL,
	.ops		= &nhmex_uncore_ops,
	.format_group	= &nhmex_uncore_ubox_format_group
};

static struct attribute *nhmex_uncore_cbox_formats_attr[] = {
	&format_attr_event.attr,
	&format_attr_umask.attr,
	&format_attr_edge.attr,
	&format_attr_inv.attr,
	&format_attr_thresh8.attr,
	NULL,
};

static struct attribute_group nhmex_uncore_cbox_format_group = {
	.name = "format",
	.attrs = nhmex_uncore_cbox_formats_attr,
};

/* msr offset for each instance of cbox */
static unsigned nhmex_cbox_msr_offsets[] = {
	0x0, 0x80, 0x40, 0xc0, 0x20, 0xa0, 0x60, 0xe0, 0x240, 0x2c0,
};

static struct intel_uncore_type nhmex_uncore_cbox = {
	.name			= "cbox",
	.num_counters		= 6,
	.num_boxes		= 10,
	.perf_ctr_bits		= 48,
	.event_ctl		= NHMEX_C0_MSR_PMON_EV_SEL0,
	.perf_ctr		= NHMEX_C0_MSR_PMON_CTR0,
	.event_mask		= NHMEX_PMON_RAW_EVENT_MASK,
	.box_ctl		= NHMEX_C0_MSR_PMON_GLOBAL_CTL,
	.msr_offsets		= nhmex_cbox_msr_offsets,
	.pair_ctr_ctl		= 1,
	.ops			= &nhmex_uncore_ops,
	.format_group		= &nhmex_uncore_cbox_format_group
};

static struct uncore_event_desc nhmex_uncore_wbox_events[] = {
	INTEL_UNCORE_EVENT_DESC(clockticks, "event=0xff,umask=0"),
	{ /* end: all zeroes */ },
};

static struct intel_uncore_type nhmex_uncore_wbox = {
	.name			= "wbox",
	.num_counters		= 4,
	.num_boxes		= 1,
	.perf_ctr_bits		= 48,
	.event_ctl		= NHMEX_W_MSR_PMON_CNT0,
	.perf_ctr		= NHMEX_W_MSR_PMON_EVT_SEL0,
	.fixed_ctr		= NHMEX_W_MSR_PMON_FIXED_CTR,
	.fixed_ctl		= NHMEX_W_MSR_PMON_FIXED_CTL,
	.event_mask		= NHMEX_PMON_RAW_EVENT_MASK,
	.box_ctl		= NHMEX_W_MSR_GLOBAL_CTL,
	.pair_ctr_ctl		= 1,
	.event_descs		= nhmex_uncore_wbox_events,
	.ops			= &nhmex_uncore_ops,
	.format_group		= &nhmex_uncore_cbox_format_group
};

static int nhmex_bbox_hw_config(struct intel_uncore_box *box, struct perf_event *event)
{
	struct hw_perf_event *hwc = &event->hw;
	struct hw_perf_event_extra *reg1 = &hwc->extra_reg;
	struct hw_perf_event_extra *reg2 = &hwc->branch_reg;
	int ctr, ev_sel;

	ctr = (hwc->config & NHMEX_B_PMON_CTR_MASK) >>
		NHMEX_B_PMON_CTR_SHIFT;
	ev_sel = (hwc->config & NHMEX_B_PMON_CTL_EV_SEL_MASK) >>
		  NHMEX_B_PMON_CTL_EV_SEL_SHIFT;

	/* events that do not use the match/mask registers */
	if ((ctr == 0 && ev_sel > 0x3) || (ctr == 1 && ev_sel > 0x6) ||
	    (ctr == 2 && ev_sel != 0x4) || ctr == 3)
		return 0;

	if (box->pmu->pmu_idx == 0)
		reg1->reg = NHMEX_B0_MSR_MATCH;
	else
		reg1->reg = NHMEX_B1_MSR_MATCH;
	reg1->idx = 0;
	reg1->config = event->attr.config1;
	reg2->config = event->attr.config2;
	return 0;
}

static void nhmex_bbox_msr_enable_event(struct intel_uncore_box *box, struct perf_event *event)
{
	struct hw_perf_event *hwc = &event->hw;
	struct hw_perf_event_extra *reg1 = &hwc->extra_reg;
	struct hw_perf_event_extra *reg2 = &hwc->branch_reg;

	if (reg1->idx != EXTRA_REG_NONE) {
		wrmsrl(reg1->reg, reg1->config);
		wrmsrl(reg1->reg + 1, reg2->config);
	}
	wrmsrl(hwc->config_base, NHMEX_PMON_CTL_EN_BIT0 |
		(hwc->config & NHMEX_B_PMON_CTL_EV_SEL_MASK));
}

/*
 * The Bbox has 4 counters, but each counter monitors different events.
 * Use bits 6-7 in the event config to select counter.
 */
static struct event_constraint nhmex_uncore_bbox_constraints[] = {
	EVENT_CONSTRAINT(0 , 1, 0xc0),
	EVENT_CONSTRAINT(0x40, 2, 0xc0),
	EVENT_CONSTRAINT(0x80, 4, 0xc0),
	EVENT_CONSTRAINT(0xc0, 8, 0xc0),
	EVENT_CONSTRAINT_END,
};

static struct attribute *nhmex_uncore_bbox_formats_attr[] = {
	&format_attr_event5.attr,
	&format_attr_counter.attr,
	&format_attr_match.attr,
	&format_attr_mask.attr,
	NULL,
};

static struct attribute_group nhmex_uncore_bbox_format_group = {
	.name = "format",
	.attrs = nhmex_uncore_bbox_formats_attr,
};

static struct intel_uncore_ops nhmex_uncore_bbox_ops = {
	NHMEX_UNCORE_OPS_COMMON_INIT(),
	.enable_event		= nhmex_bbox_msr_enable_event,
	.hw_config		= nhmex_bbox_hw_config,
	.get_constraint		= uncore_get_constraint,
	.put_constraint		= uncore_put_constraint,
};

static struct intel_uncore_type nhmex_uncore_bbox = {
	.name			= "bbox",
	.num_counters		= 4,
	.num_boxes		= 2,
	.perf_ctr_bits		= 48,
	.event_ctl		= NHMEX_B0_MSR_PMON_CTL0,
	.perf_ctr		= NHMEX_B0_MSR_PMON_CTR0,
	.event_mask		= NHMEX_B_PMON_RAW_EVENT_MASK,
	.box_ctl		= NHMEX_B0_MSR_PMON_GLOBAL_CTL,
	.msr_offset		= NHMEX_B_MSR_OFFSET,
	.pair_ctr_ctl		= 1,
	.num_shared_regs	= 1,
	.constraints		= nhmex_uncore_bbox_constraints,
	.ops			= &nhmex_uncore_bbox_ops,
	.format_group		= &nhmex_uncore_bbox_format_group
};

static int nhmex_sbox_hw_config(struct intel_uncore_box *box, struct perf_event *event)
{
	struct hw_perf_event *hwc = &event->hw;
	struct hw_perf_event_extra *reg1 = &hwc->extra_reg;
	struct hw_perf_event_extra *reg2 = &hwc->branch_reg;

	/* only TO_R_PROG_EV event uses the match/mask register */
	if ((hwc->config & NHMEX_PMON_CTL_EV_SEL_MASK) !=
	    NHMEX_S_EVENT_TO_R_PROG_EV)
		return 0;

	if (box->pmu->pmu_idx == 0)
		reg1->reg = NHMEX_S0_MSR_MM_CFG;
	else
		reg1->reg = NHMEX_S1_MSR_MM_CFG;
	reg1->idx = 0;
	reg1->config = event->attr.config1;
	reg2->config = event->attr.config2;
	return 0;
}

static void nhmex_sbox_msr_enable_event(struct intel_uncore_box *box, struct perf_event *event)
{
	struct hw_perf_event *hwc = &event->hw;
	struct hw_perf_event_extra *reg1 = &hwc->extra_reg;
	struct hw_perf_event_extra *reg2 = &hwc->branch_reg;

	if (reg1->idx != EXTRA_REG_NONE) {
		wrmsrl(reg1->reg, 0);
		wrmsrl(reg1->reg + 1, reg1->config);
		wrmsrl(reg1->reg + 2, reg2->config);
		wrmsrl(reg1->reg, NHMEX_S_PMON_MM_CFG_EN);
	}
	wrmsrl(hwc->config_base, hwc->config | NHMEX_PMON_CTL_EN_BIT22);
}

static struct attribute *nhmex_uncore_sbox_formats_attr[] = {
	&format_attr_event.attr,
	&format_attr_umask.attr,
	&format_attr_edge.attr,
	&format_attr_inv.attr,
	&format_attr_thresh8.attr,
	&format_attr_match.attr,
	&format_attr_mask.attr,
	NULL,
};

static struct attribute_group nhmex_uncore_sbox_format_group = {
	.name			= "format",
	.attrs			= nhmex_uncore_sbox_formats_attr,
};

static struct intel_uncore_ops nhmex_uncore_sbox_ops = {
	NHMEX_UNCORE_OPS_COMMON_INIT(),
	.enable_event		= nhmex_sbox_msr_enable_event,
	.hw_config		= nhmex_sbox_hw_config,
	.get_constraint		= uncore_get_constraint,
	.put_constraint		= uncore_put_constraint,
};

static struct intel_uncore_type nhmex_uncore_sbox = {
	.name			= "sbox",
	.num_counters		= 4,
	.num_boxes		= 2,
	.perf_ctr_bits		= 48,
	.event_ctl		= NHMEX_S0_MSR_PMON_CTL0,
	.perf_ctr		= NHMEX_S0_MSR_PMON_CTR0,
	.event_mask		= NHMEX_PMON_RAW_EVENT_MASK,
	.box_ctl		= NHMEX_S0_MSR_PMON_GLOBAL_CTL,
	.msr_offset		= NHMEX_S_MSR_OFFSET,
	.pair_ctr_ctl		= 1,
	.num_shared_regs	= 1,
	.ops			= &nhmex_uncore_sbox_ops,
	.format_group		= &nhmex_uncore_sbox_format_group
};

enum {
	EXTRA_REG_NHMEX_M_FILTER,
	EXTRA_REG_NHMEX_M_DSP,
	EXTRA_REG_NHMEX_M_ISS,
	EXTRA_REG_NHMEX_M_MAP,
	EXTRA_REG_NHMEX_M_MSC_THR,
	EXTRA_REG_NHMEX_M_PGT,
	EXTRA_REG_NHMEX_M_PLD,
	EXTRA_REG_NHMEX_M_ZDP_CTL_FVC,
};

static struct extra_reg nhmex_uncore_mbox_extra_regs[] = {
	MBOX_INC_SEL_EXTAR_REG(0x0, DSP),
	MBOX_INC_SEL_EXTAR_REG(0x4, MSC_THR),
	MBOX_INC_SEL_EXTAR_REG(0x5, MSC_THR),
	MBOX_INC_SEL_EXTAR_REG(0x9, ISS),
	/* event 0xa uses two extra registers */
	MBOX_INC_SEL_EXTAR_REG(0xa, ISS),
	MBOX_INC_SEL_EXTAR_REG(0xa, PLD),
	MBOX_INC_SEL_EXTAR_REG(0xb, PLD),
	/* events 0xd ~ 0x10 use the same extra register */
	MBOX_INC_SEL_EXTAR_REG(0xd, ZDP_CTL_FVC),
	MBOX_INC_SEL_EXTAR_REG(0xe, ZDP_CTL_FVC),
	MBOX_INC_SEL_EXTAR_REG(0xf, ZDP_CTL_FVC),
	MBOX_INC_SEL_EXTAR_REG(0x10, ZDP_CTL_FVC),
	MBOX_INC_SEL_EXTAR_REG(0x16, PGT),
	MBOX_SET_FLAG_SEL_EXTRA_REG(0x0, DSP),
	MBOX_SET_FLAG_SEL_EXTRA_REG(0x1, ISS),
	MBOX_SET_FLAG_SEL_EXTRA_REG(0x5, PGT),
	MBOX_SET_FLAG_SEL_EXTRA_REG(0x6, MAP),
	EVENT_EXTRA_END
};

/* Nehalem-EX or Westmere-EX ? */
static bool uncore_nhmex;

static bool nhmex_mbox_get_shared_reg(struct intel_uncore_box *box, int idx, u64 config)
{
	struct intel_uncore_extra_reg *er;
	unsigned long flags;
	bool ret = false;
	u64 mask;

	if (idx < EXTRA_REG_NHMEX_M_ZDP_CTL_FVC) {
		er = &box->shared_regs[idx];
		spin_lock_irqsave(&er->lock, flags);
		if (!atomic_read(&er->ref) || er->config == config) {
			atomic_inc(&er->ref);
			er->config = config;
			ret = true;
		}
		spin_unlock_irqrestore(&er->lock, flags);

		return ret;
	}
	/*
	 * The ZDP_CTL_FVC MSR has 4 fields which are used to control
	 * events 0xd ~ 0x10. Besides these 4 fields, there are additional
	 * fields which are shared.
	 */
	idx -= EXTRA_REG_NHMEX_M_ZDP_CTL_FVC;
	if (WARN_ON_ONCE(idx >= 4))
		return false;

	/* mask of the shared fields */
	if (uncore_nhmex)
		mask = NHMEX_M_PMON_ZDP_CTL_FVC_MASK;
	else
		mask = WSMEX_M_PMON_ZDP_CTL_FVC_MASK;
	er = &box->shared_regs[EXTRA_REG_NHMEX_M_ZDP_CTL_FVC];

	spin_lock_irqsave(&er->lock, flags);
	/* add mask of the non-shared field if it's in use */
	if (__BITS_VALUE(atomic_read(&er->ref), idx, 8)) {
		if (uncore_nhmex)
			mask |= NHMEX_M_PMON_ZDP_CTL_FVC_EVENT_MASK(idx);
		else
			mask |= WSMEX_M_PMON_ZDP_CTL_FVC_EVENT_MASK(idx);
	}
	if (!atomic_read(&er->ref) || !((er->config ^ config) & mask)) {
		atomic_add(1 << (idx * 8), &er->ref);
		if (uncore_nhmex)
			mask = NHMEX_M_PMON_ZDP_CTL_FVC_MASK |
				NHMEX_M_PMON_ZDP_CTL_FVC_EVENT_MASK(idx);
		else
			mask = WSMEX_M_PMON_ZDP_CTL_FVC_MASK |
				WSMEX_M_PMON_ZDP_CTL_FVC_EVENT_MASK(idx);
		er->config &= ~mask;
		er->config |= (config & mask);
		ret = true;
	}
	spin_unlock_irqrestore(&er->lock, flags);

	return ret;
}

static void nhmex_mbox_put_shared_reg(struct intel_uncore_box *box, int idx)
{
	struct intel_uncore_extra_reg *er;

	if (idx < EXTRA_REG_NHMEX_M_ZDP_CTL_FVC) {
		er = &box->shared_regs[idx];
		atomic_dec(&er->ref);
		return;
	}

	idx -= EXTRA_REG_NHMEX_M_ZDP_CTL_FVC;
	er = &box->shared_regs[EXTRA_REG_NHMEX_M_ZDP_CTL_FVC];
	atomic_sub(1 << (idx * 8), &er->ref);
}

static u64 nhmex_mbox_alter_er(struct perf_event *event, int new_idx, bool modify)
{
	struct hw_perf_event *hwc = &event->hw;
	struct hw_perf_event_extra *reg1 = &hwc->extra_reg;
	u64 idx, orig_idx = __BITS_VALUE(reg1->idx, 0, 8);
	u64 config = reg1->config;

	/* get the non-shared control bits and shift them */
	idx = orig_idx - EXTRA_REG_NHMEX_M_ZDP_CTL_FVC;
	if (uncore_nhmex)
		config &= NHMEX_M_PMON_ZDP_CTL_FVC_EVENT_MASK(idx);
	else
		config &= WSMEX_M_PMON_ZDP_CTL_FVC_EVENT_MASK(idx);
	if (new_idx > orig_idx) {
		idx = new_idx - orig_idx;
		config <<= 3 * idx;
	} else {
		idx = orig_idx - new_idx;
		config >>= 3 * idx;
	}

	/* add the shared control bits back */
	if (uncore_nhmex)
		config |= NHMEX_M_PMON_ZDP_CTL_FVC_MASK & reg1->config;
	else
		config |= WSMEX_M_PMON_ZDP_CTL_FVC_MASK & reg1->config;
	config |= NHMEX_M_PMON_ZDP_CTL_FVC_MASK & reg1->config;
	if (modify) {
		/* adjust the main event selector */
		if (new_idx > orig_idx)
			hwc->config += idx << NHMEX_M_PMON_CTL_INC_SEL_SHIFT;
		else
			hwc->config -= idx << NHMEX_M_PMON_CTL_INC_SEL_SHIFT;
		reg1->config = config;
		reg1->idx = ~0xff | new_idx;
	}
	return config;
}

static struct event_constraint *
nhmex_mbox_get_constraint(struct intel_uncore_box *box, struct perf_event *event)
{
	struct hw_perf_event_extra *reg1 = &event->hw.extra_reg;
	struct hw_perf_event_extra *reg2 = &event->hw.branch_reg;
	int i, idx[2], alloc = 0;
	u64 config1 = reg1->config;

	idx[0] = __BITS_VALUE(reg1->idx, 0, 8);
	idx[1] = __BITS_VALUE(reg1->idx, 1, 8);
again:
	for (i = 0; i < 2; i++) {
		if (!uncore_box_is_fake(box) && (reg1->alloc & (0x1 << i)))
			idx[i] = 0xff;

		if (idx[i] == 0xff)
			continue;

		if (!nhmex_mbox_get_shared_reg(box, idx[i],
				__BITS_VALUE(config1, i, 32)))
			goto fail;
		alloc |= (0x1 << i);
	}

	/* for the match/mask registers */
	if (reg2->idx != EXTRA_REG_NONE &&
	    (uncore_box_is_fake(box) || !reg2->alloc) &&
	    !nhmex_mbox_get_shared_reg(box, reg2->idx, reg2->config))
		goto fail;

	/*
	 * If it's a fake box -- as per validate_{group,event}() we
	 * shouldn't touch event state and we can avoid doing so
	 * since both will only call get_event_constraints() once
	 * on each event, this avoids the need for reg->alloc.
	 */
	if (!uncore_box_is_fake(box)) {
		if (idx[0] != 0xff && idx[0] != __BITS_VALUE(reg1->idx, 0, 8))
			nhmex_mbox_alter_er(event, idx[0], true);
		reg1->alloc |= alloc;
		if (reg2->idx != EXTRA_REG_NONE)
			reg2->alloc = 1;
	}
	return NULL;
fail:
	if (idx[0] != 0xff && !(alloc & 0x1) &&
	    idx[0] >= EXTRA_REG_NHMEX_M_ZDP_CTL_FVC) {
		/*
		 * events 0xd ~ 0x10 are functional identical, but are
		 * controlled by different fields in the ZDP_CTL_FVC
		 * register. If we failed to take one field, try the
		 * rest 3 choices.
		 */
		BUG_ON(__BITS_VALUE(reg1->idx, 1, 8) != 0xff);
		idx[0] -= EXTRA_REG_NHMEX_M_ZDP_CTL_FVC;
		idx[0] = (idx[0] + 1) % 4;
		idx[0] += EXTRA_REG_NHMEX_M_ZDP_CTL_FVC;
		if (idx[0] != __BITS_VALUE(reg1->idx, 0, 8)) {
			config1 = nhmex_mbox_alter_er(event, idx[0], false);
			goto again;
		}
	}

	if (alloc & 0x1)
		nhmex_mbox_put_shared_reg(box, idx[0]);
	if (alloc & 0x2)
		nhmex_mbox_put_shared_reg(box, idx[1]);
	return &uncore_constraint_empty;
}

static void nhmex_mbox_put_constraint(struct intel_uncore_box *box, struct perf_event *event)
{
	struct hw_perf_event_extra *reg1 = &event->hw.extra_reg;
	struct hw_perf_event_extra *reg2 = &event->hw.branch_reg;

	if (uncore_box_is_fake(box))
		return;

	if (reg1->alloc & 0x1)
		nhmex_mbox_put_shared_reg(box, __BITS_VALUE(reg1->idx, 0, 8));
	if (reg1->alloc & 0x2)
		nhmex_mbox_put_shared_reg(box, __BITS_VALUE(reg1->idx, 1, 8));
	reg1->alloc = 0;

	if (reg2->alloc) {
		nhmex_mbox_put_shared_reg(box, reg2->idx);
		reg2->alloc = 0;
	}
}

static int nhmex_mbox_extra_reg_idx(struct extra_reg *er)
{
	if (er->idx < EXTRA_REG_NHMEX_M_ZDP_CTL_FVC)
		return er->idx;
	return er->idx + (er->event >> NHMEX_M_PMON_CTL_INC_SEL_SHIFT) - 0xd;
}

static int nhmex_mbox_hw_config(struct intel_uncore_box *box, struct perf_event *event)
{
	struct intel_uncore_type *type = box->pmu->type;
	struct hw_perf_event_extra *reg1 = &event->hw.extra_reg;
	struct hw_perf_event_extra *reg2 = &event->hw.branch_reg;
	struct extra_reg *er;
	unsigned msr;
	int reg_idx = 0;
	/*
	 * The mbox events may require 2 extra MSRs at the most. But only
	 * the lower 32 bits in these MSRs are significant, so we can use
	 * config1 to pass two MSRs' config.
	 */
	for (er = nhmex_uncore_mbox_extra_regs; er->msr; er++) {
		if (er->event != (event->hw.config & er->config_mask))
			continue;
		if (event->attr.config1 & ~er->valid_mask)
			return -EINVAL;

		msr = er->msr + type->msr_offset * box->pmu->pmu_idx;
		if (WARN_ON_ONCE(msr >= 0xffff || er->idx >= 0xff))
			return -EINVAL;

		/* always use the 32~63 bits to pass the PLD config */
		if (er->idx == EXTRA_REG_NHMEX_M_PLD)
			reg_idx = 1;
		else if (WARN_ON_ONCE(reg_idx > 0))
			return -EINVAL;

		reg1->idx &= ~(0xff << (reg_idx * 8));
		reg1->reg &= ~(0xffff << (reg_idx * 16));
		reg1->idx |= nhmex_mbox_extra_reg_idx(er) << (reg_idx * 8);
		reg1->reg |= msr << (reg_idx * 16);
		reg1->config = event->attr.config1;
		reg_idx++;
	}
	/*
	 * The mbox only provides ability to perform address matching
	 * for the PLD events.
	 */
	if (reg_idx == 2) {
		reg2->idx = EXTRA_REG_NHMEX_M_FILTER;
		if (event->attr.config2 & NHMEX_M_PMON_MM_CFG_EN)
			reg2->config = event->attr.config2;
		else
			reg2->config = ~0ULL;
		if (box->pmu->pmu_idx == 0)
			reg2->reg = NHMEX_M0_MSR_PMU_MM_CFG;
		else
			reg2->reg = NHMEX_M1_MSR_PMU_MM_CFG;
	}
	return 0;
}

static u64 nhmex_mbox_shared_reg_config(struct intel_uncore_box *box, int idx)
{
	struct intel_uncore_extra_reg *er;
	unsigned long flags;
	u64 config;

	if (idx < EXTRA_REG_NHMEX_M_ZDP_CTL_FVC)
		return box->shared_regs[idx].config;

	er = &box->shared_regs[EXTRA_REG_NHMEX_M_ZDP_CTL_FVC];
	spin_lock_irqsave(&er->lock, flags);
	config = er->config;
	spin_unlock_irqrestore(&er->lock, flags);
	return config;
}

static void nhmex_mbox_msr_enable_event(struct intel_uncore_box *box, struct perf_event *event)
{
	struct hw_perf_event *hwc = &event->hw;
	struct hw_perf_event_extra *reg1 = &hwc->extra_reg;
	struct hw_perf_event_extra *reg2 = &hwc->branch_reg;
	int idx;

	idx = __BITS_VALUE(reg1->idx, 0, 8);
	if (idx != 0xff)
		wrmsrl(__BITS_VALUE(reg1->reg, 0, 16),
			nhmex_mbox_shared_reg_config(box, idx));
	idx = __BITS_VALUE(reg1->idx, 1, 8);
	if (idx != 0xff)
		wrmsrl(__BITS_VALUE(reg1->reg, 1, 16),
			nhmex_mbox_shared_reg_config(box, idx));

	if (reg2->idx != EXTRA_REG_NONE) {
		wrmsrl(reg2->reg, 0);
		if (reg2->config != ~0ULL) {
			wrmsrl(reg2->reg + 1,
				reg2->config & NHMEX_M_PMON_ADDR_MATCH_MASK);
			wrmsrl(reg2->reg + 2, NHMEX_M_PMON_ADDR_MASK_MASK &
				(reg2->config >> NHMEX_M_PMON_ADDR_MASK_SHIFT));
			wrmsrl(reg2->reg, NHMEX_M_PMON_MM_CFG_EN);
		}
	}

	wrmsrl(hwc->config_base, hwc->config | NHMEX_PMON_CTL_EN_BIT0);
}

DEFINE_UNCORE_FORMAT_ATTR(count_mode,		count_mode,	"config:2-3");
DEFINE_UNCORE_FORMAT_ATTR(storage_mode,		storage_mode,	"config:4-5");
DEFINE_UNCORE_FORMAT_ATTR(wrap_mode,		wrap_mode,	"config:6");
DEFINE_UNCORE_FORMAT_ATTR(flag_mode,		flag_mode,	"config:7");
DEFINE_UNCORE_FORMAT_ATTR(inc_sel,		inc_sel,	"config:9-13");
DEFINE_UNCORE_FORMAT_ATTR(set_flag_sel,		set_flag_sel,	"config:19-21");
DEFINE_UNCORE_FORMAT_ATTR(filter_cfg_en,	filter_cfg_en,	"config2:63");
DEFINE_UNCORE_FORMAT_ATTR(filter_match,		filter_match,	"config2:0-33");
DEFINE_UNCORE_FORMAT_ATTR(filter_mask,		filter_mask,	"config2:34-61");
DEFINE_UNCORE_FORMAT_ATTR(dsp,			dsp,		"config1:0-31");
DEFINE_UNCORE_FORMAT_ATTR(thr,			thr,		"config1:0-31");
DEFINE_UNCORE_FORMAT_ATTR(fvc,			fvc,		"config1:0-31");
DEFINE_UNCORE_FORMAT_ATTR(pgt,			pgt,		"config1:0-31");
DEFINE_UNCORE_FORMAT_ATTR(map,			map,		"config1:0-31");
DEFINE_UNCORE_FORMAT_ATTR(iss,			iss,		"config1:0-31");
DEFINE_UNCORE_FORMAT_ATTR(pld,			pld,		"config1:32-63");

static struct attribute *nhmex_uncore_mbox_formats_attr[] = {
	&format_attr_count_mode.attr,
	&format_attr_storage_mode.attr,
	&format_attr_wrap_mode.attr,
	&format_attr_flag_mode.attr,
	&format_attr_inc_sel.attr,
	&format_attr_set_flag_sel.attr,
	&format_attr_filter_cfg_en.attr,
	&format_attr_filter_match.attr,
	&format_attr_filter_mask.attr,
	&format_attr_dsp.attr,
	&format_attr_thr.attr,
	&format_attr_fvc.attr,
	&format_attr_pgt.attr,
	&format_attr_map.attr,
	&format_attr_iss.attr,
	&format_attr_pld.attr,
	NULL,
};

static struct attribute_group nhmex_uncore_mbox_format_group = {
	.name		= "format",
	.attrs		= nhmex_uncore_mbox_formats_attr,
};

static struct uncore_event_desc nhmex_uncore_mbox_events[] = {
	INTEL_UNCORE_EVENT_DESC(bbox_cmds_read, "inc_sel=0xd,fvc=0x2800"),
	INTEL_UNCORE_EVENT_DESC(bbox_cmds_write, "inc_sel=0xd,fvc=0x2820"),
	{ /* end: all zeroes */ },
};

static struct uncore_event_desc wsmex_uncore_mbox_events[] = {
	INTEL_UNCORE_EVENT_DESC(bbox_cmds_read, "inc_sel=0xd,fvc=0x5000"),
	INTEL_UNCORE_EVENT_DESC(bbox_cmds_write, "inc_sel=0xd,fvc=0x5040"),
	{ /* end: all zeroes */ },
};

static struct intel_uncore_ops nhmex_uncore_mbox_ops = {
	NHMEX_UNCORE_OPS_COMMON_INIT(),
	.enable_event	= nhmex_mbox_msr_enable_event,
	.hw_config	= nhmex_mbox_hw_config,
	.get_constraint	= nhmex_mbox_get_constraint,
	.put_constraint	= nhmex_mbox_put_constraint,
};

static struct intel_uncore_type nhmex_uncore_mbox = {
	.name			= "mbox",
	.num_counters		= 6,
	.num_boxes		= 2,
	.perf_ctr_bits		= 48,
	.event_ctl		= NHMEX_M0_MSR_PMU_CTL0,
	.perf_ctr		= NHMEX_M0_MSR_PMU_CNT0,
	.event_mask		= NHMEX_M_PMON_RAW_EVENT_MASK,
	.box_ctl		= NHMEX_M0_MSR_GLOBAL_CTL,
	.msr_offset		= NHMEX_M_MSR_OFFSET,
	.pair_ctr_ctl		= 1,
	.num_shared_regs	= 8,
	.event_descs		= nhmex_uncore_mbox_events,
	.ops			= &nhmex_uncore_mbox_ops,
	.format_group		= &nhmex_uncore_mbox_format_group,
};

static void nhmex_rbox_alter_er(struct intel_uncore_box *box, struct perf_event *event)
{
	struct hw_perf_event *hwc = &event->hw;
	struct hw_perf_event_extra *reg1 = &hwc->extra_reg;

	/* adjust the main event selector and extra register index */
	if (reg1->idx % 2) {
		reg1->idx--;
		hwc->config -= 1 << NHMEX_R_PMON_CTL_EV_SEL_SHIFT;
	} else {
		reg1->idx++;
		hwc->config += 1 << NHMEX_R_PMON_CTL_EV_SEL_SHIFT;
	}

	/* adjust extra register config */
	switch (reg1->idx % 6) {
	case 2:
		/* shift the 8~15 bits to the 0~7 bits */
		reg1->config >>= 8;
		break;
	case 3:
		/* shift the 0~7 bits to the 8~15 bits */
		reg1->config <<= 8;
		break;
	};
}

/*
 * Each rbox has 4 event set which monitor PQI port 0~3 or 4~7.
 * An event set consists of 6 events, the 3rd and 4th events in
 * an event set use the same extra register. So an event set uses
 * 5 extra registers.
 */
static struct event_constraint *
nhmex_rbox_get_constraint(struct intel_uncore_box *box, struct perf_event *event)
{
	struct hw_perf_event *hwc = &event->hw;
	struct hw_perf_event_extra *reg1 = &hwc->extra_reg;
	struct hw_perf_event_extra *reg2 = &hwc->branch_reg;
	struct intel_uncore_extra_reg *er;
	unsigned long flags;
	int idx, er_idx;
	u64 config1;
	bool ok = false;

	if (!uncore_box_is_fake(box) && reg1->alloc)
		return NULL;

	idx = reg1->idx % 6;
	config1 = reg1->config;
again:
	er_idx = idx;
	/* the 3rd and 4th events use the same extra register */
	if (er_idx > 2)
		er_idx--;
	er_idx += (reg1->idx / 6) * 5;

	er = &box->shared_regs[er_idx];
	spin_lock_irqsave(&er->lock, flags);
	if (idx < 2) {
		if (!atomic_read(&er->ref) || er->config == reg1->config) {
			atomic_inc(&er->ref);
			er->config = reg1->config;
			ok = true;
		}
	} else if (idx == 2 || idx == 3) {
		/*
		 * these two events use different fields in a extra register,
		 * the 0~7 bits and the 8~15 bits respectively.
		 */
		u64 mask = 0xff << ((idx - 2) * 8);
		if (!__BITS_VALUE(atomic_read(&er->ref), idx - 2, 8) ||
				!((er->config ^ config1) & mask)) {
			atomic_add(1 << ((idx - 2) * 8), &er->ref);
			er->config &= ~mask;
			er->config |= config1 & mask;
			ok = true;
		}
	} else {
		if (!atomic_read(&er->ref) ||
				(er->config == (hwc->config >> 32) &&
				 er->config1 == reg1->config &&
				 er->config2 == reg2->config)) {
			atomic_inc(&er->ref);
			er->config = (hwc->config >> 32);
			er->config1 = reg1->config;
			er->config2 = reg2->config;
			ok = true;
		}
	}
	spin_unlock_irqrestore(&er->lock, flags);

	if (!ok) {
		/*
		 * The Rbox events are always in pairs. The paired
		 * events are functional identical, but use different
		 * extra registers. If we failed to take an extra
		 * register, try the alternative.
		 */
		idx ^= 1;
		if (idx != reg1->idx % 6) {
			if (idx == 2)
				config1 >>= 8;
			else if (idx == 3)
				config1 <<= 8;
			goto again;
		}
	} else {
		if (!uncore_box_is_fake(box)) {
			if (idx != reg1->idx % 6)
				nhmex_rbox_alter_er(box, event);
			reg1->alloc = 1;
		}
		return NULL;
	}
	return &uncore_constraint_empty;
}

static void nhmex_rbox_put_constraint(struct intel_uncore_box *box, struct perf_event *event)
{
	struct intel_uncore_extra_reg *er;
	struct hw_perf_event_extra *reg1 = &event->hw.extra_reg;
	int idx, er_idx;

	if (uncore_box_is_fake(box) || !reg1->alloc)
		return;

	idx = reg1->idx % 6;
	er_idx = idx;
	if (er_idx > 2)
		er_idx--;
	er_idx += (reg1->idx / 6) * 5;

	er = &box->shared_regs[er_idx];
	if (idx == 2 || idx == 3)
		atomic_sub(1 << ((idx - 2) * 8), &er->ref);
	else
		atomic_dec(&er->ref);

	reg1->alloc = 0;
}

static int nhmex_rbox_hw_config(struct intel_uncore_box *box, struct perf_event *event)
{
	struct hw_perf_event *hwc = &event->hw;
	struct hw_perf_event_extra *reg1 = &event->hw.extra_reg;
	struct hw_perf_event_extra *reg2 = &event->hw.branch_reg;
	int idx;

	idx = (event->hw.config & NHMEX_R_PMON_CTL_EV_SEL_MASK) >>
		NHMEX_R_PMON_CTL_EV_SEL_SHIFT;
	if (idx >= 0x18)
		return -EINVAL;

	reg1->idx = idx;
	reg1->config = event->attr.config1;

	switch (idx % 6) {
	case 4:
	case 5:
		hwc->config |= event->attr.config & (~0ULL << 32);
		reg2->config = event->attr.config2;
		break;
	};
	return 0;
}

static void nhmex_rbox_msr_enable_event(struct intel_uncore_box *box, struct perf_event *event)
{
	struct hw_perf_event *hwc = &event->hw;
	struct hw_perf_event_extra *reg1 = &hwc->extra_reg;
	struct hw_perf_event_extra *reg2 = &hwc->branch_reg;
	int idx, port;

	idx = reg1->idx;
	port = idx / 6 + box->pmu->pmu_idx * 4;

	switch (idx % 6) {
	case 0:
		wrmsrl(NHMEX_R_MSR_PORTN_IPERF_CFG0(port), reg1->config);
		break;
	case 1:
		wrmsrl(NHMEX_R_MSR_PORTN_IPERF_CFG1(port), reg1->config);
		break;
	case 2:
	case 3:
		wrmsrl(NHMEX_R_MSR_PORTN_QLX_CFG(port),
			uncore_shared_reg_config(box, 2 + (idx / 6) * 5));
		break;
	case 4:
		wrmsrl(NHMEX_R_MSR_PORTN_XBR_SET1_MM_CFG(port),
			hwc->config >> 32);
		wrmsrl(NHMEX_R_MSR_PORTN_XBR_SET1_MATCH(port), reg1->config);
		wrmsrl(NHMEX_R_MSR_PORTN_XBR_SET1_MASK(port), reg2->config);
		break;
	case 5:
		wrmsrl(NHMEX_R_MSR_PORTN_XBR_SET2_MM_CFG(port),
			hwc->config >> 32);
		wrmsrl(NHMEX_R_MSR_PORTN_XBR_SET2_MATCH(port), reg1->config);
		wrmsrl(NHMEX_R_MSR_PORTN_XBR_SET2_MASK(port), reg2->config);
		break;
	};

	wrmsrl(hwc->config_base, NHMEX_PMON_CTL_EN_BIT0 |
		(hwc->config & NHMEX_R_PMON_CTL_EV_SEL_MASK));
}

DEFINE_UNCORE_FORMAT_ATTR(xbr_mm_cfg, xbr_mm_cfg, "config:32-63");
DEFINE_UNCORE_FORMAT_ATTR(xbr_match, xbr_match, "config1:0-63");
DEFINE_UNCORE_FORMAT_ATTR(xbr_mask, xbr_mask, "config2:0-63");
DEFINE_UNCORE_FORMAT_ATTR(qlx_cfg, qlx_cfg, "config1:0-15");
DEFINE_UNCORE_FORMAT_ATTR(iperf_cfg, iperf_cfg, "config1:0-31");

static struct attribute *nhmex_uncore_rbox_formats_attr[] = {
	&format_attr_event5.attr,
	&format_attr_xbr_mm_cfg.attr,
	&format_attr_xbr_match.attr,
	&format_attr_xbr_mask.attr,
	&format_attr_qlx_cfg.attr,
	&format_attr_iperf_cfg.attr,
	NULL,
};

static struct attribute_group nhmex_uncore_rbox_format_group = {
	.name = "format",
	.attrs = nhmex_uncore_rbox_formats_attr,
};

static struct uncore_event_desc nhmex_uncore_rbox_events[] = {
	INTEL_UNCORE_EVENT_DESC(qpi0_flit_send,		"event=0x0,iperf_cfg=0x80000000"),
	INTEL_UNCORE_EVENT_DESC(qpi1_filt_send,		"event=0x6,iperf_cfg=0x80000000"),
	INTEL_UNCORE_EVENT_DESC(qpi0_idle_filt,		"event=0x0,iperf_cfg=0x40000000"),
	INTEL_UNCORE_EVENT_DESC(qpi1_idle_filt,		"event=0x6,iperf_cfg=0x40000000"),
	INTEL_UNCORE_EVENT_DESC(qpi0_date_response,	"event=0x0,iperf_cfg=0xc4"),
	INTEL_UNCORE_EVENT_DESC(qpi1_date_response,	"event=0x6,iperf_cfg=0xc4"),
	{ /* end: all zeroes */ },
};

static struct intel_uncore_ops nhmex_uncore_rbox_ops = {
	NHMEX_UNCORE_OPS_COMMON_INIT(),
	.enable_event		= nhmex_rbox_msr_enable_event,
	.hw_config		= nhmex_rbox_hw_config,
	.get_constraint		= nhmex_rbox_get_constraint,
	.put_constraint		= nhmex_rbox_put_constraint,
};

static struct intel_uncore_type nhmex_uncore_rbox = {
	.name			= "rbox",
	.num_counters		= 8,
	.num_boxes		= 2,
	.perf_ctr_bits		= 48,
	.event_ctl		= NHMEX_R_MSR_PMON_CTL0,
	.perf_ctr		= NHMEX_R_MSR_PMON_CNT0,
	.event_mask		= NHMEX_R_PMON_RAW_EVENT_MASK,
	.box_ctl		= NHMEX_R_MSR_GLOBAL_CTL,
	.msr_offset		= NHMEX_R_MSR_OFFSET,
	.pair_ctr_ctl		= 1,
	.num_shared_regs	= 20,
	.event_descs		= nhmex_uncore_rbox_events,
	.ops			= &nhmex_uncore_rbox_ops,
	.format_group		= &nhmex_uncore_rbox_format_group
};

static struct intel_uncore_type *nhmex_msr_uncores[] = {
	&nhmex_uncore_ubox,
	&nhmex_uncore_cbox,
	&nhmex_uncore_bbox,
	&nhmex_uncore_sbox,
	&nhmex_uncore_mbox,
	&nhmex_uncore_rbox,
	&nhmex_uncore_wbox,
	NULL,
};
/* end of Nehalem-EX uncore support */

static void uncore_assign_hw_event(struct intel_uncore_box *box, struct perf_event *event, int idx)
{
	struct hw_perf_event *hwc = &event->hw;

	hwc->idx = idx;
	hwc->last_tag = ++box->tags[idx];

	if (hwc->idx == UNCORE_PMC_IDX_FIXED) {
		hwc->event_base = uncore_fixed_ctr(box);
		hwc->config_base = uncore_fixed_ctl(box);
		return;
	}

	hwc->config_base = uncore_event_ctl(box, hwc->idx);
	hwc->event_base  = uncore_perf_ctr(box, hwc->idx);
}

void uncore_perf_event_update(struct intel_uncore_box *box, struct perf_event *event)
{
	u64 prev_count, new_count, delta;
	int shift;

	if (event->hw.idx >= UNCORE_PMC_IDX_FIXED)
		shift = 64 - uncore_fixed_ctr_bits(box);
	else
		shift = 64 - uncore_perf_ctr_bits(box);

	/* the hrtimer might modify the previous event value */
again:
	prev_count = local64_read(&event->hw.prev_count);
	new_count = uncore_read_counter(box, event);
	if (local64_xchg(&event->hw.prev_count, new_count) != prev_count)
		goto again;

	delta = (new_count << shift) - (prev_count << shift);
	delta >>= shift;

	local64_add(delta, &event->count);
}

/*
 * The overflow interrupt is unavailable for SandyBridge-EP, is broken
 * for SandyBridge. So we use hrtimer to periodically poll the counter
 * to avoid overflow.
 */
static enum hrtimer_restart uncore_pmu_hrtimer(struct hrtimer *hrtimer)
{
	struct intel_uncore_box *box;
	struct perf_event *event;
	unsigned long flags;
	int bit;

	box = container_of(hrtimer, struct intel_uncore_box, hrtimer);
	if (!box->n_active || box->cpu != smp_processor_id())
		return HRTIMER_NORESTART;
	/*
	 * disable local interrupt to prevent uncore_pmu_event_start/stop
	 * to interrupt the update process
	 */
	local_irq_save(flags);

	/*
	 * handle boxes with an active event list as opposed to active
	 * counters
	 */
	list_for_each_entry(event, &box->active_list, active_entry) {
		uncore_perf_event_update(box, event);
	}

	for_each_set_bit(bit, box->active_mask, UNCORE_PMC_IDX_MAX)
		uncore_perf_event_update(box, box->events[bit]);

	local_irq_restore(flags);

	hrtimer_forward_now(hrtimer, ns_to_ktime(box->hrtimer_duration));
	return HRTIMER_RESTART;
}

void uncore_pmu_start_hrtimer(struct intel_uncore_box *box)
{
	__hrtimer_start_range_ns(&box->hrtimer,
			ns_to_ktime(box->hrtimer_duration), 0,
			HRTIMER_MODE_REL_PINNED, 0);
}

void uncore_pmu_cancel_hrtimer(struct intel_uncore_box *box)
{
	hrtimer_cancel(&box->hrtimer);
}

static void uncore_pmu_init_hrtimer(struct intel_uncore_box *box)
{
	hrtimer_init(&box->hrtimer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	box->hrtimer.function = uncore_pmu_hrtimer;
}

static struct intel_uncore_box *uncore_alloc_box(struct intel_uncore_type *type, int node)
{
	struct intel_uncore_box *box;
	int i, size;

	size = sizeof(*box) + type->num_shared_regs * sizeof(struct intel_uncore_extra_reg);

	box = kzalloc_node(size, GFP_KERNEL, node);
	if (!box)
		return NULL;

	for (i = 0; i < type->num_shared_regs; i++)
		spin_lock_init(&box->shared_regs[i].lock);

	uncore_pmu_init_hrtimer(box);
	atomic_set(&box->refcnt, 1);
	box->cpu = -1;
	box->phys_id = -1;

	/* set default hrtimer timeout */
	box->hrtimer_duration = UNCORE_PMU_HRTIMER_INTERVAL;

	INIT_LIST_HEAD(&box->active_list);

	return box;
}

/*
 * Using uncore_pmu_event_init pmu event_init callback
 * as a detection point for uncore events.
 */
static int uncore_pmu_event_init(struct perf_event *event);

static bool is_uncore_event(struct perf_event *event)
{
	return event->pmu->event_init == uncore_pmu_event_init;
}

static int
uncore_collect_events(struct intel_uncore_box *box, struct perf_event *leader, bool dogrp)
{
	struct perf_event *event;
	int n, max_count;

	max_count = box->pmu->type->num_counters;
	if (box->pmu->type->fixed_ctl)
		max_count++;

	if (box->n_events >= max_count)
		return -EINVAL;

	n = box->n_events;

	if (is_uncore_event(leader)) {
		box->event_list[n] = leader;
		n++;
	}

	if (!dogrp)
		return n;

	list_for_each_entry(event, &leader->sibling_list, group_entry) {
		if (!is_uncore_event(event) ||
		    event->state <= PERF_EVENT_STATE_OFF)
			continue;

		if (n >= max_count)
			return -EINVAL;

		box->event_list[n] = event;
		n++;
	}
	return n;
}

static struct event_constraint *
uncore_get_event_constraint(struct intel_uncore_box *box, struct perf_event *event)
{
	struct intel_uncore_type *type = box->pmu->type;
	struct event_constraint *c;

	if (type->ops->get_constraint) {
		c = type->ops->get_constraint(box, event);
		if (c)
			return c;
	}

	if (event->attr.config == UNCORE_FIXED_EVENT)
		return &uncore_constraint_fixed;

	if (type->constraints) {
		for_each_event_constraint(c, type->constraints) {
			if ((event->hw.config & c->cmask) == c->code)
				return c;
		}
	}

	return &type->unconstrainted;
}

static void uncore_put_event_constraint(struct intel_uncore_box *box, struct perf_event *event)
{
	if (box->pmu->type->ops->put_constraint)
		box->pmu->type->ops->put_constraint(box, event);
}

static int uncore_assign_events(struct intel_uncore_box *box, int assign[], int n)
{
	unsigned long used_mask[BITS_TO_LONGS(UNCORE_PMC_IDX_MAX)];
	struct event_constraint *c;
	int i, wmin, wmax, ret = 0;
	struct hw_perf_event *hwc;

	bitmap_zero(used_mask, UNCORE_PMC_IDX_MAX);

	for (i = 0, wmin = UNCORE_PMC_IDX_MAX, wmax = 0; i < n; i++) {
		c = uncore_get_event_constraint(box, box->event_list[i]);
		box->event_constraint[i] = c;
		wmin = min(wmin, c->weight);
		wmax = max(wmax, c->weight);
	}

	/* fastpath, try to reuse previous register */
	for (i = 0; i < n; i++) {
		hwc = &box->event_list[i]->hw;
		c = box->event_constraint[i];

		/* never assigned */
		if (hwc->idx == -1)
			break;

		/* constraint still honored */
		if (!test_bit(hwc->idx, c->idxmsk))
			break;

		/* not already used */
		if (test_bit(hwc->idx, used_mask))
			break;

		__set_bit(hwc->idx, used_mask);
		if (assign)
			assign[i] = hwc->idx;
	}
	/* slow path */
	if (i != n)
		ret = perf_assign_events(box->event_constraint, n,
					 wmin, wmax, n, assign);

	if (!assign || ret) {
		for (i = 0; i < n; i++)
			uncore_put_event_constraint(box, box->event_list[i]);
	}
	return ret ? -EINVAL : 0;
}

static void uncore_pmu_event_start(struct perf_event *event, int flags)
{
	struct intel_uncore_box *box = uncore_event_to_box(event);
	int idx = event->hw.idx;

	if (WARN_ON_ONCE(!(event->hw.state & PERF_HES_STOPPED)))
		return;

	if (WARN_ON_ONCE(idx == -1 || idx >= UNCORE_PMC_IDX_MAX))
		return;

	event->hw.state = 0;
	box->events[idx] = event;
	box->n_active++;
	__set_bit(idx, box->active_mask);

	local64_set(&event->hw.prev_count, uncore_read_counter(box, event));
	uncore_enable_event(box, event);

	if (box->n_active == 1) {
		uncore_enable_box(box);
		uncore_pmu_start_hrtimer(box);
	}
}

static void uncore_pmu_event_stop(struct perf_event *event, int flags)
{
	struct intel_uncore_box *box = uncore_event_to_box(event);
	struct hw_perf_event *hwc = &event->hw;

	if (__test_and_clear_bit(hwc->idx, box->active_mask)) {
		uncore_disable_event(box, event);
		box->n_active--;
		box->events[hwc->idx] = NULL;
		WARN_ON_ONCE(hwc->state & PERF_HES_STOPPED);
		hwc->state |= PERF_HES_STOPPED;

		if (box->n_active == 0) {
			uncore_disable_box(box);
			uncore_pmu_cancel_hrtimer(box);
		}
	}

	if ((flags & PERF_EF_UPDATE) && !(hwc->state & PERF_HES_UPTODATE)) {
		/*
		 * Drain the remaining delta count out of a event
		 * that we are disabling:
		 */
		uncore_perf_event_update(box, event);
		hwc->state |= PERF_HES_UPTODATE;
	}
}

static int uncore_pmu_event_add(struct perf_event *event, int flags)
{
	struct intel_uncore_box *box = uncore_event_to_box(event);
	struct hw_perf_event *hwc = &event->hw;
	int assign[UNCORE_PMC_IDX_MAX];
	int i, n, ret;

	if (!box)
		return -ENODEV;

	ret = n = uncore_collect_events(box, event, false);
	if (ret < 0)
		return ret;

	hwc->state = PERF_HES_UPTODATE | PERF_HES_STOPPED;
	if (!(flags & PERF_EF_START))
		hwc->state |= PERF_HES_ARCH;

	ret = uncore_assign_events(box, assign, n);
	if (ret)
		return ret;

	/* save events moving to new counters */
	for (i = 0; i < box->n_events; i++) {
		event = box->event_list[i];
		hwc = &event->hw;

		if (hwc->idx == assign[i] &&
			hwc->last_tag == box->tags[assign[i]])
			continue;
		/*
		 * Ensure we don't accidentally enable a stopped
		 * counter simply because we rescheduled.
		 */
		if (hwc->state & PERF_HES_STOPPED)
			hwc->state |= PERF_HES_ARCH;

		uncore_pmu_event_stop(event, PERF_EF_UPDATE);
	}

	/* reprogram moved events into new counters */
	for (i = 0; i < n; i++) {
		event = box->event_list[i];
		hwc = &event->hw;

		if (hwc->idx != assign[i] ||
			hwc->last_tag != box->tags[assign[i]])
			uncore_assign_hw_event(box, event, assign[i]);
		else if (i < box->n_events)
			continue;

		if (hwc->state & PERF_HES_ARCH)
			continue;

		uncore_pmu_event_start(event, 0);
	}
	box->n_events = n;

	return 0;
}

static void uncore_pmu_event_del(struct perf_event *event, int flags)
{
	struct intel_uncore_box *box = uncore_event_to_box(event);
	int i;

	uncore_pmu_event_stop(event, PERF_EF_UPDATE);

	for (i = 0; i < box->n_events; i++) {
		if (event == box->event_list[i]) {
			uncore_put_event_constraint(box, event);

			while (++i < box->n_events)
				box->event_list[i - 1] = box->event_list[i];

			--box->n_events;
			break;
		}
	}

	event->hw.idx = -1;
	event->hw.last_tag = ~0ULL;
}

void uncore_pmu_event_read(struct perf_event *event)
{
	struct intel_uncore_box *box = uncore_event_to_box(event);
	uncore_perf_event_update(box, event);
}

/*
 * validation ensures the group can be loaded onto the
 * PMU if it was the only group available.
 */
static int uncore_validate_group(struct intel_uncore_pmu *pmu,
				struct perf_event *event)
{
	struct perf_event *leader = event->group_leader;
	struct intel_uncore_box *fake_box;
	int ret = -EINVAL, n;

	fake_box = uncore_alloc_box(pmu->type, NUMA_NO_NODE);
	if (!fake_box)
		return -ENOMEM;

	fake_box->pmu = pmu;
	/*
	 * the event is not yet connected with its
	 * siblings therefore we must first collect
	 * existing siblings, then add the new event
	 * before we can simulate the scheduling
	 */
	n = uncore_collect_events(fake_box, leader, true);
	if (n < 0)
		goto out;

	fake_box->n_events = n;
	n = uncore_collect_events(fake_box, event, false);
	if (n < 0)
		goto out;

	fake_box->n_events = n;

	ret = uncore_assign_events(fake_box, NULL, n);
out:
	kfree(fake_box);
	return ret;
}

static int uncore_pmu_event_init(struct perf_event *event)
{
	struct intel_uncore_pmu *pmu;
	struct intel_uncore_box *box;
	struct hw_perf_event *hwc = &event->hw;
	int ret;

	if (event->attr.type != event->pmu->type)
		return -ENOENT;

	pmu = uncore_event_to_pmu(event);
	/* no device found for this pmu */
	if (pmu->func_id < 0)
		return -ENOENT;

	/*
	 * Uncore PMU does measure at all privilege level all the time.
	 * So it doesn't make sense to specify any exclude bits.
	 */
	if (event->attr.exclude_user || event->attr.exclude_kernel ||
			event->attr.exclude_hv || event->attr.exclude_idle)
		return -EINVAL;

	/* Sampling not supported yet */
	if (hwc->sample_period)
		return -EINVAL;

	/*
	 * Place all uncore events for a particular physical package
	 * onto a single cpu
	 */
	if (event->cpu < 0)
		return -EINVAL;
	box = uncore_pmu_to_box(pmu, event->cpu);
	if (!box || box->cpu < 0)
		return -EINVAL;
	event->cpu = box->cpu;

	event->hw.idx = -1;
	event->hw.last_tag = ~0ULL;
	event->hw.extra_reg.idx = EXTRA_REG_NONE;
	event->hw.branch_reg.idx = EXTRA_REG_NONE;

	event->hw.idx = -1;
	event->hw.last_tag = ~0ULL;
	event->hw.extra_reg.idx = EXTRA_REG_NONE;

	if (event->attr.config == UNCORE_FIXED_EVENT) {
		/* no fixed counter */
		if (!pmu->type->fixed_ctl)
			return -EINVAL;
		/*
		 * if there is only one fixed counter, only the first pmu
		 * can access the fixed counter
		 */
		if (pmu->type->single_fixed && pmu->pmu_idx > 0)
			return -EINVAL;

		/* fixed counters have event field hardcoded to zero */
		hwc->config = 0ULL;
	} else {
		hwc->config = event->attr.config & pmu->type->event_mask;
		if (pmu->type->ops->hw_config) {
			ret = pmu->type->ops->hw_config(box, event);
			if (ret)
				return ret;
		}
	}

	if (event->group_leader != event)
		ret = uncore_validate_group(pmu, event);
	else
		ret = 0;

	return ret;
}

static ssize_t uncore_get_attr_cpumask(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	int n = cpulist_scnprintf(buf, PAGE_SIZE - 2, &uncore_cpu_mask);

	buf[n++] = '\n';
	buf[n] = '\0';
	return n;
}

static DEVICE_ATTR(cpumask, S_IRUGO, uncore_get_attr_cpumask, NULL);

static struct attribute *uncore_pmu_attrs[] = {
	&dev_attr_cpumask.attr,
	NULL,
};

static struct attribute_group uncore_pmu_attr_group = {
	.attrs = uncore_pmu_attrs,
};

static int uncore_pmu_register(struct intel_uncore_pmu *pmu)
{
	int ret;

	if (!pmu->type->pmu) {
		pmu->pmu = (struct pmu) {
			.attr_groups	= pmu->type->attr_groups,
			.task_ctx_nr	= perf_invalid_context,
			.event_init	= uncore_pmu_event_init,
			.add		= uncore_pmu_event_add,
			.del		= uncore_pmu_event_del,
			.start		= uncore_pmu_event_start,
			.stop		= uncore_pmu_event_stop,
			.read		= uncore_pmu_event_read,
		};
	} else {
		pmu->pmu = *pmu->type->pmu;
		pmu->pmu.attr_groups = pmu->type->attr_groups;
	}

	if (pmu->type->num_boxes == 1) {
		if (strlen(pmu->type->name) > 0)
			sprintf(pmu->name, "uncore_%s", pmu->type->name);
		else
			sprintf(pmu->name, "uncore");
	} else {
		sprintf(pmu->name, "uncore_%s_%d", pmu->type->name,
			pmu->pmu_idx);
	}

	ret = perf_pmu_register(&pmu->pmu, pmu->name, -1);
	return ret;
}

static void __init uncore_type_exit(struct intel_uncore_type *type)
{
	int i;

	for (i = 0; i < type->num_boxes; i++)
		free_percpu(type->pmus[i].box);
	kfree(type->pmus);
	type->pmus = NULL;
	kfree(type->events_group);
	type->events_group = NULL;
}

static void __init uncore_types_exit(struct intel_uncore_type **types)
{
	int i;
	for (i = 0; types[i]; i++)
		uncore_type_exit(types[i]);
}

static int __init uncore_type_init(struct intel_uncore_type *type)
{
	struct intel_uncore_pmu *pmus;
	struct attribute_group *attr_group;
	struct attribute **attrs;
	int i, j;

	pmus = kzalloc(sizeof(*pmus) * type->num_boxes, GFP_KERNEL);
	if (!pmus)
		return -ENOMEM;

	type->pmus = pmus;

	type->unconstrainted = (struct event_constraint)
		__EVENT_CONSTRAINT(0, (1ULL << type->num_counters) - 1,
				0, type->num_counters, 0, 0);

	for (i = 0; i < type->num_boxes; i++) {
		pmus[i].func_id = -1;
		pmus[i].pmu_idx = i;
		pmus[i].type = type;
		INIT_LIST_HEAD(&pmus[i].box_list);
		pmus[i].box = alloc_percpu(struct intel_uncore_box *);
		if (!pmus[i].box)
			goto fail;
	}

	if (type->event_descs) {
		i = 0;
		while (type->event_descs[i].attr.attr.name)
			i++;

		attr_group = kzalloc(sizeof(struct attribute *) * (i + 1) +
					sizeof(*attr_group), GFP_KERNEL);
		if (!attr_group)
			goto fail;

		attrs = (struct attribute **)(attr_group + 1);
		attr_group->name = "events";
		attr_group->attrs = attrs;

		for (j = 0; j < i; j++)
			attrs[j] = &type->event_descs[j].attr.attr;

		type->events_group = attr_group;
	}

	type->pmu_group = &uncore_pmu_attr_group;
	return 0;
fail:
	uncore_type_exit(type);
	return -ENOMEM;
}

static int __init uncore_types_init(struct intel_uncore_type **types)
{
	int i, ret;

	for (i = 0; types[i]; i++) {
		ret = uncore_type_init(types[i]);
		if (ret)
			goto fail;
	}
	return 0;
fail:
	while (--i >= 0)
		uncore_type_exit(types[i]);
	return ret;
}

/*
 * add a pci uncore device
 */
static int __devinit uncore_pci_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct intel_uncore_pmu *pmu;
	struct intel_uncore_box *box;
	struct intel_uncore_type *type;
	int phys_id;
	bool first_box = false;

	phys_id = uncore_pcibus_to_physid[pdev->bus->number];
	if (phys_id < 0)
		return -ENODEV;

	if (UNCORE_PCI_DEV_TYPE(id->driver_data) == UNCORE_EXTRA_PCI_DEV) {
		int idx = UNCORE_PCI_DEV_IDX(id->driver_data);
		uncore_extra_pci_dev[phys_id][idx] = pdev;
		pci_set_drvdata(pdev, NULL);
		return 0;
	}

	type = uncore_pci_uncores[UNCORE_PCI_DEV_TYPE(id->driver_data)];
	box = uncore_alloc_box(type, NUMA_NO_NODE);
	if (!box)
		return -ENOMEM;

	/*
	 * for performance monitoring unit with multiple boxes,
	 * each box has a different function id.
	 */
	pmu = &type->pmus[UNCORE_PCI_DEV_IDX(id->driver_data)];
	if (pmu->func_id < 0)
		pmu->func_id = pdev->devfn;
	else
		WARN_ON_ONCE(pmu->func_id != pdev->devfn);

	box->phys_id = phys_id;
	box->pci_dev = pdev;
	box->pmu = pmu;
	uncore_box_init(box);
	pci_set_drvdata(pdev, box);

	spin_lock(&uncore_box_lock);
	if (list_empty(&pmu->box_list))
		first_box = true;
	list_add_tail(&box->list, &pmu->box_list);
	spin_unlock(&uncore_box_lock);

	if (first_box)
		uncore_pmu_register(pmu);
	return 0;
}

static void uncore_pci_remove(struct pci_dev *pdev)
{
	struct intel_uncore_box *box = pci_get_drvdata(pdev);
	struct intel_uncore_pmu *pmu;
	int i, cpu, phys_id = uncore_pcibus_to_physid[pdev->bus->number];
	bool last_box = false;

	box = pci_get_drvdata(pdev);
	if (!box) {
		for (i = 0; i < UNCORE_EXTRA_PCI_DEV_MAX; i++) {
			if (uncore_extra_pci_dev[phys_id][i] == pdev) {
				uncore_extra_pci_dev[phys_id][i] = NULL;
				break;
			}
		}
		WARN_ON_ONCE(i >= UNCORE_EXTRA_PCI_DEV_MAX);
		return;
	}

	pmu = box->pmu;
	if (WARN_ON_ONCE(phys_id != box->phys_id))
		return;

	pci_set_drvdata(pdev, NULL);

	spin_lock(&uncore_box_lock);
	list_del(&box->list);
	if (list_empty(&pmu->box_list))
		last_box = true;
	spin_unlock(&uncore_box_lock);

	for_each_possible_cpu(cpu) {
		if (*per_cpu_ptr(pmu->box, cpu) == box) {
			*per_cpu_ptr(pmu->box, cpu) = NULL;
			atomic_dec(&box->refcnt);
		}
	}

	WARN_ON_ONCE(atomic_read(&box->refcnt) != 1);
	kfree(box);

	if (last_box)
		perf_pmu_unregister(&pmu->pmu);
}

static int __init uncore_pci_init(void)
{
	int ret;

	switch (boot_cpu_data.x86_model) {
	case 45: /* Sandy Bridge-EP */
		ret = snbep_uncore_pci_init();
		break;
	case 62: /* Ivy Bridge-EP */
		ret = ivbep_uncore_pci_init();
		break;
	case 63: /* Haswell-EP */
		ret = hswep_uncore_pci_init();
		break;
	case 79: /* BDX-EP */
	case 86: /* BDX-DE */
		ret = bdx_uncore_pci_init();
		break;
	case 42: /* Sandy Bridge */
		ret = snb_uncore_pci_init();
		break;
	case 58: /* Ivy Bridge */
		ret = ivb_uncore_pci_init();
		break;
	case 60: /* Haswell */
	case 69: /* Haswell Celeron */
		ret = hsw_uncore_pci_init();
		break;
	case 61: /* Broadwell */
		ret = bdw_uncore_pci_init();
		break;
	default:
		return -ENODEV;
	}

	if (ret)
		return ret;

	ret = uncore_types_init(uncore_pci_uncores);
	if (ret)
		return ret;

	uncore_pci_driver->probe = uncore_pci_probe;
	uncore_pci_driver->remove = uncore_pci_remove;

	ret = pci_register_driver(uncore_pci_driver);
	if (ret == 0)
		pcidrv_registered = true;
	else
		uncore_types_exit(uncore_pci_uncores);

	return ret;
}

static void __cpuinit uncore_cpu_dying(int cpu)
{
	struct intel_uncore_type *type;
	struct intel_uncore_pmu *pmu;
	struct intel_uncore_box *box;
	int i, j;

	for (i = 0; uncore_msr_uncores[i]; i++) {
		type = uncore_msr_uncores[i];
		for (j = 0; j < type->num_boxes; j++) {
			pmu = &type->pmus[j];
			box = *per_cpu_ptr(pmu->box, cpu);
			*per_cpu_ptr(pmu->box, cpu) = NULL;
			if (box && atomic_dec_and_test(&box->refcnt))
				kfree(box);
		}
	}
}

static int __cpuinit uncore_cpu_starting(int cpu)
{
	struct intel_uncore_type *type;
	struct intel_uncore_pmu *pmu;
	struct intel_uncore_box *box, *exist;
	int i, j, k, phys_id;

	phys_id = topology_physical_package_id(cpu);

	for (i = 0; uncore_msr_uncores[i]; i++) {
		type = uncore_msr_uncores[i];
		for (j = 0; j < type->num_boxes; j++) {
			pmu = &type->pmus[j];
			box = *per_cpu_ptr(pmu->box, cpu);
			/* called by uncore_cpu_init? */
			if (box && box->phys_id >= 0) {
				uncore_box_init(box);
				continue;
			}

			for_each_online_cpu(k) {
				exist = *per_cpu_ptr(pmu->box, k);
				if (exist && exist->phys_id == phys_id) {
					atomic_inc(&exist->refcnt);
					*per_cpu_ptr(pmu->box, cpu) = exist;
					kfree(box);
					box = NULL;
					break;
				}
			}

			if (box) {
				box->phys_id = phys_id;
				uncore_box_init(box);
			}
		}
	}
	return 0;
}

static int __cpuinit uncore_cpu_prepare(int cpu, int phys_id)
{
	struct intel_uncore_type *type;
	struct intel_uncore_pmu *pmu;
	struct intel_uncore_box *box;
	int i, j;

	for (i = 0; uncore_msr_uncores[i]; i++) {
		type = uncore_msr_uncores[i];
		for (j = 0; j < type->num_boxes; j++) {
			pmu = &type->pmus[j];
			if (pmu->func_id < 0)
				pmu->func_id = j;

			box = uncore_alloc_box(type, cpu_to_node(cpu));
			if (!box)
				return -ENOMEM;

			box->pmu = pmu;
			box->phys_id = phys_id;
			*per_cpu_ptr(pmu->box, cpu) = box;
		}
	}
	return 0;
}

static void __cpuinit
uncore_change_context(struct intel_uncore_type **uncores, int old_cpu, int new_cpu)
{
	struct intel_uncore_type *type;
	struct intel_uncore_pmu *pmu;
	struct intel_uncore_box *box;
	int i, j;

	for (i = 0; uncores[i]; i++) {
		type = uncores[i];
		for (j = 0; j < type->num_boxes; j++) {
			pmu = &type->pmus[j];
			if (old_cpu < 0)
				box = uncore_pmu_to_box(pmu, new_cpu);
			else
				box = uncore_pmu_to_box(pmu, old_cpu);
			if (!box)
				continue;

			if (old_cpu < 0) {
				WARN_ON_ONCE(box->cpu != -1);
				box->cpu = new_cpu;
				continue;
			}

			WARN_ON_ONCE(box->cpu != old_cpu);
			if (new_cpu >= 0) {
				uncore_pmu_cancel_hrtimer(box);
				perf_pmu_migrate_context(&pmu->pmu,
						old_cpu, new_cpu);
				box->cpu = new_cpu;
			} else {
				box->cpu = -1;
			}
		}
	}
}

static void __cpuinit uncore_event_exit_cpu(int cpu)
{
	int i, phys_id, target;

	/* if exiting cpu is used for collecting uncore events */
	if (!cpumask_test_and_clear_cpu(cpu, &uncore_cpu_mask))
		return;

	/* find a new cpu to collect uncore events */
	phys_id = topology_physical_package_id(cpu);
	target = -1;
	for_each_online_cpu(i) {
		if (i == cpu)
			continue;
		if (phys_id == topology_physical_package_id(i)) {
			target = i;
			break;
		}
	}

	/* migrate uncore events to the new cpu */
	if (target >= 0)
		cpumask_set_cpu(target, &uncore_cpu_mask);

	uncore_change_context(uncore_msr_uncores, cpu, target);
	uncore_change_context(uncore_pci_uncores, cpu, target);
}

static void __cpuinit uncore_event_init_cpu(int cpu)
{
	int i, phys_id;

	phys_id = topology_physical_package_id(cpu);
	for_each_cpu(i, &uncore_cpu_mask) {
		if (phys_id == topology_physical_package_id(i))
			return;
	}

	cpumask_set_cpu(cpu, &uncore_cpu_mask);

	uncore_change_context(uncore_msr_uncores, -1, cpu);
	uncore_change_context(uncore_pci_uncores, -1, cpu);
}

static int
 __cpuinit uncore_cpu_notifier(struct notifier_block *self, unsigned long action, void *hcpu)
{
	unsigned int cpu = (long)hcpu;

	/* allocate/free data structure for uncore box */
	switch (action & ~CPU_TASKS_FROZEN) {
	case CPU_UP_PREPARE:
		uncore_cpu_prepare(cpu, -1);
		break;
	case CPU_STARTING:
		uncore_cpu_starting(cpu);
		break;
	case CPU_UP_CANCELED:
	case CPU_DYING:
		uncore_cpu_dying(cpu);
		break;
	default:
		break;
	}

	/* select the cpu that collects uncore events */
	switch (action & ~CPU_TASKS_FROZEN) {
	case CPU_DOWN_FAILED:
	case CPU_STARTING:
		uncore_event_init_cpu(cpu);
		break;
	case CPU_DOWN_PREPARE:
		uncore_event_exit_cpu(cpu);
		break;
	default:
		break;
	}

	return NOTIFY_OK;
}

static struct notifier_block uncore_cpu_nb __cpuinitdata = {
	.notifier_call	= uncore_cpu_notifier,
	/*
	 * to migrate uncore events, our notifier should be executed
	 * before perf core's notifier.
	 */
	.priority	= CPU_PRI_PERF + 1,
};

static void __init uncore_cpu_setup(void *dummy)
{
	uncore_cpu_starting(smp_processor_id());
}

static int __init uncore_cpu_init(void)
{
	int ret, max_cores;

	max_cores = boot_cpu_data.x86_max_cores;
	switch (boot_cpu_data.x86_model) {
	case 26: /* Nehalem */
	case 30:
	case 37: /* Westmere */
	case 44:
		nhm_uncore_cpu_init();
		break;
	case 42: /* Sandy Bridge */
	case 58: /* Ivy Bridge */
	case 60: /* Haswell */
	case 69: /* Haswell */
	case 70: /* Haswell */
	case 61: /* Broadwell */
	case 71: /* Broadwell */
		snb_uncore_cpu_init();
		break;
	case 45: /* Sandy Birdge-EP */
		snbep_uncore_cpu_init();
		break;
	case 46: /* Nehalem-EX */
		uncore_nhmex = true;
	case 47: /* Westmere-EX aka. Xeon E7 */
		if (!uncore_nhmex)
			nhmex_uncore_mbox.event_descs = wsmex_uncore_mbox_events;
		if (nhmex_uncore_cbox.num_boxes > max_cores)
			nhmex_uncore_cbox.num_boxes = max_cores;
		uncore_msr_uncores = nhmex_msr_uncores;
		break;
	case 62: /* Ivy Bridge-EP */
		ivbep_uncore_cpu_init();
		break;
	case 63: /* Haswell-EP */
		hswep_uncore_cpu_init();
		break;
	case 79: /* BDX-EP */
	case 86: /* BDX-DE */
		bdx_uncore_cpu_init();
		break;
	default:
		return -ENODEV;
	}

	ret = uncore_types_init(uncore_msr_uncores);
	if (ret)
		return ret;

	return 0;
}

static int __init uncore_pmus_register(void)
{
	struct intel_uncore_pmu *pmu;
	struct intel_uncore_type *type;
	int i, j;

	for (i = 0; uncore_msr_uncores[i]; i++) {
		type = uncore_msr_uncores[i];
		for (j = 0; j < type->num_boxes; j++) {
			pmu = &type->pmus[j];
			uncore_pmu_register(pmu);
		}
	}

	return 0;
}

static void __init uncore_cpumask_init(bool msr)
{
	int cpu;

	/*
	 * ony invoke once from msr or pci init code
	 */
	if (!cpumask_empty(&uncore_cpu_mask))
		return;

	get_online_cpus();

	for_each_online_cpu(cpu) {
		int i, phys_id = topology_physical_package_id(cpu);

		for_each_cpu(i, &uncore_cpu_mask) {
			if (phys_id == topology_physical_package_id(i)) {
				phys_id = -1;
				break;
			}
		}
		if (phys_id < 0)
			continue;

		if (msr)
			uncore_cpu_prepare(cpu, phys_id);

		uncore_event_init_cpu(cpu);
	}
	on_each_cpu(uncore_cpu_setup, NULL, 1);

	register_cpu_notifier(&uncore_cpu_nb);

	put_online_cpus();
}


static int __init intel_uncore_init(void)
{
	int pret, cret;

	if (boot_cpu_data.x86_vendor != X86_VENDOR_INTEL)
		return -ENODEV;

	if (cpu_has_hypervisor)
		return -ENODEV;

	pret = uncore_pci_init();
	cret = uncore_cpu_init();

	if (cret && pret)
		return -ENODEV;

	uncore_cpumask_init(!cret);

	uncore_pmus_register();
	return 0;
}
device_initcall(intel_uncore_init);
