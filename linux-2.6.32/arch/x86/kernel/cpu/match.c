#include <asm/cpu_device_id.h>
#include <asm/processor.h>
#include <linux/cpu.h>
#include <linux/module.h>

/**
 * x86_match_cpu - match current CPU again an array of x86_cpu_ids
 * @match: Pointer to array of x86_cpu_ids. Last entry terminated with
 *         {}.
 *
 * Return the entry if the current CPU matches the entries in the
 * passed x86_cpu_id match table. Otherwise NULL.  The match table
 * contains vendor (X86_VENDOR_*), family, model and feature bits or
 * respective wildcard entries.
 *
 * A typical table entry would be to match a specific CPU
 *
 * X86_MATCH_VENDOR_FAM_MODEL_FEATURE(INTEL, 6, INTEL_FAM6_BROADWELL,
 *				      X86_FEATURE_ANY, NULL);
 *
 * Fields can be wildcarded with %X86_VENDOR_ANY, %X86_FAMILY_ANY,
 * %X86_MODEL_ANY, %X86_FEATURE_ANY (except for vendor)
 *
 * asm/cpu_device_id.h contains a set of useful macros which are shortcuts
 * for various common selections. The above can be shortened to:
 *
 * X86_MATCH_INTEL_FAM6_MODEL(BROADWELL, NULL);
 *
 * Arrays used to match for this should also be declared using
 * MODULE_DEVICE_TABLE(x86_cpu, ...)
 *
 * This always matches against the boot cpu, assuming models and features are
 * consistent over all CPUs.
 */
const struct x86_cpu_id *x86_match_cpu(const struct x86_cpu_id *match)
{
	const struct x86_cpu_id *m;
	struct cpuinfo_x86 *c = &boot_cpu_data;

	for (m = match;
	     m->vendor | m->family | m->model | m->steppings | m->feature;
	     m++) {
		if (m->vendor != X86_VENDOR_ANY && c->x86_vendor != m->vendor)
			continue;
		if (m->family != X86_FAMILY_ANY && c->x86 != m->family)
			continue;
		if (m->model != X86_MODEL_ANY && c->x86_model != m->model)
			continue;
		if (m->steppings != X86_STEPPING_ANY &&
		    !(BIT(c->x86_mask) & m->steppings))
			continue;
		if (m->feature != X86_FEATURE_ANY && !cpu_has(c, m->feature))
			continue;
		return m;
	}
	return NULL;
}
EXPORT_SYMBOL(x86_match_cpu);
