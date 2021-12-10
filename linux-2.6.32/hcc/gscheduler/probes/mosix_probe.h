/**
 *  Processor load computation.
 *  @file mosix_probe.h
 *
 *  Implementation of processor load computation functions.
 *  It is a simplified version of the MOSIX functions.
 *
 *  Original work by Amnon Shiloh and Amnon Barak.
 *
 *  @author Innogrid HCC
 */

#ifndef __HCC_MOSIX_PROBE_H__
#define __HCC_MOSIX_PROBE_H__

#define MOSIX_PROBE_NAME "mosix_probe"

struct mosix_probe_data {
	unsigned long mosix_mean_load; /* Load computed and used locally:
	                                * increases slowly, decreases quickly */
	unsigned long mosix_upper_load; /* Load given to the outside: increases
					 * quickly, decreases slowly */
	unsigned long mosix_single_process_load;
	unsigned long mosix_norm_mean_load; /* Normalized mean load */
	unsigned long mosix_norm_upper_load; /* Normalized upper load */
	unsigned long mosix_norm_single_process_load;
};

#endif /* __HCC_MOSIX_PROBE_H__ */
