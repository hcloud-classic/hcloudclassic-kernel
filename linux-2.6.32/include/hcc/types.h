#ifndef __HCC_TYPES_INTERNAL__
#define __HCC_TYPES_INTERNAL__

#include <hcc/sys/types.h>

#ifdef __KERNEL__
#include <hcc/hcc_nodemask.h>
#endif

#define HCC_FCT(p) if(p!=NULL) p

#if defined(CONFIG_HCC) || defined(CONFIG_HCC_GRPC)

typedef unsigned char hcc_session_t;
typedef int hcc_subsession_t;
typedef unsigned long unique_id_t;   /**< Unique id type */

#endif /* CONFIG_HCC */

#ifdef __KERNEL__

#ifdef CONFIG_HCC_STREAM
struct dstream_socket { // shared node-wide
	unique_id_t id_socket;
	unique_id_t id_container;
	struct dstream_interface_ctnr *interface_ctnr;
	struct stream_socket *hcc_socket;
};
#endif

#endif /* __KERNEL__ */

#endif /* __HCC_TYPES_INTERNAL__ */
