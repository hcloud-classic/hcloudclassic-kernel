#ifndef NO_IPC
#include <linux/ipc.h>
#include <linux/ipc_namespace.h>
#include <linux/nsproxy.h>
#include <linux/msg.h>

struct ipc_namespace *find_get_hcc_ipcns(void)
{
	struct hcc_namespace *hcc_ns;
	struct ipc_namespace *ipc_ns;

	hcc_ns = find_get_hcc_ns();
	if (!hcc_ns)
		goto error;

	if (!hcc_ns->root_nsproxy.ipc_ns)
		goto error_ipcns;

	ipc_ns = get_ipc_ns(hcc_ns->root_nsproxy.ipc_ns);

	put_hcc_ns(hcc_ns);

	return ipc_ns;

error_ipcns:
	put_hcc_ns(hcc_ns);
error:
	return NULL;
}
#endif