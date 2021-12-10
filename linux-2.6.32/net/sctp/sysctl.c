/* SCTP kernel implementation
 * (C) Copyright IBM Corp. 2002, 2004
 * Copyright (c) 2002 Intel Corp.
 *
 * This file is part of the SCTP kernel implementation
 *
 * Sysctl related interfaces for SCTP.
 *
 * This SCTP implementation is free software;
 * you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This SCTP implementation is distributed in the hope that it
 * will be useful, but WITHOUT ANY WARRANTY; without even the implied
 *                 ************************
 * warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU CC; see the file COPYING.  If not, write to
 * the Free Software Foundation, 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 *
 * Please send any bug reports or fixes you make to the
 * email address(es):
 *    lksctp developers <lksctp-developers@lists.sourceforge.net>
 *
 * Or submit a bug report through the following website:
 *    http://www.sf.net/projects/lksctp
 *
 * Written or modified by:
 *    Mingqin Liu           <liuming@us.ibm.com>
 *    Jon Grimm             <jgrimm@us.ibm.com>
 *    Ardelle Fan           <ardelle.fan@intel.com>
 *    Ryan Layer            <rmlayer@us.ibm.com>
 *    Sridhar Samudrala     <sri@us.ibm.com>
 *
 * Any bugs reported given to us we will try to fix... any fixes shared will
 * be incorporated into the next SCTP release.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <net/sctp/structs.h>
#include <net/sctp/sctp.h>
#include <linux/sysctl.h>

static int zero = 0;
static int one = 1;
static int timer_max = 86400000; /* ms in one day */
static int int_max = INT_MAX;
static int sack_timer_min = 1;
static int sack_timer_max = 500;
static int addr_scope_max = 3; /* check sctp_scope_policy_t in include/net/sctp/constants.h for max entries */
static int rwnd_scale_max = 16;
static int rto_alpha_min = 0;
static int rto_beta_min = 0;
static int rto_alpha_max = 1000;
static int rto_beta_max = 1000;

extern int sysctl_sctp_mem[3];
extern int sysctl_sctp_rmem[3];
extern int sysctl_sctp_wmem[3];

static int proc_sctp_do_hmac_alg(ctl_table *ctl,
				int write,
				void __user *buffer, size_t *lenp,

				loff_t *ppos);
static int proc_sctp_do_auth(struct ctl_table *ctl, int write,
			     void __user *buffer, size_t *lenp,
			     loff_t *ppos);
static int proc_sctp_do_alpha_beta(struct ctl_table *ctl, int write,
				   void __user *buffer, size_t *lenp,
				   loff_t *ppos);
static ctl_table sctp_table[] = {
	{
		.ctl_name	= NET_SCTP_RTO_INITIAL,
		.procname	= "rto_initial",
		.data		= &sctp_rto_initial,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.strategy	= sysctl_intvec,
		.extra1         = &one,
		.extra2         = &timer_max
	},
	{
		.ctl_name	= NET_SCTP_RTO_MIN,
		.procname	= "rto_min",
		.data		= &sctp_rto_min,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.strategy	= sysctl_intvec,
		.extra1         = &one,
		.extra2         = &timer_max
	},
	{
		.ctl_name	= NET_SCTP_RTO_MAX,
		.procname	= "rto_max",
		.data		= &sctp_rto_max,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.strategy	= sysctl_intvec,
		.extra1         = &one,
		.extra2         = &timer_max
	},
	{
		.ctl_name	= NET_SCTP_VALID_COOKIE_LIFE,
		.procname	= "valid_cookie_life",
		.data		= &sctp_valid_cookie_life,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.strategy	= sysctl_intvec,
		.extra1         = &one,
		.extra2         = &timer_max
	},
	{
		.ctl_name	= NET_SCTP_MAX_BURST,
		.procname	= "max_burst",
		.data		= &sctp_max_burst,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.strategy	= sysctl_intvec,
		.extra1		= &zero,
		.extra2		= &int_max
	},
	{
		.ctl_name	= NET_SCTP_ASSOCIATION_MAX_RETRANS,
		.procname	= "association_max_retrans",
		.data		= &sctp_max_retrans_association,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.strategy	= sysctl_intvec,
		.extra1		= &one,
		.extra2		= &int_max
	},
	{
		.procname	= "cookie_hmac_alg",
		.maxlen		= 8,
		.mode		= 0644,
		.proc_handler	= proc_sctp_do_hmac_alg,
	},
	{
		.ctl_name	= NET_SCTP_SNDBUF_POLICY,
		.procname	= "sndbuf_policy",
		.data		= &sctp_sndbuf_policy,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
		.strategy	= sysctl_intvec
	},
	{
		.ctl_name	= NET_SCTP_RCVBUF_POLICY,
		.procname	= "rcvbuf_policy",
		.data		= &sctp_rcvbuf_policy,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
		.strategy	= sysctl_intvec
	},
	{
		.ctl_name	= NET_SCTP_PATH_MAX_RETRANS,
		.procname	= "path_max_retrans",
		.data		= &sctp_max_retrans_path,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.strategy	= sysctl_intvec,
		.extra1		= &one,
		.extra2		= &int_max
	},
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "pf_retrans",
		.data		= &sctp_pf_retrans,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &zero,
		.extra2		= &int_max
	},
	{
		.ctl_name	= NET_SCTP_MAX_INIT_RETRANSMITS,
		.procname	= "max_init_retransmits",
		.data		= &sctp_max_retrans_init,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.strategy	= sysctl_intvec,
		.extra1		= &one,
		.extra2		= &int_max
	},
	{
		.ctl_name	= NET_SCTP_HB_INTERVAL,
		.procname	= "hb_interval",
		.data		= &sctp_hb_interval,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.strategy	= sysctl_intvec,
		.extra1         = &one,
		.extra2         = &timer_max
	},
	{
		.ctl_name	= NET_SCTP_PRESERVE_ENABLE,
		.procname	= "cookie_preserve_enable",
		.data		= &sctp_cookie_preserve_enable,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
		.strategy	= sysctl_intvec
	},
	{
		.ctl_name	= NET_SCTP_RTO_ALPHA,
		.procname	= "rto_alpha_exp_divisor",
		.data		= &sctp_rto_alpha,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_sctp_do_alpha_beta,
		.strategy	= sysctl_intvec,
		.extra1		= &rto_alpha_min,
		.extra2		= &rto_alpha_max,
	},
	{
		.ctl_name	= NET_SCTP_RTO_BETA,
		.procname	= "rto_beta_exp_divisor",
		.data		= &sctp_rto_beta,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_sctp_do_alpha_beta,
		.strategy	= sysctl_intvec,
		.extra1		= &rto_beta_min,
		.extra2		= &rto_beta_max,
	},
	{
		.ctl_name	= NET_SCTP_ADDIP_ENABLE,
		.procname	= "addip_enable",
		.data		= &sctp_addip_enable,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
		.strategy	= sysctl_intvec
	},
	{
		.ctl_name	= NET_SCTP_PRSCTP_ENABLE,
		.procname	= "prsctp_enable",
		.data		= &sctp_prsctp_enable,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
		.strategy	= sysctl_intvec
	},
	{
		.ctl_name	= NET_SCTP_SACK_TIMEOUT,
		.procname	= "sack_timeout",
		.data		= &sctp_sack_timeout,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.strategy	= sysctl_intvec,
		.extra1         = &sack_timer_min,
		.extra2         = &sack_timer_max,
	},
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "sctp_mem",
		.data		= &sysctl_sctp_mem,
		.maxlen		= sizeof(sysctl_sctp_mem),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "sctp_rmem",
		.data		= &sysctl_sctp_rmem,
		.maxlen		= sizeof(sysctl_sctp_rmem),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "sctp_wmem",
		.data		= &sysctl_sctp_wmem,
		.maxlen		= sizeof(sysctl_sctp_wmem),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "auth_enable",
		.data		= &sctp_auth_enable,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_sctp_do_auth,
	},
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "addip_noauth_enable",
		.data		= &sctp_addip_noauth,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
		.strategy	= sysctl_intvec
	},
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "addr_scope_policy",
		.data		= &sctp_scope_policy,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec_minmax,
		.strategy	= &sysctl_intvec,
		.extra1		= &zero,
		.extra2		= &addr_scope_max,
	},
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "rwnd_update_shift",
		.data		= &sctp_rwnd_upd_shift,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec_minmax,
		.strategy	= &sysctl_intvec,
		.extra1		= &one,
		.extra2		= &rwnd_scale_max,
	},

	{ .ctl_name = 0 }
};

static struct ctl_path sctp_path[] = {
	{ .procname = "net", .ctl_name = CTL_NET, },
	{ .procname = "sctp", .ctl_name = NET_SCTP, },
	{ }
};

static int proc_sctp_do_hmac_alg(ctl_table *ctl,
				int write,
				void __user *buffer, size_t *lenp,
				loff_t *ppos)
{
	char tmp[8];
	ctl_table tbl;
	int ret;
	int changed = 0;
	char *none = "none";

	memset(&tbl, 0, sizeof(struct ctl_table));

	if (write) {
		tbl.data = tmp;
		tbl.maxlen = 8;
	} else {
		tbl.data = sctp_hmac_algorithm ? : none;
		tbl.maxlen = strlen(tbl.data);
	}
		ret = proc_dostring(&tbl, write, buffer, lenp, ppos);

	if (write) {
#ifdef CONFIG_CRYPTO_MD5
		if (!strncmp(tmp, "md5", 3)) {
			sctp_hmac_algorithm = "md5";
			changed = 1;
		}
#endif
#ifdef CONFIG_CRYPTO_SHA1
		if (!strncmp(tmp, "sha1", 4)) {
			sctp_hmac_algorithm = "sha1";
			changed = 1;
		}
#endif
		if (!strncmp(tmp, "none", 4)) {
			sctp_hmac_algorithm = NULL;
			changed = 1;
		}

		if (!changed)
			ret = -EINVAL;
	}

	return ret;
}

static struct ctl_table_header * sctp_sysctl_header;

static int proc_sctp_do_alpha_beta(struct ctl_table *ctl, int write,
				   void __user *buffer, size_t *lenp,
				   loff_t *ppos)
{
	if (write)
		pr_warn_once("Changing rto_alpha or rto_beta may lead to "
			     "suboptimal rtt/srtt estimations!\n");

	return proc_dointvec_minmax(ctl, write, buffer, lenp, ppos);
}

static int proc_sctp_do_auth(struct ctl_table *ctl, int write,
			     void __user *buffer, size_t *lenp,
			     loff_t *ppos)
{
	struct ctl_table tbl;
	int new_value, ret;

	memset(&tbl, 0, sizeof(struct ctl_table));
	tbl.maxlen = sizeof(unsigned int);

	if (write)
		tbl.data = &new_value;
	else
		tbl.data = &sctp_auth_enable;

	ret = proc_dointvec(&tbl, write, buffer, lenp, ppos);

	if (write) {
		struct sock *sk = sctp_get_ctl_sock();

		sctp_auth_enable = new_value;
		/* Update the value in the control socket */
		lock_sock(sk);
		sctp_sk(sk)->ep->auth_enable = new_value;
		release_sock(sk);
	}

	return ret;
}

/* Sysctl registration.  */
void sctp_sysctl_register(void)
{
	sctp_sysctl_header = register_sysctl_paths(sctp_path, sctp_table);
}

/* Sysctl deregistration.  */
void sctp_sysctl_unregister(void)
{
	unregister_sysctl_table(sctp_sysctl_header);
}
