#include <linux/sched.h>
#include <linux/shm.h>
#include <linux/lockdep.h>
#include <linux/security.h>
#include <linux/ipc_namespace.h>
#include <linux/ipc.h>


#define shm_flags	shm_perm.mode
struct kmem_cache *shmid_object_cachep;




struct shmid_kernel *create_local_shp (struct ipc_namespace *ns,
				       struct shmid_kernel *received_shp,
				       gdm_set_id_t set_id)
{
	struct shmid_kernel *shp;
	struct gdm_set *set;
	char name[13];
	int retval;

	shp = ipc_rcu_alloc(sizeof(*shp));
	if (!shp)
		return ERR_PTR(-ENOMEM);

	*shp = *received_shp;
	shp->shm_perm.security = NULL;
	retval = security_shm_alloc(shp);
	if (retval)
		goto err_putref;

	retval = local_ipc_reserveid(&shm_ids(ns), &shp->shm_perm,
				     ns->shm_ctlmni);
	if (retval)
		goto err_security_free;

	sprintf (name, "SYSV%08x", received_shp->shm_perm.key);
	shp->shm_file = shmem_file_setup(name, shp->shm_segsz, shp->shm_flags);

	if (IS_ERR(shp->shm_file)) {
		retval = PTR_ERR(shp->shm_file);
		goto err_security_free;
	}

	set = _find_get_gdm_set(gdm_def_ns, set_id);
	BUG_ON(!set);

	shp->shm_file->f_dentry->d_inode->i_ino = shp->shm_perm.id;
	shp->shm_file->f_dentry->d_inode->i_mapping->gdm_set = set;
	shp->shm_file->f_op = &hcc_shm_file_operations;
	shp->mlock_user = NULL;

	put_gdm_set(set);

	ns->shm_tot += (shp->shm_segsz + PAGE_SIZE -1) >> PAGE_SHIFT;

	shp->shm_perm.hccops = shm_ids(ns).hccops;

	local_shm_unlock(shp);

	return shp;

err_security_free:
	security_shm_free(shp);
err_putref:
	ipc_rcu_putref(shp);
	return ERR_PTR(retval);
}




int shmid_alloc_object (struct gdm_obj * obj_entry,
			struct gdm_set * set,
			objid_t objid)
{
	shmid_object_t *shp_object;

	shp_object = kmem_cache_alloc (shmid_object_cachep, GFP_KERNEL);
	if (!shp_object)
		return -ENOMEM;

	shp_object->local_shp = NULL;
	obj_entry->object = shp_object;

	return 0;
}


int shmid_insert_object (struct gdm_obj * obj_entry,
			 struct gdm_set * set,
			 objid_t objid)
{
	shmid_object_t *shp_object;
	struct shmid_kernel *shp;
	struct ipc_namespace *ns;
	int r = 0;

	shp_object = obj_entry->object;
	BUG_ON(!shp_object);

	if (shp_object->local_shp)
		goto done;

	ns = find_get_hcc_ipcns();
	BUG_ON(!ns);

	shp = create_local_shp(ns, &shp_object->mobile_shp, shp_object->set_id);
	shp_object->local_shp = shp;

	if (IS_ERR(shp)) {
		r = PTR_ERR(shp);
		BUG();
	}

	put_ipc_ns(ns);
done:
	return r;
}