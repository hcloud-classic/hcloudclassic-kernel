#ifndef __HCC_GSCHEDULER_PROBE_H__
#define __HCC_GSCHEDULER_PROBE_H__

#include <linux/configfs.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <hcc/gscheduler/pipe.h>
#include <hcc/gscheduler/global_config.h>

/** default probing period is 1 second (1000 miliseconds). */
#define GSCHEDULER_PROBE_DEFAULT_PERIOD 1000

/*
 * Structure representing a probe. A probe has top-level attributes and sources.
 * Top-level attributes are composed of a period refreshement attribute and (in
 * the future) other custom attributes.
 * A source is represented by a subdirectory in configfs, and can be linked to
 * other components collecting measurements.
 *
 * A gscheduler_probe is described by a gscheduler_probe_type.
 */
struct gscheduler_probe;
/*
 * Structure representing a probe source. A probe source is described by a
 * gscheduler_probe_source_type. The current API and implementation only allow
 * one gscheduler_probe_source per gscheduler_probe_source_type.
 */
struct gscheduler_probe_source;

/* Same limitation as configfs (see SIMPLE_ATTR_SIZE in fs/configfs/file.c) */
#define GSCHEDULER_PROBE_ATTR_SIZE 4096

/*
 * To define with GSCHEDULER_PROBE_ATTRIBUTE
 * Structure representing probe attribute. Used to implement custom
 * probe attributes.
 */
struct gscheduler_probe_attribute {
	struct configfs_attribute config;

	/** function for reading attribute's value. */
	ssize_t (*show)(struct gscheduler_probe *, char *);
	/** function for storing attribute's value. */
	ssize_t (*store)(struct gscheduler_probe *, const char *, size_t);
};

/**
 * Mandatory macro to define a gscheduler_probe_attribute.
 *
 * @param var		variable name of the gscheduler_probe_attribute
 * @param name		entry name of the attribute in the probe directory
 * @param mode		access mode of the attribute entry
 * @param _show		show callback of the attribute
 * @param _store	store callback of the attribute
 */
#define GSCHEDULER_PROBE_ATTRIBUTE(var, name, mode, _show, _store) \
	struct gscheduler_probe_attribute var = {		  \
		.config = {					  \
			.ca_name = name,			  \
			.ca_owner = THIS_MODULE,		  \
			.ca_mode = mode				  \
		},						  \
		.show = _show,					  \
		.store = _store					  \
	}

/** struct which contains each probe's operations. */
/*
 * To initialize with GSCHEDULER_PROBE_TYPE. The probe subsystem completes this
 * init.
 */
struct gscheduler_probe_type {
	struct config_item_type item_type;
	void (*perform_measurement)(void); /** function for performing resource
					     * measurement only periodically.
					     * This function is suitable for
					     * measuring dynamic resource
					     * properties. */
	struct gscheduler_probe_attribute **attrs; /** NULL-terminated array of
						    *  custom attributes */
};

/**
 * Mandatory macro to define a gscheduler_probe_type.
 *
 * @param name		Name of the variable containing the probe type.
 * @param _attrs	NULL-terminated array of custom attributes, or
 *			NULL
 * @param _perform_measurement
 *			Function to use for periodic measurement and subscribers
 *			refreshment, or NULL
 */
#define GSCHEDULER_PROBE_TYPE(name, _attrs, _perform_measurement) \
	struct gscheduler_probe_type name = {			 \
		.item_type = {					 \
			.ct_owner = THIS_MODULE,		 \
			.ct_item_ops = NULL,			 \
			.ct_group_ops = NULL,			 \
			.ct_attrs = NULL			 \
		},						 \
		.perform_measurement = _perform_measurement,	 \
		.attrs = _attrs					 \
	}

#define GSCHEDULER_PROBE_SOURCE_ATTR_SIZE 4096

/*
 * To define with GSCHEDULER_PROBE_SOURCE_ATTRIBUTE
 * Structure representing a custom probe source attribute
 */
struct gscheduler_probe_source_attribute {
	struct configfs_attribute config; /** representation of attribute in
					    * configfs. */
	ssize_t (*show)(char *);	/** Method to read the attribute in
					  * configfs */
	ssize_t (*store)(const char *, size_t); /** Method to modify the
						  * attribute with configfs */
};

/**
 * Mandatory macro to define a gscheduler_probe_source_attribute.
 *
 * @param var		variable name of the gscheduler_probe_source_attribute.
 * @param name		entry name of the attribute in the probe source
 *			directory
 * @param mode		access mode of the attribute entry
 * @param _show		show callback of the attribute
 * @param _store	store callback of the attribute
 */
#define GSCHEDULER_PROBE_SOURCE_ATTRIBUTE(var, name, mode, _show, _store) \
	struct gscheduler_probe_source_attribute var = {			 \
		.config = {						 \
			.ca_name = name,				 \
			.ca_owner = THIS_MODULE,			 \
			.ca_mode = mode					 \
		},							 \
		.show = _show,						 \
		.store = _store						 \
	}

/*
 * To initialize with GSCHEDULER_PROBE_SOURCE_TYPE_INIT (possibly through the
 * BEGIN_GSCHEDULER_PROBE_SOURCE_TYPE helper)
 * The probe subsystem completes this init.
 */
struct gscheduler_probe_source_type {
	struct gscheduler_source_type source_type;
	struct gscheduler_pipe_type pipe_type;
	int (*has_changed)(void);  /** returns 1, if attribute value has
				    *  changed since last measurement,
				    *  otherwise returns 0. You also have
				    *  to update previous value here.*/
	struct gscheduler_probe_source_attribute **attrs;
};

/**
 * Mandatory macro to define a gscheduler_probe_source_type
 *
 * @param var		variable containing the gscheduler_probe_source_type
 * @param owner		module owning the gscheduler_probe_source_type
 * @param attrs		not used yet
 * @param get_value	get_value() method of the gscheduler_probe_source, or
 *			NULL
 * @param show_value	show_value() method of the gscheduler_probe_source, or
 *			NULL
 * @param value_type	string containing the type name of
 *			gscheduler_probe_source's values
 * @param value_type_size
 *			size in bytes of a value_type value
 * @param get_param_type
 *			string containing the type name of the parameters for
 *			the get() method, or NULL
 * @param get_param_type_size
 *			size in bytes of a get_param_type parameter
 * @param _has_changed	has_changed() method of the gscheduler_probe_source, or
 *			NULL
 */
#define GSCHEDULER_PROBE_SOURCE_TYPE_INIT(var, owner, attrs,		      \
					 get_value, show_value,		      \
					 value_type, value_type_size,	      \
					 get_param_type, get_param_type_size, \
					 _has_changed)			      \
	{								      \
		.source_type =						      \
			GSCHEDULER_SOURCE_TYPE_INIT(get_value, show_value,     \
						   value_type,		      \
						   value_type_size,	      \
						   get_param_type,	      \
						   get_param_type_size),      \
		.pipe_type =						      \
			GSCHEDULER_PIPE_TYPE_INIT(owner,			      \
						 NULL, NULL,		      \
						 &var.source_type, NULL),     \
		.has_changed = _has_changed,				      \
	}

/*
 * Structure representing a probe source. As a source, a probe source implements
 * gscheduler_source. As a directory, a probe source implements
 * gscheduler_pipe.
 */
struct gscheduler_probe_source {
	struct gscheduler_source source;
	struct gscheduler_pipe pipe;
	struct global_config_attrs global_attrs;
	struct gscheduler_probe *parent; /** pointer to a gscheduler_probe which
					 *  contains this gscheduler_probe_source
					 */
	struct work_struct notify_update_work; /** aperiodic refreshment of
						*  publish-subscribe ports
						*  linked to the attribute */
};

/*
 * Convenience macros to define a gscheduler_probe_source_type
 *
 * These convenience macros should be used the following way:
 *
 * First, implemented methods must be defined using the
 * DEFINE_GSCHEDULER_PROBE_SOURCE_<method> macros. Second, the
 * gscheduler_probe_source_type must be filled using
 * {BEGIN,END}_GSCHEDULER_PROBE_SOURCE_TYPE and GSCHEDULER_PROBE_SOURCE_* macros:
 *	BEGIN_GSCHEDULER_PROBE_SOURCE_TYPE(name),
 *		.GSCHEDULER_PROBE_SOURCE_VALUE_TYPE(name, type),
 * if needed:
 *		.GSCHEDULER_PROBE_SOURCE_<method>(name),
 *		.GSCHEDULER_PROBE_SOURCE_PARAM_TYPE(name, type),
 *		.GSCHEDULER_PROBE_SOURCE_ATTRS(name, attrs),
 * and finally:
 *	END_GSCHEDULER_PROBE_SOURCE_TYPE(name);
 */

#define gscheduler_probe_source_lock_wrapper(source, call)		      \
	({								      \
		struct gscheduler_probe_source *____ps;			      \
		typeof(call) ____ret;					      \
		____ps = container_of(source,				      \
				      struct gscheduler_probe_source, source); \
		gscheduler_probe_source_lock(____ps);			      \
		____ret = call;						      \
		gscheduler_probe_source_unlock(____ps);			      \
		____ret;						      \
	})

/**
 * Convenience macro to define a typed get() method without a source argument
 * and with parameters. The typed method will be called name_get. When called
 * from the framework, the probe source lock is held.
 *
 * @param name		name of the probe_source type
 * @param type		type of the values output by the probe source (eg. int)
 * @param ptr		name of the type *arg of the method
 * @param nr		name of the array length parameter of the method
 * @param in_type	type of the parameters of the method (eg. int)
 * @param in_ptr	name of the in_type *arg of the method
 * @param in_nr		name of the parameters array length arg of the method
 */
#define DEFINE_GSCHEDULER_PROBE_SOURCE_GET_WITH_INPUT(name, type, ptr, nr,   \
					   in_type, in_ptr, in_nr)	    \
	static int name##_get(type *, unsigned int,			    \
			      const in_type *, unsigned int);		    \
	static int name##_source_get_value(struct gscheduler_source *source, \
					   void *__ptr, unsigned int __nr,  \
					   const void *__in_ptr,	    \
					   unsigned int __in_nr)	    \
	{								    \
		return gscheduler_probe_source_lock_wrapper(		    \
			source,						    \
			name##_get(__ptr, __nr, __in_ptr, __in_nr));	    \
	}								    \
	static int name##_get(type *ptr, unsigned int nr,		    \
			      const in_type *in_ptr, unsigned int in_nr)

/**
 * Convenience macro to define a typed get() method without a source argument
 * and with no parameters. The typed method will be called name_get. When called
 * from the framework, the probe source lock is held.
 *
 * @param name		name of the gscheduler_probe_source type
 * @param type		type of the values output by the probe source (eg. int)
 * @param ptr		name of the type *arg of the method
 * @param nr		name of the array length parameter of the method
 */
#define DEFINE_GSCHEDULER_PROBE_SOURCE_GET(name, type, ptr, nr)		    \
	static int name##_get(type *, unsigned int);			    \
	static int name##_source_get_value(struct gscheduler_source *source, \
					   void *__ptr, unsigned int __nr,  \
					   const void *input_ptr,	    \
					   unsigned int input_nr)	    \
	{								    \
		if (!__nr)						    \
			return 0;					    \
		return gscheduler_probe_source_lock_wrapper(source,	    \
						 name##_get(__ptr, __nr));  \
	}								    \
	static int name##_get(type *ptr, unsigned int nr)

/**
 * Convenience macro to define a show() method without a source argument. The
 * method will be called name_show. When called from the framework, the probe
 * source lock is held.
 *
 * @param name		name of the gscheduler_probe_source type
 * @param page		name of the buffer arg of the method
 */
#define DEFINE_GSCHEDULER_PROBE_SOURCE_SHOW(name, page)			\
	static ssize_t name##_show(char *page);				\
	static ssize_t name##_source_show_value(			\
		struct gscheduler_source *source,			\
		char *__page)						\
	{								\
		return gscheduler_probe_source_lock_wrapper(source,	\
						 name##_show(__page));	\
	}								\
	static ssize_t name##_show(char *page)

/**
 * Convenience macro to define a has_changed() method.
 * The method will be called name_has_changed.
 *
 * @param name		name of the gscheduler_probe_source type
 */
#define DEFINE_GSCHEDULER_PROBE_SOURCE_HAS_CHANGED(name)	\
	static int name##_has_changed(void)

/**
 * Convenience macro to start the definition of a gscheduler_probe_source_type.
 * The definition must end with END_GSCHEDULER_PROBE_SOURCE_TYPE(name). The
 * variable will be called name_type.
 *
 * @param name		name of the gscheduler_probe_source type
 */
#define BEGIN_GSCHEDULER_PROBE_SOURCE_TYPE(name)				     \
	struct gscheduler_probe_source_type name##_type = {		     \
		.source_type = GSCHEDULER_SOURCE_TYPE_INIT(NULL, NULL,	     \
							  NULL, 0, NULL, 0), \
		.pipe_type =						     \
			GSCHEDULER_PIPE_TYPE_INIT(THIS_MODULE,		     \
						 NULL, NULL,		     \
						 &name##_type.source_type,   \
						 NULL)

/**
 * Convenience macro to attach custom probe source attributes to a probe source
 * type.
 *
 * @param name		must match the name used with
 *			BEGIN_GSCHEDULER_PROBE_SOURCE_TYPE
 * @param _attrs	NULL terminated array of pointers to custom probe source
 *			attributes (struct gscheduler_probe_source_attribute)
 */
#define GSCHEDULER_PROBE_SOURCE_ATTRS(name, _attrs) \
	attrs = _attrs

/**
 * Convenience macro to attach a previously defined get() method to a probe
 * source type. The get() method must have been defined earlier with
 * DEFINE_GSCHEDULER_PROBE_SOURCE_GET[_WITH_INPUT](name, ...). The value type
 * (and parameter type if used) must be attached with
 * GSCHEDULER_PROBE_SOURCE_VALUE_TYPE(name, ...) (resp,
 * GSCHEDULER_PROBE_SOURCE_PARAM_TYPE(name, ...)).
 *
 * @param name		must match the name used with
 *			BEGIN_GSCHEDULER_PROBE_SOURCE_TYPE
 */
#define GSCHEDULER_PROBE_SOURCE_GET(name)				    \
	__GSCHEDULER_SOURCE_GET_VALUE(source_type., name##_source_get_value)

/**
 * Convenience macro to attach a previously defined show() method to a probe
 * source type. The show() method must have been defined earlier with
 * DEFINE_GSCHEDULER_PROBE_SOURCE_SHOW(name, ...).
 *
 * @param name		must match the name used with
 *			BEGIN_GSCHEDULER_PROBE_SOURCE_TYPE
 */
#define GSCHEDULER_PROBE_SOURCE_SHOW(name)				      \
	__GSCHEDULER_SOURCE_SHOW_VALUE(source_type., name##_source_show_value)

/**
 * Convenience macro to declare the value type of a probe source. Must be used
 * within all BEGIN_GSCHEDULER_PROBE_SOURCE_TYPE sections.
 *
 * @param name		must match the name used with
 *			BEGIN_GSCHEDULER_PROBE_SOURCE_TYPE
 * @param type		litteral expression of the value type output
 */
#define GSCHEDULER_PROBE_SOURCE_VALUE_TYPE(name, type)		\
	__GSCHEDULER_SOURCE_VALUE_TYPE(source_type., type)

/**
 * Convenience macro to declare the parameter type of the get() method of a
 * probe source.
 *
 * @param name		must match the name used with
 *			BEGIN_GSCHEDULER_PROBE_SOURCE_TYPE
 * @param type		litteral expression of the parameter type
 */
#define GSCHEDULER_PROBE_SOURCE_PARAM_TYPE(name, type)		\
	__GSCHEDULER_SOURCE_PARAM_TYPE(source_type., type)

/**
 * Convenience macro to attach a previously defined has_changed() method to a
 * probe source type. The has_changed() method must have been defined earlier
 * with DEFINE_GSCHEDULER_PROBE_SOURCE_HAS_CHANGED(name).
 *
 * @param name		must match the name used with
 *			BEGIN_GSCHEDULER_PROBE_SOURCE_TYPE
 */
#define GSCHEDULER_PROBE_SOURCE_HAS_CHANGED(name)	\
	has_changed = name##_has_changed

/**
 * End the definition of a gscheduler_probe_source_type. Must close any
 * BEGIN_GSCHEDULER_PROBE_SOURCE_TYPE section.
 *
 * @param name		must match the name used with
 *			BEGIN_GSCHEDULER_PROBE_SOURCE_TYPE
 */
#define END_GSCHEDULER_PROBE_SOURCE_TYPE(name)	\
	}

/* End of convenience macros */

/**
 * This function allocates memory for new probe and initializes it.
 * @author Innogrid HCC
 *
 * @param type		Type of the probe, defined with GSCHEDULER_PROBE_TYPE
 * @param name		Name of the probe. This name must be unique for each
 *			probe and must match the module file name.
 * @param sources	NULL-terminated array of probe's sources created with
 *			gscheduler_probe_source_create().
 * @param def_groups	NULL-terminated array of subdirs of the probe
 *			directory, or NULL
 *
 * @return		pointer to newly created probe or NULL if probe
 *			creation failed.
 */
struct gscheduler_probe *
gscheduler_probe_create(struct gscheduler_probe_type *type,
		       const char *name,
		       struct gscheduler_probe_source **sources,
		       struct config_group *def_groups[]);
/**
 * This function frees all the memory taken by a probe.
 * @author Innogrid HCC
 *
 * @param probe		pointer to probe whose memory we want to free.
 */
void gscheduler_probe_free(struct gscheduler_probe *probe);

/**
 * This function allocates memory and initializes a probe source.
 * @author Innogrid HCC
 *
 * @param type		Type describing the probe source, defined with
 *			GSCHEDULER_PROBE_SOURCE_TYPE
 * @param name		Name of the source's subdirectory in the probe's
 *			directory. Must be unique for a given a probe.
 *
 * @return		Pointer to the created gscheduler_probe_source, or
 *			NULL if error
 */
struct gscheduler_probe_source *
gscheduler_probe_source_create(struct gscheduler_probe_source_type *type,
			      const char *name);
void gscheduler_probe_source_free(struct gscheduler_probe_source *source);

/**
 * Lock a probe source. No sleep is allowed while a probe source is locked.
 * This actually locks the probe containing this source.
 *
 * @param probe_source	probe source to lock
 */
void gscheduler_probe_source_lock(struct gscheduler_probe_source *probe_source);
/**
 * Unlock a probe source.
 *
 * @param probe_source	probe source to unlock
 */
void gscheduler_probe_source_unlock(struct gscheduler_probe_source *probe_source);

/**
 * Function that a probe source should call when the value changes and the probe
 * does not have a perform_measurement() method.
 * Does nothing if the probe provides a perform_measurement() method.
 *
 * @param source		Source having been updated
 */
void
gscheduler_probe_source_notify_update(struct gscheduler_probe_source *source);

/**
 * This function is used for registering probe. This function has to
 * be called at the end of "init_module" function for each probe's module.
 * @author Innogrid HCC
 *
 * @param probe		pointer to the probe we wish to register.
 *
 * @return		0, if probe was successfully registered.
 *			-EEXIST, if probe with same name is already registered.
 */
int gscheduler_probe_register(struct gscheduler_probe *probe);

/**
 * This function is used for removing probe registration. This function must
 * *only* be called at module unloading (from "cleanup_module" function).
 * @author Innogrid HCC
 *
 * @param probe		pointer to the probe we wish to unregister.
 */
void gscheduler_probe_unregister(struct gscheduler_probe *probe);

/**
 * Lock a probe. No sleep is allowed while a probe is locked.
 *
 * @param probe		probe to lock
 */
void gscheduler_probe_lock(struct gscheduler_probe *probe);
/**
 * Unlock a probe.
 *
 * @param probe		probe to unlock
 */
void gscheduler_probe_unlock(struct gscheduler_probe *probe);

#endif /* __HCC_GSCHEDULER_PROBE_H__ */
