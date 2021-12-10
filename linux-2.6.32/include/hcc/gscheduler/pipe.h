#ifndef __HCC_GSCHEDULER_PIPE_H__
#define __HCC_GSCHEDULER_PIPE_H__

#include <linux/configfs.h>
#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/kref.h>
#include <linux/types.h>
#include <hcc/gscheduler/remote_pipe.h>

/*
 * A gscheduler_source represents a source of information.
 *
 * Information can be queried from a gscheduler_source, and a gscheduler_source
 * may publish updates to subscribers. Subscribers are represented by
 * gscheduler_sink structures.
 *
 * To make its value(s) available, a gscheduler_source provides a get_value()
 * method. The value(s) can be queried using
 * gscheduler_source_get_value(). Values are typed, and an optional, typed array
 * of parameters can be given to gscheduler_source_get_value(). A source can also
 * make its value(s) available as text through a show_value() method. This
 * method must be called through the gscheduler_source_show_value() function.
 *
 * To publish updates to its subscribers (gscheduler_sink), a gscheduler_source
 * calls gscheduler_source_publish(). To this end a gscheduler_sink subscribing to
 * a gscheduler_source must provide an update_value() method.
 *
 * To access the values of the source connected to a gscheduler_sink, one can use
 * the gscheduler_sink_get_value() (typed) and gscheduler_sink_show_value() (text)
 * methods.
 *
 * A gscheduler_pipe represents a gscheduler_source or a gscheduler_sink, or both
 * as a single directory in configfs. The value of the gscheduler_source can be
 * read in the "value" configfs_attribute of the gscheduler_pipe's directory,
 * provided that the gscheduler_source provides a show_value() method. The value
 * collected by the gscheduler_sink from its connected source (if any) can be
 * read in the "collected_value" configfs_attribute of the gscheduler_pipe's
 * directory.
 */

/* Structure representing the types used in a get_value method */
struct get_value_types {
	const char *out_type; /* type output by the method */
	size_t out_type_size;
	const char *in_type; /* parameter type of the method */
	size_t in_type_size;
};

/* Type definitions for gscheduler_source */

struct gscheduler_source;

/**
 * prototype for the method to get the source's value
 *
 * When called through gscheduler_source_get_value(), the arguments are
 * checked so that no array pointer is NULL if its size is not 0, and at least
 * one array has elements.
 *
 * Source internal locking is supposed to be explicitly handled by the method.
 *
 * @param source	source from which to read the value
 * @param value_p	array of values to be filled by the method
 * @param nr		max number of values to fill
 * @param in_value_p	array of parameters, or NULL
 * @param in_nr		number of elements in in_value_p
 *
 * @return		number of values filled, or
 *			negative error code
 */
typedef int source_get_value_t(struct gscheduler_source *source,
			       void *value_p, unsigned int nr,
			       const void *in_value_p, unsigned int in_nr);
/**
 * prototype for the method to show the source's value as text
 *
 * Source internal locking is supposed to be explicitly handled by the method.
 *
 * @param source	source from which to read the value
 * @param page		buffer to write the value to (4 Kbytes)
 *
 * @return		number of bytes written to buffer, or
 *			negative error code
 */
typedef ssize_t source_show_value_t(struct gscheduler_source *source,
				    char *page);

/* To initialize with GSCHEDULER_SOURCE_TYPE[_INIT]. */
struct gscheduler_source_type {
	/** functions for reading source's value */

	/* typed binary read with optional parameters */
	source_get_value_t *get_value;
	struct get_value_types get_value_types;

	/* textual read */
	source_show_value_t *show_value;
};

/**
 * Mandatory macro to define a gscheduler_source_type. Can be used through
 * GSCHEDULER_SOURCE_TYPE.
 *
 * @param _get_value	get_value method of the source
 * @param _show_value	show_value method of the source
 * @param value_type	string containing the type name of source's values
 * @param value_type_size
 *			size in bytes of a value_type value
 * @param get_param_type
 *			string containing the type name of the parameters for
 *			the get_value method, or NULL
 * @param get_param_type_size
 *			size in bytes of a get_param_type parameter
 */
#define GSCHEDULER_SOURCE_TYPE_INIT(_get_value, _show_value,		\
				   value_type, value_type_size,		\
				   get_param_type, get_param_type_size) \
	{								\
		.get_value = _get_value,				\
		.get_value_types = {					\
			.out_type = value_type,				\
			.out_type_size = value_type_size,		\
			.in_type = get_param_type,			\
			.in_type_size = get_param_type_size		\
		},							\
		.show_value = _show_value				\
	}

/**
 * Convenience macro to define a gscheduler_source_type.
 *
 * @param name		name of the variable for the gscheduler_source_type
 * @param get_value	get_value method of the source
 * @param show_value	show_value method of the source
 * @param value_type	type of source's values (eg. unsigned int)
 * @param get_param_type
 *			type of the parameters for the get_value method
 */
#define GSCHEDULER_SOURCE_TYPE(name,				   \
			      get_value, show_value,		   \
			      value_type, get_param_type)	   \
	struct gscheduler_source_type name =			   \
		GSCHEDULER_SOURCE_TYPE_INIT(get_value, show_value,  \
					   #value_type,		   \
					   sizeof(value_type),	   \
					   #get_param_type,	   \
					   sizeof(get_param_type))

/*
 * Internal helpers to define convenience initializing macros for super-classes
 * of gscheduler_source_type
 */

/**
 * Initializer for the get_value() method of a gscheduler_source_type
 *
 * @param prefix	prefix to the gscheduler_source_type field in the
 *			super-class initializer
 * @param _get_value	function to set as the get_value() method
 */
#define __GSCHEDULER_SOURCE_GET_VALUE(prefix, _get_value)	\
	prefix get_value = _get_value
/**
 * Initializer for the type of value output by the get_value() method of a
 * gscheduler_source_type
 *
 * @param prefix	prefix to the gscheduler_source_type field in the
 *			super-class initializer
 * @param type		litteral expression of the type to set
 */
#define __GSCHEDULER_SOURCE_VALUE_TYPE(prefix, type)		\
	prefix get_value_types.out_type = #type,		\
	.prefix get_value_types.out_type_size = sizeof(type)
/**
 * Initializer for the type of parameter taken by the get_value() method of a
 * gscheduler_source_type
 *
 * @param prefix	prefix to the gscheduler_source_type field in the
 *			super-class initializer
 * @param type		litteral expression of the type to set
 */
#define __GSCHEDULER_SOURCE_PARAM_TYPE(prefix, type)		\
	prefix get_value_types.in_type = #type,			\
	.prefix get_value_types.in_type_size = sizeof(type)
/**
 * Initializer for the show_value() method of a gscheduler_source_type
 *
 * @param prefix	prefix to the gscheduler_source_type field in the
 *			super-class initializer
 * @param _show_value	function to set as the show_value method
 */
#define __GSCHEDULER_SOURCE_SHOW_VALUE(prefix, _show_value)	\
	prefix show_value = _show_value

/*
 * Structure representing a gscheduler source. Must be initiliazed with
 * gscheduler_source_init()
 */
struct gscheduler_source {
	struct gscheduler_source_type *type;
	struct list_head pub_sub_head;
	spinlock_t lock;
};

/**
 * Get the gscheduler_source_type of a gscheduler_source
 *
 * @param source	source to get the type of
 *
 * @return		pointer to the gscheduler_source_type of source
 */
static inline
struct gscheduler_source_type *
gscheduler_source_type_of(struct gscheduler_source *source)
{
	return source->type;
}

/* Type definitions for gscheduler_sink */

struct gscheduler_sink;

/**
 * prototype for the method to notify a gscheduler_sink of an update from
 * its source
 *
 * @param sink		sink to be notified
 * @param source	source notifying sink
 */
typedef void sink_update_value_t(struct gscheduler_sink *,
				 struct gscheduler_source *);

/* To initialize with GSCHEDULER_SINK_TYPE_INIT. */
struct gscheduler_sink_type {
	sink_update_value_t *update_value;
	/* types used when calling gscheduler_sink_get_value() */
	struct get_value_types get_value_types;
};

/**
 * Mandatory macro to define a gscheduler_sink_type.
 *
 * @param _update_value	update_value() method of the sink
 * @param value_type	string containing the type name of source's values
 * @param value_type_size
 *			size in bytes of a value_type value
 * @param get_param_type
 *			string containing the type name of the parameters for
 *			the get_value method, or NULL
 * @param get_param_type_size
 *			size in bytes of a get_param_type parameter, or 0
 */
#define GSCHEDULER_SINK_TYPE_INIT(_update_value,			      \
				 value_type, value_type_size,	      \
				 get_param_type, get_param_type_size) \
	{							      \
		.update_value = _update_value,			      \
		.get_value_types = {				      \
			.out_type = value_type,			      \
			.out_type_size = value_type_size,	      \
			.in_type = get_param_type,		      \
			.in_type_size = get_param_type_size	      \
		}						      \
	}

/**
 * Initializer for the update_value() method of a gscheduler_sink_type
 *
 * @param prefix	prefix to the gscheduler_sink_type field in the
 *			super-class initializer
 * @param _update_value	function to set as the update_value() method
 */
#define __GSCHEDULER_SINK_UPDATE_VALUE(prefix, _update_value)	\
	prefix update_value = _update_value

/**
 * Initializer for the type of value output by the get_value() methods of
 * sources connected to sinks of a gscheduler_sink_type
 *
 * @param prefix	prefix to the gscheduler_sink_type field in the
 *			super-class initializer
 * @param type		litteral expression of the type to set
 */
#define __GSCHEDULER_SINK_VALUE_TYPE(prefix, type)		\
	prefix get_value_types.out_type = #type,		\
	.prefix get_value_types.out_type_size = sizeof(type)

/**
 * Initializer for the type of parameter taken by the get_value() methods of
 * sources connected to sinks of a gscheduler_sink_type
 *
 * @param prefix	prefix to the gscheduler_sink_type field in the
 *			super-class initializer
 * @param type		litteral expression of the type to set
 */
#define __GSCHEDULER_SINK_PARAM_TYPE(prefix, type)		\
	prefix get_value_types.in_type = #type,			\
	.prefix get_value_types.in_type_size = sizeof(type)

/*
 * Structure representing a gscheduler sink. Must be initialized with
 * gscheduler_sink_init()
 */
struct gscheduler_sink {
	struct gscheduler_sink_type *type;
	struct gscheduler_source *source;
	struct list_head pub_sub_list;
	int subscribed;

	/* Remote access handling */
	struct remote_pipe_desc remote_pipe;
};

/*
 * To initialize with GSCHEDULER_PIPE_TYPE[_INIT]. Initialization must be
 * completed by gscheduler_pipe_type_init() at runtime.
 */
struct gscheduler_pipe_type {
	struct config_item_type item_type;
	struct gscheduler_source_type *source_type;
	struct gscheduler_sink_type *sink_type;
};

/**
 * Mandatory macro to define a gscheduler_pipe_type. Can be used through
 * GSCHEDULER_PIPE_TYPE.
 *
 * @param owner		module providing the pipe type
 * @param item_ops	config_item_operations for the pipe configfs item
 * @param group_ops	config_group_operations for the pipe configfs group
 * @param _source_type	type of sources of this pipe type or NULL
 * @param _sink_type	type of sinks of this pipe type or NULL
 */
#define GSCHEDULER_PIPE_TYPE_INIT(owner, item_ops, group_ops, \
				 _source_type, _sink_type)   \
	{						     \
		.item_type = {				     \
			.ct_owner = owner,		     \
			.ct_item_ops = item_ops,	     \
			.ct_group_ops = group_ops,	     \
			.ct_attrs = NULL		     \
		},					     \
		.source_type = _source_type,		     \
		.sink_type = _sink_type,		     \
	}

/**
 * Convenience macro to define a gscheduler_pipe_type.
 *
 * @param name		name of the variable for the gscheduler_pipe_type
 * @param item_ops	config_item_operations for the pipe configfs item
 * @param group_ops	config_group_operations for the pipe configfs group
 * @param source_type	pointer to the type of sources of this pipe type or NULL
 * @param sink_type	pointer tp the type of sinks of this pipe type or NULL
 */
#define GSCHEDULER_PIPE_TYPE(name, item_ops, group_ops, source_type, sink_type) \
	struct gscheduler_pipe_type name =				       \
		GSCHEDULER_PIPE_TYPE_INIT(THIS_MODULE, item_ops, group_ops,     \
					 source_type, sink_type)

/**
 * Initializer for the source_type of sources of a gscheduler_pipe_type
 *
 * @param prefix	prefix to the gscheduler_pipe_type field in the
 *			super-class initializer
 * @param _source_type	pointer to the source type to set
 */
#define __GSCHEDULER_PIPE_SOURCE_TYPE(prefix, _source_type)	\
	prefix source_type = _source_type

/**
 * Get the gscheduler_pipe_type embedding a config_item_type
 *
 * @param type		pointer to the embedded config_item_type
 *
 * @return		pointer to the gscheduler_pipe_type embedding type
 */
static inline
struct gscheduler_pipe_type *
to_gscheduler_pipe_type(struct config_item_type *type)
{
	return container_of(type, struct gscheduler_pipe_type, item_type);
}

/*
 * Structure representing a gscheduler sink. Must be initialized with
 * gscheduler_pipe_init()
 */
struct gscheduler_pipe {
	struct config_group config;
	struct gscheduler_source *source;
	struct gscheduler_sink *sink;
};

/**
 * Get the gscheduler_pipe embedding a config_item
 *
 * @param item		pointer to the embedded config_item
 *
 * @return		pointer to the gscheduler_pipe embedding item
 */
static inline
struct gscheduler_pipe *to_gscheduler_pipe(struct config_item *item)
{
	return container_of(item, struct gscheduler_pipe, config.cg_item);
}

/**
 * Get the gscheduler_pipe_type of a gscheduler_pipe
 *
 * @param pipe		pipe to get the type of
 *
 * @return		pointer to the gscheduler_pipe_type of pipe
 */
static inline
struct gscheduler_pipe_type *gscheduler_pipe_type_of(struct gscheduler_pipe *pipe)
{
	return to_gscheduler_pipe_type(pipe->config.cg_item.ci_type);
}

/**
 * Initialize a gscheduler_source
 *
 * @param source	source to initialize
 * @param type		type of the source
 */
void gscheduler_source_init(struct gscheduler_source *source,
			   struct gscheduler_source_type *type);
/**
 * Cleanup a gscheduler_source (eg. before freeing the structure)
 *
 * @param source	source to cleanup
 */
static inline void gscheduler_source_cleanup(struct gscheduler_source *source)
{
}

/**
 * Initialize a gscheduler_sink
 *
 * @param sink		sink to initialize
 * @param type		type of the sink
 */
void gscheduler_sink_init(struct gscheduler_sink *sink,
			 struct gscheduler_sink_type *type);
/**
 * Cleanup a gscheduler_sink (eg. before freeing the structure)
 *
 * @param sink		sink to cleanup
 */
void gscheduler_sink_cleanup(struct gscheduler_sink *sink);

/**
 * Tells whether a sink can safely call gscheduler_source_get_value() on a
 * source, that is whether the types are compatible.
 *
 * @param sink_type	type of the sink
 * @param source_type	type of the source
 *
 * @return		0 if types are not compatible,
 *			not 0 otherwise
 */
int gscheduler_types_compatible(const struct gscheduler_sink_type *sink_type,
			       const struct gscheduler_source_type *source_type);

/**
 * Connect a sink to a source
 *
 * @param sink		sink to connect
 * @param source	source to connect the sink to
 * @param subscribe	subscribe to source's updates if not 0
 */
void gscheduler_sink_connect(struct gscheduler_sink *sink,
			    struct gscheduler_source *source,
			    int subscribe);
/**
 * Disconnect a sink from a source and break any pending request to a remote
 * pipe
 * Caller must synchronize_rcu before freeing sink and source, or reconnect sink
 * to a source
 * May block
 *
 * @param sink		sink to disconnect
 */
void gscheduler_sink_disconnect(struct gscheduler_sink *sink);

/**
 * Get the source connected to a sink, or return NULL
 * Caller must take care of races with
 * gscheduler_pipe_sink_{connect,disconnect}(), or hold RCU lock until it stops
 * using the source.
 *
 * @param sink		sink to get the source of
 *
 * @return		pointer to the connected source, or NULL
 */
struct gscheduler_source *
gscheduler_sink_get_peer_source(struct gscheduler_sink *sink);

/**
 * Test whether a source has subscribers
 * Caller may have to lock the source to be able to rely on the result
 *
 * @param source	source to test
 *
 * @return		true iff source has at least one subscriber
 */
int gscheduler_source_has_subscribers(struct gscheduler_source *source);
/**
 * Test whether a sink has subscribed to a source
 *
 * @param sink		sink to test
 *
 * @return		true iff sink has subscribed to a source
 */
int gscheduler_sink_subscribed(struct gscheduler_sink *sink);

/**
 * Lock a source. This will *not* prevent the source value from being queried
 * nor prevent the gscheduler_pipe subsystem to propagate update notifications
 * from this source. However this will block subscriptions/unsubscriptions.
 *
 * @param source	source to lock
 */
static inline void gscheduler_source_lock(struct gscheduler_source *source)
{
	spin_lock(&source->lock);
}

/**
 * Unlock a source
 *
 * @param source	source to unlock
 */
static inline void gscheduler_source_unlock(struct gscheduler_source *source)
{
	spin_unlock(&source->lock);
}

/**
 * Get the value from a source
 *
 * @param source	source to query
 * @param value_p	array of values to be filled
 * @param nr		max number of values to fill
 * @param in_value_p	array of parameters, or NULL
 * @param in_nr		number of elements in in_value_p
 *
 * @return		number of values filled, or
 *			negative error code
 */
int gscheduler_source_get_value(struct gscheduler_source *source,
			       void *value_p, unsigned int nr,
			       const void *in_value_p, unsigned int in_nr);
/**
 * Show the value from a source as a string (for instance through configfs)
 *
 * @param source	source to query
 * @param page		buffer to store the value (4 Kbytes size)
 *
 * @return		number of bytes written to buffer, or
 *			negative error code
 */
ssize_t gscheduler_source_show_value(struct gscheduler_source *source,
				    char *page);

/**
 * Publish an update to the subscribers of a source
 *
 * @param source	source publish an update
 */
void gscheduler_source_publish(struct gscheduler_source *source);

/**
 * Get the value from the source connected to a sink
 *
 * @param sink		sink to query
 * @param value_p	array of values to be filled
 * @param nr		max number of values to fill
 * @param in_value_p	array of parameters, or NULL
 * @param in_nr		number of elements in in_value_p
 *
 * @return		number of values filled, or
 *			negative error code
 */
int gscheduler_sink_get_value(struct gscheduler_sink *sink,
			     void *value_p, unsigned int nr,
			     const void *in_value_p, unsigned int in_nr);

/**
 * Show the value collected by a sink (from a its connected source) as a string
 * (for instance through configfs)
 *
 * @param sink		sink to query
 * @param page		buffer to store the value (4 Kbytes size)
 *
 * @return		number of bytes written to buffer, or
 *			negative error code
 */
ssize_t gscheduler_sink_show_value(struct gscheduler_sink *sink, char *page);


/**
 * Complete initialization of a gscheduler_pipe_type
 *
 * @param type		type to finish initializing
 * @param attrs		NULL-terminated list of custom configfs-attribute, or
 *			NULL
 *
 * @return		0 if successful,
 *			-ENOMEM if not sufficient memory could be allocated
 */
int gscheduler_pipe_type_init(struct gscheduler_pipe_type *type,
			     struct configfs_attribute **attrs);
/**
 * Cleanup a gscheduler_pipe_type (eg. before freeing the structure)
 *
 * @param type		type to cleanup
 */
void gscheduler_pipe_type_cleanup(struct gscheduler_pipe_type *type);

/**
 * Initialize a gscheduler_pipe
 *
 * @param pipe		source to initialize
 * @param name		name of the configfs directory representing the source
 * @param type		type of the pipe
 * @param source	source part of the pipe or NULL
 * @param sink		sink part of the pipe or NULL
 * @param default_groups
 *			NULL terminated array of custom config_groups displayed
 *			as subdirs of the pipe, or NULL
 *
 * @return		0 if successful,
 *			negative error code if error
 */
int gscheduler_pipe_init(struct gscheduler_pipe *pipe,
			const char *name,
			struct gscheduler_pipe_type *type,
			struct gscheduler_source *source,
			struct gscheduler_sink *sink,
			struct config_group **default_groups);
/**
 * Cleanup a gscheduler_pipe (eg. before freeing the structure)
 *
 * @param pipe		pipe to cleanup
 */
static inline void gscheduler_pipe_cleanup(struct gscheduler_pipe *pipe)
{
}

/* Functions to be used by super classes of gscheduler_pipe */

/**
 * Super classes are responsible for calling this method when their respective
 * show_attribute() method is called.
 * Depending on the value returned in *handled, the super class then knows
 * whether the attribute is a pipe default one, or a super class specific one.
 *
 * @param pipe		pipe which attribute is read
 * @param attr		attribute read
 * @param page		buffer of at least 4Kbytes length to hold the result
 * @param handled	points to an integer which on return will be not 0 iff
 *			the attribute is a pipe default one
 *
 * @return		number of bytes written in page, or
 *			negative error code
 */
ssize_t gscheduler_pipe_show_attribute(struct gscheduler_pipe *pipe,
				      struct configfs_attribute *attr,
				      char *page,
				      int *handled);
/**
 * Super classes are responsible for calling this method when their respective
 * store_attribute() method is called.
 * Depending on the value returned in *handled, the super class then knows
 * whether the attribute is a pipe default one, or a super class specific one.
 *
 * @param pipe		pipe which attribute is written to
 * @param attr		attribute written to
 * @param page		buffer holding the data to write
 * @param handled	points to an integer which on return will be not 0 iff
 *			the attribute is a pipe default one
 * @param count		number of bytes to write to attribute
 *
 * @return		number of bytes written to attribute, or
 *			negative error code
 */
ssize_t gscheduler_pipe_store_attribute(struct gscheduler_pipe *pipe,
				       struct configfs_attribute *attr,
				       const char *page, size_t count,
				       int *handled);

#endif /* __HCC_GSCHEDULER_PIPE_H__ */
