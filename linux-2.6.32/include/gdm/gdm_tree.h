/** Kddm tree implementation.
 *  @file gdm_tree.h
 *
 *  @author Innogrid HCC
 */

#ifndef __GDM_TREE__
#define __GDM_TREE__



/*--------------------------------------------------------------------------*
 *                                                                          *
 *                                 MACROS                                   *
 *                                                                          *
 *--------------------------------------------------------------------------*/



#define _2LEVELS_GDM_TREE 0
#define _NLEVELS_GDM_TREE 1

#define GDM_TREE_ADD_ENTRY 1



/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN VARIABLES                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/



extern struct gdm_set_ops gdm_tree_set_ops;
extern void *_2levels_gdm_tree_init_data;
extern void *_nlevels_gdm_tree_init_data;



/*--------------------------------------------------------------------------*
 *                                                                          *
 *                                   TYPES                                  *
 *                                                                          *
 *--------------------------------------------------------------------------*/



/** GDM tree level struct type */
struct gdm_tree_lvl {
	int nr_obj;
	struct gdm_tree_lvl **sub_lvl;
};

/** GDM tree type */
struct gdm_tree {
	struct gdm_tree_lvl *lvl1;
	unsigned long max_data;
	int tree_type;
	int nr_level;
	int bit_width; /*!< width of index 20, 32, 64 */
	int bit_size; /*!< normal bits per level, last level is the rest  */
	int bit_size_last; /*!< bits for last level (zero, if width%size=0) */
};

#endif // __GDM_TREE__
