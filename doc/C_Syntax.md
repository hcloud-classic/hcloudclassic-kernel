Table of Contents
=================

* [define Container_of](#define-container_of)
   * [예제](#예제)

## define Container_of

type이라는 구조체안의 member가 ptr로 부터 메모리상에서 얼마나 떨어져 있는지 offset을 구함.

```c
/**
 * container_of - cast a member of a structure out to the containing structure
 * @ptr:	the pointer to the member.
 * @type:	the type of the container struct this is embedded in.
 * @member:	the name of the member within the struct.
 *
 */
#define container_of(ptr, type, member) ({				\
// ptr구조체를 __mptr에 할당
void *__mptr = (void *)(ptr);					\
// 할당된 구조체가 찾아가려는 멤버와 같은지를 체크한다. 출발지와 도착지가 같으면 오류이기 때문
BUILD_BUG_ON_MSG(!__same_type(*(ptr), ((type *)0)->member) &&	\
// 인자로 받은 ptr 구조체가 void 인지 체크한다.
		 !__same_type(*(ptr), void),			\
		 "pointer type mismatch in container_of()");	\
// mptr에 할당 했던 구조체와 type 구조체의 member 변수와의 메모리상에서 떨어진 정도를 찾는다.
((type *)(__mptr - offsetof(type, member))); })
```





### 예제

다음 예제는 선형 리스트를 예로 들어서 `container_of` 에 대한 이해도를 높여준다.

```c
#include <stdio.h>

//include/linux/stddef.h
#define offsetof(TYPE, MEMBER) ((unsigned long) &((TYPE *)0)->MEMBER)

//include/linux/kernel.h
#define container_of(ptr, type, member) ({	\
	const typeof( ((type *)0)->member ) *__mptr = (ptr); \
	(type *)( (char *)__mptr - offsetof(type, member) ); })

struct list_head {
	struct list_head *next, *prev;
};

#define LIST_HEAD_INIT(name) { &(name), &(name) }

#define LIST_HEAD(name) \
	struct list_head name = LIST_HEAD_INIT(name)

static inline void INIT_LIST_HEAD(struct list_head *list)
{
	list->next = list;
	list->prev = list;
}

struct fox {
	unsigned long tail_length;
	unsigned long weight;
	int			  is_fantastic;
	struct list_head	list;
};

struct fox red_fox = {
	.tail_length = 40,
	.weight = 10,
	.is_fantastic = 0,
	.list = LIST_HEAD_INIT (red_fox.list),
	//INIT_LIST_HEAD (&red_fox->list);
};

int main (void)
{
	printf ("size: %d, %d, %d, %d\n",
        sizeof(struct fox), sizeof(unsigned long), sizeof(int), sizeof(struct list_head));

	printf ("red_fox value: %d, %d, %d\n"
        , red_fox.tail_length, red_fox.weight, red_fox.is_fantastic);

	printf ("red_fox addr: 0x%X, 0x%X, 0x%X, 0x%X, 0x%X\n"
        , &red_fox, &red_fox.tail_length, &red_fox.weight, &red_fox.is_fantastic, &red_fox.list);

	printf ("offset: %d, %d, %d, %d\n", offsetof(struct fox, tail_length)
									, offsetof(struct fox, weight)
									, offsetof(struct fox, is_fantastic)
									, offsetof(struct fox, list));

	printf ("container_of: 0x%X, 0x%X\n", container_of(&red_fox.weight, struct fox, weight)
									, container_of(&red_fox.list, struct fox,is_fantastic ) );
	return 0;
}
```



```shell
$ gcc list01.c
$ ./a.out
size: 40, 8, 4, 16
red_fox value: 40, 10, 0
red_fox addr: 0x601060, 0x601060, 0x601068, 0x601070, 0x601078
offset: 0, 8, 16, 24
container_of: 0x601060, 0x601068
```





