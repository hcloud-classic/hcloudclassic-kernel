# IDR 소개

radix tree를 기반으로 정수 ID를 관리하는 기법을 말한다.
idr_layer라는 구조체를 통해 256개의 ID가 관리된다.<br>
idr_layer 구조체 사이에는 계층적인 관계를 구성할 수 있다.

* 32bit 시스템 레이어
	* 1 레이어: 0 ~ 0xff ID 관리
	* 2 레이어: 0 ~ 0xffff ID 관리
	* 3 레이어: 0 ~ 0xffffff ID 관리
	* 4 레이어: 0 ~ 0x7fffffff ID 관리

* 64bit 시스템 레이어
	* 1 레이어: 0 ~ 0xff ID 관리
	* 2 레이어: 0 ~ 0xffff ID 관리
	* 3 레이어: 0 ~ 0xffffff ID 관리
	* 4 레이어: 0 ~ 0xffffffff ID 관리
	* 5 레이어: 0 ~ 0xff_ffffffff ID 관리
	* 6 레이어: 0 ~ 0xffff_ffffffff ID 관리
	* 7 레이어: 0 ~ 0xffffff_ffffffff ID 관리
	* 8 레이어: 0 ~ 0x7fffffff_ffffffff ID 관리

* ID 관리
* IDR preload 버퍼

idr_preload_head에 연결된 idr_layer들 중 idr_layer를 선정하여 제공한다. 이는 SLAB 캐시를 통해 관리된다.<br>
idr_layer가 종횡으로 빠르게 공급할 수 있도록 설계되었다.



![idr-2](assets/idr-2.png)

![idr-1](assets/idr-1.png)

