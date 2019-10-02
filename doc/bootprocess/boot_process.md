# Bootup Process

* [Booting](#booting)
   * [Kernel Load](#kernel-load)
   * [Initramfs, initrd Load](#initramfs-initrd-load)
      * [initramfs](#initramfs)
      * [<a href="https://foxutech.com/how-to-rebuild-the-initial-ramdisk-image/" rel="nofollow">initrd(initial ramdisk)</a>](#initrdinitial-ramdisk)

## Booting

Legacy Boot Loader or Pxeboot 두가지 과정 모두 초기 부팅에는 kernel 이미지(vmlinuz)와 초기 파일 시스템(initramfs/initrd)가 필요하다.

부트 로더 혹은 Pxeboot를 통해 커널과 초기 파일 시스템이 순서대로 메모리상에 로드된다.

### Kernel Load

제공 받은 커널이 메모리에 적재

### Initramfs, initrd Load

초기 파일 시스템 메모리 적재되면 해당 커널에 필요한 드라이버 혹은 모듈이 로드된다.

해당 단계에서 마운트 가능한 특수 파일시스템도 마운트하여 사용한다.

두가지 초기 램디스크 혹은 파일시스템의 기능을 살펴보면 크게 3가지이다.

- 디바이스를 시스템에 적절히 매핑
- 분할된 partition은 시스템에 설정된 파티션에 맞게 remount
- 서비스 시작

#### initramfs

initramfs는 tmpfs(유연한 크기의, 메모리 기반 경량 파일 시스템) 기반의 초기 램 파일 시스템이며 분할 블록 장치를 사용하지 않는다.

initrd처럼, 실제 루트 파일 시스템의 `init` 바이너리를 호출하기 전에 파일 시스템을 마운트하는데 필요한 도구와 스크립트를 넣는다.

initramfs는 cpio 아카이브를 만들어서 구성한다. cpio를 통해 모든파일, 도구, 라이브러리, 환경 설정등을 넣는다. 다음 과정으로 gzip을 통해 압축하여 리눅스 커너부분에 저장.

커널이 로드되고 난후 iniramfs를 감지하면 tmpfs파일시스템을 만들고, 내용을 이 파일시스템에서 추출한 다음, tmpfs 파일 시스템의 루트에 위치한 init 스크립트를 실행한다.

init 스크립트를 통해 실제 루트 파일시스템을 마운트 하고 나머지 파일 시스템도 활성화한다.

루트 파일 시스템과 다른 실제 파일 시스템을 마운트 하고 나면 initramfs의 init 스크립트는 실제 루트 시스템으로 전환하고, 실제 루트 시스템의 /sbin/init을 호출하여 부팅 과정을 계속 진행한다.



#### [initrd(initial ramdisk)](https://foxutech.com/how-to-rebuild-the-initial-ramdisk-image/)

initrd는 Device 로서 메모리 상에 적재 되므로 OS의 전원이 꺼지기 전까지 메모리 상에 상주하게 된다.

initrd는 물리 드라이브에 존재하는 루트 파일시스템을 불러오기 이전에 inird에 구성된 초기 루트파일 시스템을 사전에 Read-Only로 마운트 해준다.

initrd는 커널의 바운더리에서 커널의 부트 프로시저의 일부분으로 로드된다.

커널은 inird를 두단계를 거쳐서 마운트 한다.

1. 물리 드라이브에 존재 하는 실제 루트 파일시스템이 마운트 될수 있도록 해당 모듈들을 로드 한다.
2. 모듈이 로드완료 되면 실제 루트 파일시스템을 마운트한다.

두단계를 거쳐 실제 루트 파일시스템이 마운트 되면 RAM Disk에 에 적재했던 루트 파일시스템은 다른 디렉토리로 옮겨진후 단계적으로 unmount 된다.

이후 최종단계에서 실제 루트 파일시스템이 마운트 되면 해당 파일시스템의 init 프로세스가 PID 1, PPID 0 으로 실행된다.

`Operation Flow`


```shell
1. the boot loader loads the kernel and the initial RAM disk
2. the kernel converts initrd into a “normal” RAM disk and frees the memory used by initrd
3. if the root device is not /dev/ram0, the old (deprecated) change_root procedure is followed. see the “Obsolete root change mechanism” section below.
4. root device is mounted. if it is /dev/ram0, the initrd image is then mounted as root
5. /sbin/init is executed (this can be any valid executable, including shell scripts; it is run with uid 0 and can do basically everything init can do).
6. init mounts the “real” root file system
7. init places the root file system at the root directory using the pivot_root system call
8. init execs the /sbin/init on the new root filesystem, performing the usual boot sequence
9. the initrd file system is removed
```

이러한 동작방식은 구 버전의 데비안 계열의 OS에서 사용한다.


