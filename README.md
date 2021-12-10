# hcloudclassic-kernel

`Kernel 2.6.32 SSI Optimize`

## 빌드 방법

아래 명령어를 통해 빌드 옵션을 설정한다.

```shell
# make defconfig
```
아래 명령어를 통해 빌드 작업을 수행한다. 

```shell
# make -j<코어 수>
```

아래 명령어를 통해 모듈 설치를 수행한다.

```shell
# make modules_install
```

아래 명령을 통해 커널 설치를 진행한다.

```shell
# make install
```

