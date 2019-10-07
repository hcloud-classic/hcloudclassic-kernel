# hcloudclassic-kernel

`Kernel 4.15 SSI Optimize`

## 커널 빌드 방법

아래 명령어를 통해 빌드 옵션을 설정한다.

```shell
# make menuconfig
```
아래 옵션을 활성화 한다.

* Hcloud-Classic support ---> Add the HCloud-Classic support ---> hcc ghotplug
* Hcloud-Classic support ---> Add the HCloud-Classic support ---> hcc gcap
* Hcloud-Classic support ---> Add the HCloud-Classic support ---> hcc gproc
* Networking support ---> Networking options ---> The TIPC Protocol ---> Hcloud-Classic RPC Protocol

아래 명령어를 통해 빌드 작업을 수행한다. 

```shell
# make -j<코어 수>
```
