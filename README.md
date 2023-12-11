# MPC HD GG18

本项目基于：

1. ZenGo-X的GG18实现 <https://github.com/KZen-networks/multi-party-ecdsa>

同时参考：

1. CryptoChill的GG18应用实例 <https://travis-ci.com/cryptochill/tss-ecdsa-cli>

对BIP39的支持基于：

1. Crate tiny-bip39 1.0.0

对BIP32的支持基于：

1. Crate bitcoin 0.29.1下的Module bip32

默认情况下，本项目支持：

1. 含HD路径的$(t,n)$-门限ECDSA签名算法GG18（`keygen`、`sign`）
2. 遵循BIP39词库的24位助记词
3. 遵循BIP32和BIP44的non-hardened和hardened子公钥派生（`pubkey`、`pubkeyH`）
4. 导出主私钥$x$（**警告：毁灭性操作！**）(`retrieve`)
5. 不少于$t+1$方共同参与、刷新全局$x_i$及分片持有方的转移（`reshare`）
6. 支持一方导入助记词恢复$x_i$和`keys.store`（`derive`）
7. 支持$(t,n)$-门限ECDSA签名算法下仅由一方通过导入助记词产生私钥（`keygen_dumb`）
8. 支持$(t,n)$-门限ECDSA签名算法下仅由一方通过随机助记词产生私钥（`keygen_dumb_dumb`）
9. 支持含HD路径的$(t,n)$-门限ECDSA签名的批量产生（`sign_batch`）

## Build

```sh
cargo build --release
```

## Manager

运行`manager`，以管理各个参与方之间的通信。

```sh
./target/release/mpc_hd_gg18 manager
```

可修改`Rocket.toml`或使用`[env vars]`覆盖，以使用不同的host/port，参见 <https://api.rocket.rs/v0.4/rocket/config/index.html#environment-variables> 。

```sh
ROCKET_ADDRESS=127.0.0.1 ROCKET_PORT=8008 ./target/release/mpc_hd_gg18 manager
```

## Keygen

$(t,n)$-门限签名下，支持$n$方（如$P_1, P_2, ..., P_n$）共同发起`keygen`命令。

***输入：函数体内、函数体外不需要读取 `keys.store`***

***输出：生成 `keys1.store`、`keys2.store`、……、`keysn.store`***

```sh
USAGE:
    mpc_hd_gg18 keygen [OPTIONS] <keysfile> <params>

OPTIONS:
    -a, --addr <manager_addr>    URL to manager. E.g. http://127.0.0.2:8002

ARGS:
    <keysfile>  Target keys file
    <params>    Threshold/parties
                例如1/3表示(1,3)-门限签名

t=1 && n=3; for i in $(seq 1 $n)
do
    echo "key gen for client $i out of $n"
    ./target/release/mpc_hd_gg18 keygen keys$i.store $t/$n &
    sleep 2
done

./target/release/mpc_hd_gg18 keygen -a http://127.0.0.1:8008 keys1.store 1/3
./target/release/mpc_hd_gg18 keygen -a http://127.0.0.1:8008 keys2.store 1/3
./target/release/mpc_hd_gg18 keygen -a http://127.0.0.1:8008 keys3.store 1/3    
```

## Keygen from imported mnemonic

$(t,n)$-门限签名下，支持$n$方（$P_1, P_2, ..., P_n$）共同发起`keygen_dumb`命令，由其中一方通过导入的助记词，生成私钥并进行分片派发。

***输入：函数体内、函数体外不需要读取 `keys.store`***

***输出：生成 `keys1.store`、`keys2.store`***

```sh
USAGE:
    mpc_hd_gg18 keygen_dumb [OPTIONS] <keysfile> <params>

OPTIONS:
    -a, --addr <manager_addr>   URL to manager. E.g. http://127.0.0.2:8002
    -m, --mnem <mnemonic>       mnemonic of secret key
                                （用英文状态下的一对单引号（''）括起）
    -w, --pwd  <password>       password for seed
                                （用英文状态下的一对单引号（''）括起）

ARGS:
    <keysfile>      Target keys file
    <params>        Threshold/parties
                    例如1/3表示(1,3)-门限签名

./target/release/mpc_hd_gg18 keygen_dumb -a http://127.0.0.1:8008 -m '......' keys1.store 1/3
./target/release/mpc_hd_gg18 keygen_dumb -a http://127.0.0.1:8008 keys2.store 1/3
./target/release/mpc_hd_gg18 keygen_dumb -a http://127.0.0.1:8008 keys3.store 1/3

./target/release/mpc_hd_gg18 keygen_dumb -a http://127.0.0.1:8008 -m '......' -w 'abcdefg' keys1.store 1/3
./target/release/mpc_hd_gg18 keygen_dumb -a http://127.0.0.1:8008 keys2.store 1/3
./target/release/mpc_hd_gg18 keygen_dumb -a http://127.0.0.1:8008 keys3.store 1/3

对输入参数的检错能力包括：
1. <phrase>不符合BIP39
2. <phrase>多于一个不为空
3. <phrase>全部为空
4. <password>指派给非master方（即<phrase>为空的参与方）

对输入参数的检错能力不包括：
1. <keysfile>重复
2. <params>不一致
```

## Keygen from random mnemonic

$(t,n)$-门限签名下，支持$n$方（$P_1, P_2, ..., P_n$）共同发起`keygen_dumb_dumb`命令，由其中一方通过随机产生的助记词，生成私钥并进行分片派发。

***输入：函数体内、函数体外不需要读取 `keys.store`***

***输出：生成 `keys1.store`、`keys2.store`***

```sh
USAGE:
    mpc_hd_gg18 keygen_dumb_dumb [OPTIONS] <keysfile> <params>

OPTIONS:
    -a, --addr <manager_addr>   URL to manager. E.g. http://127.0.0.2:8002
    -l, --len  <phrase_length>  length of mnemonic of secret key
                                （支持12，15，18，21，24）
    -w, --pwd  <password>       password for seed
                                （用英文状态下的一对单引号（''）括起）

ARGS:
    <keysfile>      Target keys file
    <params>        Threshold/parties
                    例如1/3表示(1,3)-门限签名

./target/release/mpc_hd_gg18 keygen_dumb_dumb -a http://127.0.0.1:8008 -l 12 keys1.store 1/3
./target/release/mpc_hd_gg18 keygen_dumb_dumb -a http://127.0.0.1:8008 keys2.store 1/3
./target/release/mpc_hd_gg18 keygen_dumb_dumb -a http://127.0.0.1:8008 keys3.store 1/3

./target/release/mpc_hd_gg18 keygen_dumb_dumb -a http://127.0.0.1:8008 -w 'abcdefg' -l 12 keys1.store 1/3
./target/release/mpc_hd_gg18 keygen_dumb_dumb -a http://127.0.0.1:8008 keys2.store 1/3
./target/release/mpc_hd_gg18 keygen_dumb_dumb -a http://127.0.0.1:8008 keys3.store 1/3

对输入参数的检错能力包括：
1. <phrase_length>不符合BIP39（不等于12、15、18、21、24）
2. <phrase_length>多于一个不为空
3. <phrase_length>全部为空
4. <password>指派给非master方（即<phrase_length>为空的参与方）

对输入参数的检错能力不包括：
1. <keysfile>重复
2. <params>不一致
```

## Get HD public key for path

### Non-hardened child

返回HD Wallet中相应路径下的non-hardened子公钥的x坐标和y坐标。

***输入：函数体外需要读取一个 `keys.store`***

***输出：不生成 `keys.store`***

```sh
USAGE:
    mpc_hd_gg18 pubkey [OPTIONS] <keysfile>

OPTIONS:
    -p, --path <path>   Derivation path（以m/开头）

ARGS:
    <keysfile>    Keys file

./target/release/mpc_hd_gg18 pubkey keys1.store

./target/release/mpc_hd_gg18 pubkey -p m/0/1/2 keys1.store

对输入参数的检错能力包括:
1. <path>经过强化衍生子节点
```

### Hardened child

返回HD Wallet中相应路径下的hardened子公钥的x坐标和y坐标。

***输入：函数体外不需要读取 `keys.store`***

***输出：不生成 `keys.store`***

```sh
USAGE:
    mpc_hd_gg18 pubkeyH [OPTION] <keysfile> <mnemonic>

OPTIONS:
    -p, --path <path>   Derivation path（以m/开头）

ARGS:
    <keysfile>   Keys file
    <mnemonic>   mnemonic of secret key
                （用英文状态下的一对单引号（''）括起）

./target/release/mpc_hd_gg18 pubkeyH keys1.store '......'

./target/release/mpc_hd_gg18 pubkeyH -p m/0/2147483647'/1/2147483646'/2 keys1.store '......'

对输入参数的检错能力不包括：
1. <mnemonic>单词长度不等于24
2. <mnemonic>与私钥不对应
```

## Sign message

$(t,n)$-门限签名下，支持$t'$方（$t < t'\le n$，如$P_1, P_2, ..., P_{t'}$）共同发起`sign`命令、对一条信息进行标准ECDSA签名。

***输入：函数体外需要读取 $t'$个 `keys.store`***

***输出：不生成 `keys.store`***

```sh
USAGE:
    mpc_hd_gg18 sign [OPTIONS] <keysfile> <params> <message>

OPTIONS:
    -a, --addr <manager_addr>    URL to manager
    -p, --path <path>            Derivation path（以m/开头）

ARGS:
    <keysfile>  Keys file
    <params>    Threshold/parties/share_count
                例如1/2/3表示(1,3)-门限签名下由2方发起
    <message>   Message in hex format

./target/release/mpc_hd_gg18 sign -p m/0/1/2 -a http://127.0.0.1:8001 keys1.store 1/3/3 message
./target/release/mpc_hd_gg18 sign -p m/0/1/2 -a http://127.0.0.1:8001 keys2.store 1/3/3 message
./target/release/mpc_hd_gg18 sign -p m/0/1/2 -a http://127.0.0.1:8001 keys3.store 1/3/3 message

./target/release/mpc_hd_gg18 sign -p m/0/1/2 -a http://127.0.0.1:8001 keys1.store 1/2/3 message
./target/release/mpc_hd_gg18 sign -p m/0/1/2 -a http://127.0.0.1:8001 keys3.store 1/2/3 message

对输入参数的检错能力包括：
1. parties < threshold + 1
2. parties > share_count

对输入参数的检错能力不包括：
1. <path>经过强化衍生子节点
2. <keysfile>重复
3. <params>不一致
4. <message>不一致
```

## Sign batch of messages

$(t,n)$-门限签名下，支持$t'$方（$t < t'\le n$，如$P_1, P_2, ..., P_{t'}$）共同发起`sign_batch`命令、对一组信息（如$m$条信息）进行标准ECDSA签名，最终产生$m$个`signature`文件。

***输入：函数体外需要读取 $t'$个 `keys.store`***

***输出：不生成 `keys.store`***

```sh
USAGE:
    mpc_hd_gg18 sign_batch [OPTIONS] --path <path> --msg <message> <keysfile> <params>

OPTIONS:
    -a, --addr <manager_addr>    URL to manager

ARGS:
    --path <path>       Derivation path（以m/开头）
                        多个<path>对应多个--path
                        注意<path>不能为空，master key的<path>为""（引号内没有空格）
    --msg <message>     Message in hex format
                        多个<message>对应多个--msg
    <keysfile>          Keys file
    <params>            Threshold/parties/share_count
                        例如1/2/3表示(1,3)-门限签名下由2方发起

./target/release/mpc_hd_gg18 sign_batch -a http://127.0.0.1:8008 --path m/0/45/45 --path "" --msg SignMe --msg SignYou keys1.store 1/3/3
./target/release/mpc_hd_gg18 sign_batch -a http://127.0.0.1:8008 --path m/0/45/45 --path "" --msg SignMe --msg SignYou keys2.store 1/3/3
./target/release/mpc_hd_gg18 sign_batch -a http://127.0.0.1:8008 --path m/0/45/45 --path "" --msg SignMe --msg SignYou keys3.store 1/3/3

./target/release/mpc_hd_gg18 sign_batch -a http://127.0.0.1:8008 --path m/0/45/45 --path "" --path m/0/4/5/6 --path m/0/311/31231 --path m/0/3 --path m/0/56 --path m/0/987 --path "" --path m/0/3/4/778 --path m/0/1/2/3  --msg SignMeONE --msg SignMeTWO --msg SignMeTHREE --msg SignMeFOUR --msg SignMeFIVE --msg SignMeSIX --msg SignMeSEVEN --msg SignMeEIGHT --msg SignMeNINE --msg SignMeTEN keys1.store 1/2/3
./target/release/mpc_hd_gg18 sign_batch -a http://127.0.0.1:8008 --path m/0/45/45 --path "" --path m/0/4/5/6 --path m/0/311/31231 --path m/0/3 --path m/0/56 --path m/0/987 --path "" --path m/0/3/4/778 --path m/0/1/2/3  --msg SignMeONE --msg SignMeTWO --msg SignMeTHREE --msg SignMeFOUR --msg SignMeFIVE --msg SignMeSIX --msg SignMeSEVEN --msg SignMeEIGHT --msg SignMeNINE --msg SignMeTEN keys2.store 1/2/3

对输入参数的检错能力包括：
1. parties < threshold + 1
2. parties > share_count
3. <path>个数与<message>个数不相等

对输入参数的检错能力不包括：
1. <path>经过强化衍生子节点
2. <keysfile>重复
3. <params>不一致
4. <message>不一致
```

## Retrieve secret key

$(t,n)$-门限签名下，支持$t'$方（$t < t'\le n$，如$P_1, P_2, ..., P_{t'}$）共同发起`retrieve`命令，在不泄露任何一方的私钥分片$x_i$的前提下，各方在本地恢复出私钥$x$。（**警告：毁灭性操作！**）

***输入：函数体外需要读取 $t'$个 `keys.store`***

***输出：不生成 `keys.store`***

``` sh
USAGE:
    mpc_hd_gg18 retrieve [OPTIONS] <keysfile> <params>

OPTIONS:
    -a, --addr <manager_addr>    URL to manager
    -p, --path <path>            Derivation path （以m/开头）

ARGS:
    <keysfile>  Keys file
    <params>    Threshold/parties/share_count
                例如1/2/3表示(1,3)-门限签名下由2方发起

./target/release/mpc_hd_gg18 retrieve -p m/0/1/2 -a http://127.0.0.1:8008 keys1.store 1/2/3
./target/release/mpc_hd_gg18 retrieve -p m/0/1/2 -a http://127.0.0.1:8008 keys2.store 1/2/3

对输入参数的检错能力包括：
1. parties < threshold + 1
2. parties > share_count

对输入参数的检错能力不包括：
1. <path>经过强化衍生子节点
2. <keysfile>重复
3. <params>不一致 
```

## Reshare all $x_i$

$(t,n)$-门限签名下，支持$m$方（$n \le m \le 2n$）共同发起`reshare`命令，在不读取任何旧$u_i$的条件下，利用$t'$方（$t < t' \le n$，如$P_1, P_2, ..., P_{t'}$）的$x_1, x_2, ..., x_{t'}$, 刷新全局的私钥分片$x_i$。

也即，记提供$x_i$的参与方为集合$A$，所有原$x_i$持有方为集合$B$，`reshare`之后所有新$x_i$持有方为集合$C$，满足：

1. $A\in B$
2. ${\rm Card}(A) > t$
3. ${\rm Card}(B)={\rm Card}(C)=n$
4. $n \le {\rm Card}(A \cup C) = m \le 2n$

我们实现：

1. 当$B=C$且全部`keys.store`可读取时，保留原持有$u_i$，只刷新$x_i$；
2. 当$B\ne C$或$B=C$但某些`keys.store`不可读取时，同时刷新$u_i$和$x_i$；
3. 写入`keys.store`的${\rm ID}$在运行时会重新分配，出现例如`keys1.store`中存储${\rm ID}=2$的所有密钥信息是正常现象。

***输入：函数体内需要读取 $t'$ 或 $n$ 个 `keys.store`***

***输出：生成 `keys1.store`、`keys2.store`、……、`keysn.store`***

``` sh
USAGE:
    mpc_hd_gg18 reshare [OPTIONS] <keysfile> <params> <if_give> <if_hold> <if_receive>

OPTIONS:
    -a, --addr <manager_addr>    URL to manager

ARGS:
    <keysfile>      Keys file
    <params>        Threshold/parties/share_count
                    例如1/4/3表示(1,3)-门限签名下由4方发起
    <if_give>       t/T表示提供x_j，f/F表示不提供x_j
    <if_hold>       t/T表示持有旧x_j，f/F表示不持有旧x_j
    <if_receive>    t/T表示接收新x_j，f/F表示不接收新x_j

./target/release/mpc_hd_gg18 reshare -a http://127.0.0.1:8008 keys1.store 1/3/3 t t t
./target/release/mpc_hd_gg18 reshare -a http://127.0.0.1:8008 keys2.store 1/3/3 f t t
./target/release/mpc_hd_gg18 reshare -a http://127.0.0.1:8008 keys3.store 1/3/3 t t t

./target/release/mpc_hd_gg18 reshare -a http://127.0.0.1:8008 keys1.store 1/4/3 t t t
./target/release/mpc_hd_gg18 reshare -a http://127.0.0.1:8008 keys3.store 1/4/3 t t f
./target/release/mpc_hd_gg18 reshare -a http://127.0.0.1:8008 keys2.store 1/4/3 f f t
./target/release/mpc_hd_gg18 reshare -a http://127.0.0.1:8008 keys3.store 1/4/3 f f t

对输入参数的检错能力包括：
1. parties < share_count
2. parties > 2 * share_count
3. dead party，即<if_give> == false 且<if_receive> == false
4. <if_give> == true 但<if_hold> == false
5. 任一<if_give> == true 的<keysfile>不存在
6. Num( <if_give> == true ) <= threshold
7. Num( <if_hold> == true ) > share_count
8. Num( <if_receive> == true ) != share_count

对输入参数的检错能力不包括：
1. givers（ 即<if_give> == true ）的<keysfile>重复
2. receivers（即<if_receive> == true ）的<keysfile>重复
3. receivers（即<if_receive> == true ）的<keysfile>序号超出(1..=share_count)
4. 某两个<params>不一致
5. <params>与需要读取的<keysfile>文件内的params不一致
6. <manager_addr>不一致
```

## Derive one $x_i$

$(t,n)$-门限签名下，支持$n$方共同发起`derive`命令，利用至少$t$方（如$P_1, P_2, ..., P_t$）的$x_i$（即$x_1, x_2, ..., x_t$）和$n$方的$u_i$（即$u_1, u_2, ..., u_n$），恢复另外任意一方$P_s$的$x_s$及相应的`keys.store`。

其中，$P_s$方的$u_s$设定为由24位助记词导入。

***输入：函数体内需要读取 $n-1$个 `keys.store`***

***输出：生成 `keys1.store`、`keys2.store`、……、`keysn.store`***

``` sh
USAGE:
    mpc_hd_gg18 derive [OPTIONS] <keysfile> <params> <if_give> <mnemonic>

OPTIONS:
    -a, --addr <manager_addr>   URL to manager
    -m, --mnem <mnemonic>       mnemonic of u_s
                                （用英文状态下的一对单引号（''）括起）

ARGS:
    <keysfile>      Keys file
    <params>        Threshold/parties/share_count
                    例如1/2/3表示(1,3)-门限签名下由3方发起，其中2方提供x_j
    <if_give>       t/T表示提供x_i的一方，f/F表示不提供x_i的一方

./target/release/mpc_hd_gg18 derive -a http://127.0.0.1:8008 keys1.store 1/1/3 f
./target/release/mpc_hd_gg18 derive -a http://127.0.0.1:8008 -m '......' keys2.store 1/1/3 f
./target/release/mpc_hd_gg18 derive -a http://127.0.0.1:8008 keys3.store 1/1/3 t

对输入参数的检错能力包括：
1. parties < threshold
2. parties > share_count
3. <if_give> == true 且<mnemonic>不为空
4. 全部<mnemonic>为空
5. 多于1个<mnemonic>不为空
6. 任一<mnemonic>为空的参与方的<keysfile>不存在
7. <keysfile>重复

对输入参数的检错能力不包括：
1. 某两个<params>不一致
2. <params>与需要读取的<keysfile>文件内的params不一致
3. <manager_addr>不一致
4. <mnemonic>单词长度不等于24
```

## Note

由于目前`manager.rs`在分配参与方uuid方面的调试问题，`keygen`、`sign`、`retrieve`、`derive`、`reshare`在以下场景中会出现参与方之间存在两种${\rm uuid}$的bug。

也即，记第一轮`sign`有$t'_1$方，第二轮`sign`有$t'_2$方。当$t'_1<t'_2$时，第二轮分配${\rm uuid}$时会出现

$$
\begin{align*}
    P_1:~~&{\rm ID} = t'_1 + 1 &{\rm uuid} = {\rm uuid}_1 \\
    P_2:~~&{\rm ID} = t'_1 + 2 &{\rm uuid} = {\rm uuid}_1 \\
    ...... \\
    P_{t'_2-t'_1}:~~&{\rm ID} = t'_2 &{\rm uuid} = {\rm uuid}_1 \\
    P_{t'_2-t'_1+1}:~~&{\rm ID} = 1 &{\rm uuid} = {\rm uuid}_2 \\
    P_{t'_2-t'_1+2}:~~&{\rm ID} = 2 &{\rm uuid} = {\rm uuid}_2 \\
    ...... \\
    P_{t'_2}:~~&{\rm ID} = t'_1 &{\rm uuid} = {\rm uuid}_2
\end{align*}
$$

例如，`sign`第一轮的参数是`1/2/3`，第二轮的参数是`1/3/3`，则两轮${\rm uuid}$的具体分配情况分别是：

$$
\begin{align*}
    P_1:~~&{\rm ID} = 1 &{\rm uuid} = {\rm uuid}_1 \\
    P_2:~~&{\rm ID} = 2 &{\rm uuid} = {\rm uuid}_1
\end{align*}
$$

$$
\begin{align*}
    P_1:~~&{\rm ID} = 3 &{\rm uuid} = {\rm uuid}_1 \\
    P_2:~~&{\rm ID} = 1 &{\rm uuid} = {\rm uuid}_2 \\
    P_3:~~&{\rm ID} = 2 &{\rm uuid} = {\rm uuid}_2
\end{align*}
$$

虽然${\rm ID}$的分配是没有必要按照从$1$到$n$升序排列的，但每一轮只能有一种${\rm uuid}$。因此，在上述场景中，第二轮的所有参与方会一直处于等待$P_1$传输数据的状态。

目前可以通过以下两种方式解决：

1. 重新运行`manager`；
2. $P_1$重新调用`sign`命令。
