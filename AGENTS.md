# AGENTS.md

本文件记录仓库当前状态、两条利用路线及其支持情况，以及如何为新的内核/设备添加支持。

## 仓库状态

- 项目：ghostlock-app —— 面向 Android 内核的 ghostlock（CVE-2026-43499）提权利用实现。
- 触发链：futex `FUTEX_WAIT_REQUEUE_PI` 使内核在栈上放置 `rt_mutex_waiter`；运行时伪造 waiter 布局并配合内核页（fake FOPS 等）完成提权。
- 当前工作树有大量未提交改动（含 mcast 路线），既有改动一律保留，默认不提交。
- 构建：
  - 原生库：`make ghostlock`（NDK clang，`src/core/*.c`）。
  - APK：`.\gradlew.bat :app:assembleDebug`（`buildGhostlockNative` → `prepareGhostlockJniLibs` 拷到 `app/src/main/jniLibs/arm64-v8a/libghostlock.so`）。
  - 校验：`llvm-nm -C ghostlock` 查符号；APK 内 `lib/arm64-v8a/libghostlock.so` 应与剥离后二进制一致。
- 实时日志：`init_file_log()` 在 `init_runtime_paths()` 后按可用性依次尝试 `GHOSTLOCK_LOG`（显式）→ `/sdcard/Download/ghostlock.log`（root/shell 直跑可用）→ `GHOSTLOCK_LOG_DIR/ghostlock.log`（App 传外部私有目录，作用域存储下可写）→ `$GHOSTLOCK_HOME/ghostlock.log`（兜底），用 `open(O_WRONLY|O_CREAT|O_APPEND)` 打开日志 fd。所有 `pr_*` 宏经 `log_line()` 用 `write()` 同步输出：stdout 写彩色行（与旧 printf 字节一致），日志 fd 写剥色行。落盘：`log_line()` **每输出一行立即 `fdatasync()`**，`log_flush_file()` 再在 `spawn_child()`/`clone_child()` fork 前和每次 write attempt 前强制刷盘，避免卡死/panic 重启后脏页与文件长度丢失导致 `ghostlock.log` 为 0 字节（代价：punch 热路径里每行日志会增加 ~1-5ms 同步 I/O）。全程无后台线程、无 stdio 缓冲，保证 spawn/exploit 每次 fork 都是单线程——上一版 tee 线程在 `fwrite/fflush` 持 stdio/malloc 锁时被 fork，锁会继承进 W3 子进程，导致其 `fopen/fread("/proc/self/comm")` 偶发挂死（表现为“不是次次失败”）。App 跑完后还会通过 MediaStore 把 `ghostlock.log` 发布到 `/sdcard/Download/`，无需 root 即可用文件管理器/ADB 拉取。

## 两条路线

### 1. pselect 路线（默认）

- `do_pselect_fake_lock_route()`（`src/core/fops.c`）：构造 fd_set，使 `pselect()` 的内核栈拷贝覆盖 futex waiter，fake waiter 放入用户可控的 fd_set 字区。
- 参数 `pselect_waiter_shift`：waiter 相对 fd_set 起点的 qword 偏移；0 用 `target.h` 默认值。
- 适用：大部分 6.6 / 6.12 内核（shift = -2 或 0）。

### 2. mcast 路线（setsockopt 栈拷贝）

- `do_mcast_fake_lock_route()`（`src/core/fops.c`）：创建 IPv6 DGRAM socket，调用 `setsockopt(AF_INET6, IPPROTO_IPV6, 46, optval, 264)`；`do_ipv6_setsockopt` 会把 264 字节整段拷到内核栈，若该拷贝区覆盖 futex waiter，就把 fake waiter 放进 `optval[mcast_payload_off]`。
- socket 获取：`mcast_open_socket()` 按口味列表依次尝试（DGRAM/UDP/CLOEXEC/STREAM/RAW 等）并记录每个 errno；App 必须声明 `android.permission.INTERNET`，否则 HyperOS 会在 `security_socket_create`（SELinux）处对 `socket(AF_INET6, SOCK_DGRAM, 0)` 返回 `EPERM`（真机实测 errno=1）。
- 参数 `mcast_payload_off`：waiter 在 264 字节拷贝区内的偏移；0 = 走 pselect 路线。
- 两个已支持内核的 optname 46 均落在 switch case 45（264 字节拷贝块）。
- 拷贝先于校验：readmik70 反汇编显示 case 45 先 `memset(sp+0x40, 0, 0x108)` 再 `copy_from_user(sp+0x40, optval, 0x108)`，之后才校验组播参数，所以 `setsockopt` 返回 `-1/errno=99`（EADDRNOTAVAIL）时 264 字节仍然落栈，属预期行为。
- 窗口用 vDSO `clock_gettime` 忙等（避免深 syscall 破坏栈拷贝），consumer/cfi 阶段与 pselect 共用。

### punch 触发（`src/core/main.c` 的 `consumer_thread`）

- 触发链要求内核在 `FUTEX_WAIT_REQUEUE_PI` 超时后仍保留指向栈上 waiter 的引用（vendor bug 的 pi_state / pi_blocked_on 悬挂），punch 让内核再次遍历该链并对伪造 waiter 的 `pi_tree` 节点做 `rb_erase`，从而写出值。
- 三种 punch 模式（`punch_mode`，默认 2）：
  - 0 = `sched`：对 waiter tid 做 `sched_setattr(SCHED_BATCH, nice)`；失败时回退 `FUTEX_LOCK_PI`。
  - 1 = `futex`：只对 `f_pi_target` 做 `FUTEX_LOCK_PI`（50ms 超时）——直接在 pi_state 链上入队并遍历，是最直接的触发；`ETIMEDOUT/EAGAIN` 视为已入队走过链（owner 不会释放锁）。
  - 2 = `both`：先 sched 再 futex。
- 每轮 punch 记录 `sched=%d/%d futex=%d/%d locked=%d entered=%d`；`mcast window done` / `mcast route done` 行均带这些计数。

### 运行时选择（`src/core/main.c` 的 `waiter_thread`）

- `active_offsets->mcast_payload_off != 0` → `do_mcast_fake_lock_route()`
- 否则 → `do_pselect_fake_lock_route()`

## 支持情况

| 内核（uname -r） | 设备 | pselect | mcast |
| --- | --- | --- | --- |
| `5.15.194-android13-8-00019-gf4321180a397-ab15212794` | Redmi K70 | 不可行（waiter 与 fd_set 负重叠 -232） | 可行，`mcast_payload_off=0xa8` |
| `6.6.77-android15-8-gf9a1d4bd8353-abogki440974771-4k` | Xiaomi 15 | 不可行（waiter 在 fd_set 上方 12 qword，shift 最多 3） | 可行，`mcast_payload_off=0x90` |
| 其余表内 6.6.77 / 6.6.89 / 6.6.118 / 6.12.23 内核 | Redmi K90 / Civi 5 Pro / Xiaomi 15 与 15 Pro / OPPO Pad 4 Pro / Find N5 / K90 Ultra / Pad 5 / Find X8 系 / K90 Pro Max / Xiaomi 17 系 / OnePlus 15 | 可行（shift = -2 或 0） | 未启用 |

- 真机实测进度（Xiaomi 15，`6.6.77-gf9a1d4bd8353`）：
  - 第 1 轮：heap spray 偶发成功，但 `socket(AF_INET6, SOCK_DGRAM, 0)` 返回 `errno=1` → 补 `android.permission.INTERNET` + socket 口味回退。
  - 第 2 轮：socket 成功，mcast 路线报告 `calls=1 success=1` 但 W1 8 次全失败（`/sys/fs/selinux/enforce` 始终不可读）。分析认为 `sched_setattr` 成功不等于写原语落地（waiter 已脱离 pi 链时它对 pi_state 无遍历），故将默认 punch 改为 `both`（sched + `FUTEX_LOCK_PI` 直链遍历）并加每轮计数日志。
  - 下一步真机：观察 `mcast window done` 的 `futex entered>0`（证明入队并走过链）以及 W1 是否生效；仍失败则核对 6.6.77 的 `futex_wait_requeue_pi`/`rt_mutex` 反汇编与 `mcast_payload_off=0x90` 几何。
- 调试旋钮（env 或 `$GHOSTLOCK_HOME/ghostlock.conf` 的 `KEY=VALUE`，env 优先；App 启动只传 `GHOSTLOCK_HOME/TMPDIR/HOME`，App 内跑需用 conf 文件）：
  - `PUNCH` = `sched` / `futex` / `both`（默认 `both`）
  - `VARY_NICE` = 1（sched 的 nice 按 1..19 轮换，替代固定 19）
  - `CALLS` = 每轮 punch 次数（默认 1）、`BURST` = 每次连打（默认 1）、`DELAY_USEC` = punch 相对拷贝的延时（默认跟随 `route_delay_usec`）
- 结构体布局按内核宏区分：`src/kernels/offsets.h` 的 `STRUCT_OFFSETS_5_15 / STRUCT_OFFSETS_6_6 / STRUCT_OFFSETS_6_12`，配合 `src/core/runtime_struct_offsets.h` 的 `FAKE_WAITER_* / FOPS_* / CRED_* / STRUCT_PAGE_*` 宏（表内为 0 时回退 `target.h` 默认值）。
- 参考链几何（提取器 `--check-route` 实测）：
  - `5.15.194`：`__arm64_sys_futex(0xa0) → do_futex(0x140) → futex_wait_requeue_pi(0x1b0)`，waiter 栈 `sp+0x98`（abs -0x2f8）；mcast 链 `__arm64_sys_setsockopt(0x10) → __sys_setsockopt(0x80) → sock_common_setsockopt(0x40) → udpv6_setsockopt(0x50) → do_ipv6_setsockopt(0x2c0)`，copy=0x40。
  - `6.6.77-gf9a1d4bd8353`：`__arm64_sys_futex(0x70) → do_futex(0x60) → futex_wait_requeue_pi(0x1c0)`，waiter 栈 `sp+0x90`（abs -0x200）；mcast 链 `__arm64_sys_setsockopt(0x10) → __sys_setsockopt(0x50) → do_sock_setsockopt(0x50) → sock_common_setsockopt(0x10) → udpv6_setsockopt(0x10) → ipv6_setsockopt(0x40) → do_ipv6_setsockopt(0x2c0)`，copy=0x140。

## 如何支持新内核

1. 放镜像：`devices/<厂商>/<版本>/` 下放 `boot.img` 与 `xbl_config.img`（XBL 用于解析内核物理加载地址）。
2. 推导路线：

   ```powershell
   python tools/extract_target.py devices/<厂商>/<版本>/boot.img `
     --xbl-config devices/<厂商>/<版本>/xbl_config.img --check-route
   ```

   输出 futex 链、waiter 栈偏移、pselect 可行性、mcast 可行性（payload/copy/case）。
   - pselect 可行 → 记录 `pselect_waiter_shift`
   - mcast 可行 → 记录 `mcast_payload_off`
3. 注册偏移表：`python tools/extract_target.py <boot> --xbl-config <xbl> --register`。表已存在会跳过，需先删 `src/kernels/<release>/` 再注册；缺符号可用 `--allow-missing` 排查。
4. 核对 per-kernel 结构体布局（waiter / cred / fops / struct page），必要时补 `STRUCT_OFFSETS_*` 宏。
5. 构建验证：`make ghostlock`；`.\gradlew.bat :app:assembleDebug`；解包 APK 确认 `lib/arm64-v8a/libghostlock.so` 含新逻辑。
6. 更新 `README.md` / `README_ZH.md` 支持表与路线说明；真机实测后更新“已验证”结论。

## 注意事项

- Windows 下文件可能 CRLF/LF 混杂，`apply_patch` 失败时先统一转 LF 再打补丁。
- 只改与任务相关的文件，保留工作树既有未提交改动，不要提交。
