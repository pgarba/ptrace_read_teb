#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

// Reads the value at gs:[0x30] in the main thread of the remote process with
// the given PID. Returns true on success, false on failure. The value is stored
// in *value.
#include <dirent.h>
#include <string>

bool read_gs_0x30(pid_t pid, uint64_t *value) {
  if (!value)
    return false;

  // Attach to the main thread
  if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) == -1) {
    perror("ptrace(PTRACE_ATTACH)");
    return false;
  }

  // Wait for the thread to stop
  int status = 0;
  if (waitpid(pid, &status, 0) == -1) {
    perror("waitpid");
    ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
    return false;
  }

  // Calculate the offset to gs_base in the user_regs_struct
  // The user area is defined in <sys/user.h> and contains the user_regs_struct
  struct user_regs_struct regs;
  int GS_BASE_OFFSET = offsetof(struct user, regs);
  GS_BASE_OFFSET += offsetof(struct user_regs_struct, gs_base);

  // Read the GS base from the main thread's user area
  unsigned long gs_base = 0;

#if defined(__x86_64__)
  errno = 0;
  gs_base = ptrace(PTRACE_PEEKUSER, pid, GS_BASE_OFFSET, nullptr);
  if (errno != 0) {
    perror("ptrace(PTRACE_PEEKUSER) for GS base");
    ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
    return false;
  }
#else
  ptrace(PTRACE_DETACH, tid, nullptr, nullptr);
  fprintf(stderr, "Only supported on x86_64\n");
  return false;
#endif

  // Now read the value at gs_base + 0x30 in the remote process
  errno = 0;
  uint64_t remote_addr = gs_base + 0x30;
  uint64_t data = ptrace(PTRACE_PEEKDATA, pid, (void *)remote_addr, nullptr);
  if (errno != 0) {
    perror("ptrace(PTRACE_PEEKDATA)");
    ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
    return false;
  }

  *value = data;

  // Detach from the thread
  ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
  return true;
}

int main(int argc, char *argv[]) {
  if (argc != 2) {
    fprintf(stderr, "Usage: %s <pid>\n", argv[0]);
    return 1;
  }

  pid_t pid = atoi(argv[1]);
  uint64_t value = 0;

  if (read_gs_0x30(pid, &value)) {
    printf("Value at gs:[0x30] in process %d: 0x%lx\n", pid, value);
  } else {
    fprintf(stderr, "Failed to read gs:[0x30] in process %d\n", pid);
    return 1;
  }

  return 0;
}