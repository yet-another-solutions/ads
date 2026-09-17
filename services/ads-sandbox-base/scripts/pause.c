/* Guest PID 1: reap children and block until SIGTERM/SIGINT. */
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile sig_atomic_t stop = 0;

static void on_term(int sig) {
  (void)sig;
  stop = 1;
}

static void on_chld(int sig) {
  (void)sig;
  while (waitpid(-1, NULL, WNOHANG) > 0) {
  }
}

int main(void) {
  struct sigaction sa;

  sa.sa_handler = on_term;
  sa.sa_flags = 0;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGTERM, &sa, NULL);
  sigaction(SIGINT, &sa, NULL);

  sa.sa_handler = on_chld;
  sa.sa_flags = SA_NOCLDSTOP;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGCHLD, &sa, NULL);

  while (!stop) {
    pause();
  }
  return 0;
}
