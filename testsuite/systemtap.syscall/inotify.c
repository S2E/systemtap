/* COVERAGE: inotify_init inotify_init1 inotify_add_watch inotify_rm_watch */

#include <sys/inotify.h>

int main()
{
  int fd = inotify_init();
  //staptest// inotify_init () = NNNN

  int wd = inotify_add_watch(fd, "/tmp", IN_ALL_EVENTS);
  //staptest// inotify_add_watch (NNNN, "/tmp", IN_ACCESS|IN_MODIFY|IN_ATTRIB|IN_CLOSE_WRITE|IN_CLOSE_NOWRITE|IN_OPEN|IN_MOVED_FROM|IN_MOVED_TO|IN_CREATE|IN_DELETE|IN_DELETE_SELF|IN_MOVE_SELF) = NNNN
  
  inotify_rm_watch(fd, wd);
  //staptest// inotify_rm_watch (NNNN, NNNN) = 0

#ifdef IN_CLOEXEC
  inotify_init1(IN_NONBLOCK);
  //staptest// inotify_init1 (IN_NONBLOCK) = NNNN

  inotify_init1(IN_CLOEXEC);
  //staptest// inotify_init1 (IN_CLOEXEC) = NNNN

  inotify_init1(IN_NONBLOCK|IN_CLOEXEC);
  //staptest// inotify_init1 (IN_NONBLOCK|IN_CLOEXEC) = NNNN
#endif

  inotify_init1(-1);
  //staptest// inotify_init1 (IN_[^ ]+|XXXX) = -NNNN

  inotify_add_watch(-1, "/tmp", IN_MODIFY);
  //staptest// inotify_add_watch (-1, "/tmp", IN_MODIFY) = -NNNN

  inotify_add_watch(fd, (char *)-1, IN_MODIFY);
#ifdef __s390__
  //staptest// inotify_add_watch (NNNN, [7]?[f]+, IN_MODIFY) = -NNNN (EFAULT)
#else
  //staptest// inotify_add_watch (NNNN, [f]+, IN_MODIFY) = -NNNN (EFAULT)
#endif

  wd = inotify_add_watch(fd, "/tmp", -1);
  //staptest// inotify_add_watch (NNNN, "/tmp", IN_[^ ]+|XXXX) =

  inotify_rm_watch(fd, wd);
  //staptest// inotify_rm_watch (NNNN, NNNN) =

  inotify_rm_watch(-1, wd);
  //staptest// inotify_rm_watch (-1, NNNN) = -NNNN (EBADF)

  inotify_rm_watch(fd, -1);
  //staptest// inotify_rm_watch (NNNN, -1) = -NNNN (EINVAL)

  return 0;
}
