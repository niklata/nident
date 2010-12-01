set(NCMLIB_SRCS
  malloc.c
  pidfile.c
  signals.c
  exec.c
  strlist.c
  strl.c
  log.c
  chroot.c
  network.c
  io.c
  )

add_library(ncmlib ${NCMLIB_SRCS})