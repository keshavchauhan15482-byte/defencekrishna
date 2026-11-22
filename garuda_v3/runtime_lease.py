"""Single-writer pilot ownership; kernel lock releases on process death."""
import os
from pathlib import Path
import stat


class RuntimeLease:
    def __init__(self, folder):
        try:
            import fcntl
        except ImportError as exc:
            raise ValueError('Pilot runtime ownership currently requires POSIX file locking') from exc
        self.fd = None
        fd = os.open(Path(folder)/'instance.lock', os.O_RDWR | os.O_CREAT | getattr(os,'O_NOFOLLOW',0), 0o600)
        try:
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)&0o077:
                raise ValueError('Runtime lock must be a private regular file owned by the service account')
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise ValueError('Runtime already owned by another pilot instance') from exc
            self.fd=fd
        except BaseException:
            os.close(fd)
            raise

    def close(self):
        if self.fd is not None:
            os.close(self.fd);self.fd=None
        # Do not unlink: replacing the lock inode enables split ownership.
