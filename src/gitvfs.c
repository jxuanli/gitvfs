#include <errno.h>
#define FUSE_USE_VERSION 31

#include "utils.c"
#include <asm-generic/errno-base.h>
#include <asm-generic/errno.h>
#include <assert.h>
#include <bits/pthreadtypes.h>
#include <bits/time.h>
#include <fcntl.h>
#include <fuse.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define DEBUG
#define MD5_LEN 16
#define MAX_FILESIZE 0x1000000
#define MAX_NAMELEN 0x1000
#define MAX_NUM_RECORDS_PER_FILE 0x100
#define MAX_NUM_LINKS 0x1000
#define FLAG1 "FLAG1"

struct record {
  uint8_t hash[MD5_LEN];
  size_t len;
  char *buf;
  struct record *next;
};

struct file {
  struct stat stat;
  char *buf;
  atomic_bool inuse;
  uint32_t rcnt;
  struct record *records;
};

struct node {
  uint8_t hash[MD5_LEN];
  size_t namelen;
  struct node *parent, *sibling, *child;
  size_t pad;
  struct file *file;
  char name[];
};

struct node *root = NULL;

#define MAX(x, y) (x > y ? x : y)
// https://elixir.bootlin.com/linux/v6.19.3/source/include/linux/err.h#L63
#define MAX_ERRNO 4095
#define IS_ERR_VALUE(x) (unsigned long)(void *)(x) >= (unsigned long)-MAX_ERRNO
static inline void *ERR_PTR(long error) { return (void *)error; }
static inline long PTR_ERR(const void *ptr) { return (long)ptr; }
static inline bool IS_ERR(const void *ptr) {
  return IS_ERR_VALUE((unsigned long)ptr);
}

void *cmalloc(size_t size) {
  // just a simply wrapper so the allocation method can be easily changed
  // malloc is used instead as tcache would not be used if calloc were used
  // instead
  void *result = malloc(size);
  if (result == NULL)
    return NULL;
  memset(result, 0, size);
  return result;
}

#include <pthread.h>
void __attribute__((always_inline)) logg(const char *action, const char *name,
                                         void *addr) {
#ifdef DEBUG
  FILE *f = fopen("/log", "a");
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  fprintf(f, "[%ld.%03ld] %012lx @ %012p: %s (%s)\n", ts.tv_sec % 1000,
          ts.tv_nsec / 1000000, pthread_self(), addr, action, name);
  fflush(f);
  fclose(f);
#endif
}

struct node *alloc_node(const char *name, struct node *parent, mode_t mode) {
  size_t namelen = strlen(name);
  if (namelen > MAX_NAMELEN)
    return NULL;
  struct node *node = cmalloc(sizeof(struct node) + namelen + 1);
  logg("alloc", name, node);
  if (node == NULL)
    return NULL;
  node->file = cmalloc(sizeof(struct file));
  if (node->file == NULL) {
    free(node);
    return NULL;
  }
  struct fuse_context *ctx = fuse_get_context();
  int uid = getuid(), gid = getgid();
  if (ctx != NULL) {
    uid = ctx->uid;
    gid = ctx->gid;
  }
  strncpy(node->name, name, namelen);
  node->namelen = namelen;
  clock_gettime(CLOCK_REALTIME, &node->file->stat.st_atim);
  clock_gettime(CLOCK_REALTIME, &node->file->stat.st_ctim);
  clock_gettime(CLOCK_REALTIME, &node->file->stat.st_mtim);
  node->file->stat.st_mode = mode;
  node->file->stat.st_gid = gid;
  node->file->stat.st_uid = uid;
  if (parent) {
    node->parent = parent;
    struct node *cur = parent->child;
    if (cur == NULL || strcmp(node->name, cur->name) < 0) {
      node->sibling = cur;
      parent->child = node;
    } else {
      while (cur) {
        if (cur->sibling == NULL ||
            (strcmp(cur->name, node->name) < 0 &&
             strcmp(node->name, cur->sibling->name) < 0)) {
          node->sibling = cur->sibling;
          cur->sibling = node;
          break;
        }
        cur = cur->sibling;
      }
    }
  } else {
    node->parent = node;
  }
  node->file->stat.st_nlink = 1;
  md5((uint8_t *)node->name, namelen, node->hash);
  return node;
}

void unlink_node(struct node *node) {
  struct node *cur = node->parent->child, *prev;
  if (cur == node) {
    node->parent->child = cur->sibling;
  } else {
    prev = cur;
    for (cur = cur->sibling; cur != NULL; cur = cur->sibling) {
      if (node == cur) {
        prev->sibling = cur->sibling;
        break;
      }
      prev = cur;
    }
  }
}

void free_node(struct node *node) {
  uint8_t hash[MD5_LEN];
  md5((uint8_t *)node->name, node->namelen, hash);
  if (memcmp(hash, node->hash, MD5_LEN)) {
    return;
  }
  unlink_node(node);
  free(node);
  logg("free", node->name, node);
  if (node->file->stat.st_nlink == 0) {
    free(node->file);
    logg("free", node->name, node->file);
    for (struct record *r = node->file->records; r != NULL;) {
      struct record *next = r->next;
      md5(r->buf, r->len, hash);
      if (memcmp(hash, r->hash, MD5_LEN) == 0) {
        free(r->buf);
        free(r);
        logg("free", "rbuffer", r->buf);
      }
      r = next;
    }
    free(node->file->buf);
    logg("free", "filebuffer", node->file->buf);
  }
}

struct node *resolve_path(const char *path) {
  if (strlen(path) == 0)
    return NULL;
  char *s = strdup(path);
  char *next = strtok(s, "/");
  struct node *cur = root;
  while (next && cur) {
    struct node *found = NULL;
    if (S_ISDIR(cur->file->stat.st_mode))
      for (struct node *pos = cur->child; pos != NULL; pos = pos->sibling) {
        if (strcmp(pos->name, next) == 0) {
          found = pos;
          break;
        }
      }
    next = strtok(NULL, "/");
    cur = found;
  }
  free(s);
  return cur;
}

struct node *alloc_helper(const char *path, mode_t mode) {
  struct node *node = resolve_path(path);
  if (node)
    return ERR_PTR(-EEXIST);
  int idx = -1;
  for (int i = strlen(path) - 1; i >= 0; i--) {
    if (path[i] == '/') {
      idx = i;
      break;
    }
  }
  if (idx < 0)
    return ERR_PTR(-EACCES);
  char *dir = strndup(path, idx + 1);
  if (dir == NULL)
    return ERR_PTR(-ENOMEM);
  struct node *parent = resolve_path(dir);
  if (parent == NULL) {
    node = ERR_PTR(-ENOENT);
    goto free_dir;
  }
  node = alloc_node(path + idx + 1, parent, mode);
  if (node == NULL)
    node = ERR_PTR(-ENOMEM);
free_dir:
  free(dir);
  return node;
}

struct node *alloc_flag(char *flagstr) {
  struct node *flag = alloc_helper("/flag1", S_IFREG | 0622);
  size_t sz = strlen(flagstr);
  flag->file->stat.st_size = sz;
  flag->file->buf = strdup(flagstr);
  return flag;
}

bool __attribute__((always_inline)) try_lock_file(struct file *file) {
  return atomic_exchange(&file->inuse, true);
}

void __attribute__((always_inline)) unlock_file(struct file *file) {
  atomic_exchange(&file->inuse, false);
}

// FUSE ops:

static int getattr_op(const char *path, struct stat *stbuf,
                      struct fuse_file_info *fi) {
  struct node *node = resolve_path(path);
  if (!node)
    return -ENOENT;
  memcpy(stbuf, &node->file->stat, sizeof(*stbuf));
  return 0;
}

static int readlink_op(const char *path, char *buf, size_t size) {
  int ret;
  struct node *node = resolve_path(path);
  if (!node)
    return -ENOENT;

  struct file *file = node->file;
  if (try_lock_file(file))
    return -EBUSY;
  int i = 0;
  for (i = 0; i < size - 1; i++) {
    if (file->buf[i] == 0)
      break;
    buf[i] = file->buf[i];
  }
  if (file->buf[i] != 0)
    ret = i;
  buf[i] = 0;
  unlock_file(file);
  return ret;
}

static int mkdir_op(const char *path, mode_t mode) {
  struct node *node = alloc_helper(path, mode | S_IFDIR);
  if (IS_ERR(node))
    return PTR_ERR(node);
  node->file->stat.st_nlink += 1;
  node->parent->file->stat.st_nlink += 1;
  node->file->stat.st_size = 0x1000; // making it more authentic xD
  return 0;
}

static int unlink_op(const char *path) {
  int ret;
  bool need_unlock = true;
  struct node *node = resolve_path(path);
  if (!node)
    return -ENOENT;
  struct file *file = node->file;
  if (try_lock_file(file))
    return -EBUSY;
  if (S_ISDIR(file->stat.st_mode)) {
    ret = -EISDIR;
    need_unlock = true;
    goto done;
  }
  file->stat.st_nlink -= 1;
  need_unlock = file->stat.st_nlink > 0;
  free_node(node);
done:
  if (need_unlock) {
    unlock_file(file);
  }
  return 0;
}

static int rmdir_op(const char *path) {
  struct node *node = resolve_path(path);
  if (node == root)
    return -EPERM;
  if (node == NULL)
    return -ENOENT;
  if (!S_ISDIR(node->file->stat.st_mode))
    return -ENOTDIR;
  if (node->child != NULL)
    return -ENOTEMPTY;
  if (node->file->stat.st_nlink == 2) {
    node->parent->file->stat.st_nlink -= 1;
    node->file->stat.st_nlink -= 2;
    free_node(node);
  } else {
    return -ENOTEMPTY;
  }
  return 0;
}

static int symlink_op(const char *target, const char *linkpath) {
  struct node *node = alloc_helper(linkpath, 0777 | S_IFLNK);
  if (IS_ERR(node))
    return PTR_ERR(node);
  node = resolve_path(linkpath);
  node->file->stat.st_size = strlen(target);
  node->file->buf = strdup(target);
  return 0;
}

static int rename_op(const char *oldpath, const char *newpath,
                     unsigned int flags) {
  struct node *old = resolve_path(oldpath);
  unlink_node(old);
  struct node *new = alloc_helper(newpath, old->file->stat.st_mode);
  free(new->file);
  new->file = old->file;
  if (S_ISDIR(old->file->stat.st_mode)) {
    new->child = old->child;
    for (struct node *cur = new->child; cur != NULL; cur = cur->sibling) {
      cur->parent = new;
    }
  }
  free(old);
  return 0;
}

static int link_op(const char *from, const char *to) {
  int ret;
  struct node *nfrom, *nto;
  nfrom = resolve_path(from);
  if (nfrom == NULL)
    return -ENOENT;
  struct file *file = nfrom->file;
  if (try_lock_file(file))
    return -EBUSY;
  if (file->stat.st_mode) {
  }
  if (file->stat.st_nlink > MAX_NUM_LINKS)
    return -EMLINK;
  nto = resolve_path(to);
  if (nto != NULL) {
    ret = -EEXIST;
    goto done;
  }
  nto = alloc_helper(to, file->stat.st_mode);
  if (nto == NULL) {
    ret = -ENOMEM;
    goto done;
  }
  nto->file = file;
  nfrom->file->stat.st_nlink += 1;
  ret = 0;
done:
  unlock_file(file);
  return ret;
}

static void *init_op(struct fuse_conn_info *conn, struct fuse_config *cfg) {
  conn->max_background = 64;
  conn->congestion_threshold = 32;
  cfg->kernel_cache = 0;
  cfg->direct_io = 1;
  return NULL;
}

static int readdir_op(const char *path, void *buf, fuse_fill_dir_t filler,
                      off_t offset, struct fuse_file_info *fi,
                      enum fuse_readdir_flags flags) {
  struct node *node = resolve_path(path);
  if (node == NULL)
    return -ENOENT;
  struct file *file = node->file;
  if (!S_ISDIR(file->stat.st_mode))
    return -ENOTDIR;
  filler(buf, ".", NULL, 0, 0);
  filler(buf, "..", NULL, 0, 0);
  struct node *pos;
  for (struct node *pos = node->child; pos != NULL; pos = pos->sibling) {
    if (filler(buf, pos->name, NULL, 0, 0))
      return -EINVAL;
  }
  return 0;
}

int create_op(const char *path, mode_t mode, struct fuse_file_info *fi) {
  if (!S_ISREG(mode))
    return -EINVAL;
  void *ret = alloc_helper(path, mode);
  return IS_ERR(ret) ? PTR_ERR(ret) : 0;
}

static int open_op(const char *path, struct fuse_file_info *fi) {
  struct node *node = resolve_path(path);
  if (node == NULL)
    return -ENOENT;
  return 0;
}

static int read_op(const char *path, char *buf, size_t size, off_t offset,
                   struct fuse_file_info *fi) {
  int ret;
  struct node *node = resolve_path(path);
  if (node == NULL)
    return -ENOENT;

  struct file *file = node->file;
  if (try_lock_file(file))
    return -EBUSY;
  if (!S_ISREG(file->stat.st_mode)) {
    ret = -EINVAL;
    goto done;
  }
  size_t filesize = file->stat.st_size;
  if (file->buf && offset < filesize && size < MAX_FILESIZE) {
    if (offset + size > filesize) {
      size = filesize - offset;
    }
    memcpy(buf, file->buf + offset, size);
  } else {
    size = 0;
  }

  ret = size;
done:
  unlock_file(file);
  return ret;
}

static int write_op(const char *path, const char *buf, size_t size,
                    off_t offset, struct fuse_file_info *fi) {
  int ret;
  size_t newsize;
  struct node *node;

  if (size == 0)
    return 0;
  if (size > MAX_FILESIZE || offset > MAX_FILESIZE ||
      offset + size > MAX_FILESIZE)
    return -EFBIG;
  node = resolve_path(path);
  if (node == NULL)
    return -ENOENT;

  struct file *file = node->file;
  if (try_lock_file(file))
    return -EBUSY;
  if (!S_ISREG(file->stat.st_mode)) {
    ret = -EINVAL;
    goto done;
  }
  newsize = MAX(file->stat.st_size, offset + size);
  if (newsize < file->stat.st_size) {
    ret = -EFBIG;
    goto done;
  }
  char *newbuf = cmalloc(newsize);
  if (newbuf == NULL) {
    ret = -ENOMEM;
    goto done;
  }
  logg("write", path, newbuf);
  memcpy(newbuf + offset, buf, size);
  if (file->buf) {
    if (file->rcnt < MAX_NUM_RECORDS_PER_FILE) {
      struct record *record = cmalloc(sizeof(struct record));
      if (record != NULL) {
        record->buf = file->buf;
        record->len = file->stat.st_size;
        md5((uint8_t *)record->buf, file->stat.st_size, record->hash);
        record->next = file->records;
        file->records = record;
        file->rcnt += 1;
      }
    }
  }
  file->buf = newbuf;
  file->stat.st_size = newsize;
  ret = size;
done:
  unlock_file(file);
  return ret;
}

int getxattr_op(const char *path, const char *name, char *value, size_t size) {
  int ret;
  char hash[MD5_LEN];
  struct node *node;

  size_t namelen = strlen(name);
  if (namelen != MD5_LEN * 2)
    return -ENODATA;
  node = resolve_path(path);
  if (node == NULL)
    return -ENOENT;

  struct file *file = node->file;
  if (try_lock_file(file))
    return -EBUSY;
  if (!S_ISREG(file->stat.st_mode)) {
    ret = -EINVAL;
    goto done;
  }
  for (int i = 0; i < MD5_LEN; i++) {
    sscanf(name + i * 2, "%2hhx", hash + i);
  }
  for (struct record *r = file->records; r != NULL; r = r->next) {
    if (memcmp(&r->hash, hash, MD5_LEN) == 0) {
      if (size > 0 && size < r->len) {
        ret = -ERANGE;
        goto done;
      }
      if (size > 0) {
        memcpy(value, r->buf, r->len);
      }
      ret = r->len;
      goto done;
    }
  }
  ret = -ENODATA;
done:
  unlock_file(file);
  return ret;
};

int listxattr_op(const char *path, char *list, size_t size) {
  int ret;
  size_t listlen;
  struct node *node = resolve_path(path);
  if (node == NULL)
    return -ENOENT;

  struct file *file = node->file;
  if (try_lock_file(file))
    return -EBUSY;
  if (!S_ISREG(file->stat.st_mode)) {
    ret = -EINVAL;
    goto done;
  }
  listlen = file->rcnt * (2 * MD5_LEN + 1);
  if (size < listlen || file->rcnt > MAX_NUM_RECORDS_PER_FILE) {
    ret = -ERANGE;
    goto done;
  }
  ret = listlen;
  for (struct record *r = file->records; r != NULL; r = r->next) {
    for (int i = 0; i < MD5_LEN; i++) {
      sprintf(list + i * 2, "%02x", r->hash[i]);
    }
    *(list + MD5_LEN * 2) = 0;
    list += MD5_LEN * 2 + 1;
  }
done:
  unlock_file(file);
  return ret;
}

int removexattr_op(const char *path, const char *name) {
  int ret;
  char hash[MD5_LEN];
  struct record *cur, *prev;
  struct node *node;

  size_t namelen = strlen(name);
  if (namelen != MD5_LEN * 2)
    return -ENODATA;
  node = resolve_path(path);
  if (node == NULL)
    return -ENOENT;

  struct file *file = node->file;
  if (try_lock_file(file))
    return -EBUSY;
  if (!S_ISREG(file->stat.st_mode)) {
    ret = -ENOTSUP;
    goto done;
  }
  ret = -ENODATA;
  for (int i = 0; i < MD5_LEN; i++) {
    sscanf(name + i * 2, "%2hhx", hash + i);
  }
  cur = file->records;
  if (cur == NULL || file->rcnt == 0) {
    goto done;
  }
  if (memcmp(cur->hash, hash, MD5_LEN) == 0) {
    file->records = cur->next;
    goto success;
  }
  prev = cur;
  for (cur = cur->next; cur != NULL; cur = cur->next) {
    if (memcmp(cur->hash, hash, MD5_LEN) == 0) {
      prev->next = cur->next;
      goto success;
    }
  }
  goto done;
success:
  free(cur->buf);
  free(cur);
  file->rcnt -= 1;
  ret = 0;
done:
  unlock_file(file);
  return ret;
}

static int utimens_op(const char *path, const struct timespec tv[2],
                      struct fuse_file_info *fi) {
  struct node *node = resolve_path(path);
  if (node == NULL)
    return -ENOENT;
  struct file *file = node->file;
  if (try_lock_file(file))
    return -EBUSY;
  clock_gettime(CLOCK_REALTIME, &file->stat.st_ctim);
  clock_gettime(CLOCK_REALTIME, &file->stat.st_mtim);
  unlock_file(file);
  return 0;
};

static const struct fuse_operations ops = {
    .getattr = getattr_op,
    .readlink = readlink_op,
    .mkdir = mkdir_op,
    // .link = link_op,
    .unlink = unlink_op,
    .rmdir = rmdir_op,
    .symlink = symlink_op,
    .rename = rename_op,
    .init = init_op,
    .readdir = readdir_op,
    .create = create_op,
    .open = open_op,
    .read = read_op,
    .write = write_op,
    .getxattr = getxattr_op,
    .listxattr = listxattr_op,
    .removexattr = removexattr_op,
    .utimens = utimens_op,
};

int main(int argc, char *argv[]) {
  int ret;
  char *flag1 = getenv(FLAG1);
  if (flag1 == NULL) {
    printf("Did not find the %s environment variable.\n", FLAG1);
    return -1;
  }
  root = alloc_node("", NULL, S_IFDIR | 01777);
  struct node *flag = alloc_flag(flag1);
  unsetenv(FLAG1);
  char *dir = "/mnt/gitvfs";
  mkdir(dir, 01777);
  char *fuse_argv[] = {
      "gitvfs",
      dir,
      "-o",
      "allow_other,default_permissions,max_threads=2",
  };
  struct fuse_args args =
      FUSE_ARGS_INIT(sizeof(fuse_argv) / sizeof(*fuse_argv), fuse_argv);

  ret = fuse_main(args.argc, args.argv, &ops, NULL);
  return ret;
}
