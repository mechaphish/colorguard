naive_atoi_c_template = """
#include <libcgc.h>
#include <stdlib.h>
#include <boolector.h>
#include <string.h>

enum register_t
{
    eax = 0,
    ecx = 1,
    edx = 2,
    ebx = 3,
    esp = 4,
    ebp = 5,
    esi = 6,
    edi = 7
};

void die(const char *str) {
    transmit(2, str, strlen(str), NULL);
    _terminate(1);
}

void debug_str(const char *str) {
    transmit(2, str, strlen(str), NULL);
}

/*
 * Test file descriptor readiness.
 */

int fd_ready(int fd) {
  struct timeval tv;
  fd_set rfds;
  int readyfds = 0;

  FD_SET(fd, &rfds);

  tv.tv_sec = 1;
  tv.tv_usec = 0;

  int ret;
  ret = fdwait(fd + 1, &rfds, NULL, &tv, &readyfds);

  /* bail if fdwait fails */
  if (ret != 0) {
    return 0;
  }
  if (readyfds == 0)
    return 0;

  return 1;
}

size_t receive_n( int fd, unsigned char *dst, size_t n_bytes )
{
  size_t len = 0;
  size_t rx = 0;
  while(len < n_bytes) {
    if (receive(fd, dst + len, n_bytes - len, &rx) != 0) {
      len = 0;
      break;
    }
    len += rx;
  }

  return len;
}

int send_all(int fd, const void *msg, size_t n_bytes)
{
  size_t len = 0;
  size_t tx = 0;
  while(len < n_bytes) {
    if (transmit(fd, (char *)msg + len, n_bytes - len, &tx) != 0) {
      return 1;
    }
    len += tx;
  }
  return 0;
}

void debug_print(const char *msg) {
  size_t len = (size_t)strlen(msg);
  transmit(2, msg, len, 0);
}

int fd_ready_timeout(int fd, int timeout_us) {
  struct timeval tv;
  fd_set rfds;
  int readyfds = 0;

  FD_SET(fd, &rfds);

  tv.tv_sec = timeout_us/1000000;
  tv.tv_usec = timeout_us % 1000000;

  int ret;
  ret = fdwait(fd + 1, &rfds, NULL, &tv, &readyfds);

  /* bail if fdwait fails */
  if (ret != 0) {
    return 0;
  }
  if (readyfds == 0)
    return 0;

  return 1;
}

size_t receive_n_timeout( int fd, void *dst_buf, size_t n_bytes, int timeout_us )
{
  char *dst = dst_buf;
  size_t len = 0;
  size_t rx = 0;
  while(len < n_bytes) {
    if (!fd_ready_timeout(fd, timeout_us)) {
      return len;
    }

    if (receive(fd, dst + len, n_bytes - len, &rx) != 0) {
      len = 0;
      break;
    }
    if (rx == 0) {
      return len;
    }
    len += rx;
  }

  return len;
}

/*
 * Receive n_bytes into no particular buffer.
 */
size_t blank_receive( int fd, size_t n_bytes )
{
  size_t len = 0;
  size_t rx = 0;
  char junk_byte;

  while (len < n_bytes) {
    if (!fd_ready(fd)) {
        return len;
    }
    if (receive(fd, &junk_byte, 1, &rx) != 0) {
      len = 0;
      break;
    }
    len += rx;
  }

  return len;
}

unsigned char
to_bin(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    else if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    else if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    else
        return 0;
}

unsigned int hex_to_uint(char *s)
{
    unsigned int ret = 0;
    size_t i;

    for (i = 4; i > 0; i--) {
        ret = (ret << 8) | (to_bin(s[2 * (i - 1)]) << 4);
        ret |= to_bin(s[2 * (i - 1) + 1]);
    }

    return ret;
}


void from_hex(char *dst, char *src) {
    int h = hex_to_uint(src);

    memcpy(dst, &h, 4);
}


typedef struct type2_vals_ {
   unsigned int region_addr;
   unsigned int region_size;
   unsigned int read_size;
} type2_vals;

/*
 * Negotiate a type 2 pov.
 * Returns 0 on success. On success, the t2vals structure holds the address
 * (t2vals->region_addr) and size of a memory region (t2vals->region_size)
 * from which the POV must leak a specific number of bytes (t2vals->read_size).
 */
int type2_negotiate(type2_vals *t2vals) {
   uint32_t povType = 2;
   if (send_all(3, &povType, sizeof(povType))) {
      return -1;
   }
   if (receive_n(3, (unsigned char *)t2vals, sizeof(type2_vals)) != sizeof(type2_vals)) {
      return -1;
   }
   return 0;
}

/*
 * Submit the len bytes in the val buffer as the results of a type 2 POV
 * Returns 0 on success
 */
int type2_submit(const unsigned char *val, size_t len) {
   return send_all(3, val, len);
}

int do_pov() {
  type2_vals t2vals;
  if (type2_negotiate(&t2vals) != 0) {
    die("type 2 negotiate failure\\n");
  }

  const char payload[] = "{raw_payload}";
  size_t recv_buf_len = {recv_buf_len};
  char *received_data = calloc(recv_buf_len, 1);
  if (!received_data)
    die("failed to calloc received data\\n");

  send_all(1, payload, {payload_len});

  receive_n_timeout(0, received_data, recv_buf_len, 500000);

  char str_flag[12] = {0};
  str_flag[0] = received_data[{flag_byte_1}];
  str_flag[1] = received_data[{flag_byte_2}];
  str_flag[2] = received_data[{flag_byte_3}];
  str_flag[3] = received_data[{flag_byte_4}];
  str_flag[4] = received_data[{flag_byte_5}];
  str_flag[5] = received_data[{flag_byte_6}];
  str_flag[6] = received_data[{flag_byte_7}];
  str_flag[7] = received_data[{flag_byte_8}];
  str_flag[8] = received_data[{flag_byte_9}];
  str_flag[9] = received_data[{flag_byte_10}];
  str_flag[10] = received_data[{flag_byte_11}];

  int flag = strtol(str_flag, NULL, 10);

  type2_submit((unsigned char *)&flag, t2vals.read_size);

  return 0;
}

int main(void) {
    /* align the stack so that boolector can work in all circumstances */
    asm(\"and $0xfffffff0, %esp\\n\");

    /* terminate, stack hasn't been fixed up */
    _terminate(do_pov());
}

"""
