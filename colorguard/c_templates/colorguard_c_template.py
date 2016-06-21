c_template = """
#include <libcgc.h>

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

typedef char int8_t;
typedef unsigned char uint8_t;
typedef short int16_t;
typedef unsigned short uint16_t;
typedef int int32_t;
typedef unsigned int uint32_t;
typedef long long int64_t;
typedef unsigned long long uint64_t;


int strlen(const char *s) {
    int i = 0;

    while (*s) {
        s++; i++;
    }

    return i;
}

void debug(const char *str) {
    transmit(2, str, strlen(str), NULL);
}

void memset(char *dst, char v, size_t n) {
   size_t i;

   for(i=0;i<n;i++) dst[n] = v;
}

void *memcpy(void *dst, const void *src, size_t n) {
   char *d = (char*)dst;
   const char *s = (const char *)src;
   while (n--) {*d++ = *s++;}
   return dst;
}

char *reverse(char *str, size_t n) {

    char tmp, *src, *dst;
    size_t len;
    if (str != NULL)
    {
        len = n;
        if (len > 1) {
            src = str;
            dst = src + len - 1;
            while (src < dst) {
                tmp = *src;
                *src++ = *dst;
                *dst-- = tmp;
            }
        }
    }
    return str;
}

/* could probably just be *((int *)reverse(str, n)) */
long long to_int(char *str, size_t n) {
   size_t i;
   long long result = 0;

   for(i=0;i<n;i++) {
      result |= ((uint8_t) str[n-i-1]) << (i * 8);
   }

   return result;
}

char *from_int(char *dst, long long val, size_t n) {
   size_t i;

   for(i=0;i<n;i++) {
      dst[n-i-1] = (unsigned char)((val & (0xff << (i * 8))) >> (i * 8));
   }

   return dst;
}

char *sub(char *dst, long long operand, size_t n) {
   long long cint = 0;

   cint = to_int(dst, n) - operand;
   return from_int(dst, cint, n);
}

char *add(char *dst, long long operand, size_t n) {
   long long cint = 0;

   cint = to_int(dst, n) + operand;
   return from_int(dst, cint, n);
}

char *and(char *dst, long long operand, size_t n) {
   long long cint = 0;

   cint = to_int(dst, n) & operand;
   return from_int(dst, cint, n);
}

char *xor(char *dst, long long operand, size_t n) {
   long long cint = 0;

   cint = to_int(dst, n) ^ operand;
   return from_int(dst, cint, n);
}

size_t receive_until(int fd, char *dst, char delim, size_t max )
{
    size_t len = 0;
    size_t rx = 0;
    char c = 0;

    while( len < max ) {
        dst[len] = 0x00;

        if ( receive( fd, &c, 1, &rx ) != 0 ) {
            len = 0;
            goto end;
        }

        if ( c == delim ) {
            goto end;
        }

        dst[len] = c;
        len++;
    }
end:
    return len;
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

/*
 * Reverse an integer, same as converting endianness.
 * n is always expected to be 4 at the moment.
 */
int reverse_int(int to_reverse, size_t n)
{
  int new_int = 0;

  if (n == 4) {
    new_int |= (to_reverse >> 24) & 0xff;
    new_int |= ((to_reverse >> 16) & 0xff) << 8;
    new_int |= ((to_reverse >> 8) & 0xff) << 16;
    new_int |= (to_reverse & 0xff) << 24;
  }

  return new_int;
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

typedef struct type1_vals_ {
   unsigned int ipval;
   unsigned int regval;
} type1_vals;

typedef struct type2_vals_ {
   unsigned int region_addr;
   unsigned int region_size;
   unsigned int read_size;
} type2_vals;


/*
 * Negotiate a type 1 pov. Caller specifies an ip bit mask, a register bit mask
 * and a general purpose register number (see the list below).
 *
   0 - eax
   1 - ecx
   2 - edx
   3 - ebx
   4 - esp
   5 - ebp
   6 - esi
   7 - edi
 *
 * Returns 0 on success. On success, the t1vals structure holds required IP
 * and register values that must be found when the target CB crashes. At the
 * time of the crash the following must hold:
 *  (crash_eip & ipmask) == t1vals->ipval
 *  (crash_REG & regmask) == t1vals->regval
 */
int type1_negotiate(unsigned int ipmask, unsigned int regmask, unsigned int regnum, type1_vals *t1vals) {
   uint32_t povType = 1;
   if (send_all(3, &povType, sizeof(povType)) ||
       send_all(3, &ipmask, sizeof(ipmask)) ||
       send_all(3, &regmask, sizeof(regmask)) ||
       send_all(3, &regnum, sizeof(regnum))) {
      return -1;
   }
   if (receive_n(3, (unsigned char *)t1vals, sizeof(type1_vals)) != sizeof(type1_vals)) {
      return -1;
   }
   return 0;
}

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


int main() {
  type2_vals t2vals;
  if (type2_negotiate(&t2vals) != 0) {
    _terminate(0);
  }

  char payload[] = "{payload}";
  long long ti;

  send_all(1, payload, {payloadsize});

  {transformation_code}


  flag = reverse_int(flag, 4);
  type2_submit((unsigned char *)&flag, t2vals.read_size);

  return 0;
}

"""
