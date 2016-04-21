#include <unistd.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <arpa/inet.h>
#include <libgen.h>

#include <uthash.h>
#include <hiredis.h>
#include <async.h>
#include <adapters/libevent.h>

#include <libmnl/libmnl.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/ipset/ip_set.h>

void _redisPrintReply(FILE *fp, const char *prefix, const redisReply *reply)
{
  switch (reply->type) {
    case REDIS_REPLY_STRING:
      fprintf(fp, "%sS:%s\n", prefix, reply->str);
      break;
    case REDIS_REPLY_ARRAY:
      {
        int j;
        char buf[1024];

        fprintf(fp, "%sARRAY:\n", prefix);
        snprintf(buf, sizeof(buf), "%s%s", prefix,prefix);
        for (j = 0; j < reply->elements; j++) {
          _redisPrintReply(fp, buf, reply->element[j]);
        }
      }
      break;
    case REDIS_REPLY_INTEGER:
      fprintf(fp, "%sINT:%lld\n", prefix, reply->integer);
      break;
    case REDIS_REPLY_NIL:
      fprintf(fp, "%sNIL\n", prefix);
      break;
    case REDIS_REPLY_STATUS:
      fprintf(fp, "%sST:%s\n", prefix, reply->str);
      break;
    case REDIS_REPLY_ERROR:
      fprintf(fp, "%sERR:%s\n", prefix, reply->str);
      break;
  }
}

#define DOMAIN_SIZE 128
#define IPSET_SIZE  32

typedef struct domain_entry { 
  char domain[DOMAIN_SIZE];
  char table[IPSET_SIZE];
  uint32_t domain_len;
  uint32_t flags;
  UT_hash_handle hh;
} domain_entry_t;

struct domain_entry *domains = NULL;

struct in_addr_entry { 
  struct in_addr addr;
  UT_hash_handle hh;
};

struct in_addr_entry *addrs = NULL;


domain_entry_t *domain_entry_create(const char *domain, const char *table) {
    domain_entry_t *entry = calloc (1, sizeof(domain_entry_t));

    strncpy (entry->domain, domain, DOMAIN_SIZE);
    strncpy (entry->table, table, IPSET_SIZE);

    entry->domain_len = strlen(domain);

    return entry;
}

int ipset_in_addr_op(const char *table, const struct in_addr *sa, int op) {
  struct nlmsghdr *nlh;
  struct nfgenmsg *nfg;
  struct mnl_socket *mnl;
  struct nlattr *nested[2];

  char buffer[256];
  int rc = 0;

  if (strlen(table) >= IPSET_MAXNAMELEN) {
    errno = ENAMETOOLONG;
    return -1;
  }

  nlh = mnl_nlmsg_put_header(buffer);
  nlh->nlmsg_type = op | (NFNL_SUBSYS_IPSET << 8);
  nlh->nlmsg_flags = NLM_F_REQUEST;

  nfg = mnl_nlmsg_put_extra_header(nlh, sizeof(struct nfgenmsg));
  nfg->nfgen_family = AF_INET;
  nfg->version = NFNETLINK_V0;
  nfg->res_id = htons(0);
  mnl_attr_put_u8(nlh, IPSET_ATTR_PROTOCOL, IPSET_PROTOCOL);
  mnl_attr_put(nlh, IPSET_ATTR_SETNAME, strlen(table) + 1, table);
  nested[0] = mnl_attr_nest_start(nlh, IPSET_ATTR_DATA);
  nested[1] = mnl_attr_nest_start(nlh, IPSET_ATTR_IP);

  mnl_attr_put(nlh, IPSET_ATTR_IPADDR_IPV4 | NLA_F_NET_BYTEORDER,
          sizeof(struct in_addr), sa);

  mnl_attr_nest_end(nlh, nested[1]);
  mnl_attr_nest_end(nlh, nested[0]);

  mnl = mnl_socket_open(NETLINK_NETFILTER);
  if (mnl <= 0)
    return -1;
  if (mnl_socket_bind(mnl, 0, MNL_SOCKET_AUTOPID) < 0) {
    rc = -1;
    goto close;
  }
  if (mnl_socket_sendto(mnl, nlh, nlh->nlmsg_len) < 0) {
    rc = -1;
    goto close;
  }
close:
  mnl_socket_close(mnl);
  return rc;
}

/*
int ipset_ip_op(const char *setname, const char *ipaddr, int af, int op) {
  struct nlmsghdr *nlh;
  struct nfgenmsg *nfg;
  struct mnl_socket *mnl;
  struct nlattr *nested[2];

  char buffer[256];
  int rc = 0;
  union {
    struct in_addr sa;
    struct in6_addr sa6;
  } inaddr;

  fprintf(stdout, "ipset %s %s %s\n", op == IPSET_CMD_ADD ? "ADD" : "DEL",  setname, ipaddr); 
  fflush(stdout);

  if (strlen(setname) >= IPSET_MAXNAMELEN) {
    errno = ENAMETOOLONG;
    return -1;
  }

  if (af != AF_INET && af != AF_INET6) {
    errno = EAFNOSUPPORT;
    return -1;
  }

  if (af == AF_INET) {
    inet_pton(af, ipaddr, &inaddr.sa);
  } else {
    inet_pton(af, ipaddr, &inaddr.sa6);
  }

  nlh = mnl_nlmsg_put_header(buffer);
  nlh->nlmsg_type = op | (NFNL_SUBSYS_IPSET << 8);
  nlh->nlmsg_flags = NLM_F_REQUEST;

  nfg = mnl_nlmsg_put_extra_header(nlh, sizeof(struct nfgenmsg));
  nfg->nfgen_family = AF_INET;
  nfg->version = NFNETLINK_V0;
  nfg->res_id = htons(0);
  mnl_attr_put_u8(nlh, IPSET_ATTR_PROTOCOL, IPSET_PROTOCOL);
  mnl_attr_put(nlh, IPSET_ATTR_SETNAME, strlen(setname) + 1, setname);
  nested[0] = mnl_attr_nest_start(nlh, IPSET_ATTR_DATA);
  nested[1] = mnl_attr_nest_start(nlh, IPSET_ATTR_IP);

  if (af == AF_INET) {
    mnl_attr_put(nlh, IPSET_ATTR_IPADDR_IPV4 | NLA_F_NET_BYTEORDER,
        sizeof(struct in_addr), &inaddr);
  } else {
    mnl_attr_put(nlh, IPSET_ATTR_IPADDR_IPV6 | NLA_F_NET_BYTEORDER,
        sizeof(struct in6_addr), &inaddr);
  }

  mnl_attr_nest_end(nlh, nested[1]);
  mnl_attr_nest_end(nlh, nested[0]);

  mnl = mnl_socket_open(NETLINK_NETFILTER);
  if (mnl <= 0)
    return -1;
  if (mnl_socket_bind(mnl, 0, MNL_SOCKET_AUTOPID) < 0) {
    rc = -1;
    goto close;
  }
  if (mnl_socket_sendto(mnl, nlh, nlh->nlmsg_len) < 0) {
    rc = -1;
    goto close;
  }
close:
  mnl_socket_close(mnl);
  return rc;
}
*/

void hdelIpsetCb(redisAsyncContext *c,void *r, void *priv) {
  domain_entry_t *e;
  domain_entry_t *entry = priv;
  ((domain_entry_t *)priv)->flags = 0;

  HASH_FIND_STR(domains, entry->domain, e);
  if (e) {
    HASH_DEL(domains, e);
    if (e != priv) {
      free(e);
    }
  }

  free(priv);
}

void delDomainCb(redisAsyncContext *c, void *r, void *priv) {
  redisReply *reply = r;
  domain_entry_t *entry = priv;

  if (reply && (reply->type == REDIS_REPLY_ARRAY)) {
    int i;

    fprintf(stdout, "del %s (%lu ip addrs) from %s\n", entry->domain, reply->elements, entry->table); 

    for (i = 0; i < reply->elements; i++) {
      struct in_addr addr;
      struct in_addr_entry *paddr = NULL;

      if (inet_pton (AF_INET, reply->element[i]->str, &addr) != 1) {
        fprintf(stderr, "invalid ip address %s\n", reply->element[i]->str);
        continue;
      }

      HASH_FIND_INT(addrs, &addr.s_addr, paddr);
      if (paddr) {
        fprintf(stdout, "%s: -%s\n", entry->table, reply->element[i]->str);
        ipset_in_addr_op(entry->table, &addr, IPSET_CMD_DEL);
        HASH_DEL(addrs, paddr);
      }
    }
    fflush(stdout);
  }
  redisAsyncCommand(c, NULL, NULL, "DEL %s", entry->domain);
  redisAsyncCommand(c, hdelIpsetCb, entry, "HDEL IPSET %s", entry->domain);
}

/*
void delDnameCb(redisAsyncContext *c, void *r, void *priv) {
  redisReply *reply = r;
  const char *dname = priv;

  if (reply && (reply->type == REDIS_REPLY_ARRAY)) {
    int i;

    fprintf(stdout, "del %s (%lu ip addrs)\n", dname, reply->elements); 
    fflush(stdout);

    for (i = 0; i < reply->elements; i++) {
      struct in_addr addr;

      if (inet_pton (AF_INET, reply->element[i]->str, &addr) != 1) {
        fprintf(stderr, "invalid ip address %s\n", reply->element[i]->str);
        continue;
      }
      ipset_in_addr_op(table, &addr, IPSET_CMD_DEL);
    }
  }
  redisAsyncCommand(c, NULL, NULL, "DEL %s", dname);
  free (priv);
}
*/

void addDomainCb(redisAsyncContext *c, void *r, void *priv) {
  redisReply *reply = r;
  const char *table = priv;

  if (reply == NULL) return;

  if (reply->type == REDIS_REPLY_ARRAY) {
    int i;

    if (reply->elements) {
      fprintf(stdout, "add %lu ip addrs to %s\n", reply->elements, table); 
    }

    for (i = 0; i < reply->elements; i++) {
      struct in_addr addr;
      struct in_addr_entry *paddr = NULL;

      if (inet_pton (AF_INET, reply->element[i]->str, &addr) != 1) {
        fprintf(stderr, "invalid ip address %s\n", reply->element[i]->str);
        continue;
      }

      HASH_FIND_INT(addrs, &addr.s_addr, paddr);
      if (paddr == NULL) {
        fprintf(stdout, "%s: +%s\n", table, reply->element[i]->str); 
        ipset_in_addr_op(table, &addr, IPSET_CMD_ADD);

        paddr = calloc(1, sizeof(struct in_addr_entry));
        paddr->addr = addr;

        HASH_ADD_INT(addrs, addr, paddr);
      }
    }
  }
  fflush(stdout);
}


void addSubDomainCb(redisAsyncContext *c, void *r, void *priv) {
  char *table = priv;
  redisReply *reply = r;

  //fprintf(stdout, "addSubDomainCb %s\n", table);
  if (reply == NULL) return;

  if (reply->type == REDIS_REPLY_ARRAY) {
    int i;

    for (i = 0; i < reply->elements; i++) {
      const char *dname = reply->element[i]->str;
      fprintf(stdout, "add subdomain %s to table %s\n", dname, table);
      fflush(stdout);
      redisAsyncCommand(c, addDomainCb, table, "SMEMBERS %s", dname);
    }
  }
}

void delSubDomainCb(redisAsyncContext *c, void *r, void *priv) {
  redisReply *reply = r;
  domain_entry_t *entry = priv;

  if (reply == NULL) return;

  if (reply->type == REDIS_REPLY_ARRAY) {
    int i;

    for (i = 0; i < reply->elements; i++) {
      const char *dname = reply->element[i]->str;
      fprintf(stdout, "delete subdomain %s\n", dname);
      fflush(stdout);

      redisAsyncCommand(c, delDomainCb, domain_entry_create(dname, entry->table),
              "SMEMBERS %s", dname);
    }
  }
}

void ipsetCb(redisAsyncContext *c, const char *channel, char *val, void *priv) {
  char *set = strtok(val, " ");
  char *dname = strtok(NULL, " ");

  //printf("channel %s: %s\n",channel, val);
  fprintf(stdout, "%s: %s\n",set, dname);

  if (!(set && dname)) {
    return;
  }
  if (strcmp(channel, "IPSET:ADD") == 0) {
    domain_entry_t *entry = calloc (1, sizeof(domain_entry_t));

    strncpy (entry->domain, dname, DOMAIN_SIZE);
    strncpy (entry->table, set, IPSET_SIZE);
    entry->domain_len = strlen(entry->domain);

    HASH_ADD_STR(domains, domain, entry);
    entry->flags = 1;

    fprintf(stdout, "add %s to %s\n",dname, set);
    fflush(stdout);
    //        redisAsyncCommand(c, NULL, NULL, "SADD IPSET_%s %s", set, dname);
    redisAsyncCommand(c, NULL, NULL, "HSET IPSET %s %s", dname, set);
    redisAsyncCommand(c, addDomainCb, entry->table, "SMEMBERS %s", dname);
    redisAsyncCommand(c, addSubDomainCb, entry->table, "KEYS *.%s", dname);
  } else if (strcmp(channel, "IPSET:DEL") == 0) {
    domain_entry_t *entry = NULL;

    fprintf(stdout, "remove %s from %s\n",dname, set);
    HASH_FIND_STR(domains, dname, entry);
    if (!entry) {
      entry = calloc (1, sizeof(domain_entry_t));
      strncpy (entry->domain, dname, DOMAIN_SIZE);
      strncpy (entry->table, set, IPSET_SIZE);
      entry->domain_len = strlen(entry->domain);

      HASH_ADD_STR(domains, domain, entry);
    }

    fprintf(stdout, "remove %s:%s from %s\n",entry->domain, entry->table, set);

    redisAsyncCommand(c, delSubDomainCb, entry, "KEYS *.%s", dname);
    redisAsyncCommand(c, delDomainCb, entry, "SMEMBERS %s", dname);
    fflush(stdout);
  } else if (strcmp(channel, "IPSET:NEW") == 0) {

  }
}

domain_entry_t * ipsetMatchDomain(const char *domain) {
  int len;
  domain_entry_t *entry, *tmp;

  len = strlen(domain);

  HASH_ITER(hh,domains,entry,tmp) {
    int n = len - entry->domain_len;

    if (n < 0)
      continue;

    if (strncmp(entry->domain, domain + n, entry->domain_len))
      continue;

    if (!n || domain[n-1] == '.') {
        return entry;
    }
  }

  return NULL;
}

void dnameCb(redisAsyncContext *c, const char *channel, char *val, void *priv) {
  domain_entry_t *entry = ipsetMatchDomain(val);
  if (entry) {
    fprintf(stdout,"domain %s is in table %s, pattern %s\n",
        val, entry->table, entry->domain);

    redisAsyncCommand((redisAsyncContext *)priv, addDomainCb, entry->table, "SMEMBERS %s", val);
  }
}

typedef void (*SubCbFunc)(redisAsyncContext *c, const char *channel, char *val, void *priv);

typedef struct {
  char pat[32];
  SubCbFunc cb;
} subscribe_t;

subscribe_t _subscribes[] = {
  {"IPSET:*", ipsetCb},
  {"DNAME", dnameCb},
  {"", NULL},
};


void subCb(redisAsyncContext *c, void *r, void *priv) {
  redisReply *reply = r;

  if (reply == NULL)
    return;
  if ( reply->type == REDIS_REPLY_ARRAY && reply->elements == 4 ) {
    subscribe_t *sbs = &_subscribes[0];

#ifdef DEBUG
    printf( "Received message [%s] [%s] [%s]: %s\n",
        reply->element[0]->str,
        reply->element[1]->str,
        reply->element[2]->str,
        reply->element[3]->str);
#endif

    while (sbs->cb) {
      if (strcmp(sbs->pat,reply->element[1]->str) == 0) {
        sbs->cb((redisAsyncContext *)priv, reply->element[2]->str, reply->element[3]->str, priv);
        return;
      }

      sbs++;
    }
    fprintf(stderr,"Cannot find handler\n"); 
  }
}

void loadIpsetCb(redisAsyncContext *c, void *r, void *priv) {
  redisReply *reply = r;
  if (reply == NULL) return;
  if ( reply->type == REDIS_REPLY_ARRAY && reply->elements > 0 ) {
    int i;
    for (i = 0; i < reply->elements; i+= 2) {
      domain_entry_t *entry = calloc (1, sizeof(domain_entry_t));
      strncpy (entry->domain, reply->element[i]->str, DOMAIN_SIZE);
      strncpy (entry->table, reply->element[i+1]->str, IPSET_SIZE);
      entry->domain_len = strlen(entry->domain);

      fprintf(stdout,"hash add %s => %s\n", entry->domain, entry->table);
      HASH_ADD_STR(domains, domain, entry);
      entry->flags = 1;

      redisAsyncCommand(c, addDomainCb, entry->table, "SMEMBERS %s", entry->domain);
      redisAsyncCommand(c, addSubDomainCb, entry->table, "KEYS *.%s", entry->domain);
    }
  }

  redisAsyncCommand((redisAsyncContext *)priv, subCb, c,  "PSUBSCRIBE DNAME IPSET:*");
}

void connectCb(const redisAsyncContext *c, int status) {
  if (status != REDIS_OK) {
    fprintf(stderr, "Connect failed: %s\n", c->errstr);
    return;
  }
  fprintf(stdout,"Connected...\n");
}

void disconnectCb(const redisAsyncContext *c, int status) {
  if (status != REDIS_OK) {
    fprintf(stderr, "Disconnect failed: %s\n", c->errstr);
    return;
  }
  fprintf(stdout, "Disconnected...\n");
}

int redis_port=6379;

const char *redis_sock = "/var/run/redis/redis.sock";

const char *redis_host=NULL;

int main (int argc, char **argv) {
  int opt;

  redisAsyncContext *c, *c2;
  struct event_base *base = event_base_new();

  signal(SIGPIPE, SIG_IGN);

  while ((opt = getopt(argc, argv, "h:s:p:")) != -1) {
    switch (opt) {
      case 'h':
        redis_host = optarg;
        while (*redis_host==' ')
          redis_host++;
        break;
      case 's':
        redis_sock = optarg;
        break;
      case 'p':
        redis_port = atoi(optarg);
        break;
      default:
        fprintf(stderr, "Usage: %s [-s socket] | [-h host -p redis_port]", basename(argv[0]));
        exit (1);
    }
  }

  if (redis_host) {
    fprintf(stdout, "connect to host%s:%d\n", redis_host, redis_port);
    fflush(stdout);
    c = redisAsyncConnect(redis_host, redis_port);
  }
  else {
    fprintf(stdout,"connect to socket %s\n", redis_sock);
    fflush(stdout);
    c = redisAsyncConnectUnix(redis_sock);
  }

  if (c->err) {
    /* Let *c leak for now... */
    fprintf(stderr, "Error: %s\n", c->errstr);
    return 1;
  }

  if (redis_host) {
    printf("connect to host %s:%d\n", redis_host, redis_port);
    fflush(stdout);
    c2 = redisAsyncConnect(redis_host, redis_port);
  } else {
    printf("connect to socket %s\n", redis_sock);
    fflush(stdout);
    c2 = redisAsyncConnectUnix(redis_sock);
  }

  if (c2->err) {
    /* Let *c leak for now... */
    fprintf(stderr, "Error: %s\n", c2->errstr);
    return 1;
  }

  redisLibeventAttach(c,base);
  redisLibeventAttach(c2,base);
  redisAsyncSetConnectCallback(c,connectCb);
  redisAsyncSetConnectCallback(c2,connectCb);
  redisAsyncSetDisconnectCallback(c,disconnectCb);
  redisAsyncSetDisconnectCallback(c2,disconnectCb);
  redisAsyncCommand(c, loadIpsetCb, c2, "HGETALL IPSET");

  event_base_dispatch(base);
  return 0;
}

/* vim: set ts=2 sw=2 et: */
