/*
 *
 * SYNgate
 * Copyright (C) 2019 Sorint.lab
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>
 *
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/types.h>
#include <linux/moduleparam.h>
#include <linux/inet.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/netfilter/nf_conntrack.h>
#include <linux/version.h>
#include <linux/ktime.h>

#include "SYNgate_netfilter.h"
#include "SYNquark.h"
#include "SYNauth.h"
#include "SYNhelpers.h"

#define DBGTAG "SYNgate"
#define VERSION "v0.3a"

// Max number of destinations managed by the module
#define MAX_DESTINATIONS   100

#define LOCALHOSTNET   2130706432          // Decimal LE rep of 127.0.0.0
#define LOCALHOSTBCAST 2147483647          // Decimal LE rep of 127.255.255.255

static struct nf_hook_ops *nfho_out = NULL;
static int psklen[MAX_DESTINATIONS];
static s64 uptime;                    // Used to delay the load of the module
int PAYLOADLEN = 0;

MODULE_AUTHOR("Sorint.lab");
MODULE_DESCRIPTION("SYNgate");
MODULE_VERSION(VERSION);
MODULE_LICENSE("GPL");

// Module parameters management
MODULE_PARM_DESC(dstnet_list, "Destination Networks list");
static char *dstnet_list[MAX_DESTINATIONS];
static u8 dstnet_mask[MAX_DESTINATIONS];            // Used at runtime
static __be32 dstnet_addr[MAX_DESTINATIONS];       // Used at runtime
static int dstnet_list_count = 0;
module_param_array(dstnet_list, charp, &dstnet_list_count, 0000);

MODULE_PARM_DESC(psk_list, "Pre-Shared Key used for the OneTimePassword list");
static char *psk_list[MAX_DESTINATIONS];
static int psk_list_count = 0;
module_param_array(psk_list, charp, &psk_list_count, 0000);

MODULE_PARM_DESC(precision_list, "Time precision parameter list");
static unsigned int precision_list[MAX_DESTINATIONS];
static int precision_list_count = 0;
module_param_array(precision_list, uint, &precision_list_count, 0000);

MODULE_PARM_DESC(enable_antispoof_list, "Enable IP Spoofing protection list");
static unsigned int enable_antispoof_list[MAX_DESTINATIONS];
static int enable_antispoof_list_count = 0;
module_param_array(enable_antispoof_list, uint, &enable_antispoof_list_count,
                   0000);

MODULE_PARM_DESC(enable_udp_list, "Enable OTP for UDP protocol list");
static unsigned int enable_udp_list[MAX_DESTINATIONS];
static int enable_udp_list_count = 0;
module_param_array(enable_udp_list, uint, &enable_udp_list_count,
                   0000);

// Variables for the anti-replay protection
u8 *otp_trash;
int trash_overfull = 0;
int MAX_TRASH = 10;
u64 prev_added_time = 0;

// Hook func for outgoing packets
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0)
static unsigned int outgoing_pkt(void *priv, struct sk_buff *skb,
                                 const struct nf_hook_state *state)
#else
static unsigned int outgoing_pkt(unsigned int hooknum, struct sk_buff *skb,
                                 const struct net_device *in,
                                 const struct net_device *out,
                                 int (*okfn)(struct sk_buff *))
#endif
{
  struct iphdr *iph;
  struct tcphdr *tcph;
  struct udphdr *udph;
  u8 *PAYLOAD = NULL;
  uint32_t daddr = 0;
  int i;
  // Conntrack infos for UDP
  enum ip_conntrack_info ctinfo;
  struct nf_conn *ct;

#ifdef DEBUG
  if (DBGLVL >= 5)
    {
      printk(KERN_INFO "%s: OUTGOING Hook entered\n", DBGTAG);
    }
#endif

  // Perform some sanity checks on the incoming pointers...
  if (!skb)
    {
      // We are not sure what is it...let it go
      goto exit_accept;
    }

  if (unlikely(!(iph = ip_hdr(skb))))
    {
#ifdef DEBUG
      if (DBGLVL >= 1)
        {
          printk(KERN_INFO "%s: OUTGOING Hook. Cannot read IP header\n",
                 DBGTAG);
        }
#endif
      // NULL pointer here, strange: drop
      goto exit_drop;
    }
  daddr = ntohl(iph->daddr);       // Get destination address

  // Ignore packets going to LOCALHOST
  if (daddr >= LOCALHOSTNET && daddr <= LOCALHOSTBCAST)
    {
      goto exit_accept;
    }

  // Checking if is TCP protocol
  if (iph->protocol == IPPROTO_TCP)
    {
#ifdef DEBUG
      if (DBGLVL >= 4)
        {
          printk(KERN_INFO "%s: OUTGOING TCP protocol section entered\n",
                 DBGTAG);
        }
#endif

      if (unlikely(!(tcph = tcp_hdr(skb))))
        {
#ifdef DEBUG
          if (DBGLVL >= 1)
            {
              printk(KERN_INFO "%s: OUTGOING TCP protocol. Cannot read TCP"
                     " header\n", DBGTAG);
            }
#endif
          // NULL pointer here, strange: drop
          goto exit_drop;
        }
      // We care just about SYN packets
      if (tcph->syn && !tcph->ack)
        {
#ifdef DEBUG
          if (DBGLVL >= 1)
            {
              printk(KERN_INFO "%s: OUTGOING syn packet\n", DBGTAG);
            }
#endif
          if (check_linear(skb, &iph, &tcph, NULL) == -1)
            {
              printk(KERN_INFO "%s: OUTGOING TCP cannot linearize SKB\n",
                     DBGTAG);
              goto exit_drop;
            }

          // IP -> PSK logic
          for (i = 0; i < dstnet_list_count; i++)
            {
              if (cidr_match(daddr, dstnet_addr[i], dstnet_mask[i]) == 1)
                {
                  // Match found, process the packet
                  if (process_tcp_out(skb, iph, tcph, i) == 0)
                    {
                      goto exit_accept;
                    }
                  else
                    {
                      goto exit_drop;
                    }
                }
            }

          // If here, no match has been found
          goto exit_accept;
        }
    }
  else if (iph->protocol == IPPROTO_UDP)
    {
#ifdef DEBUG
      if (DBGLVL >= 4)
        {
          printk(KERN_INFO "%s: OUTGOING UDP protocol section entered\n",
                 DBGTAG);
        }
#endif
      // Gets conntrack informations
      ct = nf_ct_get(skb, &ctinfo);
      if (ct == NULL)
        {
          printk(KERN_INFO "%s: OUTGOING UDP conntrack info invalid.\n",
                 DBGTAG);
          logs_udp_error();

          // We don't have conntrack info...let it go
          goto exit_accept;
        }

      // Check if this is the first packet
      if (ctinfo % IP_CT_IS_REPLY == IP_CT_NEW)
        {
#ifdef DEBUG
          if (DBGLVL >= 1)
            {
              printk(KERN_INFO "%s: OUTGOING UDP first packet\n",
                     DBGTAG);
            }
#endif
          if (check_linear(skb, &iph, NULL, NULL) == -1)
            {
              printk(KERN_INFO "%s: OUTGOING UDP cannot linearize SKB\n",
                     DBGTAG);
              goto exit_drop;
            }

          if (unlikely(!(udph = udp_hdr(skb))))
            {
#ifdef DEBUG
              if (DBGLVL >= 1)
                {
                  printk(KERN_INFO "%s: OUTGOING UDP protocol. Cannot read UDP"
                         " header\n", DBGTAG);
                }
#endif
              // NULL pointer here, strange: drop
              goto exit_drop;
            }
          // Skip some protocols
          if (check_udp_blacklist(udph) == 1)
            {
              goto exit_accept;
            }

          // IP -> PSK logic
          for (i = 0; i < dstnet_list_count; i++)
            {
              if (cidr_match(daddr, dstnet_addr[i], dstnet_mask[i]) == 1)
                {
                  // Check if UDP is enabled
                  if (enable_udp_list[i] == 0)
                    {
                      // Not enabled, accept
                      goto exit_accept;
                    }
                  // Match found, process the packet
                  if (process_udp_out(skb, iph, udph, i) == 0)
                    {
                      goto exit_accept;
                    }
                  else
                    {
                      goto exit_drop;
                    }
                }
            }
        }
      else
        {
          // The connection is already established
          goto exit_accept;
        }
    }

exit_accept:
  kfree(PAYLOAD);
  return NF_ACCEPT;
exit_drop:
  kfree(PAYLOAD);
  return NF_DROP;
}

// Process outgoing TCP packets.
// It returns 0 if packet must be accepted, otherwise return 1
// Using gcc < 4.2.4 can raise and error at the following
// #pragma" lines, if this is the case just comment it out
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-label"
static u8 process_tcp_out(struct sk_buff *skb, struct iphdr *iph,
                          struct tcphdr *tcph, int i)
{
  u8 *PAYLOAD = NULL;
  uint32_t daddr = 0;

  daddr = ntohl(iph->daddr);       // Get destination address

  if (enable_antispoof_list[i] == 0)
    {
      // If antispoof is enabled, destination IP is part of the OTP,
      // so we leave it, but in case is disabled we need to 0 it out
      daddr = 0;
    }

  // Define PAYLOADLEN depending on psk length
  PAYLOADLEN = DIGEST + psklen[i];

  // Get OTP
  PAYLOAD = kmalloc(PAYLOADLEN, GFP_ATOMIC);
  if (unlikely(!PAYLOAD))
    {
      // Error in allocating memory
      printk(KERN_INFO "%s: OUTGOING TCP failed to allocate payload "
             "memory\n", DBGTAG);
      goto exit_accept_tcpout;
    }

  if (get_otp(PAYLOAD,
              psk_list[i],
              psklen[i],
              precision_list[i],
              daddr) != 0)
    {
      // Error in getting the OTP
      printk(KERN_INFO "%s: OUTGOING TCP failed to compute payload\n",
             DBGTAG);
      goto exit_accept_tcpout;
    }

  set_otp(PAYLOAD, skb, iph, tcph, NULL);

  goto exit_accept_tcpout;

exit_drop_tcpout:
  kfree(PAYLOAD);
  return 1;

exit_accept_tcpout:
  kfree(PAYLOAD);
  return 0;
}
#pragma GCC diagnostic pop

// Process outgoing UDP packets.
// It return 0 if packet must be accepted, otherwise return 1
// Using gcc < 4.2.4 can raise and error at the following
// #pragma" lines, if this is the case just comment it out
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-label"
static u8 process_udp_out(struct sk_buff *skb, struct iphdr *iph,
                          struct udphdr *udph, int i)
{
  u8 *PAYLOAD = NULL;
  uint32_t daddr = 0;

  daddr = ntohl(iph->daddr);       // Get destination address

  if (enable_antispoof_list[i] == 0)
    {
      // If antispoof is enabled, destination IP is part of the OTP,
      // so we leave it, but in case is disabled we need to 0 it out
      daddr = 0;
    }

  // Define PAYLOADLEN depending on psk length
  PAYLOADLEN = DIGEST + psklen[i];

  // Get OTP
  PAYLOAD = kmalloc(PAYLOADLEN, GFP_ATOMIC);
  if (unlikely(!PAYLOAD))
    {
      // Error in allocating memory
      printk(KERN_INFO "%s: OUTGOING UDP failed to allocate payload "
             "memory\n", DBGTAG);
      goto exit_accept_udpout;
    }

  if (get_otp(PAYLOAD,
              psk_list[i],
              psklen[i],
              precision_list[i],
              daddr) != 0)
    {
      // Error in getting the OTP
      printk(KERN_INFO "%s: OUTGOING UDP failed to compute payload\n",
             DBGTAG);
      goto exit_accept_udpout;
    }

  set_otp(PAYLOAD, skb, iph, NULL, udph);
  goto exit_accept_udpout;

exit_drop_udpout:
  kfree(PAYLOAD);
  return 1;

exit_accept_udpout:
  kfree(PAYLOAD);
  return 0;
}
#pragma GCC diagnostic pop

// Load the module
static int __init SYNgate_init(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
  int random_res;
#endif

  // Check for vital parameters, don't allow to proceed if not set
  if (validate_params() == 1)
    {
      printk(KERN_INFO "%s: Wrong parameters, quitting...\n", DBGTAG);
      goto exit_error;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
  // Wait for the CRNG to be properly initialized
  printk(KERN_INFO "%s: Waiting for random pool initialization...\n", DBGTAG);
  random_res = wait_for_random_bytes();
  if (random_res != 0)
    {
      printk(KERN_INFO "%s: Random pool init returned %d\n", DBGTAG,
             random_res);
      goto exit_error;
    }
#endif

  printk(KERN_INFO "%s: Injecting module %s...\n",
         DBGTAG,
         VERSION);

  // May be to replaced, on older kernel, with:
  //
  //       struct timespec  uptime;
  //       get_monotonic_boottime(&uptime);
  uptime = ktime_to_ms(ktime_get_boottime());

  nfho_out = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops),
                                          GFP_KERNEL);

  if (nfho_out != NULL)
    {
      // Initialize OUTGOING netfilter hook
      nfho_out->hook = (nf_hookfn*)outgoing_pkt;     // hook function
      nfho_out->hooknum = NF_INET_POST_ROUTING;
      nfho_out->pf = PF_INET;                        // IPv4
      nfho_out->priority = NF_IP_PRI_FIRST;          // max hook priority
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
      nf_register_net_hook(&init_net, nfho_out);
#else
      nf_register_hook(nfho_out);
#endif
      goto exit_success;
    }
  else
    {
      goto exit_error;
    }

exit_success:
  return 0;

exit_error:
  kfree(nfho_out);
  printk(KERN_INFO "%s: ERROR initializing Kernel module\n", DBGTAG);
  return -1;
}

// Unload the module
static void __exit SYNgate_exit(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
  nf_unregister_net_hook(&init_net, nfho_out);
#else
  nf_unregister_hook(nfho_out);
#endif
  kfree(nfho_out);
}

// strlen implementation...to avoid the standard one. Not sure if it make sense
// It (obviously) returns the string length
static size_t __psk_strlen(const char *str)
{
  int len = -1;

  if (str)
    {
      while (str[++len] != '\0')
        ;
    }
  return len;
}

// Check if IP "addr" is in "net"/"bits" mask
// It returns 1 if so, otherwise 0
static u8 cidr_match(__be32 addr, __be32 net, uint8_t bits)
{
  if (bits == 0)
    {
      return 1;
    }
  return !((addr ^ net) & 0xFFFFFFFFu << (32 - bits));
}

// Validates the module parameters, based on different criterias
// It returns 0 if success, otherwise 1
static u8 validate_params(void)
{
  // As a first check, ensures that the number of parameter is
  // consistent (in other words the number must be the same) and > 0
  if (psk_list_count < 1 ||
      dstnet_list_count != psk_list_count ||
      dstnet_list_count != precision_list_count ||
      dstnet_list_count != enable_udp_list_count ||
      dstnet_list_count != enable_antispoof_list_count)
    {
      printk(KERN_INFO "%s: Number of parameters is not consistent\n", DBGTAG);
      goto exit_error;
    }

  // Validate the input parameters
  if (validate_dstnet() == 1 ||
      validate_psk() == 1 ||
      validate_precision() == 1 ||
      validate_udp() == 1 ||
      validate_antispoof() == 1)
    {
      goto exit_error;
    }

  return 0;

exit_error:
  return 1;
}

// Validates the IP format
// It returns 0 if success, otherwise 1
static u8 validate_dstnet(void)
{
  int i;
  int mask;
  char *ip, *copy;

  // Check if the Network provided is valid
  for (i = 0; i < dstnet_list_count; i++)
    {
      copy = dstnet_list[i];
      // Check Mask presence
      ip = strsep(&copy, "/");
      if (copy == NULL)
        {
          // No mask provided
          printk(KERN_INFO "%s: No MASK provided in Net # %d \n",
                 DBGTAG, i + 1);
          goto exit_error;
        }
      // Check Mask validity
      if (kstrtoint(copy, 10, &mask) != 0)
        {
          printk(KERN_INFO "%s: Error managing MASK at # %d \n",
                 DBGTAG, i + 1);
          goto exit_error;
        }
      else
        {
          if (mask < 0 || mask > 32)
            {
              printk(KERN_INFO "%s: Invalid MASK at # %d \n",
                     DBGTAG, i + 1);
              goto exit_error;
            }
          dstnet_mask[i] = mask;
        }

      // Check IP validity
      if (in4_pton(ip, -1, (u8 *)&dstnet_addr[i], -1, NULL) == 0)
        {
          printk(KERN_INFO "%s: Invalid Network at # %d \n",
                 DBGTAG, i + 1);
          goto exit_error;
        }
      dstnet_addr[i] = htonl(dstnet_addr[i]);
    }

  return 0;

exit_error:
  return 1;
}

// Validates the PSK
// It returns 0 if success, otherwise 1
static u8 validate_psk(void)
{
  int i;
  size_t len;

  // Check if the len of PSK is in the accepted limits
  for (i = 0; i < psk_list_count; i++)
    {
      len = __psk_strlen(psk_list[i]);
      if (len < 32 || len > 1024)
        {
          goto exit_error;
        }
      psklen[i] = len;
    }

  return 0;

exit_error:
  printk(KERN_INFO "%s: Length of PSK # %d is not valid\n", DBGTAG, i + 1);
  return 1;
}

// Validates the precision
// It returns 0 if success, otherwise 1
static u8 validate_precision(void)
{
  int i;

  // Check if the precision is in the accepted limits
  for (i = 0; i < precision_list_count; i++)
    {
      if (precision_list[i] < 0 || precision_list[i] > MAXPRECISION)
        {
          goto exit_error;
        }
    }

  return 0;

exit_error:
  printk(KERN_INFO "%s: Precision # %d is not valid\n", DBGTAG, i + 1);
  return 1;
}

// Validates the precision
// It returns 0 if success, otherwise 1
static u8 validate_antispoof(void)
{
  int i;

  // Check if the antispoof value is 0 or 1
  for (i = 0; i < enable_antispoof_list_count; i++)
    {
      if (enable_antispoof_list[i] != 0 && enable_antispoof_list[i] != 1)
        {
          goto exit_error;
        }
    }

  return 0;

exit_error:
  printk(KERN_INFO "%s: Antispoof value # %d is not valid\n", DBGTAG, i + 1);
  return 1;
}

// Validates the enable_udp
// It returns 0 if success, otherwise 1
static u8 validate_udp(void)
{
  struct module *mod;
  uint8_t udp_used = 0;
  int i;

  // Check if the enable_udp value is 0 or 1
  for (i = 0; i < enable_udp_list_count; i++)
    {
      if (enable_udp_list[i] != 0 && enable_udp_list[i] != 1)
        {
          goto exit_error;
        }

      if (enable_udp_list[i] == 1)
        {
          udp_used = 1;
        }
    }

  // Check for needed modules (for UDP protocol)
  if (udp_used == 1)
    {
      // This is managed differently than in SYNwall: if the
      // module is not loaded, we are not loading it automatically, since
      // the startup may fail for other parameters.
      // Since this should be a "server" installation, it is left to
      // be managed manually.
      mutex_lock(&module_mutex);
      mod = find_module("xt_conntrack");
      mutex_unlock(&module_mutex);

      if (!mod)
        {
          logs_udp_error();
          goto exit_error;
        }
    }

  return 0;

exit_error:
  printk(KERN_INFO "%s: UDP value # %d is not valid\n", DBGTAG, i + 1);
  return 1;
}

// Check if a SKB is linear and try to linearize it
// It return 0 if already linear, 1 if linearized, -1 in case of errors
static u8 check_linear(struct sk_buff *skb, struct iphdr **iph,
                       struct tcphdr **tcph, struct udphdr **udph)
{
  if (skb_is_nonlinear(skb))
    {
      if (skb_linearize(skb) != 0)
        {
          // Failed
          return -1;
        }
      else
        {
          // Linarization succeeded, now we need to re-read structures
          if (iph != NULL)
            {
              if (unlikely(!(*iph = ip_hdr(skb))))
                {
                  // NULL pointer returned, error
                  return -1;
                }
            }
          if (tcph != NULL)
            {
              if (unlikely(!(*tcph = tcp_hdr(skb))))
                {
                  // NULL pointer returned, error
                  return -1;
                }
            }
          if (udph != NULL)
            {
              if (unlikely(!(*udph = udp_hdr(skb))))
                {
                  // NULL pointer returned, error
                  return -1;
                }
            }

          return 1;
        }
    }
  return 0;
}

// Check if the outgoing service is balcklisted, so it must be excluded from
// the OTP adding.
// It returns 0 if not blacklisted, 1 if blacklisted
static u8 check_udp_blacklist(struct udphdr *udph)
{
  // UDP Blacklist
  static const uint16_t udp_blacklist[] = { 53, 123 };

  unsigned int i, num;

  num = sizeof(udp_blacklist) / sizeof(uint16_t);

  for (i = 0; i < num; i++)
    {
      if (ntohs(udph->dest) == udp_blacklist[i])
        {
#ifdef DEBUG
          if (DBGLVL >= 2)
            {
              printk(KERN_INFO "%s: OUTGOING UDP skipping dstport %d\n",
                     DBGTAG, udp_blacklist[i]);
            }
#endif
          return 1;
        }
    }

  return 0;
}

// Logs UDP module error
static void logs_udp_error(void)
{
  printk(KERN_INFO "%s: Looks like some modules needed for "
         "UDP tracking are missing\n", DBGTAG);
  printk(KERN_INFO "%s: You may try the following command:\n", DBGTAG);
  printk(KERN_INFO "%s:   # sudo iptables -A OUTPUT -m conntrack -p udp "
         "--ctstate NEW,RELATED,ESTABLISHED -j ACCEPT\n", DBGTAG);
}

module_init(SYNgate_init);
module_exit(SYNgate_exit);
