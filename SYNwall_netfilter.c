/*
 *
 * SYNwall
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
#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/netfilter/nf_conntrack.h>
#include <linux/version.h>
#include <linux/ktime.h>

#include "SYNwall_netfilter.h"
#include "SYNquark.h"
#include "SYNauth.h"

#define DBGTAG "SYNwall"
#define VERSION "v0.2"

#define LOCALHOSTNET   2130706432          // Decimal LE rep of 127.0.0.0
#define LOCALHOSTBCAST 2147483647          // Decimal LE rep of 127.255.255.255

#ifdef DEBUG
static void DEBUG_test_quark(void);
#endif

static struct nf_hook_ops *nfho_in = NULL;
static struct nf_hook_ops *nfho_out = NULL;
static int psklen = 0;
static s64 uptime;                    // Used to delay the load of the module
static u8 initialized = 0;
int PAYLOADLEN = 0;

MODULE_AUTHOR("Sorint.lab");
MODULE_DESCRIPTION("SYNwall");
MODULE_VERSION(VERSION);
MODULE_LICENSE("GPL");

// Module parameters management
MODULE_PARM_DESC(psk, "Pre-Shared Key used for the OneTimePassword");
static char *psk;
module_param(psk, charp, 0200);

MODULE_PARM_DESC(precision, "Time precision parameter");
static u8 precision = 10;
module_param(precision, byte, 0000);

MODULE_PARM_DESC(disable_out, "Disable the OTP for outgoing packets");
static u8 disable_out = 0;
module_param(disable_out, byte, 0000);

MODULE_PARM_DESC(enable_udp, "Enable OTP for UDP protocol");
static u8 enable_udp = 0;
module_param(enable_udp, byte, 0000);

MODULE_PARM_DESC(enable_antidos, "Enable DoS protection");
static u8 enable_antidos = 0;
module_param(enable_antidos, byte, 0000);

MODULE_PARM_DESC(enable_antispoof, "Enable IP Spoofing protection");
static u8 enable_antispoof = 0;
module_param(enable_antispoof, byte, 0000);

MODULE_PARM_DESC(load_delay, "Delay in starting up the module functionalities"
                 " (ms)");
static unsigned int load_delay = 10000;
module_param(load_delay, uint, 0000);

MODULE_PARM_DESC(portk, "List of ports for port knocking failsafe");
static unsigned int portk[5] = { 0, 0, 0, 0, 0 };
static int portk_count = 0;
module_param_array(portk, uint, &portk_count, 0000);

// Variables for the anti-replay protection
u8 *otp_trash;
int trash_overfull = 0;
int MAX_TRASH = 10;
u64 prev_added_time = 0;

// Variables used to manage the anti-DoS protection
static s64 prev_otp_uptime = 0;
static const int allow_otp_ms = 1000;

// Variables used to manage the port knocking failsafe
static const unsigned int portk_interval = 1000;    // Interval (ms) for
                                                    // receiving the knocks
static unsigned int portk_idx = 0;
static s64 portk_begin = 0;
static uint32_t portk_saddr = 0;

// Hook func for incoming packets
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0)
static unsigned int incoming_pkt(void *priv, struct sk_buff *skb,
                                 const struct nf_hook_state *state)
#else
static unsigned int incoming_pkt(unsigned int hooknum, struct sk_buff *skb,
                                 const struct net_device *in,
                                 const struct net_device *out,
                                 int (*okfn)(struct sk_buff *))
#endif
{
  struct iphdr *iph;
  struct tcphdr *tcph;
  struct udphdr *udph;
  s64 current_uptime;
  uint32_t saddr = 0;
  // Conntrack infos for UDP
  enum ip_conntrack_info ctinfo;
  struct nf_conn *ct;

#ifdef DEBUG
  if (DBGLVL >= 5)
    {
      printk(KERN_INFO "%s: INCOMING Hook entered\n", DBGTAG);
    }
#endif

  // Before doing anything, check if the configured startup delay time has
  // been elapsed
  if (initialized == 0)
    {
      current_uptime = ktime_to_ms(ktime_get_boottime());
      if ((current_uptime - uptime) >= (load_delay))
        {
          initialized = 1;
        }
      else
        {
          goto exit_accept;
        }
    }

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
          printk(KERN_INFO "%s: INCOMING Hook. Cannot read IP header\n",
                 DBGTAG);
        }
#endif
      // NULL pointer here, strange: drop
      goto exit_drop;
    }
  saddr = ntohl(iph->saddr);       // Get source address

  // Drops incoming ICMP ECHO - FIXME: to be evaluated...
  if (iph->protocol == IPPROTO_ICMP)
    {
      if (icmp_echo(iph) == 1)
        {
          goto exit_drop;
        }
    }

  // Ignore packets coming from LOCALHOST
  if (saddr >= LOCALHOSTNET && saddr <= LOCALHOSTBCAST)
    {
      goto exit_accept;
    }

  // Checking if is TCP protocol
  if (iph->protocol == IPPROTO_TCP)
    {
#ifdef DEBUG
      if (DBGLVL >= 4)
        {
          printk(KERN_INFO "%s: INCOMING TCP protocol section entered\n",
                 DBGTAG);
        }
#endif

      if (unlikely(!(tcph = tcp_hdr(skb))))
        {
#ifdef DEBUG
          if (DBGLVL >= 1)
            {
              printk(KERN_INFO "%s: INCOMING TCP protocol. Cannot read TCP"
                     " header\n", DBGTAG);
            }
#endif
          // NULL pointer here, strange: drop
          goto exit_drop;
        }

      // We care just about SYN packets
      // We currently skip:
      //                    SYN+ACK
      // FIXME: what about  SYN+RST?
      //                    SYN+FIN+RST?
      //                    SYN+FIN?
      if (tcph->syn && !tcph->ack)
        {
          if (check_linear(skb, &iph, &tcph, NULL) == -1)
            {
              printk(KERN_INFO "%s: INCOMING TCP cannot linearize SKB\n",
                     DBGTAG);
              goto exit_drop;
            }
          // If port knocking is enabled, check it out
          if (portk_count == 5)
            {
              portk_check(ntohs(tcph->dest), ntohl(saddr));
            }

          // Make decision on the incoming packet
          if (process_tcp_in(skb, iph, tcph) == 0)
            {
              goto exit_accept;
            }
          else
            {
              goto exit_drop;
            }
        }
    }
  else if (iph->protocol == IPPROTO_UDP)
    {
      // Check if the UDP option is enabled
      if (enable_udp == 0)
        {
          // No OTP for UDP
          goto exit_accept;
        }
#ifdef DEBUG
      if (DBGLVL >= 4)
        {
          printk(KERN_INFO "%s: INCOMING UDP protocol section entered\n",
                 DBGTAG);
        }
#endif

      // Gets conntrack informations
      ct = nf_ct_get(skb, &ctinfo);
      if (ct == NULL)
        {
          printk(KERN_INFO "%s: INCOMING UDP conntrack info invalid\n",
                 DBGTAG);
          logs_udp_error();

          // We don't have conntrack info...drop
          goto exit_drop;
        }

      // Check if this is the first packet
      if (ctinfo % IP_CT_IS_REPLY == IP_CT_NEW)
        {
#ifdef DEBUG
          if (DBGLVL >= 1)
            {
              printk(KERN_INFO "%s: INCOMING UDP first packet\n",
                     DBGTAG);
            }
#endif
          if (check_linear(skb, &iph, NULL, NULL) == -1)
            {
              printk(KERN_INFO "%s: INCOMING UDP cannot linearize SKB\n",
                     DBGTAG);
              goto exit_drop;
            }

          if (unlikely(!(udph = udp_hdr(skb))))
            {
#ifdef DEBUG
              if (DBGLVL >= 1)
                {
                  printk(KERN_INFO "%s: INCOMING UDP protocol. Cannot read UDP"
                         " header\n", DBGTAG);
                }
#endif
              // NULL pointer here, strange: drop
              goto exit_drop;
            }

          if (process_udp_in(skb, iph, udph) == 0)
            {
              goto exit_accept;
            }
          else
            {
              goto exit_drop;
            }
        }
      else
        {
          // The connection is already established
          goto exit_accept;
        }
    }

exit_accept:
  return NF_ACCEPT;
exit_drop:
  return NF_DROP;
}

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
  uint32_t daddr = 0;
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

          // Process outgoing packets
          if (process_tcp_out(skb, iph, tcph) == 0)
            {
              goto exit_accept;
            }
          else
            {
              goto exit_drop;
            }
        }
    }
  else if (iph->protocol == IPPROTO_UDP)
    {
      // Check if the UDP option is enabled
      if (enable_udp == 0)
        {
          // No OTP for UDP
          goto exit_accept;
        }
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
          if (process_udp_out(skb, iph, udph) == 0)
            {
              goto exit_accept;
            }
          else
            {
              goto exit_drop;
            }
        }
      else
        {
          // The connection is already established
          goto exit_accept;
        }
    }

exit_accept:
  return NF_ACCEPT;
exit_drop:
  return NF_DROP;
}

// Load the module
static int __init SYNwall_init(void)
{
  struct module *mod;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
  int random_res;
#endif

  // Check for vital parameters, don't allow to proceed if not set
  psklen = __psk_strlen(psk);
  if (psklen < 32)
    {
      printk(KERN_INFO "%s: Wrong PSK parameter, quitting...\n", DBGTAG);
      goto exit_error;
    }

  // Check for needed modules (for UDP protocol)
  if (enable_udp == 1)
    {
      mod = find_module("xt_conntrack");
      if (!mod)
        {
          logs_udp_error();
          goto exit_error;
        }
    }
  // Define PAYLOADLEN depending on psk length
  PAYLOADLEN = DIGEST + psklen;

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

  printk(KERN_INFO "%s: Injecting module %s...(load_delay=%d (ms), "
         "precision=%d, disable_out=%d, enable_antidos=%d, "
         "enable_antispoof=%d, enable_udp=%d)\n",
         DBGTAG,
         VERSION,
         load_delay,
         precision,
         disable_out,
         enable_antidos,
         enable_antispoof,
         enable_udp);
  if (portk_count == 5)
    {
      printk(KERN_INFO "%s: Port Knocking enabled\n", DBGTAG);
#ifdef DEBUG
      if (DBGLVL >= 1)
        {
          printk(KERN_INFO "%s: Port Knocking sequence: "
                 "%d,%d,%d,%d,%d\n", DBGTAG,
                 portk[0],
                 portk[1],
                 portk[2],
                 portk[3],
                 portk[4]);
        }
#endif
    }

  // May be to replaced, on older kernel, with:
  //
  //       struct timespec  uptime;
  //       get_monotonic_boottime(&uptime);
  uptime = ktime_to_ms(ktime_get_boottime());

  nfho_in = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops),
                                         GFP_KERNEL);
  nfho_out = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops),
                                          GFP_KERNEL);
  otp_trash = kmalloc(DIGEST * MAX_TRASH, GFP_ATOMIC);

  if (nfho_in != NULL && nfho_out != NULL && otp_trash != NULL)
    {
      trash_flush();

      // Initialize INCOMING netfilter hook
      nfho_in->hook = (nf_hookfn*)incoming_pkt;     // hook function
      nfho_in->hooknum = NF_INET_PRE_ROUTING;
      nfho_in->pf = PF_INET;                        // IPv4
      nfho_in->priority = NF_IP_PRI_CONNTRACK + 1;  // Place the hook just
                                                    // after the conntrack
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
      nf_register_net_hook(&init_net, nfho_in);
#else
      nf_register_hook(nfho_in);
#endif

      if (disable_out == 0)
        {
          // Initialize OUTGOING netfilter hook
          nfho_out->hook = (nf_hookfn*)outgoing_pkt; // hook function
          nfho_out->hooknum = NF_INET_POST_ROUTING;
          nfho_out->pf = PF_INET;                    // IPv4
          nfho_out->priority = NF_IP_PRI_FIRST;      // max hook priority
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
          nf_register_net_hook(&init_net, nfho_out);
#else
          nf_register_hook(nfho_out);
#endif
        }

      goto exit_success;
    }
  else
    {
      goto exit_error;
    }

exit_success:
  return 0;

exit_error:
  kfree(nfho_in);
  kfree(nfho_out);
  kfree(otp_trash);
  printk(KERN_INFO "%s: ERROR initializing Kernel module\n", DBGTAG);
  return -1;
}

// Unload the module
static void __exit SYNwall_exit(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
  nf_unregister_net_hook(&init_net, nfho_in);
#else
  nf_unregister_hook(nfho_in);
#endif

  if (disable_out == 0)
    {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
      nf_unregister_net_hook(&init_net, nfho_out);
#else
      nf_unregister_hook(nfho_out);
#endif
    }
  kfree(nfho_in);
  kfree(nfho_out);
  kfree(otp_trash);
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

// Check if it is an ICMP echo request.
// It returns 1 if echo request, 0 otherwise
static u8 icmp_echo(struct iphdr *iph)
{
  struct icmphdr *icmp_header;

  // skb->transport_header is not ready, we calculate it
  icmp_header = (struct icmphdr *)(iph + 1);

  if (!icmp_header)
    {
      return 0;
    }
  if (icmp_header->type == ICMP_ECHO)
    {
      return 1;
    }

  return 0;
}

// Check the last time we computed an OTP and limit the frequency
// It returns 1 if the time limit is not elapsed (so packet will be discarded)
static u8 antidos_check(void)
{
  s64 curr_otp_uptime;
  u8 res = 0;

  curr_otp_uptime = ktime_to_ms(ktime_get_boottime());

  if ((curr_otp_uptime - prev_otp_uptime) < allow_otp_ms)
    {
      res = 1;
    }
  prev_otp_uptime = curr_otp_uptime;
  return res;
}

// Check if a port knocking has been received, in case disable the module
// for a while by resettin the "initialized" variable
static void portk_check(uint16_t destp, uint32_t saddr)
{
  s64 portk_now;

  // Reset the counter if "portk_interval" is elapsed
  if (portk_idx != 0)
    {
      portk_now = ktime_to_ms(ktime_get_boottime());
      if ((portk_now - portk_begin) > portk_interval)
        {
          portk_idx = 0;
          portk_begin = 0;
          portk_saddr = 0;
#ifdef DEBUG
          if (DBGLVL >= 2)
            {
              printk(KERN_INFO "%s: Port KNOCKING 1 second expired\n", DBGTAG);
            }
#endif
        }
    }

  // Enter only if is the port is matched
  if (destp == portk[portk_idx])
    {
      portk_now = ktime_to_ms(ktime_get_boottime());
      if (portk_idx == 0)
        {
          // If it's the first port of the configured sequence,
          // initialize everyhthing
          portk_saddr = saddr;
          portk_begin = portk_now;
          portk_idx++;
#ifdef DEBUG
          if (DBGLVL >= 2)
            {
              printk(KERN_INFO "%s: Port KNOCKING beginning\n", DBGTAG);
            }
#endif
        }
      else
        {
          // Accept knocking only from the IP which started the sequence
          if (saddr == portk_saddr)
            {
              portk_idx++;
#ifdef DEBUG
              if (DBGLVL >= 2)
                {
                  printk(KERN_INFO "%s: Port KNOCKING continuing\n", DBGTAG);
                }
#endif
            }
          // Correct sequence entered, disabling the module for a while
          if (portk_idx == 5)
            {
              initialized = 0;
              portk_idx = 0;
              portk_begin = 0;
              portk_saddr = 0;
              uptime = ktime_to_ms(ktime_get_boottime());
              printk(KERN_INFO "%s: Port KNOCKING detected, disabling "
                     "module for %d ms\n", DBGTAG, load_delay);
            }
        }
    }
}

// Process incoming TCP packets.
// It return 0 if OTP matches, otherwise return 1
static u8 process_tcp_in(struct sk_buff *skb, struct iphdr *iph,
                         struct tcphdr *tcph)
{
  int IP_HDR_LEN;
  int TCP_HDR_LEN;
  u8 *PAYLOAD = NULL;
  uint32_t daddr = 0;
  unsigned char *data;
  int syn_len = 0;

  // FIXME: doff needs validation? Other info?
  // From tests looks like everything is already ok

  // Length of the payload
  IP_HDR_LEN = (int)(iph->ihl) * 4;
  TCP_HDR_LEN = (int)(tcph->doff) * 4;

  syn_len = ntohs(iph->tot_len) - IP_HDR_LEN - TCP_HDR_LEN;

#ifdef DEBUG
  if (DBGLVL >= 3)
    {
      printk(KERN_INFO "%s: TCP INCOMING syn pkt additional info: "
             "FIN: %d SYN: %d RST: %d PSH: %d ACK: %d "
             "URG: %d ECE: %d CWR: %d - Length: %d\n",
             DBGTAG,
             tcph->fin,
             tcph->syn,
             tcph->rst,
             tcph->psh,
             tcph->ack,
             tcph->urg,
             tcph->ece,
             tcph->cwr,
             syn_len
             );
    }
#endif
  if (syn_len != PAYLOADLEN)
    {
#ifdef DEBUG
      if (DBGLVL >= 1)
        {
          printk(KERN_INFO "%s: TCP INCOMING syn pkt with unexpected "
                 "length received (IP:%d, Port: %d), dropping\n",
                 DBGTAG, ntohl(iph->saddr), ntohs(tcph->dest));
        }
#endif
      goto exit_drop_tcpin;
    }
  else
    {
#ifdef DEBUG
      if (DBGLVL >= 1)
        {
          printk(KERN_INFO "%s: TCP INCOMING syn_pkt len: %d\n", DBGTAG,
                 syn_len);
        }

      if (DBGLVL >= 2)
        {
          DEBUG_test_quark();
        }
#endif

      // Anti-DoS protection (if enabled)
      if (enable_antidos != 0)
        {
          if (antidos_check() == 1)
            {
#ifdef DEBUG
              if (DBGLVL >= 1)
                {
                  printk(KERN_INFO "%s: TCP INCOMING DoS protection,"
                         " dropping\n", DBGTAG);
                }
#endif
              goto exit_drop_tcpin;
            }
        }
      // OK, some payload is there, we need to validate it
      data = (unsigned char *)skb_header_pointer(skb, IP_HDR_LEN +
                                                 TCP_HDR_LEN, 0, NULL);

      // Get OTP
      PAYLOAD = kmalloc(PAYLOADLEN, GFP_ATOMIC);
      if (unlikely(!PAYLOAD))
        {
          // Error in allocating memory
          printk(KERN_INFO "%s: TCP INCOMING failed to allocate payload "
                 "memory\n", DBGTAG);
          goto exit_drop_tcpin;
        }

      ////////////////////////////////////////
      // Making final decision on the packet
      ////////////////////////////////////////

      if (enable_antispoof != 0)
        {
          // If antispoof is enabled, destination IP is part of the OTP
          daddr = ntohl(iph->daddr);
        }
      if (validate_otp(data, psk, psklen, precision, daddr) == 0)
        {
#ifdef DEBUG
          if (DBGLVL >= 1)
            {
              printk(KERN_INFO "%s: TCP INCOMING valid OTP, accepting\n",
                     DBGTAG);
            }
#endif
          goto exit_accept_tcpin;
        }
      else
        {
#ifdef DEBUG
          if (DBGLVL >= 1)
            {
              printk(KERN_INFO "%s: TCP INCOMING invalid OTP, dropping\n",
                     DBGTAG);
            }
#endif
          goto exit_drop_tcpin;
        }
    }

exit_accept_tcpin:
  kfree(PAYLOAD);
  return 0;
exit_drop_tcpin:
  kfree(PAYLOAD);
  return 1;
}

// Process outgoing TCP packets.
// It return 0 if packet must be accepted, otherwise return 1
// Using gcc < 4.2.4 can raise and error at the following
// #pragma" lines, if this is the case just comment it out
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-label"
static u8 process_tcp_out(struct sk_buff *skb, struct iphdr *iph,
                          struct tcphdr *tcph)
{
  u8 *PAYLOAD = NULL;
  uint32_t daddr = 0;

  daddr = ntohl(iph->daddr);       // Get destination address

  if (enable_antispoof == 0)
    {
      // If antispoof is enabled, destination IP is part of the OTP,
      // so we leave it, but in case is disabled we need to 0 it out
      daddr = 0;
    }

  // Get OTP
  PAYLOAD = kmalloc(PAYLOADLEN, GFP_ATOMIC);
  if (unlikely(!PAYLOAD))
    {
      // Error in allocating memory
      printk(KERN_INFO "%s: OUTGOING TCP failed to allocate payload "
             "memory\n", DBGTAG);
      goto exit_accept_tcpout;
    }

  if (get_otp(PAYLOAD, psk, psklen, precision, daddr)
      != 0)
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
                          struct udphdr *udph)
{
  u8 *PAYLOAD = NULL;
  uint32_t daddr = 0;

  daddr = ntohl(iph->daddr);       // Get destination address

  if (enable_antispoof == 0)
    {
      // If antispoof is enabled, destination IP is part of the OTP,
      // so we leave it, but in case is disabled we need to 0 it out
      daddr = 0;
    }

  // Get OTP
  PAYLOAD = kmalloc(PAYLOADLEN, GFP_ATOMIC);
  if (unlikely(!PAYLOAD))
    {
      // Error in allocating memory
      printk(KERN_INFO "%s: OUTGOING UDP failed to allocate payload "
             "memory\n", DBGTAG);
      goto exit_accept_udpout;
    }

  if (get_otp(PAYLOAD, psk, psklen, precision, daddr) != 0)
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

// Process incoming UDP packets.
// It return 0 if packet must be accepted, otherwise return 1
static u8 process_udp_in(struct sk_buff *skb, struct iphdr *iph,
                         struct udphdr *udph)
{
  int IP_HDR_LEN;
  int L4_HDR_LEN = 8;                     // UDP header length
  u8 *PAYLOAD = NULL;
  uint32_t daddr = 0;
  unsigned char *data;
  int existing_payload_len = 0;

  // Length of the payload
  IP_HDR_LEN = (int)(iph->ihl) * 4;

  existing_payload_len = ntohs(iph->tot_len) - IP_HDR_LEN - L4_HDR_LEN;

#ifdef DEBUG
  if (DBGLVL >= 3)
    {
      printk(KERN_INFO "%s: UDP INCOMING pkt additional info: "
             "Length: %d\n", DBGTAG, existing_payload_len);
    }
#endif
  if (existing_payload_len <= PAYLOADLEN)
    {
#ifdef DEBUG
      if (DBGLVL >= 1)
        {
          printk(KERN_INFO "%s: UDP INCOMING pkt with unexpected "
                 "length received (IP:%d, Port: %d), dropping\n",
                 DBGTAG, ntohl(iph->saddr), ntohs(udph->dest));
        }
#endif
      // No OTP is present
      goto exit_drop_udpin;
    }
  else
    {
#ifdef DEBUG
      if (DBGLVL >= 1)
        {
          printk(KERN_INFO "%s: UDP INCOMING syn_pkt len: %d\n", DBGTAG,
                 existing_payload_len);
        }
#endif

      // Anti-DoS protection (if enabled)
      if (enable_antidos != 0)
        {
          if (antidos_check() == 1)
            {
#ifdef DEBUG
              if (DBGLVL >= 1)
                {
                  printk(KERN_INFO "%s: UDP INCOMING DoS protection,"
                         " dropping\n", DBGTAG);
                }
#endif
              goto exit_drop_udpin;
            }
        }
      // OK, some payload is there, we need to validate it
      data = (unsigned char *)skb_header_pointer(skb, ntohs(iph->tot_len) -
                                                 PAYLOADLEN, 0, NULL);

      // Get OTP
      PAYLOAD = kmalloc(PAYLOADLEN, GFP_ATOMIC);
      if (unlikely(!PAYLOAD))
        {
          // Error in allocating memory
          printk(KERN_INFO "%s: UDP INCOMING failed to allocate payload "
                 "memory\n", DBGTAG);
          goto exit_drop_udpin;
        }

      ////////////////////////////////////////
      // Making final decision on the packet
      ////////////////////////////////////////

      if (enable_antispoof != 0)
        {
          // If antispoof is enabled, destination IP is part of the OTP
          daddr = ntohl(iph->daddr);
        }
      if (validate_otp(data, psk, psklen, precision, daddr) == 0)
        {
#ifdef DEBUG
          if (DBGLVL >= 1)
            {
              printk(KERN_INFO "%s: UDP INCOMING valid OTP, accepting\n",
                     DBGTAG);
            }
#endif
          // FIXME: Right now I'm passing the packet even we se an error
          // here. To be evaluated
          strip_otp(skb, iph, NULL, udph);

          goto exit_accept_udpin;
        }
      else
        {
#ifdef DEBUG
          if (DBGLVL >= 1)
            {
              printk(KERN_INFO "%s: UDP INCOMING invalid OTP, dropping\n",
                     DBGTAG);
            }
#endif
          goto exit_drop_udpin;
        }
    }

exit_accept_udpin:
  kfree(PAYLOAD);
  return 0;
exit_drop_udpin:
  kfree(PAYLOAD);
  return 1;
}

// Logs UDP module error
static void logs_udp_error(void)
{
  printk(KERN_INFO "%s: Looks like some modules needed for"
         "UDP tracking are missing\n", DBGTAG);
  printk(KERN_INFO "%s: You may try the following command:\n", DBGTAG);
  printk(KERN_INFO "%s:   # iptables -A OUTPUT -m conntrack -p udp "
         "--ctstate NEW,RELATED,ESTABLISHED -j ACCEPT\n", DBGTAG);
}

#ifdef DEBUG
// Debug func to test the HASH computation
static void DEBUG_test_quark(void)
{
  u8 out[DIGEST];

  // hash the empty string
  quark(out, NULL, 0);

  printk(KERN_INFO "%s: Quark hash computed\n", DBGTAG);
}
#endif

module_init(SYNwall_init);
module_exit(SYNwall_exit);
