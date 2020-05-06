/*
 *
 * SYNwall - Auth library
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

#include <linux/ktime.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/random.h>
#include <linux/netfilter.h>
#include <net/udp.h>
#include <net/tcp.h>

#if LINUX_VERSION_CODE <= KERNEL_VERSION(4, 0, 0)
#include <linux/skbuff.h>
#endif

#include "SYNquark.h"
#include "SYNauth.h"

#define DBGTAG "SYNauth: "

extern int PAYLOADLEN;

// Get the current time of the system, rounding it at given
// precision.
// The precision is expressed in power of two:
//        ...
//         9  ->   1 second
//        10  ->   8 seconds
//        ...
// It returns the rounded value
static u64 get_current_time(unsigned char precision)
{
  u64 pow_table[MAXPRECISION] = { 0, 7, 127, 1023, 8191, 131071, 1048575,
                                  8388607, 134217727, 1073741823, 8589934591,
                                  137438953471 };

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)
  u64 current_time = ktime_get_real_ns();
#else
  u64 current_time = ktime_to_ns(ktime_get_real());
#endif

#ifdef DEBUG
  if (DBGLVL >= 2)
    {
      printk(KERN_INFO "%s: OTP time before rounding: %lld\n", DBGTAG,
             current_time);
    }
#endif

  // This has been done to avoid MODULO operations, which could be heavy and
  // cumbersome for low end devices...I know looks ugly...
  // The pow_table contains the "nearest" (power of two - 1) values to the
  // decimal rounding
  if (precision > MAXPRECISION - 1)
    {
      precision = MAXPRECISION - 1;
    }
  current_time = (current_time - (current_time & pow_table[precision]));

#ifdef DEBUG
  if (DBGLVL >= 2)
    {
      printk(KERN_INFO "%s: OTP time after rounding: %lld\n", DBGTAG,
             current_time);
    }
#endif

  return current_time;
}

// Just a replacement of memcmp
static int __internal_memcmp(u8 *buff1, u8 *buff2, int length)
{
  int i;
  int valid = 0;

  for (i = 0; i < length; i++)
    {
      if (*buff1 != *buff2)
        {
          valid = 1;
          break;
        }
      buff1++;
      buff2++;
    }
  return valid;
}

// BEGIN: OTP Trash management functions
extern u8 *otp_trash;
extern int trash_overfull;
extern int MAX_TRASH;
extern u64 prev_added_time;

// Check if a value is in the trash
// It returns 0 if not found, otherwise 1
static int trash_dive(u8 *hash)
{
  int i;
  int ret = 0;

  for (i = 0; i < trash_overfull; i++)
    {
      if (__internal_memcmp(otp_trash + (DIGEST * i), hash, DIGEST) == 0)
        {
#ifdef DEBUG
          if (DBGLVL >= 2)
            {
              printk("%s: TRASH DIVE found\n", DBGTAG);
            }
#endif
          ret = 1;
          break;
        }
    }
  return ret;
}

// Add a HASH in the trash (used)
// It returns 0 if added or 1 if full
static int trash_add(u8 *hash)
{
  int ret = 0;

  if (trash_overfull < MAX_TRASH)
    {
      memcpy(otp_trash + (DIGEST * trash_overfull), hash, DIGEST);
      trash_overfull++;
      ret = 0;
#ifdef DEBUG
      if (DBGLVL >= 2)
        {
          printk("%s: TRASH ADD\n", DBGTAG);
        }
#endif
    }
  else
    {
      ret = 1;
#ifdef DEBUG
      if (DBGLVL >= 2)
        {
          printk("%s: TRASH overfull\n", DBGTAG);
        }
#endif
    }
  return ret;
}

// Remove all entries from OTP trash
void trash_flush(void)
{
  memset(otp_trash, 0, DIGEST * MAX_TRASH);
  trash_overfull = 0;
}

// END: OTP Trash management functions

// XOR the content of the buffers for given length
static void XOR(u8* buff1, u8* buff2, u8* outbuff, int len)
{
  while (len--)
    {
      *outbuff++ = *buff1++ ^ *buff2++;
    }
}

// Compute the QUARK HASH.
// The result is returned in "otp" parameter.
// It retruns 0 if everything is fine, otherwise 1
static int HASH(u8 *key, u64 time, u8 *random, uint32_t daddr, u8 *otp,
                int keylen)
{
  u8 *otp_buffer;
  u64 otp_buffer_len;
  int ret = 0;

  // Allocate necessary buffers. The otp_buffer is making space for:
  //     PSK + TIME + RANDOMBUFFER + DESTIP
  // Destination IP could be disabled (== 0)
  otp_buffer_len = keylen + sizeof(u64) + keylen + sizeof(uint32_t);
  otp_buffer = kmalloc(otp_buffer_len, GFP_ATOMIC);

  if (likely(otp_buffer))
    {
      // Put together the values for the HASH
      memcpy(otp_buffer, key, keylen);                        // Key
      memcpy(otp_buffer + keylen, (char*)&time, sizeof(u64)); // Keylen
      memcpy(otp_buffer + keylen + sizeof(u64), random,
             keylen);                                        // Rnd buff
      memcpy(otp_buffer + keylen + sizeof(u64) + keylen,
             (char*)&daddr, sizeof(uint32_t));               // Dst IP

      quark(otp, otp_buffer, otp_buffer_len);
    }
  else
    {
      printk("%s: HASH function failed to allocate memory\n", DBGTAG);
      ret = 1;
    }

  kfree(otp_buffer);
  return ret;
}

// This is in charge to check if the OTP is already been used.
// It uses a pool (trash) where OTP are stored and kept until
// expiration.
// It returns 0 if we can accept the OTP
static int validate_otp_replay(u8 *hash, u64 time)
{
  int ret = 1;

  // Check if we need to expire the trash
  if (prev_added_time != time)
    {
      trash_flush();
    }

  if (trash_dive(hash) == 0)
    {
      if (trash_add(hash) == 0)
        {
          // OTP not used already
          ret = 0;
          prev_added_time = time;
        }
    }


  return ret;
}

// It performs several checks, first by computing a valid OTP as compare
// value, then by checking if OTP is already been used.
// It returns 0 if the OTP is valid
int validate_otp(u8 *otp, u8 *key, int keylen, unsigned char precision,
                 uint32_t daddr)
{
  u64 time;
  u8 *rnd_buffer;
  u8 *hash_buffer;
  int ret = 0;

  // Get the time
  time = get_current_time(precision);

  rnd_buffer = kmalloc(keylen, GFP_ATOMIC);
  hash_buffer = kmalloc(DIGEST, GFP_ATOMIC);
  if (likely(rnd_buffer && hash_buffer))
    {
      XOR(key, otp + DIGEST, rnd_buffer, keylen);
      if (HASH(key, time, rnd_buffer, daddr, hash_buffer, keylen) == 0)
        {
          if (__internal_memcmp(hash_buffer, otp, DIGEST) == 0)
            {
              ret = validate_otp_replay(hash_buffer, time);
            }
          else
            {
              // HASHes are different
              ret = 1;
            }
        }
      else
        {
          // Error in HASH computation
          ret = 1;
        }
    }
  else
    {
      // Error in allocating memory
      ret = 1;
    }
  kfree(rnd_buffer);
  kfree(hash_buffer);

  return ret;
}

// Compute the OTP.
// It gets the otp buffer, the key and keylength.
// It return 0 if OK or 1 in case of errors. The "otp" buffer will contain
// the computed OTP + a XOR between PSK and a random buffer.
// At the end the OTP will be DIGEST + PSK length (at least 32)
int get_otp(u8 *otp, u8 *key, int keylen, unsigned char precision,
            uint32_t daddr)
{
  u64 time;
  u8 *rnd_buffer;
  u8 *xor_buffer;
  int ret = 0;

  // Get the time
  time = get_current_time(precision);
#ifdef DEBUG
  if (DBGLVL >= 2)
    {
      printk("%s: OTP function entered\n", DBGTAG);
    }
#endif

  // Allocates necessary buffers.
  rnd_buffer = kmalloc(keylen, GFP_ATOMIC);
  xor_buffer = kmalloc(keylen, GFP_ATOMIC);

  if (likely(rnd_buffer && xor_buffer))
    {
      get_random_bytes(rnd_buffer, keylen);
      if (HASH(key, time, rnd_buffer, daddr, otp, keylen) == 0)
        {
          XOR(key, rnd_buffer, xor_buffer, keylen);

          // Append the XOR
          memcpy(otp + DIGEST, xor_buffer, keylen);
        }
      else
        {
          // Error occured
          ret = 1;
        }
    }
  else
    {
      printk("%s: OTP function failed to allocate memory\n", DBGTAG);
      ret = 1;
    }

  kfree(rnd_buffer);
  kfree(xor_buffer);
  return ret;
}

// Remove the payload from the packet
// Depending on the ISO/OSI level 4 structure passed, it works on UDP or TCP.
// The other one must me set as NULL. As an example:
//     UDP:  strip_otp(skb,iph,NULL,udph)
//     TCP:  strip_otp(skb,iph,tcph,NULL)
//
// WARNING: right now only UDP is implemented
//
// It returns 0 if success, otherwise 1
int strip_otp(struct sk_buff *skb, struct iphdr *iph,
              struct tcphdr *tcph, struct udphdr *udph)
{
  // Check if SKB is writeable
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 3, 0)
  if (skb_ensure_writable(skb, skb->len))
#else
  if (!skb_make_writable(skb, skb->len))
#endif
    {
      // Stop processing
      printk(KERN_INFO "%s: OUTGOING skb not writable\n", DBGTAG);
      goto exit_error;
    }

  // Parameters sanity checks. The check on UDP only is done because
  // only UDP is implemented right now. It will be removed when TCP will
  // be implemented as well
  if ((tcph == NULL && udph == NULL) || (tcph != NULL && udph != NULL) ||
      (udph == NULL))
    {
      goto exit_error;
    }

  // Remove data from the buffer
  skb_trim(skb, skb->len - PAYLOADLEN);
  // Re-read structure content after the changes
  iph = ip_hdr(skb);
  if (tcph != NULL)
    {
      tcph = tcp_hdr(skb);                    // TCP
    }
  else
    {
      udph = udp_hdr(skb);                   // UDP
    }

  // Avoid checksum offloading
  skb->ip_summed = CHECKSUM_NONE;
  // Rebuild headers infos
  udph->len = htons(ntohs(udph->len) - PAYLOADLEN);
  iph->tot_len = htons(ntohs(iph->tot_len) - PAYLOADLEN);
  // IP header checksum
  iph->check = 0;
  ip_send_check(iph);

  // Level 4 checksum
  l4_send_check(skb, iph);

  return 0;
exit_error:
  return 1;
}

// Add the payload to the packet
// Depending on the ISO/OSI level 4 structure passed, it works on UDP or TCP.
// The other one must me set as NULL. As an example:
//     UDP:  set_otp(skb,iph,NULL,udph)
//     TCP:  set_otp(skb,iph,tcph,NULL)
//
// It returns 0 if success, otherwise 1
int set_otp(u8 *PAYLOAD, struct sk_buff *skb,
            struct iphdr *iph, struct tcphdr *tcph, struct udphdr *udph)
{
  int IP_HDR_LEN;
  int L4_HDR_LEN;
  int TOT_HDR_LEN;
  unsigned char *data;
  int existing_payload_len = 0;

  // Check if SKB is writeable
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 3, 0)
  if (skb_ensure_writable(skb, skb->len))
#else
  if (!skb_make_writable(skb, skb->len))
#endif
    {
      // Stop processing
      printk(KERN_INFO "%s: OUTGOING skb not writable\n", DBGTAG);
      goto exit_error;
    }

  // Parameters sanity checks
  if ((tcph == NULL && udph == NULL) || (tcph != NULL && udph != NULL))
    {
      goto exit_error;
    }

  // Check if there is enough space in the structure (data)
  if (skb_tailroom(skb) < PAYLOADLEN)
    {
      printk(KERN_INFO "%s: OUTGOING not enough space on "
             "skb\n", DBGTAG);

      // This call can expand the HEAD (2nd parameter) or the tail
      // (3rd parameter). In this case we are going to expand tail.
      if (pskb_expand_head(skb, 0, PAYLOADLEN - skb_tailroom(skb),
                           GFP_ATOMIC) != 0)
        {
          printk(KERN_INFO "%s: OUTGOING skb expand failed\n", DBGTAG);
          goto exit_error;
        }

      // Re-read structure content after the changes
      iph = ip_hdr(skb);
      if (tcph != NULL)
        {
          tcph = tcp_hdr(skb);                   // TCP
        }
      else
        {
          udph = udp_hdr(skb);                  // UDP
        }
    }
  // Length of the payload
  IP_HDR_LEN = (int)(iph->ihl) * 4;
  if (tcph != NULL)
    {
      // TCP Header len
      L4_HDR_LEN = (int)(tcph->doff) * 4;
    }
  else
    {
      // UDP Header len (fixed by RFC)
      L4_HDR_LEN = 8;
    }
  TOT_HDR_LEN = IP_HDR_LEN + L4_HDR_LEN;

  // Avoid checksum offloading
  skb->ip_summed = CHECKSUM_NONE;

  existing_payload_len = ntohs(iph->tot_len) - IP_HDR_LEN - L4_HDR_LEN;

  // Pointer to the payload
  data = (unsigned char *)skb_header_pointer(skb, IP_HDR_LEN +
                                             L4_HDR_LEN, 0, NULL);

  // Make space for the new payload
  if (skb_put(skb, PAYLOADLEN) == NULL)
    {
      printk(KERN_INFO "%s: OUTGOING skb append failed\n", DBGTAG);
      goto exit_error;
    }
  if (tcph != NULL)
    {
      // TCP packet, we override an existing payload, if any
      // TODO: May be this can be changed...
      memcpy(data, PAYLOAD, PAYLOADLEN);
      // Rebuild headers infos
      iph->tot_len = htons(PAYLOADLEN + TOT_HDR_LEN);
    }
  else
    {
      // UDP packet, we append to an existing payload
      memcpy(data + existing_payload_len, PAYLOAD, PAYLOADLEN);
      udph->len = htons(ntohs(udph->len) + PAYLOADLEN);
      // Rebuild headers infos
      iph->tot_len = htons(PAYLOADLEN + TOT_HDR_LEN + existing_payload_len);
    }

  // IP header checksum
  iph->check = 0;
  ip_send_check(iph);

  // Level 4 checksum
  l4_send_check(skb, iph);

#ifdef DEBUG
  if (DBGLVL >= 1)
    {
      printk(KERN_INFO "%s: OUTGOING syn packet PAYLOAD added\n",
             DBGTAG);
    }
#endif
  return 0;

exit_error:

  return 1;
}

// Compute the new checksum for L4 protocol.
// It stores the new checsum directly in the structure.
void l4_send_check(struct sk_buff *skb, struct iphdr *iph)
{
  struct tcphdr *tcpHdr;
  struct udphdr *udpHdr;
  unsigned int l4len;

  l4len = ntohs(iph->tot_len) - iph->ihl * 4;
  skb->csum = 0;

  if (iph->protocol == IPPROTO_TCP)
    {
      tcpHdr = tcp_hdr(skb);
      tcpHdr->check = 0;
      tcpHdr->check = tcp_v4_check(l4len, iph->saddr, iph->daddr,
                                   csum_partial((char *)tcpHdr, l4len, 0));
    }
  else if (iph->protocol == IPPROTO_UDP)
    {
      udpHdr = udp_hdr(skb);
      udpHdr->check = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 16, 0)
      udpHdr->check = udp_v4_check(l4len, iph->saddr, iph->daddr,
                                   csum_partial((char *)udpHdr, l4len, 0));
#else
      udpHdr->check = csum_tcpudp_magic(iph->saddr, iph->daddr, l4len,
                                        IPPROTO_UDP,
                                        csum_partial((char *)udpHdr, l4len, 0));
#endif
    }
}
