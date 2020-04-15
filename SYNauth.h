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

#define MAXPRECISION  12

/**
 *  validate_otp - validate the OTP
 *  @otp: pointer to the buffer with the OTP to check
 *  @key: pointer to the buffer with the PSK
 *  @keylen: lenght of the PSK
 *  @precision: precision for the time to compute the OTP
 *  @daddr: destination address. != 0 only if antispoof enabled
 *
 *  This basically compute a new OTP with the given data, in order to
 *  compare it with the incoming one (@otp).
 *  Returns 0 if the OTP is valid
 */
int validate_otp(u8 *otp, u8 *key, int keylen, unsigned char precision,
                 uint32_t daddr);

/**
 *  get_otp - Compute the OTP
 *  @otp: pointer to the buffer with the OTP to check
 *  @key: pointer to the buffer with the PSK
 *  @keylen: lenght of the PSK
 *  @precision: precision for the time to compute the OTP
 *  @daddr: destination address. != 0 only if antispoof enabled
 *
 *  It gets the otp buffer, the key and keylength.
 *  The "otp" buffer will contain the computed OTP + a XOR between PSK and a
 *  random buffer. At the end the OTP will be DIGEST + PSK length (at
 *  least 32).
 *  Returns 0 if OK or 1 in case of errors.
 */
int get_otp(u8 *otp, u8 *key, int keylen, unsigned char precision,
            uint32_t daddr);

/**
 *  set_otp - Add the payload to the packet
 *  @PAYLOAD: buffer with the OTP to append
 *  @skb: sk buffer pointer
 *  @iph: IP header pointer
 *  @tcph: TCP header pointer
 *  @udph: UDP header pointer
 *
 *  Depending on the ISO/OSI level 4 structure passed, it works on UDP or TCP.
 *  The other one must me set as NULL. As an example:
 *    UDP:  set_otp(PAYLOAD,skb,iph,NULL,udph)
 *    TCP:  set_otp(PAYLOAD,skb,iph,tcph,NULL)
 *
 *  The function makes several checks to ensure that the sk is accessible and
 *  writeable, it recompute checksum, etc.
 *  Returns 0 if success, otherwise 1
 */
int set_otp(u8 *PAYLOAD, struct sk_buff *skb,
            struct iphdr *iph, struct tcphdr *tcph, struct udphdr *udph);

/**
 *  strip_otp - Remove payload from the packet
 *  @skb: sk buffer pointer
 *  @iph: IP header pointer
 *  @tcph: TCP header pointer
 *  @udph: UDP header pointer
 *
 *  Depending on the ISO/OSI level 4 structure passed, it works on UDP or TCP.
 *  The other one must me set as NULL. As an example:
 *      UDP:  strip_otp(skb,iph,NULL,udph)
 *      TCP:  strip_otp(skb,iph,tcph,NULL)
 *
 *  WARNING: right now only UDP is implemented
 *
 *  Returns 0 if success, otherwise 1
 */
int strip_otp(struct sk_buff *skb, struct iphdr *iph,
              struct tcphdr *tcph, struct udphdr *udph);

/**
 *  l4_send_check - Compute the new checksum for L4 protocol
 *  @skb: sk buffer pointer
 *  @iph: IP header pointer
 *
 *  Depending on the protocol set in the sk buffer, it compute the new
 *  checksum before sending out the packet. This is used after appending the
 *  OTP to the packet.
 *  It stores the new checsum directly in the structure.
 */
void l4_send_check(struct sk_buff *skb, struct iphdr *iph);

/**
 *  trash_flush - Remove all entries from OTP trash
 *
 *  The OTP trash is one of the anti-replay protection. The trash stores
 *  all the used OTP, for a specific time precision. When the time elapses,
 *  the trash can be emptied.
 */
void trash_flush(void);
