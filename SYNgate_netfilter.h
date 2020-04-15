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

 /**
  *  __psk_strlen - retruns the length of a null terminated string
  *  @str: pointer to the string
  *
  *  This is just a replacement of the strlen lib function. Not sure if
  *  it make sense to use it instead of the standard one.
  *  Returns the length.
  */
static size_t __psk_strlen(const char *str);

/**
 *  check_linear - check the sk buffer for "linearity"
 *  @skb: sk buffer pointer
 *  @iph: IP header pointer to be refreshed if linearization occured
 *        NULL if not used
 *  @tcph: TCP header pointer to be refreshed if linearization occured
 *         NULL if not used
 *  @udph: UDP header pointer to be refreshed if linearization occured
 *         NULL if not used
 *
 *  It checks if the sk buffer is linear. If not, it tries to linearize it.
 *  Returns:
 *          0   no action done (buffer already linear)
 *          1   buffer linearized
 *         -1   linearization failed
 */
static u8 check_linear(struct sk_buff *skb, struct iphdr **iph,
                       struct tcphdr **tcph, struct udphdr **udph);

/**
 *  check_udp_blacklist - check if UDP service is blacklisted
 *  @udph: UDP header pointer
 *
 *  Since some UDP protocols are widely used for a lot of "underlying"
 *  services (NTP, DNS, etc), we need to avoid to add the OTP that may
 *  breaks the communication. This function is used to check if the current
 *  protocol is one of those.
 *  Returns 0 if not blacklisted, 1 otherwise.
 */
static u8 check_udp_blacklist(struct udphdr *udph);

/**
 *  validate_params - validates the module parameters
 *
 *  Validates the module parameters, based on different criterias
 *  (consistency and boundary). It calls a set of subfuncs named
 *  validate_* for each parameter.
 *  Returns 0 if success, 1 otherwise.
 */
static u8 validate_params(void);

/**
 *  validate_dstnet - validates dstnet parameter
 *
 *  It checks the loaded networks to be sure they are valid network
 *  addresses and masks.
 *  Returns 0 if success, 1 otherwise.
 */
static u8 validate_dstnet(void);

/**
 *  validate_psk - validates psk parameter
 *
 *  Validates the length of the psk that must be > 32 and < 1024
 *  Returns 0 if success, 1 otherwise.
 */
static u8 validate_psk(void);

/**
 *  validate_precision - validates precision parameter
 *
 *  Makes sure that the precion is between the valid values 0 and MAXPRECISION
 *  Returns 0 if success, 1 otherwise.
 */
static u8 validate_precision(void);

/**
 *  validate_antispoof - validates antispoof parameter
 *
 *  Validates the antispoof parameter (must be 0 or 1)
 *  Returns 0 if success, 1 otherwise.
 */
static u8 validate_antispoof(void);

/**
 *  validate_udp - validates UDP enabled parameter
 *
 *  Validates the UDP parameter (must be 0 for disabled or 1 for enabled)
 *  Returns 0 if success, 1 otherwise.
 */
static u8 validate_udp(void);

/**
 *  cidr_match - check if an IP is in a given NETWORK
 *  @addr: IP address to check
 *  @net: Network against which to check
 *  @bits: network mask (in bits) for the network specified before
 *
 *  It checks if the @addr is in the @net/@bits network.
 *  Returns 1 if the IP belongs to NETWORK, 0 otherwise.
 */
static u8 cidr_match(__be32 addr, __be32 net, uint8_t bits);

/**
 *  process_tcp_out - process outgoing TCP packets
 *  @skb: sk buffer pointer
 *  @iph: IP header pointer
 *  @tcph: TCP header pointer
 *  @i: index to access the parameters table
 *
 *  It process the outgoing TCP packet. The @i parameter is used to
 *  access the tables loaded when the module was injected.
 *  The function calls the OTP generation function and the OTP "append"
 *  function.
 *  It could fails for some reasons, like memory allocation issues or errors
 *  in generating the OTP.
 *  Returns 0 if packet must be accepted, otherwise return 1
 */
static u8 process_tcp_out(struct sk_buff *skb, struct iphdr *iph,
                          struct tcphdr *tcph, int i);

/**
 *  process_udp_out - process outgoing UDP packets
 *  @skb: sk buffer pointer
 *  @iph: IP header pointer
 *  @udph: UDP header pointer
 *  @i: index to access the parameters table
 *
 *  It process the outgoing UDP packet. The @i parameter is used to
 *  access the tables loaded when the module was injected.
 *  The function calls the OTP generation function and the OTP "append"
 *  function.
 *  It could fails for some reasons, like memory allocation issues or errors
 *  in generating the OTP.
 *  Returns 0 if packet must be accepted, otherwise return 1
 */
static u8 process_udp_out(struct sk_buff *skb, struct iphdr *iph,
                          struct udphdr *udph, int i);
