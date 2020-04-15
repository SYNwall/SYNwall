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
 *  portk_check - check for port knocking
 *  @dest: destination port (port knocked)
 *  @saddr: source address (who is knocking)
 *
 * Check if a port knocking has been received, in case disable the module
 * for a while by resetting the "initialized" variable.
 * The knocking sequence must be sent "portk_interval" (default 1000 mills).
 */
static void portk_check(uint16_t destp, uint32_t saddr);

/**
 *  icmp_echo - check if it's an ICMP ECHO request
 *  @iph: IP header pointer
 *
 * Check if it's an ICMP ECHO reuest.
 * Returns 1 if echo request, 0 otherwise.
 */
static u8 icmp_echo(struct iphdr *iph);

/**
 *  antidos_check - DoS check
 *
 * If enabled, this function checks the last time an OTP has been computed,
 * so we can limit the number of OTPs per time interval.
 * The limit is defined by "allow_otp_ms" (default 1000 ms). So, if enabled
 * it will limit the OTP computation to 1 per second.
 * Returns 1 if the time limit is not elapsed (so packet will be discarded)
 */
static u8 antidos_check(void);

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
 *  process_tcp_in - process incoming TCP packets
 *  @skb: sk buffer pointer
 *  @iph: IP header pointer
 *  @tcph: TCP header pointer
 *
 *  It process the incoming TCP packet.
 *  As first step it checks the lenght of the payload, to understand if
 *  something is present (usually it is 0). If so calls the OTP generation
 *  function and compare the result with the incoming value.
 *  It could fails for some reasons, like memory allocation issues or errors
 *  in generating the OTP.
 *  Returns 0 if OTP matches, otherwise return 1
 */
static u8 process_tcp_in(struct sk_buff *skb, struct iphdr *iph,
                         struct tcphdr *tcph);

/**
 *  process_tcp_out - process outgoing TCP packets
 *  @skb: sk buffer pointer
 *  @iph: IP header pointer
 *  @tcph: TCP header pointer
 *
 *  It process the outgoing TCP packet.
 *  The function calls the OTP generation function and the OTP "append"
 *  function.
 *  It could fails for some reasons, like memory allocation issues or errors
 *  in generating the OTP.
 *  Returns 0 if packet must be accepted, otherwise return 1
 */
static u8 process_tcp_out(struct sk_buff *skb, struct iphdr *iph,
                          struct tcphdr *tcph);

/**
 *  process_udp_out - process outgoing UDP packets
 *  @skb: sk buffer pointer
 *  @iph: IP header pointer
 *  @udph: UDP header pointer
 *
 *  It process the outgoing UDP packet.
 *  The function calls the OTP generation function and the OTP "append"
 *  function.
 *  It could fails for some reasons, like memory allocation issues or errors
 *  in generating the OTP.
 *  Returns 0 if packet must be accepted, otherwise return 1
 */
static u8 process_udp_out(struct sk_buff *skb, struct iphdr *iph,
                          struct udphdr *udph);

/**
 *  process_udp_in - process incoming UDP packets
 *  @skb: sk buffer pointer
 *  @iph: IP header pointer
 *  @udph: UDP header pointer
 *
 *  It process the incoming UDP packet.
 *  As first step it checks the lenght of the payload, to understand if
 *  a minmimal length is present. If so calls the OTP generation
 *  function and compare the result with the incoming value.
 *  It could fails for some reasons, like memory allocation issues or errors
 *  in generating the OTP.
 *  If the OTP is recognized and validated, is then stripped from the packet.
 *  Returns 0 if OTP matches, otherwise return 1
 */
static u8 process_udp_in(struct sk_buff *skb, struct iphdr *iph,
                         struct udphdr *udph);
