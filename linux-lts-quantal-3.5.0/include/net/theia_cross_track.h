#ifndef __THEIA_CROSS_TRACK_H__
#define __THEIA_CROSS_TRACK_H__

extern bool theia_cross_toggle;

typedef uint32_t theia_udp_tag;

bool theia_is_track_cross(struct socket *sock);

theia_udp_tag get_theia_udp_send_tag(struct sock *sk);
void set_theia_udp_recv_tag(struct sock *sk, theia_udp_tag tag);
theia_udp_tag peek_theia_udp_send_tag(struct sock *sk);
theia_udp_tag peek_theia_udp_recv_tag(struct sock *sk);

#endif
