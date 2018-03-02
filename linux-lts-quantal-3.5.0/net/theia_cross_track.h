#ifndef __THEIA_CROSS_TRACK_H__
#define __THEIA_CROSS_TRACK_H__

extern bool theia_cross_toggle;

typedef uint32_t theia_udp_tag;

bool theia_is_track_cross();

theia_udp_tag get_theia_udp_tag(struct sock *sk);

#endif
