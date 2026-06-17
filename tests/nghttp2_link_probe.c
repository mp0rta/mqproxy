/* nghttp2_link_probe — minimal link/runtime guard for the nghttp2 dependency
 * (Phase 7 Slice 3 Task 4).
 *
 * Confirms the build can both COMPILE against <nghttp2/nghttp2.h> and LINK +
 * RUN a call into the chosen libnghttp2 (system .so in the dynamic build, the
 * multiarch libnghttp2.a in the MQPROXY_STATIC_XQUIC build). Prints the runtime
 * version string and exits 0. Permanent, low-cost guard: it fails loudly if the
 * nghttp2 dependency ever silently drops out of the build, independent of the
 * heavier H2 MITM adapter tests. */
#include <nghttp2/nghttp2.h>
#include <stdio.h>

int
main(void)
{
    nghttp2_info *info = nghttp2_version(0);
    if (info == NULL || info->version_str == NULL) {
        fprintf(stderr, "nghttp2_version() returned NULL\n");
        return 1;
    }
    printf("nghttp2 link probe OK: version %s (version_num=0x%08x)\n", info->version_str,
           info->version_num);
    return 0;
}
