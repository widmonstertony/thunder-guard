#include "PeerClassifier.h"
#include <assert.h>
#include <string.h>

static void web_traffic_passes(void) {
    PGStream http = {0};
    const uint8_t request[] = "POST /login HTTP/1.1\r\n";
    const uint8_t tls[] = {22,3,1,0,0,1,0,0,0};
    const uint8_t proprietary[] = {19,12,9,32};
    assert(pg_classify(&http, false, 0, request, sizeof request).action == PGUnidentified);
    assert(pg_classify(&http, false, 0, tls, sizeof tls).action == PGUnidentified);
    assert(pg_classify(&http, false, 0, proprietary, sizeof proprietary).action == PGUnidentified);
}

static void peer_frames_are_directional(void) {
    uint8_t hs[68] = "\023BitTorrent protocol";
    PGStream client = {0}, server = {0};
    assert(pg_classify(&client, false, 0, hs, 1).count == 20);
    assert(pg_classify(&client, false, 0, hs, 20).count == 68);
    assert(pg_classify(&client, false, 0, hs, sizeof hs).action == PGPass);
    assert(pg_classify(&server, true, 0, hs, sizeof hs).action == PGPass);

    const uint8_t metaAndPiece[] = {0,0,0,4,20,9,'d','e', 0,0,0,10,7,0,0,0,0,0,0,0,0,'f'};
    PGDecision meta = pg_classify(&server, true, 68, metaAndPiece, sizeof metaAndPiece);
    assert(meta.action == PGPass && meta.count == 8);
    assert(pg_classify(&server, true, 76, metaAndPiece + 8, 4).action == PGPeek);
    assert(pg_classify(&server, true, 76, metaAndPiece + 8, 5).action == PGBlockDownload);
    assert(pg_classify(&client, false, 68, metaAndPiece + 8, 5).action == PGBlockUpload);
    const uint8_t request[] = {0,0,0,13,6};
    assert(pg_classify(&client, false, 68, request, sizeof request).action == PGBlockDownload);
    assert(pg_classify(&server, true, 76, request, sizeof request).action == PGBlockUpload);
}

int main(void) {
    web_traffic_passes();
    peer_frames_are_directional();
}
