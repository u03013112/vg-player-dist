# vg-player-dist

VGPlayer 书签方案的 CDN 分发目录。源码在私有 repo `video_grabber_91/bookmarklet/`,通过 `publish.sh` 同步到这里。

- `vg_player.bundle.js` — 主播放器脚本(loadScript 串联 CryptoJS + hls.js + Plyr)
- `csp_probe_payload.js` — CSP 探针回调

经 jsDelivr 分发:
- https://cdn.jsdelivr.net/gh/u03013112/vg-player-dist@main/vg_player.bundle.js
- https://cdn.jsdelivr.net/gh/u03013112/vg-player-dist@main/csp_probe_payload.js
