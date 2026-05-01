# vg-player-dist

VGPlayer 书签 + Userscript 方案的 CDN 分发目录。源码在私有 repo `video_grabber_91`,通过 `bookmarklet/publish.sh` 同步到这里。

## 产物

- `vg_player_v3.user.js` — **iOS Userscripts 最终产品(推荐)**,走 /api/app/media/play 拿完整片 + 全屏播放器 + 悬浮按钮
- `vg_player.bundle.js` — 旧版主播放器脚本(loadScript 串联 CryptoJS + hls.js + Plyr)
- `vg_probe_url.console.js` — Console 版资源获取探针
- `vg_play_stored.console.js` — Console 版播放器(从 localStorage 读 URL)
- `vg_full_player.console.js` — Console 版 all-in-one
- `csp_probe_payload.js` — CSP 探针回调

## jsDelivr CDN URL

- https://cdn.jsdelivr.net/gh/u03013112/vg-player-dist@main/vg_player_v3.user.js
- https://cdn.jsdelivr.net/gh/u03013112/vg-player-dist@main/vg_player.bundle.js
- https://cdn.jsdelivr.net/gh/u03013112/vg-player-dist@main/vg_probe_url.console.js
- https://cdn.jsdelivr.net/gh/u03013112/vg-player-dist@main/vg_play_stored.console.js
- https://cdn.jsdelivr.net/gh/u03013112/vg-player-dist@main/vg_full_player.console.js
- https://cdn.jsdelivr.net/gh/u03013112/vg-player-dist@main/csp_probe_payload.js
