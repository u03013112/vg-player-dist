# vg-player-dist

VGPlayer 书签 + Userscript 方案的 CDN 分发目录。源码在私有 repo `video_grabber_91`,通过 `bookmarklet/publish.sh` 同步到这里。

## 产物

- `vg_player_v3.user.js` — **iOS Userscripts 最终产品(推荐)**,走 /api/app/media/play 拿完整片 + 全屏播放器 + 悬浮按钮
- `vg_player.console.js` — **Console/书签一体版(推荐)**:详情页自动探针+播放,其他页读 localStorage 缓存
- `vg_library.junma.console.js` — **骏马(2v56) VG Library 原型**:书签自带选片 UI(搜索/换一批)+ ks 同款播放器,仅技术验证
- `vg_library.junma.debug.console.js` — 骏马排障构建:屏上日志面板+连通性差分探测(①CORS fetch/②no-cors/③XHR/④404对照/⑤m3u8预检)
- `vg_player.bundle.js` — 旧版主播放器脚本(loadScript 串联 CryptoJS + hls.js + Plyr)
- `vg_probe_url.console.js` — Console 版资源获取探针(拆分版)
- `vg_play_stored.console.js` — Console 版播放器(拆分版,从 localStorage 读 URL)
- `vg_full_player.console.js` — Console 版 all-in-one(旧)
- `csp_probe_payload.js` — CSP 探针回调

## jsDelivr CDN URL

- https://cdn.jsdelivr.net/gh/u03013112/vg-player-dist@main/vg_player_v3.user.js
- https://cdn.jsdelivr.net/gh/u03013112/vg-player-dist@main/vg_player.console.js
- https://cdn.jsdelivr.net/gh/u03013112/vg-player-dist@main/vg_library.junma.console.js
- https://cdn.jsdelivr.net/gh/u03013112/vg-player-dist@main/vg_library.junma.debug.console.js
- https://cdn.jsdelivr.net/gh/u03013112/vg-player-dist@main/vg_player.bundle.js
- https://cdn.jsdelivr.net/gh/u03013112/vg-player-dist@main/vg_probe_url.console.js
- https://cdn.jsdelivr.net/gh/u03013112/vg-player-dist@main/vg_play_stored.console.js
- https://cdn.jsdelivr.net/gh/u03013112/vg-player-dist@main/vg_full_player.console.js
- https://cdn.jsdelivr.net/gh/u03013112/vg-player-dist@main/csp_probe_payload.js
