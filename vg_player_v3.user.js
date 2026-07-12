// ==UserScript==
// @name         VG Player (Butterfly 完整片 · 多站统一版)
// @namespace    https://github.com/u03013112/video_grabber_91
// @version      5.0.0
// @description  纯主动请求取流(k5j7u / ksXVideo 共用同一套签名+解密算法与 key),不依赖网络拦截,随时点开都行;内置悬浮播放按钮 + hls.js 全屏播放器
// @author       u03013112
// @match        https://dsq3p4z6gl5ag.cloudfront.net/*
// @match        https://k5j7u.com/*
// @match        https://d270v74snrdyr6.cloudfront.net/*
// @run-at       document-idle
// @grant        none
// @require      https://cdn.jsdelivr.net/npm/crypto-js@4.2.0/crypto-js.min.js
// @require      https://cdn.jsdelivr.net/npm/hls.js@1.5.15/dist/hls.min.js
// ==/UserScript==

(function () {
  'use strict';

  // ==========================================================================
  // 通用常量
  // ==========================================================================
  var STORAGE_KEY = '__vg_full_url__';
  var FAB_ID = '__vg_fab__';

  var log = function (m) { try { console.log('[vg]', m); } catch (e) {} };

  function getIdFromUrl() {
    var m = location.href.match(/[?&]id=([^&]+)/);
    return m ? decodeURIComponent(m[1]) : null;
  }

  // ==========================================================================
  // 通用:主动请求方案(k5j7u / ksXVideo 共用同一套签名+解密算法和 key ——
  // 两站被逆向确认是同一运营方的马甲站,连 REQ_SIGN_KEY/INTERFACE_KEY 都没换,
  // 只是请求头组装格式、时间戳单位、m3u8 URL 参数略有不同,见 SITE_CONFIGS)。
  // ==========================================================================
  var REQ_SIGN_KEY = 'jR6dO6fT1yD9zY7u';
  var INTERFACE_KEY = 'vEukA&w15z4VAD3kAY#fkL#rBnU!WDhN';
  var CDN_FALLBACK = 'https://s2s1.eaekgu.cn';

  function getToken() {
    var raw = localStorage.getItem('token');
    if (!raw) throw new Error('localStorage.token 不存在 — 请先在浏览器里进过首页/登录');
    try { return JSON.parse(raw); } catch (e) { return raw; }
  }
  function getSid() {
    var raw = localStorage.getItem('__web_sdk_sid__') || '';
    try { var obj = JSON.parse(raw); return obj && obj.sid ? obj.sid : ''; } catch (e) { return ''; }
  }
  function getCdnHost() {
    try {
      var g = JSON.parse(sessionStorage.getItem('global') || '{}');
      if (g && g.videoRoadLine && g.videoRoadLine.url) return g.videoRoadLine.url;
    } catch (e) {}
    return CDN_FALLBACK;
  }
  function buildUA(sid) {
    return 'DevType=Apple iPhone mobile;SysType=h5_ios;Ver=1.0.0;BuildID=Mobile Safari 17.0;DeviceBrand=Apple;DeviceModel=iPhone;SystemName=Android;SystemVersion=6.0;Sid=' + sid;
  }
  function uuid() {
    var hex = '0123456789abcdef', s = '';
    for (var i = 0; i < 32; i++) s += hex[(Math.random() * 16) | 0];
    return s.slice(0, 8) + '-' + s.slice(8, 12) + '-' + s.slice(12, 16) + '-' + s.slice(16, 20) + '-' + s.slice(20);
  }

  // 时间戳单位按站点配置(k5 用毫秒,ksXVideo 用秒),消息结构固定:
  // token & apiPath & XUserAgent & timestamp & nonce,HmacSHA1 签名。
  function computeSign(cfg, token, apiPath, ua) {
    var ts = cfg.tsUnit === 's' ? String(Math.floor(Date.now() / 1000)) : String(Date.now());
    var nonce = uuid();
    var msg = (token || '') + '&' + apiPath + '&' + ua + '&' + ts + '&' + nonce;
    var sign = CryptoJS.HmacSHA1(msg, REQ_SIGN_KEY).toString(CryptoJS.enc.Hex);
    return { ts: ts, nonce: nonce, sign: sign };
  }

  function strToBytes(s) {
    var out = [];
    for (var i = 0; i < s.length; i++) {
      var c = s.charCodeAt(i);
      if (c < 0x80) out.push(c);
      else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f));
      else out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
    }
    return out;
  }
  function wordsToBytes(words, sigBytes) {
    var out = [];
    for (var i = 0; i < sigBytes; i++) out.push((words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff);
    return out;
  }
  function bytesToWordArray(bytes) {
    var words = [];
    for (var i = 0; i < bytes.length; i++) {
      words[i >>> 2] = (words[i >>> 2] || 0) | (bytes[i] << (24 - (i % 4) * 8));
    }
    return CryptoJS.lib.WordArray.create(words, bytes.length);
  }
  function sha256Bytes(bytes) {
    var digest = CryptoJS.SHA256(bytesToWordArray(bytes));
    return wordsToBytes(digest.words, digest.sigBytes);
  }

  // 移植自 reference/k5j7u_legacy/src/decrypt_media_play.py,并在 ksXVideo
  // 打包 JS(decodeHttpResponseData)里逐步核对确认是同一套算法:
  // salt=raw[:12], INTERFACE_KEY+salt 经 SHA256 编织派生 key(32B)/iv(16B),
  // AES-256-CBC/PKCS7。
  function qyDecrypt(b64) {
    var raw = CryptoJS.enc.Base64.parse(b64);
    var rawBytes = wordsToBytes(raw.words, raw.sigBytes);
    if (rawBytes.length < 12) throw new Error('payload too short');
    var salt = rawBytes.slice(0, 12);
    var cipher = rawBytes.slice(12);
    var baseKey = strToBytes(INTERFACE_KEY);
    var o = baseKey.concat(salt);
    var n = Math.floor(o.length / 2);
    var l = sha256Bytes(o).slice(8, 24);
    var p = sha256Bytes(l.concat(o.slice(0, n)));
    var u = sha256Bytes(o.slice(n).concat(l));
    var key = p.slice(0, 8).concat(u.slice(8, 24)).concat(p.slice(24, 32));
    var iv = u.slice(0, 4).concat(p.slice(12, 20)).concat(u.slice(28, 32));
    if (key.length !== 32) throw new Error('key len ' + key.length);
    if (iv.length !== 16) throw new Error('iv len ' + iv.length);
    var d = CryptoJS.AES.decrypt(
      { ciphertext: bytesToWordArray(cipher) },
      bytesToWordArray(key),
      { iv: bytesToWordArray(iv), mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 }
    );
    return d.toString(CryptoJS.enc.Utf8);
  }

  // ==========================================================================
  // 站点配置:按 hostname 分流。签名/加密算法和 key 两站完全一致,只有请求头
  // 组装格式、时间戳单位、m3u8 URL 参数不同 —— 差异都封装在这里,activeFetch()
  // 主流程本身不用关心站点差异。
  // ==========================================================================
  var K5_SITE_CONFIG = {
    id: 'k5j7u',
    apiBase: '/api/app',
    tsUnit: 'ms',
    buildHeaders: function (token, ua, sig) {
      return {
        'Authorization': token,
        'X-User-Agent': ua,
        'X-Timestamp': sig.ts,
        'X-Nonce': sig.nonce,
        'X-Sign': sig.sign
      };
    },
    m3u8SignUA: function (ua) { return ua; },
    buildM3u8Url: function (apiBase, path, token, sig) {
      var qs =
        'token=' + encodeURIComponent(token) +
        '&timestamp=' + sig.ts +
        '&sign=' + sig.sign +
        '&nonce=' + sig.nonce +
        '&c=' + encodeURIComponent(getCdnHost());
      return apiBase + '/media/h5/m3u8/' + path + '?' + qs;
    }
  };
  var KSXVIDEO_SITE_CONFIG = {
    id: 'ksxvideo',
    apiBase: '/api/app',
    tsUnit: 's',
    buildHeaders: function (token, ua, sig) {
      return {
        'Authorization': token,
        'X-User-Agent': ua,
        'x-api-key': 'timestamp=' + sig.ts + ';sign=' + sig.sign + ';nonce=' + sig.nonce
      };
    },
    // ksXVideo 的前端对 m3u8 URL 签名时,XUserAgent 传空字符串(不是完整 UA),
    // 且不带 &c= CDN 参数 —— 这是从其打包 JS 的 encode_play_url 里核对到的,
    // 不是随意约定,改动这里会导致签名对不上。
    m3u8SignUA: function () { return ''; },
    buildM3u8Url: function (apiBase, path, token, sig) {
      var qs =
        'token=' + encodeURIComponent(token) +
        '&timestamp=' + sig.ts +
        '&sign=' + sig.sign +
        '&nonce=' + sig.nonce;
      return apiBase + '/media/h5/m3u8/' + path + '?' + qs;
    }
  };
  var SITE_CONFIGS = {
    'dsq3p4z6gl5ag.cloudfront.net': K5_SITE_CONFIG,
    'k5j7u.com': K5_SITE_CONFIG,
    'd270v74snrdyr6.cloudfront.net': KSXVIDEO_SITE_CONFIG
  };
  function getSiteConfig() { return SITE_CONFIGS[location.hostname] || null; }

  // 主动请求方案:直接调 /media/play 拿完整片源,不依赖、不等待站点自己的
  // 原生播放请求,随时点开都行,跟 k5 原始方案的使用体验完全一致。
  async function activeFetch(cfg, id) {
    var token = getToken();
    var ua = buildUA(getSid());
    var mediaPlayPath = cfg.apiBase + '/media/play';
    var sig = computeSign(cfg, token, mediaPlayPath, ua);
    var headers = cfg.buildHeaders(token, ua, sig);
    headers['Content-Type'] = 'application/json';

    var resp = await fetch(mediaPlayPath, {
      method: 'POST',
      headers: headers,
      body: JSON.stringify({ id: Number(id) })
    });
    if (!resp.ok) throw new Error('media/play HTTP ' + resp.status);
    var j = await resp.json();
    if (!j || typeof j.data !== 'string') throw new Error('media/play 响应异常');
    var outer = JSON.parse(qyDecrypt(j.data));
    var info = outer.mediaInfo || outer;
    if (!info.videoUrl) throw new Error('mediaInfo.videoUrl 为空');

    var path = info.videoUrl.replace(/^\/+/, '');
    var m3u8Path = cfg.apiBase + '/media/h5/m3u8/' + path;
    var m3u8Ua = cfg.m3u8SignUA(ua);
    var sig2 = computeSign(cfg, token, m3u8Path, m3u8Ua);
    var fullUrl = cfg.buildM3u8Url(cfg.apiBase, path, token, sig2);

    return { title: info.title || '', videoUrl: info.videoUrl, fullUrl: fullUrl };
  }

  // ==========================================================================
  // 通用:广告/弹窗遮罩清理
  // ==========================================================================
  var AD_SELECTORS = ['.van-overlay', '.van-popup', '.tipBox', '.vue-nice-modal-root'];

  function sweepAds() {
    AD_SELECTORS.forEach(function (sel) {
      try { document.querySelectorAll(sel).forEach(function (el) { el.remove(); }); } catch (e) {}
    });
  }
  function startAdCleaner() {
    sweepAds();
    try {
      var mo = new MutationObserver(sweepAds);
      mo.observe(document.body, { childList: true, subtree: true });
      return mo;
    } catch (e) { return null; }
  }

  // ==========================================================================
  // 通用:localStorage 缓存
  // ==========================================================================
  function saveRecord(id, title, fullUrl, videoUrl) {
    var record = {
      id: id || null, title: title || '', videoUrl: videoUrl,
      fullUrl: fullUrl, origin: location.origin, savedAt: Date.now()
    };
    localStorage.setItem(STORAGE_KEY, JSON.stringify(record));
    log('✅ 已缓存: ' + record.title);
    return record;
  }
  function loadCachedRecord() {
    try {
      var rec = JSON.parse(localStorage.getItem(STORAGE_KEY) || 'null');
      return (rec && rec.fullUrl) ? rec : null;
    } catch (e) { return null; }
  }

  // 解析当前应该播放的 record:纯主动请求,不依赖任何网络拦截。
  async function resolveRecord(id, cfg) {
    if (!cfg) {
      var cachedUnknown = loadCachedRecord();
      if (cachedUnknown) return cachedUnknown;
      throw new Error('当前站点尚未适配(未收录签名 key),且没有缓存可用');
    }
    if (id) {
      try {
        var got = await activeFetch(cfg, id);
        return saveRecord(id, got.title, got.fullUrl, got.videoUrl);
      } catch (e) {
        var cachedSame = loadCachedRecord();
        if (cachedSame && String(cachedSame.id) === String(id)) return cachedSame;
        throw e;
      }
    }
    var cached = loadCachedRecord();
    if (cached) return cached;
    throw new Error('当前非详情页(URL 无 ?id=),且没有缓存');
  }

  // ==========================================================================
  // 通用:播放器 UI(全屏 hls.js 播放器,旋转/进度条/快进快退/悬浮控制条)
  // ==========================================================================
  function fmt(s) {
    if (!isFinite(s)) return '0:00';
    s = Math.max(0, s | 0);
    var m = (s / 60) | 0, ss = s % 60;
    return m + ':' + (ss < 10 ? '0' : '') + ss;
  }

  function mountPlayer(rec) {
    ['__vg_wrap__', '__vg_float__'].forEach(function (id) {
      var el = document.getElementById(id); if (el) el.remove();
    });
    if (window.__vg_hls_inst) { try { window.__vg_hls_inst.destroy(); } catch (e) {} }

    var wrap = document.createElement('div');
    wrap.id = '__vg_wrap__';
    wrap.style.cssText = 'position:fixed;inset:0;z-index:2147483646;background:#000;display:flex;flex-direction:column;';
    var bar = document.createElement('div');
    bar.style.cssText = 'height:40px;background:#111;color:#fff;display:flex;align-items:center;justify-content:space-between;padding:0 12px;font:13px/1 -apple-system,sans-serif;flex-shrink:0;';
    bar.innerHTML = '<span id="__vg_status__">' + (rec.title || 'loading...') + '</span>' +
      '<button id="__vg_close__" style="background:#e33;color:#fff;border:0;padding:6px 14px;border-radius:4px;">× 关闭</button>';
    var vid = document.createElement('video');
    vid.id = '__vg_video__';
    vid.autoplay = true; vid.playsInline = true; vid.controls = false;
    vid.style.cssText = 'flex:1;width:100%;background:#000;object-fit:contain;';
    wrap.appendChild(bar); wrap.appendChild(vid);
    document.body.appendChild(wrap);

    var floatBox = document.createElement('div');
    floatBox.id = '__vg_float__';
    floatBox.style.cssText = [
      'position:fixed','left:50%','top:50%','transform:translate(-50%,-50%)',
      'z-index:2147483647','background:rgba(0,0,0,0.7)','color:#fff',
      'padding:16px 20px','border-radius:12px','display:flex','flex-direction:column','gap:10px',
      'width:82%','max-width:380px','font:14px/1.3 -apple-system,sans-serif',
      'box-shadow:0 6px 24px rgba(0,0,0,0.6)'
    ].join(';');
    floatBox.innerHTML =
      '<div id="__vg_track__" style="position:relative;height:16px;background:#444;border-radius:8px;cursor:pointer;">' +
        '<div id="__vg_buf__"  style="position:absolute;left:0;top:0;bottom:0;background:#777;border-radius:8px;width:0%;"></div>' +
        '<div id="__vg_prog__" style="position:absolute;left:0;top:0;bottom:0;background:#e33;border-radius:8px;width:0%;"></div>' +
        '<div id="__vg_knob__" style="position:absolute;top:50%;transform:translate(-50%,-50%);left:0%;width:22px;height:22px;background:#fff;border-radius:50%;box-shadow:0 2px 6px rgba(0,0,0,.5);pointer-events:none;"></div>' +
      '</div>' +
      '<div style="display:flex;align-items:center;justify-content:space-between;gap:10px;">' +
        '<button id="__vg_pp__" style="background:#2a7;color:#fff;border:0;padding:10px 18px;border-radius:6px;font-size:16px;">▶︎/❚❚</button>' +
        '<span id="__vg_t__" style="font-variant-numeric:tabular-nums;">0:00 / 0:00</span>' +
        '<button data-d="-10" class="__vg_seek__" style="background:#333;color:#fff;border:0;padding:10px 12px;border-radius:6px;">−10s</button>' +
        '<button data-d="10"  class="__vg_seek__" style="background:#333;color:#fff;border:0;padding:10px 12px;border-radius:6px;">+10s</button>' +
        '<button id="__vg_hide__" style="background:#555;color:#fff;border:0;padding:10px 10px;border-radius:6px;" title="隐藏(双击视频恢复)">▽</button>' +
      '</div>';
    document.body.appendChild(floatBox);

    var status = document.getElementById('__vg_status__');
    var track = document.getElementById('__vg_track__');
    var prog = document.getElementById('__vg_prog__');
    var knob = document.getElementById('__vg_knob__');
    var buf = document.getElementById('__vg_buf__');
    var tEl = document.getElementById('__vg_t__');
    var pp = document.getElementById('__vg_pp__');
    var hide = document.getElementById('__vg_hide__');
    function setStatus(s) { if (status) status.textContent = s; log(s); }

    document.getElementById('__vg_close__').onclick = function () {
      if (window.__vg_hls_inst) { try { window.__vg_hls_inst.destroy(); } catch (e) {} }
      wrap.remove(); floatBox.remove();
    };
    pp.onclick = function () { vid.paused ? vid.play() : vid.pause(); };
    document.querySelectorAll('.__vg_seek__').forEach(function (b) {
      b.onclick = function () {
        vid.currentTime = Math.max(0, Math.min(vid.duration || 0, vid.currentTime + parseFloat(b.dataset.d)));
      };
    });
    hide.onclick = function () { floatBox.style.display = 'none'; };
    vid.addEventListener('dblclick', function () { floatBox.style.display = 'flex'; });

    function seekFromEvt(e) {
      var r = track.getBoundingClientRect();
      var cx = e.touches ? e.touches[0].clientX : e.clientX;
      var pct = Math.max(0, Math.min(1, (cx - r.left) / r.width));
      if (vid.duration) vid.currentTime = pct * vid.duration;
    }
    var dragging = false;
    track.addEventListener('mousedown', function (e) { dragging = true; seekFromEvt(e); e.preventDefault(); });
    window.addEventListener('mousemove', function (e) { if (dragging) seekFromEvt(e); });
    window.addEventListener('mouseup', function () { dragging = false; });
    track.addEventListener('touchstart', function (e) { dragging = true; seekFromEvt(e); }, { passive: true });
    window.addEventListener('touchmove', function (e) { if (dragging) seekFromEvt(e); }, { passive: true });
    window.addEventListener('touchend', function () { dragging = false; });

    function tick() {
      if (vid.duration) {
        var pct = (vid.currentTime / vid.duration) * 100;
        prog.style.width = pct + '%';
        knob.style.left = pct + '%';
        if (vid.buffered.length) {
          var bEnd = vid.buffered.end(vid.buffered.length - 1);
          buf.style.width = (bEnd / vid.duration * 100) + '%';
        }
      }
      tEl.textContent = fmt(vid.currentTime) + ' / ' + fmt(vid.duration);
      requestAnimationFrame(tick);
    }
    tick();

    var hls = new Hls({ enableWorker: true });
    window.__vg_hls_inst = hls;
    hls.on(Hls.Events.MANIFEST_PARSED, function () {
      var lvl = hls.levels[0] && hls.levels[0].details;
      if (lvl) setStatus((rec.title || '') + ' · ' + lvl.fragments.length + ' frags · ' + fmt(lvl.totalduration));
      vid.play().catch(function (e) { setStatus('play() ' + e.message); });
    });
    hls.on(Hls.Events.FRAG_LOADED, function (_, d) {
      setStatus((rec.title || '') + ' · frag ' + d.frag.sn + ' · ' + fmt(vid.currentTime) + ' / ' + fmt(vid.duration));
    });
    hls.on(Hls.Events.ERROR, function (_, d) {
      setStatus('ERR ' + d.type + '/' + d.details + (d.response ? ' http=' + d.response.code : ''));
      console.log('[vg:error]', d);
    });
    hls.loadSource(rec.fullUrl);
    hls.attachMedia(vid);
  }

  // ==========================================================================
  // 悬浮播放按钮(FAB):点击时若已有可用缓存直接播,否则触发一次 resolveRecord()
  // ==========================================================================
  function setFabState(state, text) {
    var fab = document.getElementById(FAB_ID);
    if (!fab) return;
    var colors = { idle: '#666', loading: '#e90', ready: '#2a7', error: '#e33' };
    fab.style.background = colors[state] || '#666';
    fab.textContent = text;
    fab.dataset.state = state;
  }

  function ensureFab() {
    if (document.getElementById(FAB_ID)) return;
    var fab = document.createElement('button');
    fab.id = FAB_ID;
    fab.style.cssText = [
      'position:fixed','right:16px','bottom:16px','z-index:2147483645',
      'width:64px','height:64px','border-radius:50%','border:0',
      'background:#666','color:#fff','font:600 13px/1 -apple-system,sans-serif',
      'box-shadow:0 4px 16px rgba(0,0,0,.5)','cursor:pointer',
      'display:flex','align-items:center','justify-content:center','text-align:center',
      'padding:0','user-select:none','-webkit-user-select:none'
    ].join(';');
    fab.textContent = '...';
    fab.dataset.state = 'idle';
    fab.addEventListener('click', async function () {
      var id = getIdFromUrl();
      var cached = loadCachedRecord();
      if (cached && (!id || String(cached.id) === String(id))) {
        mountPlayer(cached);
        return;
      }
      setFabState('loading', '抓取中');
      try {
        var cfg = getSiteConfig();
        var rec = await resolveRecord(id, cfg);
        setFabState('ready', '▶ 播放');
        mountPlayer(rec);
      } catch (e) {
        setFabState('error', '失败');
        alert('[vg] 获取失败: ' + e.message);
      }
    });
    document.body.appendChild(fab);
  }

  // 页面/路由变化时,后台静默尝试一次 resolveRecord(),提前把 FAB 状态刷新成
  // “ready”,不用等用户点了才去请求。
  async function autoResolveOnRoute() {
    var id = getIdFromUrl();
    if (!id) return;
    var cached = loadCachedRecord();
    if (cached && String(cached.id) === String(id) && (Date.now() - cached.savedAt < 10 * 60 * 1000)) {
      setFabState('ready', '▶ 播放');
      log('复用缓存: ' + cached.title);
      return;
    }
    setFabState('loading', '抓取中');
    try {
      var cfg = getSiteConfig();
      await resolveRecord(id, cfg);
      setFabState('ready', '▶ 播放');
    } catch (e) {
      setFabState('idle', '...');
      log('autoResolve 失败: ' + e.message);
    }
  }

  function watchRouteChange() {
    var lastHref = location.href;
    setInterval(function () {
      if (location.href !== lastHref) {
        lastHref = location.href;
        log('route -> ' + location.href);
        autoResolveOnRoute();
      }
    }, 800);
  }

  function init() {
    if (window.__vg_inited__) return;
    window.__vg_inited__ = true;
    startAdCleaner();
    ensureFab();
    autoResolveOnRoute();
    watchRouteChange();
    log('VG Player(纯主动请求·多站统一版) inited, match=' + location.href);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
