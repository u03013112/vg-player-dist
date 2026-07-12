// ==UserScript==
// @name         VG Player (Butterfly 完整片 · 多站统一版)
// @namespace    https://github.com/u03013112/video_grabber_91
// @version      4.0.0
// @description  网络拦截式统一取流(优先),k5 站超时自动 fallback 到 /api/app/media/play 主动请求;内置悬浮播放按钮 + hls.js 全屏播放器
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
  function isDetailLikePage() {
    // 详情页(?id=)或短视频/信息流路由(无 id 但仍可能自动触发原生播放请求)
    return true;
  }

  // ==========================================================================
  // k5 (dsq3p4z6gl5ag.cloudfront.net / k5j7u.com) 专属 fallback:
  // 主动伪造签名请求拿完整片源。逆向出来的签名/加密逻辑,一字不改,仅在
  // “网络拦截超时未命中”时才会被调用,不再是唯一路径。
  // ==========================================================================
  var K5_REQ_SIGN_KEY = 'jR6dO6fT1yD9zY7u';
  var K5_INTERFACE_KEY = 'vEukA&w15z4VAD3kAY#fkL#rBnU!WDhN';
  var K5_API_BASE = '/api/app';
  var K5_CDN_FALLBACK = 'https://s2s1.eaekgu.cn';

  function k5GetToken() {
    var raw = localStorage.getItem('token');
    if (!raw) return null;
    try { return JSON.parse(raw); } catch (e) { return raw; }
  }
  function k5GetSid() {
    var raw = localStorage.getItem('__web_sdk_sid__') || '';
    try { var obj = JSON.parse(raw); return obj && obj.sid ? obj.sid : ''; } catch (e) { return ''; }
  }
  function k5GetCdnHost() {
    try {
      var g = JSON.parse(sessionStorage.getItem('global') || '{}');
      if (g && g.videoRoadLine && g.videoRoadLine.url) return g.videoRoadLine.url;
    } catch (e) {}
    return K5_CDN_FALLBACK;
  }
  function k5BuildUA(sid) {
    return 'DevType=Apple iPhone mobile;SysType=h5_ios;Ver=1.0.0;BuildID=Mobile Safari 17.0;DeviceBrand=Apple;DeviceModel=iPhone;SystemName=Android;SystemVersion=6.0;Sid=' + sid;
  }
  function k5Uuid() {
    var hex = '0123456789abcdef', s = '';
    for (var i = 0; i < 32; i++) s += hex[(Math.random() * 16) | 0];
    return s.slice(0, 8) + '-' + s.slice(8, 12) + '-' + s.slice(12, 16) + '-' + s.slice(16, 20) + '-' + s.slice(20);
  }
  function k5SignApiKey(token, ua) {
    var ts = String(Date.now());
    var nonce = k5Uuid();
    var msg = token + '&' + K5_API_BASE + '&' + ua + '&' + ts + '&' + nonce;
    var sign = CryptoJS.HmacSHA1(msg, K5_REQ_SIGN_KEY).toString(CryptoJS.enc.Hex);
    return { ts: ts, nonce: nonce, sign: sign };
  }
  function k5StrToBytes(s) {
    var out = [];
    for (var i = 0; i < s.length; i++) {
      var c = s.charCodeAt(i);
      if (c < 0x80) out.push(c);
      else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f));
      else out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
    }
    return out;
  }
  function k5WordsToBytes(words, sigBytes) {
    var out = [];
    for (var i = 0; i < sigBytes; i++) out.push((words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff);
    return out;
  }
  function k5BytesToWordArray(bytes) {
    var words = [];
    for (var i = 0; i < bytes.length; i++) {
      words[i >>> 2] = (words[i >>> 2] || 0) | (bytes[i] << (24 - (i % 4) * 8));
    }
    return CryptoJS.lib.WordArray.create(words, bytes.length);
  }
  function k5Sha256Bytes(bytes) {
    var digest = CryptoJS.SHA256(k5BytesToWordArray(bytes));
    return k5WordsToBytes(digest.words, digest.sigBytes);
  }

  // 移植自 reference/k5j7u_legacy/src/decrypt_media_play.py:
  // salt=raw[:12], base_key+salt 经 SHA256 编织派生 key(32B)/iv(16B), AES-256-CBC/PKCS7
  function k5QyDecrypt(b64) {
    var raw = CryptoJS.enc.Base64.parse(b64);
    var rawBytes = k5WordsToBytes(raw.words, raw.sigBytes);
    if (rawBytes.length < 12) throw new Error('payload too short');
    var salt = rawBytes.slice(0, 12);
    var cipher = rawBytes.slice(12);
    var baseKey = k5StrToBytes(K5_INTERFACE_KEY);
    var o = baseKey.concat(salt);
    var n = Math.floor(o.length / 2);
    var l = k5Sha256Bytes(o).slice(8, 24);
    var p = k5Sha256Bytes(l.concat(o.slice(0, n)));
    var u = k5Sha256Bytes(o.slice(n).concat(l));
    var key = p.slice(0, 8).concat(u.slice(8, 24)).concat(p.slice(24, 32));
    var iv = u.slice(0, 4).concat(p.slice(12, 20)).concat(u.slice(28, 32));
    if (key.length !== 32) throw new Error('key len ' + key.length);
    if (iv.length !== 16) throw new Error('iv len ' + iv.length);
    var d = CryptoJS.AES.decrypt(
      { ciphertext: k5BytesToWordArray(cipher) },
      k5BytesToWordArray(key),
      { iv: k5BytesToWordArray(iv), mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 }
    );
    return d.toString(CryptoJS.enc.Utf8);
  }

  async function k5ActiveFetch(id) {
    var token = k5GetToken();
    if (!token) throw new Error('未登录: localStorage.token 缺失');
    var sid = k5GetSid();
    var ua = k5BuildUA(sid);
    var sig = k5SignApiKey(token, ua);
    var resp = await fetch(K5_API_BASE + '/media/play', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': token,
        'X-User-Agent': ua,
        'X-Timestamp': sig.ts,
        'X-Nonce': sig.nonce,
        'X-Sign': sig.sign
      },
      body: JSON.stringify({ id: Number(id) })
    });
    if (!resp.ok) throw new Error('media/play HTTP ' + resp.status);
    var j = await resp.json();
    if (!j || typeof j.data !== 'string') throw new Error('media/play 响应异常');
    var outer = JSON.parse(k5QyDecrypt(j.data));
    var info = outer.mediaInfo || outer;
    if (!info.videoUrl) throw new Error('mediaInfo.videoUrl 为空');
    var sig2 = k5SignApiKey(token, ua);
    var path = info.videoUrl.replace(/^\/+/, '');
    var fullUrl = K5_API_BASE + '/media/h5/m3u8/' + path +
      '?token=' + encodeURIComponent(token) +
      '&timestamp=' + sig2.ts +
      '&sign=' + sig2.sign +
      '&nonce=' + sig2.nonce +
      '&c=' + encodeURIComponent(k5GetCdnHost());
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
  // 通用:截断后缀去除(见 ksxvideo_fm/README.md 的 _0001 案例)
  // ==========================================================================
  var TRUNCATE_SUFFIX_RE = /_0\d*(\.m3u8)(\?|$)/i;
  function stripTruncationSuffix(url) {
    if (typeof url !== 'string') return url;
    return url.replace(TRUNCATE_SUFFIX_RE, '$1$2');
  }

  // ==========================================================================
  // 通用:网络拦截模块(可重复 waitForHook 的可替换回调设计,见 console.js 同名注释)
  // ==========================================================================
  function installNetworkHook() {
    if (window.__vg_hook_installed__) return;
    window.__vg_hook_installed__ = true;

    var origOpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function (method, url) {
      var args = Array.prototype.slice.call(arguments);
      if (typeof url === 'string' && url.indexOf('.m3u8') !== -1) {
        var fixed = stripTruncationSuffix(url);
        if (fixed !== url) log('拦截到截断后缀,已改写: ' + url + ' -> ' + fixed);
        args[1] = fixed;
        if (window.__vg_hook_listener__) {
          try { window.__vg_hook_listener__(fixed); } catch (e) {}
        }
      }
      return origOpen.apply(this, args);
    };

    var origFetch = window.fetch;
    if (origFetch) {
      window.fetch = function (input, init) {
        var args = Array.prototype.slice.call(arguments);
        var u = (typeof input === 'string') ? input : (input && input.url);
        if (typeof u === 'string' && u.indexOf('.m3u8') !== -1) {
          var fixed = stripTruncationSuffix(u);
          if (fixed !== u) {
            log('拦截到截断后缀,已改写: ' + u + ' -> ' + fixed);
            args[0] = (typeof input === 'string') ? fixed : new Request(fixed, init);
          }
          if (window.__vg_hook_listener__) {
            try { window.__vg_hook_listener__(fixed); } catch (e) {}
          }
        }
        return origFetch.apply(this, args);
      };
    }
  }

  function waitForHook(timeoutMs) {
    installNetworkHook();
    return new Promise(function (resolve) {
      var settled = false;
      window.__vg_hook_listener__ = function (url) {
        if (settled) return;
        settled = true;
        window.__vg_hook_listener__ = null;
        resolve(url);
      };
      if (timeoutMs != null) {
        setTimeout(function () {
          if (settled) return;
          settled = true;
          window.__vg_hook_listener__ = null;
          resolve(null);
        }, timeoutMs);
      }
    });
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

  // ==========================================================================
  // 站点配置
  // ==========================================================================
  var K5_SITE_CONFIG = { id: 'k5j7u', fallback: { timeoutMs: 2000, fetch: k5ActiveFetch } };
  var DEFAULT_SITE_CONFIG = { id: 'generic', fallback: null };
  var SITE_CONFIGS = {
    'dsq3p4z6gl5ag.cloudfront.net': K5_SITE_CONFIG,
    'k5j7u.com': K5_SITE_CONFIG
  };
  function getSiteConfig() { return SITE_CONFIGS[location.hostname] || DEFAULT_SITE_CONFIG; }

  // 解析当前应该播放的 record:优先网络拦截,k5 超时才退回主动请求方案
  async function resolveRecord(id, cfg) {
    if (cfg.fallback) {
      var hookedUrl = await waitForHook(cfg.fallback.timeoutMs);
      if (hookedUrl) return saveRecord(id, document.title, hookedUrl);
      if (!id) {
        var cached = loadCachedRecord();
        if (cached) return cached;
        throw new Error('拦截超时且非详情页,又没有缓存');
      }
      var got = await cfg.fallback.fetch(id);
      return saveRecord(id, got.title, got.fullUrl, got.videoUrl);
    }
    // 无 fallback:纯拦截,不设超时,一直等到站点自己发起播放请求
    var url = await waitForHook(null);
    return saveRecord(id, document.title, url);
  }

  // ==========================================================================
  // 通用:播放器 UI(与 bookmarklet/vg_player.console.js 的 mount() 逻辑一致,
  // 仅函数名沿用 user.js 原有的 mountPlayer 命名,内部实现原样保留)
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
  // “ready”——命中原生自动播放请求或者 k5 fallback 都会在这里被捕获。
  async function autoResolveOnRoute() {
    if (!isDetailLikePage()) return;
    var id = getIdFromUrl();
    var cached = loadCachedRecord();
    if (cached && id && String(cached.id) === String(id) && (Date.now() - cached.savedAt < 10 * 60 * 1000)) {
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
      log('autoResolve 未命中: ' + e.message);
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
    log('VG Player(统一版) inited, match=' + location.href);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
