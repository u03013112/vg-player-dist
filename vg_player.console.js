(function () {
  'use strict';

  // ==========================================================================
  // 通用常量
  // ==========================================================================
  var CRYPTO_JS_SRC = 'https://cdn.jsdelivr.net/npm/crypto-js@4.2.0/crypto-js.min.js';
  var HLS_JS_SRC = 'https://cdn.jsdelivr.net/npm/hls.js@1.5.15/dist/hls.min.js';
  var STORAGE_KEY = '__vg_full_url__';
  var DEFAULT_HOOK_TIMEOUT_MS = 10000;

  var log = function (m) { try { console.log('[vg-player]', m); } catch (e) {} };

  function loadScript(src, globalKey) {
    return new Promise(function (rs, rj) {
      if (globalKey && window[globalKey]) return rs();
      var s = document.createElement('script');
      s.src = src;
      s.onload = function () { rs(); };
      s.onerror = function () { rj(new Error('加载失败: ' + src)); };
      document.head.appendChild(s);
    });
  }

  function getIdFromUrl() {
    var m = location.href.match(/[?&]id=([^&]+)/);
    return m ? decodeURIComponent(m[1]) : null;
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
    if (!raw) throw new Error('localStorage.token 不存在 — 请先在浏览器里进过首页/登录');
    try { return JSON.parse(raw); } catch (e) { return raw; }
  }

  function k5GetSid() {
    var raw = localStorage.getItem('__web_sdk_sid__') || '';
    try {
      var obj = JSON.parse(raw);
      return obj && obj.sid ? obj.sid : '';
    } catch (e) { return ''; }
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
    var hex = '0123456789abcdef';
    var s = '';
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
      if (c < 0x80) { out.push(c); }
      else if (c < 0x800) { out.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f)); }
      else { out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f)); }
    }
    return out;
  }
  function k5WordsToBytes(words, sigBytes) {
    var out = [];
    for (var i = 0; i < sigBytes; i++) {
      out.push((words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff);
    }
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
    var wa = k5BytesToWordArray(bytes);
    var digest = CryptoJS.SHA256(wa);
    return k5WordsToBytes(digest.words, digest.sigBytes);
  }

  // 移植自 reference/k5j7u_legacy/src/decrypt_media_play.py:
  // salt=raw[:12], base_key+salt 经 SHA256 编织派生 key(32B)/iv(16B), AES-256-CBC/PKCS7
  function k5QyDecrypt(b64) {
    var C = CryptoJS;
    var raw = C.enc.Base64.parse(b64);
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

    var decrypted = C.AES.decrypt(
      { ciphertext: k5BytesToWordArray(cipher) },
      k5BytesToWordArray(key),
      { iv: k5BytesToWordArray(iv), mode: C.mode.CBC, padding: C.pad.Pkcs7 }
    );
    return decrypted.toString(C.enc.Utf8);
  }

  async function k5CallMediaPlay(id) {
    var token = k5GetToken();
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
    if (!j || typeof j.data !== 'string') {
      throw new Error('media/play 响应异常: ' + JSON.stringify(j).slice(0, 200));
    }
    var plain = k5QyDecrypt(j.data);
    var outer = JSON.parse(plain);
    var info = outer.mediaInfo || outer;
    log('mediaInfo code=' + (outer.code != null ? outer.code : info.code) + ' videoUrl=' + (info.videoUrl || '').slice(0, 60));
    if (!info.videoUrl) throw new Error('mediaInfo.videoUrl 为空: ' + plain.slice(0, 200));
    return { info: info, token: token, ua: ua };
  }

  function k5BuildFullM3u8Url(videoUrl, token, ua) {
    var sig = k5SignApiKey(token, ua);
    var cdn = k5GetCdnHost();
    var path = videoUrl.replace(/^\/+/, '');
    var qs =
      'token=' + encodeURIComponent(token) +
      '&timestamp=' + sig.ts +
      '&sign=' + sig.sign +
      '&nonce=' + sig.nonce +
      '&c=' + encodeURIComponent(cdn);
    return K5_API_BASE + '/media/h5/m3u8/' + path + '?' + qs;
  }

  // k5 专属:主动请求方案入口(仅在网络拦截超时未命中时调用)
  async function k5ActiveFetch(id) {
    await loadScript(CRYPTO_JS_SRC, 'CryptoJS');
    var mp = await k5CallMediaPlay(id);
    var fullUrl = k5BuildFullM3u8Url(mp.info.videoUrl, mp.token, mp.ua);
    return { title: mp.info.title || '', videoUrl: mp.info.videoUrl, fullUrl: fullUrl };
  }

  // ==========================================================================
  // 通用:广告/弹窗遮罩清理(所有站点共用一套选择器,持续清理)
  // ==========================================================================
  var AD_SELECTORS = ['.van-overlay', '.van-popup', '.tipBox', '.vue-nice-modal-root'];

  function sweepAds() {
    AD_SELECTORS.forEach(function (sel) {
      try {
        document.querySelectorAll(sel).forEach(function (el) { el.remove(); });
      } catch (e) {}
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
  // 通用:截断后缀去除
  // 已知案例(ksXVideo):部分视频原生请求的 m3u8 文件名(不是 query 参数)带
  // `_0001` 这种数字后缀,只返回中段 2 个分片(阉割预览)。把文件名里这个后缀
  // 去掉、访问同名不带后缀的 m3u8,能拿到从 0 号分片开始的完整分片列表。
  // 只处理 query string 之前的 path 部分,token/sign 等签名参数不受影响
  // (站点签名只覆盖 query string,不校验 path 文件名)。
  // ==========================================================================
  var TRUNCATE_SUFFIX_RE = /_0\d*(\.m3u8)(\?|$)/i;

  function stripTruncationSuffix(url) {
    if (typeof url !== 'string') return url;
    return url.replace(TRUNCATE_SUFFIX_RE, '$1$2');
  }

  // ==========================================================================
  // 通用:网络拦截模块
  // 给 XHR/fetch 打补丁,监听任意 .m3u8 请求;命中截断后缀就在发出前改写 URL
  // 再放行(这样站点自己的原生播放器也会自动拿到修正后的完整流),同时把当前
  // 捕获到的(已改写)URL 通过可替换的回调上报给上层逻辑。
  //
  // 注意:monkey-patch 本身只安装一次(整页生命周期内幂等),但“当前监听者”
  // 通过 window.__vg_hook_listener__ 这个可替换引用来实现——这样同一次页面
  // 会话里多次点书签(比如连续切换视频)时,每次 waitForHook() 都能拿到新的
  // 一次性回调,而不会被第一次安装时的旧闭包卡住。
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

  // 等待网络拦截命中一次 m3u8 请求。timeoutMs 为 null/undefined 表示不设超时,
  // 一直等到命中为止(用于没有 fallback 的站点)。
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
  // 通用:localStorage 缓存(行为与原版一致)
  // ==========================================================================
  function saveRecord(id, title, fullUrl, videoUrl) {
    var record = {
      id: id || null,
      title: title || '',
      videoUrl: videoUrl,
      fullUrl: fullUrl,
      origin: location.origin,
      savedAt: Date.now()
    };
    localStorage.setItem(STORAGE_KEY, JSON.stringify(record));
    log('已写入 localStorage.' + STORAGE_KEY + ': ' + record.title);
    return record;
  }

  function loadCachedRecord() {
    var raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    try {
      var rec = JSON.parse(raw);
      if (!rec || !rec.fullUrl) return null;
      return rec;
    } catch (e) { return null; }
  }

  // ==========================================================================
  // 通用:等待提示(纯拦截、无 fallback 的站点在等待命中期间显示,不打断操作)
  // ==========================================================================
  var WAIT_HINT_ID = '__vg_wait_hint__';

  function showWaitHint(text) {
    var el = document.getElementById(WAIT_HINT_ID);
    if (!el) {
      el = document.createElement('div');
      el.id = WAIT_HINT_ID;
      el.style.cssText = 'position:fixed;left:50%;bottom:24px;transform:translateX(-50%);z-index:2147483647;background:rgba(0,0,0,0.75);color:#fff;padding:8px 16px;border-radius:20px;font:13px/1.4 -apple-system,sans-serif;pointer-events:none;';
      document.body.appendChild(el);
    }
    el.textContent = text;
  }

  function hideWaitHint() {
    var el = document.getElementById(WAIT_HINT_ID);
    if (el) el.remove();
  }

  // ==========================================================================
  // 通用:播放器 UI(全屏 hls.js 播放器,旋转/进度条/快进快退/悬浮控制条)
  // 与站点无关,拿到 { title, fullUrl } 就能播,内部实现原样保留不改动。
  // ==========================================================================
  function fmt(s) {
    if (!isFinite(s)) return '0:00';
    s = Math.max(0, s | 0);
    var m = (s / 60) | 0, ss = s % 60;
    return m + ':' + (ss < 10 ? '0' : '') + ss;
  }

  function mount(rec, sourceNote) {
    ['__vg_wrap__', '__vg_float__'].forEach(function (id) {
      var el = document.getElementById(id); if (el) el.remove();
    });
    if (window.__vg_hls_inst) { try { window.__vg_hls_inst.destroy(); } catch (e) {} }

    var wrap = document.createElement('div');
    wrap.id = '__vg_wrap__';
    wrap.style.cssText = 'position:fixed;left:0;top:0;width:100vw;height:100vh;z-index:2147483646;background:#000;display:flex;flex-direction:column;transform-origin:center center;transition:transform .2s;';

    var bar = document.createElement('div');
    bar.style.cssText = 'height:40px;background:#111;color:#fff;display:flex;align-items:center;justify-content:space-between;padding:0 12px;font:13px/1 -apple-system,sans-serif;flex-shrink:0;';
    bar.innerHTML =
      '<span id="__vg_status__">' + ((rec.title || 'loading...') + (sourceNote ? ' · ' + sourceNote : '')) + '</span>' +
      '<div style="display:flex;gap:8px;">' +
        '<button id="__vg_rotate__" style="background:#37a;color:#fff;border:0;padding:6px 10px;border-radius:4px;">⟳ 旋转</button>' +
        '<button id="__vg_fs__" style="background:#555;color:#fff;border:0;padding:6px 10px;border-radius:4px;">⛶ 全屏</button>' +
        '<button id="__vg_close__" style="background:#e33;color:#fff;border:0;padding:6px 14px;border-radius:4px;">× 关闭</button>' +
      '</div>';

    var vid = document.createElement('video');
    vid.id = '__vg_video__';
    vid.autoplay = true;
    vid.playsInline = true;
    vid.controls = false;
    vid.style.cssText = 'flex:1;width:100%;background:#000;object-fit:contain;';

    wrap.appendChild(bar);
    wrap.appendChild(vid);
    document.body.appendChild(wrap);

    var floatBox = document.createElement('div');
    floatBox.id = '__vg_float__';
    floatBox.style.cssText = [
      'position:absolute', 'left:50%', 'top:50%', 'transform:translate(-50%,-50%)',
      'z-index:2147483647', 'background:rgba(0,0,0,0.7)', 'color:#fff',
      'padding:16px 20px', 'border-radius:12px', 'display:flex',
      'flex-direction:column', 'gap:10px', 'width:82%', 'max-width:380px',
      'font:14px/1.3 -apple-system,sans-serif',
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
    wrap.appendChild(floatBox);

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
      wrap.remove();
    };

    var rotated = false;
    function applyLayout() {
      var vw = window.innerWidth, vh = window.innerHeight;
      if (rotated) {
        wrap.style.width = vh + 'px';
        wrap.style.height = vw + 'px';
        wrap.style.left = (vw - vh) / 2 + 'px';
        wrap.style.top = (vh - vw) / 2 + 'px';
        wrap.style.transform = 'rotate(90deg)';
      } else {
        wrap.style.width = '100vw';
        wrap.style.height = '100vh';
        wrap.style.left = '0';
        wrap.style.top = '0';
        wrap.style.transform = 'none';
      }
    }
    function autoRotateOnMeta() {
      var vw = window.innerWidth, vh = window.innerHeight;
      var screenPortrait = vh > vw;
      var videoLandscape = vid.videoWidth > vid.videoHeight && vid.videoWidth > 0;
      if (screenPortrait && videoLandscape && !rotated) {
        rotated = true;
        applyLayout();
        setStatus('↻ 自动旋转至横屏');
      }
    }
    vid.addEventListener('loadedmetadata', autoRotateOnMeta);
    window.addEventListener('resize', applyLayout);
    window.addEventListener('orientationchange', function () {
      setTimeout(function () { rotated = false; applyLayout(); autoRotateOnMeta(); }, 300);
    });

    document.getElementById('__vg_rotate__').onclick = function () {
      rotated = !rotated;
      applyLayout();
    };

    document.getElementById('__vg_fs__').onclick = function () {
      var el = wrap;
      var req = el.requestFullscreen || el.webkitRequestFullscreen || el.webkitEnterFullscreen;
      var vreq = vid.webkitEnterFullscreen;
      if (req) {
        try { req.call(el); return; } catch (e) {}
      }
      if (vreq) {
        try { vreq.call(vid); return; } catch (e) {}
      }
      alert('本浏览器不支持容器全屏,已是沉浸式遮罩状态');
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
      var cy = e.touches ? e.touches[0].clientY : e.clientY;
      var pct;
      if (rotated) {
        pct = Math.max(0, Math.min(1, (cy - r.top) / r.height));
      } else {
        pct = Math.max(0, Math.min(1, (cx - r.left) / r.width));
      }
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
      console.log('[vg-player:error]', d);
    });

    hls.loadSource(rec.fullUrl);
    hls.attachMedia(vid);
  }

  // ==========================================================================
  // 站点配置:按 hostname 分流。只有 k5 需要 fallback(主动伪造请求),
  // 其余站点(ksXVideo、未来新站)默认走纯拦截,不需要任何专属签名 key。
  // ==========================================================================
  var K5_SITE_CONFIG = {
    id: 'k5j7u',
    fallback: {
      timeoutMs: 2000,
      fetch: k5ActiveFetch
    }
  };
  var DEFAULT_SITE_CONFIG = {
    id: 'generic',
    fallback: null
  };
  var SITE_CONFIGS = {
    'dsq3p4z6gl5ag.cloudfront.net': K5_SITE_CONFIG,
    'k5j7u.com': K5_SITE_CONFIG
  };

  function getSiteConfig() {
    return SITE_CONFIGS[location.hostname] || DEFAULT_SITE_CONFIG;
  }

  // ==========================================================================
  // 主流程
  // ==========================================================================
  async function resolveRecord() {
    var cfg = getSiteConfig();
    var id = getIdFromUrl();
    var cached = loadCachedRecord();

    if (cfg.fallback) {
      // 有 fallback 的站点(目前只有 k5):先给网络拦截一个短窗口机会,
      // 命中就直接用(说明这一站原生也会自己发起完整请求,统一逻辑生效);
      // 超时未命中再退回主动伪造请求方案。
      showWaitHint('检测中…');
      var hookedUrl = await waitForHook(cfg.fallback.timeoutMs);
      hideWaitHint();

      if (hookedUrl) {
        return { rec: saveRecord(id, document.title, hookedUrl), note: 'hooked' };
      }
      if (id) {
        log('拦截超时,回退到主动请求方案(' + cfg.id + ')');
        try {
          var got = await cfg.fallback.fetch(id);
          return { rec: saveRecord(id, got.title, got.fullUrl, got.videoUrl), note: 'fallback' };
        } catch (e) {
          log('主动请求方案失败: ' + e.message);
          if (cached && String(cached.id) === String(id)) {
            return { rec: cached, note: 'cached(fallback失败)' };
          }
          throw e;
        }
      }
      if (cached) return { rec: cached, note: 'cached' };
      throw new Error('拦截超时且当前非详情页,又没有缓存 — 请先进入视频详情页并点击播放');
    }

    // 无 fallback 的站点(ksXVideo 及未来新站):纯拦截。
    // 只有在“非详情页 + 已有缓存”时才直接复用缓存;否则等站点自己发起
    // 播放请求(不管是不是详情页,SPA 内的视频信息流一样能拦截到)。
    // 给一个较宽松的超时(而不是无限等),避免"视频在点书签前就已经自动
    // 播完加载"导致的请求错过拦截窗口时,脚本静默卡死不报错。
    if (!id && cached) {
      return { rec: cached, note: 'cached' };
    }
    showWaitHint('等待视频开始播放…');
    var genericUrl = await waitForHook(DEFAULT_HOOK_TIMEOUT_MS);
    hideWaitHint();
    if (!genericUrl) {
      if (cached) return { rec: cached, note: 'cached(拦截超时)' };
      throw new Error(
        DEFAULT_HOOK_TIMEOUT_MS / 1000 + ' 秒内未拦截到播放请求 — ' +
        '很可能是视频在点书签之前就已经自动播完加载了(拦截错过窗口)。' +
        '请退出这个视频重新进入一次,或切到下一个视频后再点书签。'
      );
    }
    return { rec: saveRecord(id, document.title, genericUrl), note: 'hooked' };
  }

  async function main() {
    try {
      await loadScript(HLS_JS_SRC, 'Hls');
      startAdCleaner();

      var result = await resolveRecord();
      mount(result.rec, result.note);
    } catch (e) {
      hideWaitHint();
      console.error('[vg-player]', e);
      alert('[vg-player] ❌ ' + e.message);
    }
  }

  main();
})();
