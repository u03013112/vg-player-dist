(function () {
  'use strict';

  var REQ_SIGN_KEY = 'jR6dO6fT1yD9zY7u';
  var INTERFACE_KEY = 'vEukA&w15z4VAD3kAY#fkL#rBnU!WDhN';
  var API_BASE = '/api/app';
  var CDN_FALLBACK = 'https://s2s1.eaekgu.cn';
  var CRYPTO_JS_SRC = 'https://cdn.jsdelivr.net/npm/crypto-js@4.2.0/crypto-js.min.js';
  var HLS_JS_SRC = 'https://cdn.jsdelivr.net/npm/hls.js@1.5.15/dist/hls.min.js';
  var STORAGE_KEY = '__vg_full_url__';

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

  function getToken() {
    var raw = localStorage.getItem('token');
    if (!raw) throw new Error('localStorage.token 不存在 — 请先在浏览器里进过首页/登录');
    try { return JSON.parse(raw); } catch (e) { return raw; }
  }

  function getSid() {
    var raw = localStorage.getItem('__web_sdk_sid__') || '';
    try {
      var obj = JSON.parse(raw);
      return obj && obj.sid ? obj.sid : '';
    } catch (e) { return ''; }
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
    var hex = '0123456789abcdef';
    var s = '';
    for (var i = 0; i < 32; i++) s += hex[(Math.random() * 16) | 0];
    return s.slice(0, 8) + '-' + s.slice(8, 12) + '-' + s.slice(12, 16) + '-' + s.slice(16, 20) + '-' + s.slice(20);
  }

  function signApiKey(token, ua) {
    var ts = String(Date.now());
    var nonce = uuid();
    var msg = token + '&' + API_BASE + '&' + ua + '&' + ts + '&' + nonce;
    var sign = CryptoJS.HmacSHA1(msg, REQ_SIGN_KEY).toString(CryptoJS.enc.Hex);
    return { ts: ts, nonce: nonce, sign: sign };
  }

  function strToBytes(s) {
    var out = [];
    for (var i = 0; i < s.length; i++) {
      var c = s.charCodeAt(i);
      if (c < 0x80) { out.push(c); }
      else if (c < 0x800) { out.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f)); }
      else { out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f)); }
    }
    return out;
  }
  function wordsToBytes(words, sigBytes) {
    var out = [];
    for (var i = 0; i < sigBytes; i++) {
      out.push((words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff);
    }
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
    var wa = bytesToWordArray(bytes);
    var digest = CryptoJS.SHA256(wa);
    return wordsToBytes(digest.words, digest.sigBytes);
  }

  // 移植自 src/k5j7u_com/decrypt_media_play.py:
  // salt=raw[:12], base_key+salt 经 SHA256 编织派生 key(32B)/iv(16B), AES-256-CBC/PKCS7
  function qyDecrypt(b64) {
    var C = CryptoJS;
    var raw = C.enc.Base64.parse(b64);
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

    var decrypted = C.AES.decrypt(
      { ciphertext: bytesToWordArray(cipher) },
      bytesToWordArray(key),
      { iv: bytesToWordArray(iv), mode: C.mode.CBC, padding: C.pad.Pkcs7 }
    );
    return decrypted.toString(C.enc.Utf8);
  }

  async function callMediaPlay(id) {
    var token = getToken();
    var sid = getSid();
    var ua = buildUA(sid);
    var sig = signApiKey(token, ua);

    var resp = await fetch(API_BASE + '/media/play', {
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
    var plain = qyDecrypt(j.data);
    var outer = JSON.parse(plain);
    var info = outer.mediaInfo || outer;
    log('mediaInfo code=' + (outer.code != null ? outer.code : info.code) + ' videoUrl=' + (info.videoUrl || '').slice(0, 60));
    if (!info.videoUrl) throw new Error('mediaInfo.videoUrl 为空: ' + plain.slice(0, 200));
    return { info: info, token: token, ua: ua };
  }

  function buildFullM3u8Url(videoUrl, token, ua) {
    var sig = signApiKey(token, ua);
    var cdn = getCdnHost();
    var path = videoUrl.replace(/^\/+/, '');
    var qs =
      'token=' + encodeURIComponent(token) +
      '&timestamp=' + sig.ts +
      '&sign=' + sig.sign +
      '&nonce=' + sig.nonce +
      '&c=' + encodeURIComponent(cdn);
    return API_BASE + '/media/h5/m3u8/' + path + '?' + qs;
  }

  async function probeAndSave(id) {
    await loadScript(CRYPTO_JS_SRC, 'CryptoJS');
    var mp = await callMediaPlay(id);
    var fullUrl = buildFullM3u8Url(mp.info.videoUrl, mp.token, mp.ua);
    var record = {
      id: id,
      title: mp.info.title || '',
      videoUrl: mp.info.videoUrl,
      fullUrl: fullUrl,
      origin: location.origin,
      savedAt: Date.now()
    };
    localStorage.setItem(STORAGE_KEY, JSON.stringify(record));
    log('探针成功 id=' + id + ' 已写入 localStorage.' + STORAGE_KEY);
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

  (async function main() {
    try {
      await loadScript(HLS_JS_SRC, 'Hls');

      var id = getIdFromUrl();
      var cached = loadCachedRecord();
      var rec = null;
      var note = '';

      if (id) {
        log('检测到详情页 id=' + id + ',启动探针...');
        try {
          rec = await probeAndSave(id);
          note = 'fresh';
        } catch (e) {
          log('探针失败: ' + e.message);
          if (cached && String(cached.id) === String(id)) {
            rec = cached;
            note = 'cached(探针失败)';
            log('降级到 localStorage 缓存(同 id)');
          } else if (cached) {
            throw new Error('探针失败且缓存 id 不匹配:\n' + e.message);
          } else {
            throw e;
          }
        }
      } else {
        if (!cached) {
          throw new Error('当前 URL 无 id 参数,且 localStorage 无缓存 — 请先在视频详情页执行');
        }
        rec = cached;
        note = 'cached';
        log('非详情页,使用 localStorage 缓存 id=' + rec.id);
      }

      mount(rec, note);
    } catch (e) {
      console.error('[vg-player]', e);
      alert('[vg-player] ❌ ' + e.message);
    }
  })();
})();
