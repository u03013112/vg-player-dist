(function () {
  'use strict';

  var HLS_JS_SRC = 'https://cdn.jsdelivr.net/npm/hls.js@1.5.15/dist/hls.min.js';
  var STORAGE_KEY = '__vg_full_url__';

  var log = function (m) { try { console.log('[vg-play]', m); } catch (e) {} };

  function loadScript(src) {
    return new Promise(function (rs, rj) {
      if (window.Hls) return rs();
      var s = document.createElement('script');
      s.src = src;
      s.onload = function () { rs(); };
      s.onerror = function () { rj(new Error('加载 hls.js 失败: ' + src)); };
      document.head.appendChild(s);
    });
  }

  function loadRecord() {
    var raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) throw new Error('localStorage.' + STORAGE_KEY + ' 不存在 — 请先在视频详情页跑 vg_probe_url.console.js');
    var rec;
    try { rec = JSON.parse(raw); } catch (e) { throw new Error(STORAGE_KEY + ' 解析失败'); }
    if (!rec || !rec.fullUrl) throw new Error(STORAGE_KEY + ' 结构异常,缺 fullUrl');
    if (rec.origin && rec.origin !== location.origin) {
      log('警告: record 来自 ' + rec.origin + ',当前 origin ' + location.origin + ' — 仍尝试播放');
    }
    return rec;
  }

  function fmt(s) {
    if (!isFinite(s)) return '0:00';
    s = Math.max(0, s | 0);
    var m = (s / 60) | 0, ss = s % 60;
    return m + ':' + (ss < 10 ? '0' : '') + ss;
  }

  function mount(rec) {
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
      '<span id="__vg_status__">' + (rec.title || 'loading...') + '</span>' +
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
      console.log('[vg-play:error]', d);
    });

    hls.loadSource(rec.fullUrl);
    hls.attachMedia(vid);
  }

  (async function main() {
    try {
      var rec = loadRecord();
      log('record id=' + rec.id + ' title=' + rec.title);
      await loadScript(HLS_JS_SRC);
      mount(rec);
    } catch (e) {
      console.error('[vg-play]', e);
      alert('[vg-play] ❌ ' + e.message);
    }
  })();
})();
