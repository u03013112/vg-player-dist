/*!
 * VG Library — 骏马(2v56) 技术验证原型【DEBUG 构建】(不做成产品,仅验证"API 有墙 / CDN 存储层裸奔"绕过路线)
 *
 * 与正式版 vg_library.junma.console.js 的差异(仅排障用,功能路径完全一致):
 *   1. 片库左下角常驻日志面板:全部网络动作(取身份/列表/封面)带时间戳上屏,
 *      "复制日志"按钮一键回传(clipboard 失败回退 execCommand→prompt)。
 *   2. 列表渲染后自动跑 5 项连通性探测(取第一条封面 URL):
 *      ① fetch CORS 模式(正式路径) ② new Image() 无 CORS(等同直接导航)
 *      ③ XMLHttpRequest(老接口) ④ 同 CDN 故意 404(区分"可达但被拒"vs"挂起")
 *      ⑤ m3u8 预检(播放路径)。①败②成 = 链路对 XHR 型请求干扰;
 *      ①②全败 = 到 CDN 的原始连通性断;全超时 = 黑洞(防火墙丢包)。
 *   3. 封面失败占位文字改亮红色(正式版曾用 #5a6070 深灰,深底上不可见——已回修正式版)。
 *
 * 运行环境:2v56(骏马) 站点任意页面(如 .../client/index.html?suhmal=...&debug=1)。
 * 与 ks/OIO 播放器的差异:本站未付费时点击视频 URL 不变(弹购买框),不存在
 * "详情页拿视频身份"的入口,所以书签自带选片 UI(搜索/换一批),不再依赖原站点击流。
 *
 * 逆向事实(2026-09-04 调查):
 *   签名   X-Request-Verify = MD5("DsVerify_2026_A8x3Qp:<unix秒>:<METHOD>:<规范化path>")
 *          (无请求体加密,比 ks/OIO 的 HmacSHA1+AES-CBC 简单一个量级)
 *   身份   userKey 由 agentCode+IP 派生(getToken),localStorage['userKey']/['code'] 现成可用
 *   列表   POST /app/getMoreList?title=&num=12&code=<agentCode>
 *          → data[{uuid, price, tags, thumb, title(base64)}](一次最多 8 条,"换一批"随机流)
 *   封面   thumb 指向 CDN <目录>/1.txt(内容 = 倒序的 jpeg base64,站点模块 94466 的解码即
 *          endsWith('/j9/') 则整串 reverse),KEY1/KEY2 签名参数实际不校验
 *   播放   <目录>/index.m3u8(master) → hls/index.m3u8(完整 media,#EXT-X-ENDLIST)
 *          → #EXT-X-KEY URI="key.key"(16B 裸 key,IV=0) ;CDN 无 Referer/签名校验,
 *          CORS Access-Control-Allow-Origin:* → hls.js 直接播,无需改写 manifest
 *
 * 入口模式:
 *   默认 — 同步 window.open 新标签页,document.write 写入完整 UI(与 vg_player 同款骨架);
 *          新标签页内所有请求都用 opener 传入的绝对 API origin(不依赖 about:blank 的
 *          baseURI 继承行为,详见 doc/vg_player_result/summary.md 世代六的坑)。
 *   测试 — 预设 window.__VG_LIB_INLINE__=true 时写入当前页临时 iframe(便于无头验证),
 *          与新标签页共用同一个 buildAppHtml/writeApp 文档路径。
 */
(function () {
  'use strict';

  // ==========================================================================
  // 配置(逆向自站点 bundle)
  // ==========================================================================
  var HOST_PATTERN = /jmcdnk|lfce\.cn/i; // 随机子域轮换,只认平台域名特征
  var SIGN_SECRET = 'DsVerify_2026_A8x3Qp';
  var API_PATH_TOKEN = '/app/getToken';
  var CRYPTO_JS_SRC = 'https://cdn.jsdelivr.net/npm/crypto-js@4.2.0/crypto-js.min.js';
  var HLS_JS_SRC = 'https://cdn.jsdelivr.net/npm/hls.js@1.5.15/dist/hls.min.js';
  var LIST_SIZE = 12;

  var log = function (m) { try { console.log('[vg-library]', m); } catch (e) {} };

  // ==========================================================================
  // 小工具
  // ==========================================================================
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

  // localStorage 值是 JSON.stringify 过的('"660611"'),剥引号
  function stripQuotes(v) {
    if (v == null) return '';
    var s = String(v).trim();
    if (s.length >= 2 && s.charAt(0) === '"' && s.charAt(s.length - 1) === '"') {
      s = s.slice(1, -1);
    }
    return s;
  }

  function readLS(key) {
    try { return stripQuotes(window.localStorage.getItem(key)); } catch (e) { return ''; }
  }

  // 注意:dirFromThumb 只在 appMain(新文档)内部使用,故定义在 appMain 里——
  // appMain 会被 toString() 后内嵌进新文档运行,引用不到外层作用域的任何标识符。

  function sigHeaders(method, apiPath) {
    var ts = Math.floor(Date.now() / 1000).toString();
    var p = ('/' + String(apiPath).split('?')[0].split('#')[0]).replace(/\/{2,}/g, '/');
    var ver = window.CryptoJS.MD5(SIGN_SECRET + ':' + ts + ':' + method.toUpperCase() + ':' + p).toString();
    return { 'X-Request-Timestamp': ts, 'X-Request-Verify': ver };
  }

  // ==========================================================================
  // 身份:code/userKey(localStorage 现成;缺失时走 getToken 兜底)
  // ==========================================================================
  function fetchToken(apiOrigin, code) {
    var q = '?code=' + encodeURIComponent(code || '');
    return fetch(apiOrigin + API_PATH_TOKEN + q, { method: 'GET', headers: sigHeaders('GET', API_PATH_TOKEN) })
      .then(function (r) { return r.json(); })
      .then(function (j) {
        if (j && j.code === 200 && j.data && j.data.userKey) return j.data.userKey;
        throw new Error('getToken 失败: ' + (j && j.msg));
      });
  }

  // agentCode 兜底链:localStorage.code → sessionStorage.localConfig.agentCode → 实例默认值。
  // 直连实例域时 SPA 可能没把 code 写进 localStorage(入口参数缺失),getToken 不带 code
  // 只回 {"msg":"操作成功"} 无 data,必须先补上 code。
  var DEFAULT_AGENT_CODE = '660611';

  function readConfigCode() {
    try {
      var raw = window.sessionStorage.getItem('localConfig');
      if (!raw) return '';
      var cfg = JSON.parse(raw);
      return stripQuotes((cfg && cfg.agentCode) || '');
    } catch (e) { return ''; }
  }

  function resolveIdentity() {
    var apiOrigin = location.origin;
    var code = readLS('code') || readConfigCode() || DEFAULT_AGENT_CODE;
    var userKey = readLS('userKey');
    var p = userKey ? Promise.resolve(userKey)
      : fetchToken(apiOrigin, code).then(function (uk) {
          try { window.localStorage.setItem('userKey', JSON.stringify(uk)); } catch (e) {}
          return uk;
        });
    return p.then(function (uk) {
      return { apiOrigin: apiOrigin, code: code, userKey: uk };
    });
  }

  // ==========================================================================
  // 应用主体(运行在新标签页/测试 iframe 里;通过 window.__VG_CFG__ 接收配置)
  // 注意:本函数会被 toString() 后内嵌进新文档,只能引用自身作用域与全局
  // ==========================================================================
  function appMain() {
    var cfg = window.__VG_CFG__ || {};
    var API = cfg.apiOrigin;
    var SECRET = cfg.signSecret;
    var LIST_SIZE = cfg.listSize || 12;

    var state = { items: [], hls: null, retries: 0, rafId: 0, cleanup: [] };

    // ===================== debug 日志面板(仅 debug 构建) =====================
    var dbgLines = [];
    function DBG(tag, msg) {
      var d = new Date();
      var ts = d.toTimeString().slice(0, 8) + '.' + ('00' + (d.getMilliseconds())).slice(-3);
      var line = ts + ' [' + tag + '] ' + msg;
      dbgLines.push(line);
      if (dbgLines.length > 400) dbgLines.shift();
      var box = document.getElementById('vg-dbg-log');
      if (box) {
        var el = document.createElement('div');
        el.textContent = line;
        box.appendChild(el);
        box.scrollTop = box.scrollHeight;
      }
      try { console.log('[vg-dbg]', line); } catch (e) {}
    }
    function DBGcopyFallback(text, ok) {
      var ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand('copy'); ok(); }
      catch (e) { prompt(' clipboard 不可用,请手动复制:', text); }
      document.body.removeChild(ta);
    }
    function DBGbindPanel() {
      var copyBtn = document.getElementById('vg-dbg-copy');
      var clearBtn = document.getElementById('vg-dbg-clear');
      var toggleBtn = document.getElementById('vg-dbg-toggle');
      if (toggleBtn) toggleBtn.addEventListener('click', function () {
        var box = document.getElementById('vg-dbg-log');
        var open = box.style.display !== 'none';
        box.style.display = open ? 'none' : 'block';
        toggleBtn.textContent = open ? '展开 ▸' : '收起 ▾';
      });
      if (copyBtn) copyBtn.addEventListener('click', function () {
        var text = dbgLines.join('\n');
        function ok() { copyBtn.textContent = '已复制✓'; setTimeout(function () { copyBtn.textContent = '复制日志'; }, 1500); }
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(text).then(ok, function () { DBGcopyFallback(text, ok); });
        } else DBGcopyFallback(text, ok);
      });
      if (clearBtn) clearBtn.addEventListener('click', function () {
        dbgLines.length = 0;
        var box = document.getElementById('vg-dbg-log');
        if (box) box.innerHTML = '';
      });
    }

    function $(sel) { return document.querySelector(sel); }
    function status(msg, isErr) {
      var el = $('#vg-status');
      if (el) { el.textContent = msg; el.style.color = isErr ? '#ff6b6b' : '#8b93a7'; }
    }

    function sig(method, apiPath) {
      var ts = Math.floor(Date.now() / 1000).toString();
      var p = ('/' + String(apiPath).split('?')[0].split('#')[0]).replace(/\/{2,}/g, '/');
      var ver = window.CryptoJS.MD5(SECRET + ':' + ts + ':' + method.toUpperCase() + ':' + p).toString();
      return { 'X-Request-Timestamp': ts, 'X-Request-Verify': ver };
    }

    function loadList(title) {
      var q = '?title=' + encodeURIComponent(title || '') + '&num=' + LIST_SIZE + '&code=' + encodeURIComponent(cfg.code || '');
      status('加载中...');
      DBG('list', 'GET_MORE_LIST → ' + API + '/app/getMoreList' + q);
      var t0 = Date.now();
      fetch(API + '/app/getMoreList' + q, {
        method: 'POST',
        headers: Object.assign({ 'Content-Type': 'application/x-www-form-urlencoded' }, sig('POST', '/app/getMoreList'))
      })
        .then(function (r) { return r.json(); })
        .then(function (j) {
          if (!j || j.code !== 200) { status('接口异常: ' + (j && j.msg), true); DBG('list', '接口异常 ' + (Date.now() - t0) + 'ms: ' + (j && j.msg)); return; }
          state.items = j.data || [];
          status('已加载 ' + state.items.length + ' 部 · 点击封面直接播放完整片');
          DBG('list', 'OK ' + state.items.length + ' 条 · ' + (Date.now() - t0) + 'ms');
          renderGrid();
        })
        .catch(function (e) { status('列表加载失败: ' + e.message, true); DBG('list', '失败 ' + (Date.now() - t0) + 'ms: ' + e.message); });
    }

    function decodeTitle(b64) {
      try {
        var bin = atob(String(b64).replace(/\s+/g, ''));
        var bytes = new Uint8Array(bin.length);
        for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
        return new TextDecoder('utf-8').decode(bytes);
      } catch (e) { return '(标题解码失败)'; }
    }

    // 封面 1.txt:内容是倒序 base64(endsWith('/j9/') 则 reverse),data URI 直接可用。
    // 失败时把原因(HTTP 状态码/超时/网络拒绝)抛给调用方显示在卡片占位上——
    // 真机排障用:同一 URL 直连能开但 fetch 失败 = 链路对 XHR 型请求的干扰,
    // 15 秒超时兜底(fetch 默认无超时,挂起会永远停在占位动画)。
    var thumbCache = {};
    function decodeThumb(url, cb) {
      if (thumbCache[url]) return cb(thumbCache[url]);
      var t0 = Date.now();
      DBG('thumb', 'fetch → ' + url);
      var ctrl = ('AbortController' in window) ? new window.AbortController() : null;
      var timer = ctrl ? setTimeout(function () { ctrl.abort(); }, 15000) : null;
      fetch(url, ctrl ? { signal: ctrl.signal } : {})
        .then(function (r) {
          if (!r.ok) throw new Error('HTTP ' + r.status);
          return r.text();
        })
        .then(function (t) {
          if (timer) clearTimeout(timer);
          t = t.trim();
          var reversed = false;
          if (t.slice(-4) === '/j9/') { t = t.split('').reverse().join(''); reversed = true; }
          var uri = 'data:image/jpeg;base64,' + t;
          thumbCache[url] = uri;
          DBG('thumb', 'OK ' + t.length + 'B · ' + (Date.now() - t0) + 'ms · reversed=' + reversed +
            ' · head24=' + t.slice(0, 24) + ' · tail16=' + t.slice(-16) +
            (t.slice(0, 4) === '/9j/' ? '' : ' ⚠非JPEG头(解码必败)'));
          cb(uri);
        })
        .catch(function (e) {
          if (timer) clearTimeout(timer);
          var reason = (e && e.name === 'AbortError') ? '超时15s(请求挂起)' : ((e && e.message) || 'error');
          DBG('thumb', '失败 · ' + (Date.now() - t0) + 'ms · ' + reason);
          cb('', reason);
        });
    }

    // ============ 连通性差分探测(仅 debug 构建;列表渲染后自动跑一次) ============
    // 结论判读:①败+②成 = 链路只掐 CORS 型请求(放行普通 GET,典型 DPI 特征);
    //          ①②③全败/全超时 = 到 CDN 的连通性断(黑洞/封禁);
    //          ④快速失败(任意形式) = CDN 可达且响应明确;④超时 = 黑洞丢包;
    //          ⑤失败 = 播放路径同样会挂(封面和视频同域同命运)。
    //          ②用 mode:'no-cors'(成功=连通,内容不可读是预期,opaque response)。
    var probeDone = false;
    function probeFetch(name, url, opts) {
      var t0 = Date.now();
      var init = opts || {};
      var ctrl = ('AbortController' in window) ? new window.AbortController() : null;
      if (ctrl) { init.signal = ctrl.signal; }
      var timer = ctrl ? setTimeout(function () { ctrl.abort(); }, 10000) : null;
      fetch(url, init)
        .then(function (r) {
          if (timer) clearTimeout(timer);
          DBG('probe', name + ': HTTP ' + r.status + (r.status === 0 ? '(opaque,连通)' : '') + ' · ' + (Date.now() - t0) + 'ms');
        })
        .catch(function (e) {
          if (timer) clearTimeout(timer);
          var why = (e && e.name === 'AbortError') ? '超时10s(请求挂起=黑洞特征)' : ('失败 ' + ((e && e.message) || ''));
          DBG('probe', name + ': ' + why + ' · ' + (Date.now() - t0) + 'ms');
        });
    }
    function runProbes() {
      if (probeDone || !state.items.length) return;
      probeDone = true;
      var url = state.items[0].thumb;
      var dir = dirFromThumb(url);
      DBG('probe', '===== 连通性探测开始(' + url + ') =====');
      DBG('env', 'UA: ' + navigator.userAgent);
      if (navigator.connection) {
        DBG('env', 'connection: effectiveType=' + navigator.connection.effectiveType +
          ' rtt=' + navigator.connection.rtt + ' downlink=' + navigator.connection.downlink);
      }
      probeFetch('① fetch CORS(正式路径)', url);
      probeFetch('② fetch no-cors(绕过CORS检查)', url, { mode: 'no-cors' });
      var t2 = Date.now();
      try {
        var x = new XMLHttpRequest();
        x.open('GET', url, true);
        x.timeout = 15000;
        x.onload = function () { DBG('probe', '③ XHR: HTTP ' + x.status + ' · ' + (Date.now() - t2) + 'ms'); };
        x.onerror = function () { DBG('probe', '③ XHR: 失败 · ' + (Date.now() - t2) + 'ms'); };
        x.ontimeout = function () { DBG('probe', '③ XHR: 超时15s(请求挂起=黑洞特征)'); };
        x.send();
      } catch (e) { DBG('probe', '③ XHR: 异常 ' + e.message); }
      if (dir) {
        probeFetch('④ 同CDN故意404(对照:快速失败=可达/超时=黑洞)', dir + '/__vg_probe_404__.txt');
        probeFetch('⑤ m3u8预检(播放路径)', dir + '/index.m3u8');
      }
    }

    function renderGrid() {
      var grid = $('#vg-grid');
      grid.innerHTML = '';
      state.items.forEach(function (it) {
        var card = document.createElement('div');
        card.className = 'vg-card';

        var box = document.createElement('div');
        box.className = 'vg-thumb';
        var ph = document.createElement('div');
        ph.className = 'vg-ph';
        box.appendChild(ph);
        var img = document.createElement('img');
        img.alt = '';
        img.loading = 'lazy';
        img.style.display = 'none';
        img.onload = function () { img.style.display = 'block'; ph.style.display = 'none'; };
        img.onerror = function () {
          ph.textContent = '图片解码失败(dataURI ' + (img.src || '').length + 'B)';
          ph.classList.add('vg-ph-err');
          DBG('thumb', '⚠ img解码失败 · dataURI长度=' + (img.src || '').length +
            ' · 前80=' + String(img.src || '').slice(0, 80));
        };
        box.appendChild(img);
        if (it.price != null) {
          var price = document.createElement('span');
          price.className = 'vg-price';
          price.textContent = it.price + '币';
          box.appendChild(price);
        }

        var title = document.createElement('div');
        title.className = 'vg-title';
        title.textContent = decodeTitle(it.title); // textContent 防注入

        card.appendChild(box);
        card.appendChild(title);
        card.addEventListener('click', function () { openPlayer(it); });
        grid.appendChild(card);

        decodeThumb(it.thumb, function (uri, reason) {
          if (uri) { img.src = uri; }
          else { ph.textContent = '封面缺失(' + (reason || '?') + ')'; ph.classList.add('vg-ph-err'); }
        });
      });
      runProbes();
    }

    // 封面 URL → CDN 目录(绝对地址)。thumb 形如
    // http://host/20250516/xxxx/1.txt?KEY1=..&KEY2=.. → http://host/20250516/xxxx
    function dirFromThumb(thumb) {
      try {
        var u = new URL(thumb);
        var parts = u.pathname.split('/');
        parts.pop(); // 去掉 1.txt
        return u.origin + parts.join('/');
      } catch (e) { return ''; }
    }

    // ------------------------------------------------------------------
    // 播放器(浮层):控制 UI/交互与 vg_player.ks.console.js 的 buildPlayerHtml()
    // 完全一致 —— 旋转/自动横屏/±10s/双击隐藏控制条/自绘进度条(含缓冲显示)/
    // frag 加载进度状态/容器全屏/rAF tick 卡死兜底 + fatal 按类型重试(上限 3)。
    // 相对 ks 的两处适配:
    //   1) 容器从"独立标签页文档"改为片库页内全屏浮层;片库文档跨多次播放持久存在,
    //      所以 window 级监听器必须登记并在 closePlayer 里统一清理(ks 靠重写文档
    //      自然销毁,这里不清理会随播放次数累积泄漏)。
    //   2) 起播带 muted 回退(无用户手势场景的 autoplay 策略;真实点击链路会恢复声音)。
    // ------------------------------------------------------------------
    function closePlayer() {
      if (state.rafId) { cancelAnimationFrame(state.rafId); state.rafId = 0; }
      if (state.hls) { try { state.hls.destroy(); } catch (e) {} state.hls = null; }
      while (state.cleanup.length) { try { state.cleanup.pop()(); } catch (e) {} }
      var ov = $('#vg-player');
      if (ov) ov.parentNode.removeChild(ov);
    }

    function openPlayer(item) {
      var dir = dirFromThumb(item.thumb);
      if (!dir) { status('无法推导资源目录', true); return; }
      var playUrl = dir + '/index.m3u8';
      state.retries = 0;
      closePlayer();

      var ov = document.createElement('div');
      ov.id = 'vg-player';
      ov.innerHTML =
        '<div class="vg-pv-bar"><span id="vg-pv-status">加载中...</span><div class="vg-pv-btns">' +
        '  <button id="vg-pv-rotate" class="vg-pv-b vg-b-blue">⟳ 旋转</button>' +
        '  <button id="vg-pv-fs" class="vg-pv-b vg-b-gray">⛶ 全屏</button>' +
        '  <button id="vg-pv-close" class="vg-pv-b vg-b-red">× 关闭</button>' +
        '</div></div>' +
        '<video id="vg-pv-video" autoplay playsinline muted></video>' +
        '<div id="vg-pv-float">' +
        '  <div id="vg-pv-track"><div id="vg-pv-buf"></div><div id="vg-pv-prog"></div><div id="vg-pv-knob"></div></div>' +
        '  <div class="vg-pv-row">' +
        '    <button id="vg-pv-pp" class="vg-pv-b vg-b-green">▶︎/❚❚</button>' +
        '    <span id="vg-pv-time">0:00 / 0:00</span>' +
        '    <button data-d="-10" class="vg-pb-seek vg-pv-b vg-b-dark">−10s</button>' +
        '    <button data-d="10" class="vg-pb-seek vg-pv-b vg-b-dark">+10s</button>' +
        '    <button id="vg-pv-hide" class="vg-pv-b vg-b-gray" title="隐藏(双击视频恢复)">▽</button>' +
        '  </div>' +
        '</div>';
      document.body.appendChild(ov);

      var title = decodeTitle(item.title);
      var wrapEl = ov;
      var vid = $('#vg-pv-video');
      var track = $('#vg-pv-track');
      var prog = $('#vg-pv-prog');
      var buf = $('#vg-pv-buf');
      var knob = $('#vg-pv-knob');
      var timeEl = $('#vg-pv-time');
      var pp = $('#vg-pv-pp');
      var floatBox = $('#vg-pv-float');
      var statusEl = $('#vg-pv-status');
      var rotated = false;
      var retryCount = 0;
      var MAX_RETRY = 3;

      // window 级监听登记(关闭浮层时统一摘除,见 closePlayer)
      function on(target, ev, fn, opts) {
        target.addEventListener(ev, fn, opts);
        state.cleanup.push(function () { target.removeEventListener(ev, fn, opts); });
      }

      function setStatus(s) { statusEl.textContent = s; }
      function fmt(s) { if (!isFinite(s)) return '0:00'; s = Math.max(0, s | 0); var m = (s / 60) | 0, ss = s % 60; return m + ':' + (ss < 10 ? '0' : '') + ss; }
      setStatus(title || 'loading...');

      $('#vg-pv-close').addEventListener('click', closePlayer);
      pp.addEventListener('click', function () { vid.paused ? vid.play() : vid.pause(); });
      Array.prototype.forEach.call(document.querySelectorAll('.vg-pb-seek'), function (b) {
        b.addEventListener('click', function () {
          vid.currentTime = Math.max(0, Math.min(vid.duration || 0, vid.currentTime + parseFloat(b.dataset.d)));
        });
      });
      $('#vg-pv-hide').addEventListener('click', function () { floatBox.style.display = 'none'; });
      vid.addEventListener('dblclick', function () { floatBox.style.display = 'flex'; });

      // 旋转/自动横屏(与 ks 同款:transform 旋转整个容器)
      function applyLayout() {
        var vw = window.innerWidth, vh = window.innerHeight;
        if (rotated) {
          wrapEl.style.width = vh + 'px'; wrapEl.style.height = vw + 'px';
          wrapEl.style.left = ((vw - vh) / 2) + 'px'; wrapEl.style.top = ((vh - vw) / 2) + 'px';
          wrapEl.style.transform = 'rotate(90deg)';
        } else {
          wrapEl.style.width = '100vw'; wrapEl.style.height = '100vh';
          wrapEl.style.left = '0'; wrapEl.style.top = '0'; wrapEl.style.transform = 'none';
        }
      }
      function autoRotateOnMeta() {
        var vw = window.innerWidth, vh = window.innerHeight;
        var screenPortrait = vh > vw;
        var videoLandscape = vid.videoWidth > vid.videoHeight && vid.videoWidth > 0;
        if (screenPortrait && videoLandscape && !rotated) { rotated = true; applyLayout(); setStatus('↻ 自动旋转至横屏'); }
      }
      vid.addEventListener('loadedmetadata', autoRotateOnMeta);
      on(window, 'resize', applyLayout);
      on(window, 'orientationchange', function () {
        setTimeout(function () { rotated = false; applyLayout(); autoRotateOnMeta(); }, 300);
      });
      $('#vg-pv-rotate').addEventListener('click', function () { rotated = !rotated; applyLayout(); });

      // 容器全屏(含 iOS webkit 回退)
      $('#vg-pv-fs').addEventListener('click', function () {
        var req = wrapEl.requestFullscreen || wrapEl.webkitRequestFullscreen;
        var vreq = vid.webkitEnterFullscreen;
        if (req) { try { req.call(wrapEl); return; } catch (e) {} }
        if (vreq) { try { vreq.call(vid); return; } catch (e) {} }
        setStatus('本浏览器不支持容器全屏,已是沉浸式遮罩状态');
      });

      // 自绘进度条:鼠标+触摸拖动;旋转时按纵向映射(与 ks 同款)
      function seekFromEvt(e) {
        var r = track.getBoundingClientRect();
        var cx = e.touches ? e.touches[0].clientX : e.clientX;
        var cy = e.touches ? e.touches[0].clientY : e.clientY;
        var pct;
        if (rotated) { pct = Math.max(0, Math.min(1, (cy - r.top) / r.height)); }
        else { pct = Math.max(0, Math.min(1, (cx - r.left) / r.width)); }
        if (vid.duration) vid.currentTime = pct * vid.duration;
      }
      var dragging = false;
      track.addEventListener('mousedown', function (e) { dragging = true; seekFromEvt(e); e.preventDefault(); });
      on(window, 'mousemove', function (e) { if (dragging) seekFromEvt(e); });
      on(window, 'mouseup', function () { dragging = false; });
      track.addEventListener('touchstart', function (e) { dragging = true; seekFromEvt(e); }, { passive: true });
      on(window, 'touchmove', function (e) { if (dragging) seekFromEvt(e); }, { passive: true });
      on(window, 'touchend', function () { dragging = false; });

      // 起播(适配点:muted 回退;真实点击手势链路会正常恢复声音)
      function tryPlay() {
        vid.play().then(function () {
          vid.muted = false;
          var p2 = vid.play();
          if (p2 && p2.catch) p2.catch(function () { vid.muted = true; });
        }).catch(function () { vid.muted = true; try { vid.play(); } catch (e) {} });
      }

      var hls = null;
      function startLoad() {
        setStatus(title + ' · 连接资源...');
        if (window.Hls && window.Hls.isSupported()) {
          if (state.hls) { try { state.hls.destroy(); } catch (e) {} }
          hls = new window.Hls({ enableWorker: true });
          state.hls = hls;
          hls.on(window.Hls.Events.MANIFEST_PARSED, function () {
            var lvl = hls.levels[0] && hls.levels[0].details;
            if (lvl) setStatus(title + ' · ' + lvl.fragments.length + ' frags · ' + fmt(lvl.totalduration));
            tryPlay();
          });
          hls.on(window.Hls.Events.FRAG_LOADED, function (_, d) {
            setStatus(title + ' · frag ' + d.frag.sn + ' · ' + fmt(vid.currentTime) + ' / ' + fmt(vid.duration));
          });
          hls.on(window.Hls.Events.ERROR, function (_, d) {
            if (!d.fatal) return; // 非致命交给 tick() 的静默卡死兜底
            retryCount++;
            if (retryCount > MAX_RETRY) {
              setStatus('❌ 播放失败(重试' + MAX_RETRY + '次无效): ' + d.type + '/' + d.details + ' — 请记录此视频反馈');
              return;
            }
            setStatus('⚠ ' + d.type + '/' + d.details + ' 恢复中(' + retryCount + '/' + MAX_RETRY + ')...');
            try {
              if (d.type === window.Hls.ErrorTypes.NETWORK_ERROR) { hls.startLoad(); }
              else if (d.type === window.Hls.ErrorTypes.MEDIA_ERROR) { hls.recoverMediaError(); }
              else { hls.destroy(); setStatus('❌ 播放失败(无法恢复): ' + d.type + '/' + d.details); }
            } catch (e) { setStatus('❌ 恢复出错: ' + e.message); }
          });
          hls.loadSource(playUrl);
          hls.attachMedia(vid);
        } else if (vid.canPlayType('application/vnd.apple.mpegurl')) {
          vid.src = playUrl; // Safari 原生 HLS
          vid.addEventListener('loadedmetadata', tryPlay);
        } else {
          setStatus('当前环境不支持 HLS 播放');
        }
      }
      startLoad();

      // tick():进度渲染 + 静默卡死兜底(hls.js 内部自愈失败时不报 fatal、
      // 播放头不推进也无事件,只能主动侧写检测 —— 与 ks 同款 8 秒策略)
      var lastProgressAt = Date.now(), lastCT = 0, stallCooldownAt = 0;
      function tick() {
        if (!vid.isConnected) return; // 浮层已关闭,停止循环
        if (vid.duration) {
          var pct = (vid.currentTime / vid.duration) * 100;
          prog.style.width = pct + '%';
          knob.style.left = pct + '%';
          if (vid.buffered.length) {
            var bEnd = vid.buffered.end(vid.buffered.length - 1);
            buf.style.width = (bEnd / vid.duration * 100) + '%';
          }
        }
        timeEl.textContent = fmt(vid.currentTime) + ' / ' + fmt(vid.duration);
        var now = Date.now();
        if (!vid.paused && vid.currentTime === lastCT) {
          if (now - lastProgressAt > 8000 && now - stallCooldownAt > 8000) {
            setStatus('⚠ 播放卡住,尝试恢复...');
            try { if (hls) hls.startLoad(vid.currentTime); } catch (e) {}
            stallCooldownAt = now;
          }
        } else { lastCT = vid.currentTime; lastProgressAt = now; }
        state.rafId = requestAnimationFrame(tick);
      }
      tick();
    }

    // ------------------------------------------------------------------
    // 静态骨架 + 事件绑定
    // ------------------------------------------------------------------
    $('#vg-search-btn').addEventListener('click', function () {
      loadList($('#vg-search-input').value.trim());
    });
    $('#vg-search-input').addEventListener('keydown', function (e) {
      if (e.key === 'Enter') loadList(this.value.trim());
    });
    $('#vg-more-btn').addEventListener('click', function () { loadList(''); });
    DBGbindPanel();
    DBG('env', 'appMain 启动 · API=' + API + ' · code=' + cfg.code + ' · userKey=' + (cfg.userKey || '(空)'));
    loadList('');
  }

  // ==========================================================================
  // 文档模板(新标签页与测试 iframe 共用)
  // ==========================================================================
  function buildAppHtml(cfg) {
    var appJs = '(' + appMain.toString() + ')();';
    var cfgJs = 'window.__VG_CFG__ = ' + JSON.stringify(cfg) + ';';
    return '<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">' +
      '<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">' +
      '<title>VG Library · junma 原型</title>' +
      '<style>' + APP_CSS + '</style>' +
      '</head><body>' +
      '<div class="vg-app">' +
      '  <div class="vg-head">' +
      '    <div class="vg-brand">VG Library <span class="vg-sub">junma 技术验证原型</span></div>' +
      '    <div class="vg-search">' +
      '      <input id="vg-search-input" type="text" placeholder="搜索关键字">' +
      '      <div id="vg-search-btn" class="vg-btn">搜索</div>' +
      '      <div id="vg-more-btn" class="vg-btn vg-btn-ghost">换一批</div>' +
      '    </div>' +
      '  </div>' +
      '  <div id="vg-status" class="vg-status">初始化...</div>' +
      '  <div id="vg-grid" class="vg-grid"></div>' +
      '</div>' +
      '<div id="vg-dbg">' +
      '  <div class="vg-dbg-bar"><span>VG Debug(仅排障构建)</span>' +
      '    <span id="vg-dbg-toggle" class="vg-dbg-btn">收起 ▾</span>' +
      '    <span id="vg-dbg-copy" class="vg-dbg-btn">复制日志</span>' +
      '    <span id="vg-dbg-clear" class="vg-dbg-btn">清空</span>' +
      '  </div>' +
      '  <div id="vg-dbg-log"></div>' +
      '</div>' +
      '<script src="' + CRYPTO_JS_SRC + '"><\/script>' +
      '<script src="' + HLS_JS_SRC + '"><\/script>' +
      '<script>' + cfgJs + '<\/script>' +
      '<script>' + appJs + '<\/script>' +
      '</body></html>';
  }

  var APP_CSS =
    '*{margin:0;padding:0;box-sizing:border-box}' +
    'body{background:#0f1115;color:#e8eaf0;font-family:-apple-system,"PingFang SC","Segoe UI",Roboto,sans-serif}' +
    '.vg-app{max-width:860px;margin:0 auto;padding:16px 14px 40px}' +
    '.vg-head{display:flex;flex-direction:column;gap:10px;margin-bottom:10px}' +
    '.vg-brand{font-size:18px;font-weight:700;letter-spacing:.5px}' +
    '.vg-sub{font-size:11px;font-weight:400;color:#8b93a7;margin-left:6px}' +
    '.vg-search{display:flex;gap:8px}' +
    '.vg-search input{flex:1;background:#1a1d24;border:1px solid #2a2f3a;border-radius:8px;' +
    'color:#e8eaf0;padding:9px 12px;font-size:14px;outline:none}' +
    '.vg-search input:focus{border-color:#4f8cff}' +
    '.vg-btn{background:#4f8cff;color:#fff;border-radius:8px;padding:9px 14px;font-size:14px;' +
    'cursor:pointer;user-select:none;white-space:nowrap}' +
    '.vg-btn:active{opacity:.8}' +
    '.vg-btn-ghost{background:transparent;border:1px solid #2a2f3a;color:#8b93a7}' +
    '.vg-status{font-size:12px;color:#8b93a7;margin:2px 0 12px;min-height:16px}' +
    '.vg-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:12px}' +
    '.vg-card{cursor:pointer}' +
    '.vg-thumb{position:relative;aspect-ratio:3/4;border-radius:10px;overflow:hidden;' +
    'background:#1a1d24;border:1px solid #22262f}' +
    '.vg-thumb img{width:100%;height:100%;object-fit:cover;display:block}' + // 修复原站拉伸失真
    '.vg-ph{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;' +
    'color:#3a404d;font-size:12px;background:linear-gradient(110deg,#1a1d24 8%,#22262f 18%,#1a1d24 33%)}' +
    '.vg-ph-err{color:#ff6b6b;font-size:11px;padding:4px;text-align:center;line-height:1.5}' +
    '#vg-dbg{position:fixed;left:8px;bottom:8px;width:min(560px,86vw);z-index:2147483000;' +
    'background:rgba(8,10,14,.94);border:1px solid #2a2f3a;border-radius:8px;overflow:hidden;' +
    'font:11px/1.5 Menlo,Consolas,monospace}' +
    '.vg-dbg-bar{display:flex;gap:10px;align-items:center;padding:5px 9px;background:#141821;color:#8b93a7}' +
    '.vg-dbg-btn{cursor:pointer;color:#4f8cff;border:1px solid #2a2f3a;border-radius:5px;padding:1px 7px;margin-left:auto}' +
    '.vg-dbg-btn + .vg-dbg-btn{margin-left:0}' +
    '#vg-dbg-log{max-height:34vh;overflow-y:auto;padding:6px 9px;color:#a8b3c7;' +
    'white-space:pre-wrap;word-break:break-all}' +
    '.vg-price{position:absolute;top:6px;right:6px;background:rgba(0,0,0,.65);color:#ffd166;' +
    'font-size:11px;padding:2px 7px;border-radius:6px}' +
    '.vg-title{font-size:13px;line-height:1.4;color:#c9cedb;margin-top:7px;height:36px;' +
    'overflow:hidden;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical}' +
    '.vg-card:active .vg-thumb{opacity:.85}' +
    '#vg-player{position:fixed;left:0;top:0;width:100vw;height:100vh;background:#000;' +
    'z-index:2147483647;display:flex;flex-direction:column;transform-origin:center center;' +
    'transition:transform .2s}' +
    '.vg-pv-bar{height:40px;background:#111;color:#fff;display:flex;align-items:center;' +
    'justify-content:space-between;padding:0 12px;font:13px/1 -apple-system,sans-serif;' +
    'box-sizing:border-box;flex-shrink:0}' +
    '.vg-pv-btns{display:flex;gap:8px}' +
    '#vg-pv-video{flex:1;width:100%;min-height:0;background:#000;object-fit:contain;display:block}' +
    '#vg-pv-float{position:absolute;left:50%;top:50%;transform:translate(-50%,-50%);z-index:999;' +
    'background:rgba(0,0,0,.7);color:#fff;padding:16px 20px;border-radius:12px;display:flex;' +
    'flex-direction:column;gap:10px;width:82%;max-width:380px;font:14px/1.3 -apple-system,sans-serif;' +
    'box-shadow:0 6px 24px rgba(0,0,0,.6)}' +
    '#vg-pv-track{position:relative;height:16px;background:#444;border-radius:8px;cursor:pointer}' +
    '#vg-pv-buf{position:absolute;left:0;top:0;bottom:0;background:#777;border-radius:8px;width:0%}' +
    '#vg-pv-prog{position:absolute;left:0;top:0;bottom:0;background:#e33;border-radius:8px;width:0%}' +
    '#vg-pv-knob{position:absolute;top:50%;transform:translate(-50%,-50%);left:0%;width:22px;height:22px;' +
    'background:#fff;border-radius:50%;box-shadow:0 2px 6px rgba(0,0,0,.5);pointer-events:none}' +
    '.vg-pv-b{border:0;border-radius:6px;color:#fff;padding:8px 12px;font-size:13px;cursor:pointer}' +
    '.vg-b-blue{background:#37a}.vg-b-gray{background:#555}.vg-b-red{background:#e33}' +
    '.vg-b-green{background:#2a7;font-size:16px}.vg-b-dark{background:#333}' +
    '.vg-pv-row{display:flex;align-items:center;justify-content:space-between;gap:10px}' +
    '#vg-pv-time{font-variant-numeric:tabular-nums}';

  // ==========================================================================
  // 入口
  // ==========================================================================
  function main() {
    if (!HOST_PATTERN.test(location.hostname)) {
      alert('VG Library: 请在 2v56(骏马) 站点页面上运行');
      return;
    }
    resolveIdentity()
      .then(function (cfg) {
        cfg.signSecret = SIGN_SECRET;
        cfg.listSize = LIST_SIZE;
        var html = buildAppHtml(cfg);

        // 测试模式:写进当前页临时 iframe(与新标签页走同一条 writeApp 路径)
        if (window.__VG_LIB_INLINE__ === true) {
          var f = document.createElement('iframe');
          f.setAttribute('style', 'position:fixed;inset:0;width:100vw;height:100vh;' +
            'border:0;z-index:2147483647;background:#0f1115');
          document.body.appendChild(f);
          var idoc = f.contentDocument || f.contentWindow.document;
          idoc.open();
          idoc.write(html);
          idoc.close();
          window.__vg_lib_iframe__ = f;
          log('inline 模式已挂载');
          return;
        }

        // 默认:写入(loader 同步打开的)新标签页
        var w = (window.__vg_player_win__ && !window.__vg_player_win__.closed)
          ? window.__vg_player_win__
          : window.open('', '_blank');
        if (!w) { alert('VG Library: 新标签页被拦截,请允许弹窗后重试'); return; }
        w.document.open();
        w.document.write(html);
        w.document.close();
        log('新标签页已挂载');
      })
      .catch(function (e) {
        alert('VG Library 初始化失败: ' + e.message);
      });
  }

  // 依赖(签名需要 CryptoJS 的 MD5;应用文档里会各自再加载一份供新文档使用)
  loadScript(CRYPTO_JS_SRC, 'CryptoJS')
    .then(main)
    .catch(function (e) { alert('VG Library: ' + e.message); });
})();
