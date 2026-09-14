(function () {
  'use strict';

  // ==========================================================================
  // VG Player 91p —— 91PORN (OIO族·vid代平台) 书签播放器
  // 目标站点: d2539of4u288zx.cloudfront.net (H5) / API 池: d122lhoqt6shfh,
  //          d2dyiyxr71jnmg.cloudfront.net, gx5q5.com
  //
  // 协议(逆向自 main-c9fc37b3.*.js, 2026-09-14 验证):
  // - 请求加密: AES-CBC-PKCS7(key=iv="BxJand%xf5h3sycH") over JSON → base64
  //   POST body {"data":"<b64>"} / GET ?data=<urlencode(b64)>
  // - 响应解密: {"data":"<b64>","hash":true} → 前12字节盐+密文,
  //   双SHA256派生(interfaceKey="65dc07d1b7915c6b2937432b091837a7") → AES-CBC
  // - 无请求签名(无 x-api-key), 只有 temp:"test" + X-User-Agent + Authorization
  // - 登录: POST /mine/login/h5 {devID,sysType,cutInfos,isAppStore} → 新账号
  //   (watchCount=3 免费额度, 且有 4007 频率限制文案)
  // - 付费墙只在前端: /vid/info 对未购买视频也返回完整 sourceURL,
  //   m3u8 端点 /api/app/vid/h5/m3u8/<sourceURL>?token= 不校验购买(实测
  //   50金币未购买视频返回全片 295s/34 片), AES key /api/app/vid/sec 连
  //   token 都不要。ts 为 AES-128-CBC, IV=media sequence(hls.js 自动处理)。
  //
  // 用法: 在 91p H5 任意页面点击。URL 带 ?vid= 时直接播该片; 否则拉推荐列表
  // 让用户输序号选择。每次点击自动注册全新账号(不消耗用户自己账号)。
  // ==========================================================================

  var H5_HOST = 'd2539of4u288zx.cloudfront.net';
  var API_CANDIDATES = [
    'https://d122lhoqt6shfh.cloudfront.net',
    'https://d2dyiyxr71jnmg.cloudfront.net',
    'https://gx5q5.com'
  ];
  var PARAM_KEY = 'BxJand%xf5h3sycH';
  var PARAM_IV = 'BxJand%xf5h3sycH';
  var INTERFACE_KEY = '65dc07d1b7915c6b2937432b091837a7';
  var CRYPTO_JS_SRC = 'https://cdn.jsdelivr.net/npm/crypto-js@4.2.0/crypto-js.min.js';
  var HLS_JS_SRC = 'https://cdn.jsdelivr.net/npm/hls.js@1.6.19/dist/hls.min.js';
  var LS_TOKEN_KEY = 'vg91p_stored_token';

  var log = function (m) { try { console.log('[vg-91p]', m); } catch (e) {} };

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

  // ==========================================================================
  // 加密/解密
  // ==========================================================================

  function paramEncrypt(params) {
    var raw = CryptoJS.enc.Utf8.parse(JSON.stringify(params));
    var key = CryptoJS.enc.Utf8.parse(PARAM_KEY);
    var iv = CryptoJS.enc.Utf8.parse(PARAM_IV);
    var enc = CryptoJS.AES.encrypt(raw, key, { iv: iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
    return CryptoJS.enc.Base64.stringify(enc.ciphertext);
  }

  function wordsToBytes(words, sigBytes) {
    var out = [];
    for (var i = 0; i < sigBytes; i++) out.push((words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff);
    return out;
  }
  function bytesToWordArray(bytes) {
    var words = [];
    for (var i = 0; i < bytes.length; i++) words[i >>> 2] = (words[i >>> 2] || 0) | (bytes[i] << (24 - (i % 4) * 8));
    return CryptoJS.lib.WordArray.create(words, bytes.length);
  }
  function sha256Bytes(bytes) {
    var d = CryptoJS.SHA256(bytesToWordArray(bytes));
    return wordsToBytes(d.words, d.sigBytes);
  }
  function concatBytes() {
    var out = [], i, j;
    for (i = 0; i < arguments.length; i++) for (j = 0; j < arguments[i].length; j++) out.push(arguments[i][j]);
    return out;
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

  function respDecrypt(b64) {
    var raw = CryptoJS.enc.Base64.parse(b64);
    var rawBytes = wordsToBytes(raw.words, raw.sigBytes);
    if (rawBytes.length < 12) throw new Error('payload too short');
    var salt = rawBytes.slice(0, 12);
    var cipher = rawBytes.slice(12);
    var o = concatBytes(strToBytes(INTERFACE_KEY), salt);
    var n = Math.floor(o.length / 2);
    var l = sha256Bytes(o).slice(8, 24);
    var p = sha256Bytes(concatBytes(l, o.slice(0, n)));
    var u = sha256Bytes(concatBytes(o.slice(n), l));
    var key = concatBytes(p.slice(0, 8), u.slice(8, 24), p.slice(24, 32));
    var iv = concatBytes(u.slice(0, 4), p.slice(12, 20), u.slice(28, 32));
    var dec = CryptoJS.AES.decrypt(
      { ciphertext: bytesToWordArray(cipher) },
      bytesToWordArray(key),
      { iv: bytesToWordArray(iv), mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 }
    );
    return JSON.parse(dec.toString(CryptoJS.enc.Utf8));
  }

  // ==========================================================================
  // API 层
  // ==========================================================================

  function uuid32() {
    var hex = '0123456789abcdef', s = '';
    for (var i = 0; i < 32; i++) s += hex[(Math.random() * 16) | 0];
    return s.toUpperCase();
  }

  var API_BASE = sessionStorage.getItem('vg91p_api') || '';

  // 站方 pinia config store 里存着当前 baseUrl(比 ping 探测更准)
  function readSiteConfig() {
    try {
      var app = document.getElementById('app').__vue_app__;
      var pinia = app.config.globalProperties.$pinia;
      var cfg = pinia._s.get('config');
      var base = cfg && cfg.baseUrl;
      if (base && /^https?:\/\//.test(base)) { API_BASE = base; sessionStorage.setItem('vg91p_api', base); }
    } catch (e) {}
  }

  async function resolveApiBase() {
    if (API_BASE) return API_BASE;
    readSiteConfig();
    if (API_BASE) return API_BASE;
    for (var i = 0; i < API_CANDIDATES.length; i++) {
      var host = API_CANDIDATES[i];
      try {
        var ctl = new AbortController();
        var t = setTimeout(function () { ctl.abort(); }, 5000);
        var r = await fetch(host + '/api/app/ping/check', { signal: ctl.signal });
        clearTimeout(t);
        if (r.ok) { API_BASE = host; sessionStorage.setItem('vg91p_api', host); log('API base: ' + host); return host; }
      } catch (e) { log('ping 失败 ' + host + ': ' + e.message); }
    }
    throw new Error('所有 API 主机不可达: ' + API_CANDIDATES.join(', '));
  }

  function buildUA(devid, sid) {
    return 'BuildID=com.abc.Butterfly;SysType=ios;DevID=' + devid + ';Ver=1.0.0;DevType=iPhone;' +
      'DeviceBrand=Apple;DeviceModel=iPhone;SystemName=iOS;SystemVersion=17.0;Terminal=1;IsH5=1;Sid=' + sid;
  }

  async function apiCall(path, params, token, method) {
    var devid = window.__vg91p_devid__ || uuid32();
    window.__vg91p_devid__ = devid;
    var sid = window.__vg91p_sid__ || (window.__vg91p_sid__ = uuid32().toLowerCase());
    var headers = {
      'temp': 'test',
      'X-User-Agent': buildUA(devid, sid),
      'Content-Type': 'application/json'
    };
    if (token) headers['Authorization'] = token;
    // 网关节点配置漂移(实测同一端点在不同主机上会 404/超时), 逐主机故障转移
    var hosts = [];
    if (API_BASE) hosts.push(API_BASE);
    for (var i = 0; i < API_CANDIDATES.length; i++) {
      if (API_CANDIDATES[i] !== API_BASE) hosts.push(API_CANDIDATES[i]);
    }
    var body = method === 'POST' ? JSON.stringify(params ? { data: paramEncrypt(params) } : {}) : undefined;
    var qs = (method !== 'POST' && params) ? '?data=' + encodeURIComponent(paramEncrypt(params)) : '';
    var lastErr = '';
    for (var h = 0; h < hosts.length; h++) {
      var base = hosts[h];
      try {
        var ctl = new AbortController();
        var t = setTimeout(function () { ctl.abort(); }, 8000);
        var r = await fetch(base + '/api/app' + path + qs, {
          method: method || 'GET', headers: headers, body: body, signal: ctl.signal
        });
        clearTimeout(t);
        var j = await r.json();
        if (j && typeof j.code !== 'undefined') {
          API_BASE = base; sessionStorage.setItem('vg91p_api', base);
          if (j.hash && typeof j.data === 'string') {
            try { j.data = respDecrypt(j.data); } catch (e) { log('解密失败: ' + e.message); }
          }
          j._http = r.status;
          return j;
        }
        lastErr = 'http ' + r.status + ' ' + JSON.stringify(j).slice(0, 80);
        log('主机不可用 ' + base + ': ' + lastErr);
      } catch (e) {
        lastErr = e.message;
        log('主机失败 ' + base + ': ' + e.message);
      }
    }
    throw new Error('全部 API 主机失败(' + path + '): ' + lastErr);
  }

  // 站方自己的 token 只存内存(pinia user store), 不落 localStorage
  function readSiteToken() {
    try {
      var app = document.getElementById('app').__vue_app__;
      var pinia = app.config.globalProperties.$pinia;
      var user = pinia._s.get('user');
      var t = user && (user.token || (user.userInfo && user.userInfo.token));
      return (t && typeof t === 'string' && t.length > 40) ? t : '';
    } catch (e) { return ''; }
  }

  async function getToken() {
    // 1) 站方现成登录态(零成本, 用户正常打开 App 后必有)
    var site = readSiteToken();
    if (site) { log('使用站方 token'); return { token: site, fresh: false }; }
    // 2) 上次书签存的 token
    var stored = localStorage.getItem(LS_TOKEN_KEY) || '';
    if (stored) { log('使用书签缓存 token'); return { token: stored, fresh: false }; }
    // 3) 全新注册(每次新号 watchCount=3; IP 限频 4007 时走不到这)
    try {
      return { token: await registerFresh(), fresh: true };
    } catch (e) { log('注册登录失败: ' + e.message); }
    throw new Error('无法取得 token: 站方未登录且新号注册被限频(4007), 请等几分钟或先在站内登录');
  }

  async function registerFresh() {
    var j = await apiCall('/mine/login/h5',
      { devID: uuid32(), sysType: 'ios', cutInfos: '', isAppStore: false }, '', 'POST');
    if (j.code === 200 && j.data && j.data.token) {
      log('全新账号登录成功 uid=' + j.data.uid + ' watchCount=' + j.data.watchCount);
      localStorage.setItem(LS_TOKEN_KEY, j.data.token);
      return j.data.token;
    }
    throw new Error('登录 code=' + j.code + ' tip=' + (j.tip || j.msg || ''));
  }

  async function getVidFromUrl() {
    var m = location.href.match(/[?&]vid=([^&]+)/) || location.href.match(/[?&]videoID=([^&]+)/);
    return m ? decodeURIComponent(m[1]) : '';
  }

  async function pickFromList(token) {
    var j = await apiCall('/recommend/vid/list', { pageNumber: 1, pageSize: 20 }, token, 'GET');
    var items = (j.data && j.data.vInfos) || [];
    if (!items.length) throw new Error('推荐列表为空');
    var lines = items.map(function (v, i) {
      return (i + 1) + '. [' + ((v.originCoins || 0) > 0 ? v.originCoins + '币' : '免费') + '] ' +
        String(v.title || '').slice(0, 24);
    }).join('\n');
    var pick = prompt('未检测到 ?vid= 参数, 输入序号播放:\n\n' + lines, '1');
    if (!pick) throw new Error('已取消');
    var idx = parseInt(pick, 10) - 1;
    if (!(idx >= 0 && idx < items.length)) throw new Error('序号无效');
    return items[idx];
  }

  function apiHosts() {
    var hosts = [];
    if (API_BASE) hosts.push(API_BASE);
    for (var i = 0; i < API_CANDIDATES.length; i++) {
      if (API_CANDIDATES[i] !== API_BASE) hosts.push(API_CANDIDATES[i]);
    }
    return hosts;
  }

  async function fetchM3u8Text(token, sourceURL) {
    var rel = '/api/app/vid/h5/m3u8/' + sourceURL.replace(/^\/+/, '') +
      '?token=' + encodeURIComponent(token) + '&c=';
    var lastErr = '';
    var hosts = apiHosts();
    for (var h = 0; h < hosts.length; h++) {
      try {
        var r = await fetch(hosts[h] + rel);
        var text = await r.text();
        if (text.charAt(0) === '{') {
          var j = JSON.parse(text);
          lastErr = 'm3u8 错误: ' + (j.tip || j.msg || 'code ' + j.code);
          log('m3u8 ' + hosts[h] + ' -> ' + lastErr);
          continue;
        }
        API_BASE = hosts[h]; sessionStorage.setItem('vg91p_api', hosts[h]);
        // 返回真实签名 URL: iOS 原生 HLS 兜底时直接交给系统播放器(不受 MSE/CORS 限制)
        return { text: text, url: hosts[h] + rel };
      } catch (e) { lastErr = e.message; log('m3u8 主机失败 ' + hosts[h] + ': ' + e.message); }
    }
    throw new Error(lastErr || 'm3u8 全部主机失败');
  }

  // 91p 服务端在路径/额度异常时不报错、静默回吐兜底预告片(实测 13.5s 单片),
  // 原生播放器会无声播完预告即结束 —— 用户完全无从 debug。拿到 m3u8 先体检:
  // 短清单 = 预告 → 刷额度重试, 仍预告则明确报错。
  function inspectM3u8(text) {
    var frags = (text.match(/#EXTINF/g) || []).length;
    var dur = 0, re = /#EXTINF:([\d.]+)/g, m;
    while ((m = re.exec(text))) dur += parseFloat(m[1]);
    return { frags: frags, duration: Math.round(dur), isPreview: dur > 0 && dur < 90 };
  }

  async function fetchKeyBytes(token) {
    var hosts = apiHosts();
    for (var h = 0; h < hosts.length; h++) {
      try {
        var r = await fetch(hosts[h] + '/api/app/vid/sec?token=' + encodeURIComponent(token));
        var buf = await r.arrayBuffer();
        var bytes = new Uint8Array(buf);
        if (bytes.length === 16) return bytes;
        log('key 主机 ' + hosts[h] + ' 返回 ' + bytes.length + ' 字节');
      } catch (e) { log('key 主机失败 ' + hosts[h] + ': ' + e.message); }
    }
    throw new Error('AES key 获取失败(全部主机)');
  }

  async function injectKey(m3u8Text, token) {
    var m = m3u8Text.match(/#EXT-X-KEY:METHOD=AES-128,URI="([^"]*)"/);
    if (!m) { log('无加密行, 原样使用'); return m3u8Text; }
    var bytes = await fetchKeyBytes(token);
    var s = '';
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    var dataUri = 'data:application/octet-stream;base64,' + btoa(s);
    return m3u8Text.replace(/(#EXT-X-KEY:METHOD=AES-128,URI=")[^"]*(")/, '$1' + dataUri + '$2');
  }

  // ==========================================================================
  // 播放器(与 OIO 同款: 新标签页 + Blob m3u8 + hls.js)
  // ==========================================================================

  function openPlayerWindow() {
    try {
      var pre = window.__vg_player_win__;
      if (pre && !pre.closed) return pre;
    } catch (e) {}
    try { return window.open('', '_blank'); } catch (e) { return null; }
  }

  function buildPlayerHtml(title, m3u8Text, m3u8Url) {
    var titleSafe = (title || 'VG Player 91p').replace(/</g, '&lt;');
    var m3u8Json = JSON.stringify(m3u8Text);
    var titleJson = JSON.stringify(title || '');
    var realUrlJson = JSON.stringify(m3u8Url || '');
    return '<!DOCTYPE html><html><head><meta charset="utf-8">' +
      '<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">' +
      '<title>' + titleSafe + '</title>' +
      '<style>' +
        'html,body{margin:0;padding:0;height:100%;background:#000;overflow:hidden;}' +
        '#wrap{position:fixed;left:0;top:0;width:100vw;height:100vh;background:#000;display:flex;flex-direction:column;transform-origin:center center;transition:transform .2s;}' +
        '#bar{height:40px;background:#111;color:#fff;display:flex;align-items:center;justify-content:space-between;padding:0 12px;font:13px/1 -apple-system,sans-serif;box-sizing:border-box;flex-shrink:0;}' +
        '#bar .btns{display:flex;gap:8px;}' +
        '#video{flex:1;width:100%;background:#000;object-fit:contain;display:block;}' +
        '#float{position:absolute;left:50%;top:50%;transform:translate(-50%,-50%);z-index:999;background:rgba(0,0,0,.7);color:#fff;padding:16px 20px;border-radius:12px;display:flex;flex-direction:column;gap:10px;width:82%;max-width:380px;font:14px/1.3 -apple-system,sans-serif;box-shadow:0 6px 24px rgba(0,0,0,.6);}' +
        '#track{position:relative;height:16px;background:#444;border-radius:8px;cursor:pointer;}' +
        '#buf{position:absolute;left:0;top:0;bottom:0;background:#777;border-radius:8px;width:0%;}' +
        '#prog{position:absolute;left:0;top:0;bottom:0;background:#e33;border-radius:8px;width:0%;}' +
        '#knob{position:absolute;top:50%;transform:translate(-50%,-50%);left:0%;width:22px;height:22px;background:#fff;border-radius:50%;box-shadow:0 2px 6px rgba(0,0,0,.5);pointer-events:none;}' +
        'button{border:0;border-radius:6px;color:#fff;padding:8px 12px;font-size:13px;}' +
      '</style></head><body>' +
      '<div id="wrap">' +
        '<div id="bar"><span id="status">加载中...</span><div class="btns">' +
          '<button id="rotateBtn" style="background:#37a;">⟳ 旋转</button>' +
          '<button id="fsBtn" style="background:#555;">⛶ 全屏</button>' +
          '<button id="closeBtn" style="background:#e33;">× 关闭</button>' +
        '</div></div>' +
        '<video id="video" autoplay playsinline></video>' +
        '<div id="float">' +
          '<div id="track"><div id="buf"></div><div id="prog"></div><div id="knob"></div></div>' +
          '<div style="display:flex;align-items:center;justify-content:space-between;gap:10px;">' +
            '<button id="pp" style="background:#2a7;font-size:16px;">▶︎/❚❚</button>' +
            '<span id="t" style="font-variant-numeric:tabular-nums;">0:00 / 0:00</span>' +
            '<button data-d="-10" class="seek" style="background:#333;">−10s</button>' +
            '<button data-d="10" class="seek" style="background:#333;">+10s</button>' +
            '<button id="hideBtn" style="background:#555;" title="隐藏(双击视频恢复)">▽</button>' +
          '</div>' +
        '</div>' +
      '</div>' +
      '<script src="https://cdn.jsdelivr.net/npm/hls.js@1.6.19/dist/hls.min.js"></script>' +
      '<script>(function(){' +
        'var diagLock=false;' +
        'var m3u8Text=' + m3u8Json + ';' +
        'var realUrl=' + realUrlJson + ';' +
        'var titleText=' + titleJson + ';' +
        'var wrap=document.getElementById("wrap");' +
        'var vid=document.getElementById("video");' +
        'var status=document.getElementById("status");' +
        'var track=document.getElementById("track");' +
        'var prog=document.getElementById("prog");' +
        'var buf=document.getElementById("buf");' +
        'var knob=document.getElementById("knob");' +
        'var t=document.getElementById("t");' +
        'var pp=document.getElementById("pp");' +
        'var floatBox=document.getElementById("float");' +
        'function fmt(s){if(!isFinite(s))return "0:00";s=Math.max(0,s|0);var m=(s/60)|0,ss=s%60;return m+":"+(ss<10?"0":"")+ss;}' +
        'function setStatus(s){status.textContent=s;}' +
        'setStatus(titleText||"loading...");' +
        'document.getElementById("closeBtn").onclick=function(){window.close();};' +
        'pp.onclick=function(){vid.paused?vid.play():vid.pause();};' +
        'document.querySelectorAll(".seek").forEach(function(b){b.onclick=function(){vid.currentTime=Math.max(0,Math.min(vid.duration||0,vid.currentTime+parseFloat(b.dataset.d)));};});' +
        'document.getElementById("hideBtn").onclick=function(){floatBox.style.display="none";};' +
        'vid.addEventListener("dblclick",function(){floatBox.style.display="flex";});' +
        'var rotated=false;' +
        'function applyLayout(){' +
          'var vw=window.innerWidth,vh=window.innerHeight;' +
          'if(rotated){' +
            'wrap.style.width=vh+"px";wrap.style.height=vw+"px";' +
            'wrap.style.left=((vw-vh)/2)+"px";wrap.style.top=((vh-vw)/2)+"px";' +
            'wrap.style.transform="rotate(90deg)";' +
          '}else{' +
            'wrap.style.width="100vw";wrap.style.height="100vh";' +
            'wrap.style.left="0";wrap.style.top="0";wrap.style.transform="none";' +
          '}' +
        '}' +
        'function autoRotateOnMeta(){' +
          'var vw=window.innerWidth,vh=window.innerHeight;' +
          'var screenPortrait=vh>vw;' +
          'var videoLandscape=vid.videoWidth>vid.videoHeight&&vid.videoWidth>0;' +
          'if(screenPortrait&&videoLandscape&&!rotated){rotated=true;applyLayout();setStatus("↻ 自动旋转至横屏");}' +
        '}' +
        'vid.addEventListener("loadedmetadata",autoRotateOnMeta);' +
        'window.addEventListener("resize",applyLayout);' +
        'window.addEventListener("orientationchange",function(){setTimeout(function(){rotated=false;applyLayout();autoRotateOnMeta();},300);});' +
        'document.getElementById("rotateBtn").onclick=function(){rotated=!rotated;applyLayout();};' +
        'document.getElementById("fsBtn").onclick=function(){' +
          'var el=document.documentElement;' +
          'var req=el.requestFullscreen||el.webkitRequestFullscreen||el.webkitEnterFullscreen;' +
          'var vreq=vid.webkitEnterFullscreen;' +
          'if(req){try{req.call(el);return;}catch(e){}}' +
          'if(vreq){try{vreq.call(vid);return;}catch(e){}}' +
          'alert("本浏览器不支持容器全屏,已是沉浸式遮罩状态");' +
        '};' +
        'function seekFromEvt(e){var r=track.getBoundingClientRect();var cx=e.touches?e.touches[0].clientX:e.clientX;var cy=e.touches?e.touches[0].clientY:e.clientY;var pct;if(rotated){pct=Math.max(0,Math.min(1,(cy-r.top)/r.height));}else{pct=Math.max(0,Math.min(1,(cx-r.left)/r.width));}if(vid.duration)vid.currentTime=pct*vid.duration;}' +
        'var dragging=false;' +
        'track.addEventListener("mousedown",function(e){dragging=true;seekFromEvt(e);e.preventDefault();});' +
        'window.addEventListener("mousemove",function(e){if(dragging)seekFromEvt(e);});' +
        'window.addEventListener("mouseup",function(){dragging=false;});' +
        'track.addEventListener("touchstart",function(e){dragging=true;seekFromEvt(e);},{passive:true});' +
        'window.addEventListener("touchmove",function(e){if(dragging)seekFromEvt(e);},{passive:true});' +
        'window.addEventListener("touchend",function(){dragging=false;});' +
        'var lastProgressAt=Date.now(),lastCT=0,stallCooldownAt=0,retryCount=0,MAX_RETRY=3;' +
        'function tick(){' +
          'if(vid.duration){var pct=(vid.currentTime/vid.duration)*100;prog.style.width=pct+"%";knob.style.left=pct+"%";if(vid.buffered.length){var bEnd=vid.buffered.end(vid.buffered.length-1);buf.style.width=(bEnd/vid.duration*100)+"%";}}' +
          't.textContent=fmt(vid.currentTime)+" / "+fmt(vid.duration);' +
          'var now=Date.now();' +
          'if(!vid.paused&&vid.currentTime===lastCT){' +
            'if(now-lastProgressAt>8000&&now-stallCooldownAt>8000){' +
              'setStatus("⚠ 播放卡住,尝试恢复...");' +
              'try{hls.startLoad(vid.currentTime);}catch(e){}' +
              'stallCooldownAt=now;' +
            '}' +
          '}else{lastCT=vid.currentTime;lastProgressAt=now;}' +
          'requestAnimationFrame(tick);' +
        '}' +
        'tick();' +
        'function tapToPlay(){setStatus("▶ 点击画面播放(恢复声音)");vid.onclick=function(){vid.muted=false;vid.play().catch(function(e){setStatus("play() "+e.message);});};}' +
        'var nativeStarted=false;' +
        'function tryNative(reason){' +
          'if(nativeStarted||!realUrl)return false;' +
          'nativeStarted=true;' +
          'setStatus(titleText+" · 切换系统播放器(原生 HLS)"+(reason?" ["+reason+"]":"")+"...");' +
          'vid.src=realUrl;' +
          'vid.addEventListener("loadedmetadata",function(){setStatus(titleText+" · "+fmt(vid.duration));});' +
          'vid.play().catch(function(){vid.muted=true;vid.play().catch(function(){tapToPlay();});});' +
          'return true;' +
        '}' +
        'if(window.Hls&&Hls.isSupported()){' +
          'var hls=new Hls({enableWorker:true});' +
          'hls.on(Hls.Events.MANIFEST_PARSED,function(){var L0=hls.levels[0]||{};var vc=L0.videoCodec||"?";var lvl=L0.details;if(lvl)setStatus(titleText+" · "+lvl.fragments.length+" frags · "+fmt(lvl.totalduration)+" · "+vc);vid.play().catch(function(){vid.muted=true;vid.play().catch(function(){tapToPlay();});});function judge(total){if(vid.currentTime>0.5){diagLock=false;setStatus("✅ 播放中 "+fmt(vid.currentTime)+"s · "+(vid.muted?"(静音,点画面恢复声音)":vc));return;}var bf=vid.buffered.length?vid.buffered.end(vid.buffered.length-1):0;if(total&&vid.paused&&bf>0.5){setStatus("▶ 数据已就绪("+fmt(bf)+"s) 点击画面播放");setTimeout(function(){judge((total||0)+10);},10000);return;}if(total&&vid.networkState!==2){diagLock=true;setStatus("❌ 播放未启动("+total+"s)");alert("[vg-91p] 播放未启动 | readyState="+vid.readyState+" paused="+vid.paused+" buffered="+fmt(bf)+"s codec="+vc+" netState="+vid.networkState+" frags="+(lvl?lvl.fragments.length+"/"+fmt(lvl.totalduration):"?")+" | 反复出现请截图反馈");console.error("[vg-91p-diag] play-fail codec="+vc);}else{setStatus(total>5?("⏳ 缓冲中 "+total+"s (网络活动中, 大清单首载较慢)..."):"⏳ 缓冲中...");setTimeout(function(){judge((total||0)+10);},10000);}}setTimeout(function(){judge(5);},5000);});' +
          'hls.on(Hls.Events.FRAG_LOADED,function(_,d){if(vid.currentTime>0.5)diagLock=false;if(diagLock)return;setStatus(titleText+" · frag "+d.frag.sn+" · "+fmt(vid.currentTime)+" / "+fmt(vid.duration));});' +
          'hls.on(Hls.Events.ERROR,function(_,d){' +
            'console.log("[vg-91p:error]",d);' +
            'if(!d.fatal)return;' +
            'window.__vg_alerted=window.__vg_alerted||{};' +
            'var ek=d.type+"/"+d.details;' +
            'if(!window.__vg_alerted[ek]){window.__vg_alerted[ek]=1;alert("[vg-91p] ❌ 播放错误: "+ek+(d.frag&&d.frag.url?("\\n失败分片: "+String(d.frag.url).slice(-80)):"")+"\\n(尝试自动恢复中...)");}' +
                        'retryCount++;' +
            'var fragU=(d.frag&&d.frag.url)?(" · "+String(d.frag.url).slice(-70)):"";' +
            'if(retryCount>MAX_RETRY){' +
              'hls.destroy();' +
              'if(tryNative("hls.js 重试无效"))return;' +
              'setStatus("❌ 播放失败(重试"+MAX_RETRY+"次无效): "+d.type+"/"+d.details+fragU);return;' +
            '}' +
            'setStatus("⚠ "+d.type+"/"+d.details+fragU+" 恢复中("+retryCount+"/"+MAX_RETRY+")...");' +
            'try{' +
              'if(d.type===Hls.ErrorTypes.NETWORK_ERROR){hls.startLoad();}' +
              'else if(d.type===Hls.ErrorTypes.MEDIA_ERROR){hls.recoverMediaError();}' +
              'else{hls.destroy();if(tryNative(d.type))return;setStatus("❌ 播放失败(无法恢复): "+d.type+"/"+d.details+fragU);}' +
            '}catch(e){setStatus("❌ 恢复出错: "+e.message);}' +
          '});' +
          'var blob=new Blob([m3u8Text],{type:"application/vnd.apple.mpegurl"});' +
          'var blobUrl=URL.createObjectURL(blob);' +
          'hls.loadSource(blobUrl);' +
          'hls.attachMedia(vid);' +
        '}else if(vid.canPlayType("application/vnd.apple.mpegurl")){' +
          'if(!tryNative())setStatus("❌ 当前浏览器既不支持 MSE 也不支持原生 HLS");' +
        '}else{' +
          'setStatus("❌ 当前浏览器既不支持 MSE 也不支持原生 HLS");' +
        '}' +
      '})();</script>' +
      '</body></html>';
  }

  function mountInNewTab(playerWin, title, m3u8Text, m3u8Url) {
    if (!playerWin) {
      alert('[vg-91p] 新标签页被浏览器拦截了, 请允许弹窗后重试');
      return;
    }
    try {
      playerWin.document.open();
      playerWin.document.write(buildPlayerHtml(title, m3u8Text, m3u8Url));
      playerWin.document.close();
    } catch (e) {
      try { playerWin.close(); } catch (e2) {}
      alert('[vg-91p] 写入新标签页失败: ' + e.message);
    }
  }

  function errorHtml(msg) {
    var safe = String(msg || '').replace(/</g, '&lt;');
    return '<!DOCTYPE html><html><head><meta charset="utf-8">' +
      '<meta name="viewport" content="width=device-width,initial-scale=1"></head>' +
      '<body style="margin:0;background:#200;color:#fff;font:14px/1.5 -apple-system,sans-serif;' +
      'padding:24px;display:flex;align-items:center;justify-content:center;height:100vh;box-sizing:border-box">' +
      '<div><strong style="color:#f44">VG Player 91p ❌</strong><br><br>' + safe + '<br><br>' +
      '<button onclick="window.close()" style="background:#444;color:#fff;border:0;' +
      'padding:10px 20px;border-radius:6px;font-size:14px">关闭</button></div></body></html>';
  }

  // ==========================================================================
  // 主流程
  // ==========================================================================

  async function main() {
    var playerWin = openPlayerWindow();
    if (playerWin) {
      try {
        playerWin.document.open();
        playerWin.document.write('<!DOCTYPE html><html><head><meta charset="utf-8">' +
          '<meta name="viewport" content="width=device-width,initial-scale=1"></head>' +
          '<body style="margin:0;background:#000;color:#fff;font:16px/1.4 -apple-system,sans-serif;' +
          'display:flex;align-items:center;justify-content:center;height:100vh">' +
          '<div style="text-align:center">VG Player 91p<br>' +
          '<span style="font-size:13px;opacity:.7">加载中…</span></div></body></html>');
        playerWin.document.close();
      } catch (e) {}
    }
    try {
      if (location.hostname !== H5_HOST) throw new Error('请在 91p H5 页面(' + H5_HOST + ')使用本书签');
      log('加载 CryptoJS...');
      await loadScript(CRYPTO_JS_SRC, 'CryptoJS');
      var auth = await getToken();
      var vid = await getVidFromUrl();
      var title = '', sourceURL = '';
      if (vid) {
        var ji = await apiCall('/vid/info', { videoID: vid }, auth.token, 'GET');
        if (ji.code !== 200 || !ji.data) throw new Error('vid/info 失败 code=' + ji.code + ' ' + (ji.tip || ''));
        title = ji.data.title || vid;
        sourceURL = ji.data.sourceURL || '';
        if (!sourceURL) throw new Error('vid/info 无 sourceURL(视频可能已下架)');
      } else {
        var picked = await pickFromList(auth.token);
        vid = picked.id; title = picked.title || vid; sourceURL = picked.sourceURL || '';
        if (!sourceURL) throw new Error('该条目无 sourceURL');
      }
      log('目标: ' + title.slice(0, 30) + ' sourceURL=' + sourceURL.slice(0, 40));
      var mm = await fetchM3u8Text(auth.token, sourceURL);
      var mi = inspectM3u8(mm.text);
      log('m3u8 OK: ' + mi.frags + ' 片段 / ' + mi.duration + 's' + (mi.isPreview ? ' ⚠疑似预告片' : ''));
      if (mi.isPreview && !auth.fresh) {
        // 缓存/站方 token 额度可能已耗尽(服务端静默回吐预告): 弃缓存强制新号重试一次
        log('⚠ 拿到的是 ' + mi.duration + 's 预告片 — token 额度可能耗尽, 弃缓存强制新号重试...');
        localStorage.removeItem(LS_TOKEN_KEY);
        auth = { token: await registerFresh(), fresh: true };
        var ji2 = await apiCall('/vid/info', { videoID: vid }, auth.token, 'GET');
        if (ji2.code !== 200 || !ji2.data || !(ji2.data.sourceURL || ''))
          throw new Error('刷新额度后 vid/info 仍无 sourceURL code=' + ji2.code);
        sourceURL = ji2.data.sourceURL;
        mm = await fetchM3u8Text(auth.token, sourceURL);
        mi = inspectM3u8(mm.text);
        log('重试 m3u8: ' + mi.frags + ' 片段 / ' + mi.duration + 's' + (mi.isPreview ? ' ⚠仍是预告' : ''));
      }
      if (mi.isPreview) {
        throw new Error('服务端只返回 ' + mi.duration + 's 预告片(非正片) — 新号额度刷新也无效, 该视频可能本身无正片权限');
      }
      var prepared = await injectKey(mm.text, auth.token);
      mountInNewTab(playerWin, title + ' (' + mi.frags + 'frags/' + mi.duration + 's)', prepared, mm.url);
    } catch (e) {
      if (playerWin) {
        try {
          playerWin.document.open();
          playerWin.document.write(errorHtml(e.message));
          playerWin.document.close();
        } catch (e2) { try { playerWin.close(); } catch (e3) {} }
      }
      console.error('[vg-91p]', e);
      alert('[vg-91p] ❌ ' + e.message);
    }
  }

  main();
})();
