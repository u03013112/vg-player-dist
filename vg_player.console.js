(function () {
  'use strict';

  // ==========================================================================
  // 目标站点:目前专注 ksXVideo 单站打磨,k5 兼容暂缓(旧的 k5 主动请求代码
  // 在 git 历史里可以找回,不复杂,以后要恢复兼容再加回来)。
  // ==========================================================================
  var TARGET_HOSTNAME = 'd270v74snrdyr6.cloudfront.net';
  var API_BASE = '/api/app';
  var REQ_SIGN_KEY = 'jR6dO6fT1yD9zY7u';
  var INTERFACE_KEY = 'vEukA&w15z4VAD3kAY#fkL#rBnU!WDhN';
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

  function isSupportedSite() {
    return location.hostname === TARGET_HOSTNAME;
  }

  // ==========================================================================
  // 主动请求方案:签名(HmacSHA1)+ 响应解密(SHA256 编织派生 key/iv 的
  // AES-256-CBC),逆向自 ksXVideo 打包 JS 的 encodeSign/decodeHttpResponseData。
  // ==========================================================================
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

  function buildUA(sid) {
    return 'DevType=Apple iPhone mobile;SysType=h5_ios;Ver=1.0.0;BuildID=Mobile Safari 17.0;DeviceBrand=Apple;DeviceModel=iPhone;SystemName=Android;SystemVersion=6.0;Sid=' + sid;
  }

  function uuid() {
    var hex = '0123456789abcdef';
    var s = '';
    for (var i = 0; i < 32; i++) s += hex[(Math.random() * 16) | 0];
    return s.slice(0, 8) + '-' + s.slice(8, 12) + '-' + s.slice(12, 16) + '-' + s.slice(16, 20) + '-' + s.slice(20);
  }

  // 消息结构:token & apiPath & XUserAgent & timestamp(秒) & nonce,HmacSHA1 签名。
  function computeSign(token, apiPath, ua) {
    var ts = String(Math.floor(Date.now() / 1000));
    var nonce = uuid();
    var msg = (token || '') + '&' + apiPath + '&' + ua + '&' + ts + '&' + nonce;
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

  // salt=raw[:12], INTERFACE_KEY+salt 经 SHA256 编织派生 key(32B)/iv(16B),
  // AES-256-CBC/PKCS7,跟 k5j7u 的 qyDecrypt 是同一套算法(逆向确认两站
  // 签名/加密 key 完全相同)。
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

  // 主动请求方案:直接调 /media/play 拿完整片源,不依赖、不等待站点自己的
  // 原生播放请求,随时点书签都行。
  async function activeFetch(id) {
    await loadScript(CRYPTO_JS_SRC, 'CryptoJS');
    var token = getToken();
    var ua = buildUA(getSid());
    var mediaPlayPath = API_BASE + '/media/play';
    var sig = computeSign(token, mediaPlayPath, ua);

    var resp = await fetch(mediaPlayPath, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': token,
        'X-User-Agent': ua,
        'x-api-key': 'timestamp=' + sig.ts + ';sign=' + sig.sign + ';nonce=' + sig.nonce
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

    var path = info.videoUrl.replace(/^\/+/, '');
    var m3u8Path = API_BASE + '/media/h5/m3u8/' + path;
    // m3u8 URL 签名时 XUserAgent 传空字符串(不是完整 UA)——逆向自其
    // encode_play_url 函数,不是随意约定,改动会导致签名对不上。
    var sig2 = computeSign(token, m3u8Path, '');
    var fullUrl = m3u8Path +
      '?token=' + encodeURIComponent(token) +
      '&timestamp=' + sig2.ts +
      '&sign=' + sig2.sign +
      '&nonce=' + sig2.nonce;

    return { title: info.title || '', videoUrl: info.videoUrl, fullUrl: fullUrl };
  }

  // ==========================================================================
  // 通用:广告/弹窗遮罩清理
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
  // 通用:localStorage 缓存
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
  // 播放器 UI:渲染到一个独立的新标签页(而不是覆盖在原页面上),彻底隔离原生
  // 播放器(xgplayer 等)、广告 MutationObserver、原站 JS 的任何干扰。
  //
  // 关键坑:window.open() 必须在"用户手势"仍然有效时调用,一旦中间插了
  // await(网络请求)再调,浏览器(尤其 Safari)大概率会当成非用户触发的弹窗
  // 直接拦截。所以 main() 里 window.open() 是第一行、同步执行,拿到一个空白
  // 窗口引用后,再异步去请求数据、用 document.write() 把内容写进这个已经
  // 打开好的窗口——弹窗拦截器只检查"打开窗口"这个动作本身是否同步于用户
  // 手势,不管之后往里写什么内容,所以能绕开。已在 Safari(webkit)内核实测
  // 验证:window.open 未被拦截,写入的独立播放器正常加载并播放。
  // ==========================================================================
  function openBlankPlayerWindow() {
    try { return window.open('', '_blank'); } catch (e) { return null; }
  }

  function buildPlayerHtml(rec, sourceNote) {
    var titleSafe = (rec.title || 'VG Player').replace(/</g, '&lt;');
    var fullUrlJson = JSON.stringify(rec.fullUrl);
    var titleJson = JSON.stringify((rec.title || '') + (sourceNote ? ' · ' + sourceNote : ''));
    return '<!DOCTYPE html><html><head><meta charset="utf-8">' +
      '<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">' +
      '<title>' + titleSafe + '</title>' +
      '<style>' +
        'html,body{margin:0;padding:0;height:100%;background:#000;overflow:hidden;}' +
        '#bar{height:40px;background:#111;color:#fff;display:flex;align-items:center;justify-content:space-between;padding:0 12px;font:13px/1 -apple-system,sans-serif;box-sizing:border-box;}' +
        '#video{width:100%;height:calc(100% - 40px);background:#000;object-fit:contain;display:block;}' +
        '#float{position:fixed;left:50%;top:50%;transform:translate(-50%,-50%);z-index:999;background:rgba(0,0,0,.7);color:#fff;padding:16px 20px;border-radius:12px;display:flex;flex-direction:column;gap:10px;width:82%;max-width:380px;font:14px/1.3 -apple-system,sans-serif;box-shadow:0 6px 24px rgba(0,0,0,.6);}' +
        '#track{position:relative;height:16px;background:#444;border-radius:8px;cursor:pointer;}' +
        '#buf{position:absolute;left:0;top:0;bottom:0;background:#777;border-radius:8px;width:0%;}' +
        '#prog{position:absolute;left:0;top:0;bottom:0;background:#e33;border-radius:8px;width:0%;}' +
        '#knob{position:absolute;top:50%;transform:translate(-50%,-50%);left:0%;width:22px;height:22px;background:#fff;border-radius:50%;box-shadow:0 2px 6px rgba(0,0,0,.5);pointer-events:none;}' +
        'button{border:0;border-radius:6px;color:#fff;padding:8px 12px;font-size:13px;}' +
      '</style></head><body>' +
      '<div id="bar"><span id="status">加载中...</span><button id="closeBtn" style="background:#e33;padding:6px 14px;">× 关闭</button></div>' +
      '<video id="video" autoplay playsinline></video>' +
      '<div id="float">' +
        '<div id="track"><div id="buf"></div><div id="prog"></div><div id="knob"></div></div>' +
        '<div style="display:flex;align-items:center;justify-content:space-between;gap:10px;">' +
          '<button id="pp" style="background:#2a7;font-size:16px;">▶︎/❚❚</button>' +
          '<span id="t" style="font-variant-numeric:tabular-nums;">0:00 / 0:00</span>' +
          '<button data-d="-10" class="seek" style="background:#333;">−10s</button>' +
          '<button data-d="10" class="seek" style="background:#333;">+10s</button>' +
        '</div>' +
      '</div>' +
      '<script src="https://cdn.jsdelivr.net/npm/hls.js@1.5.15/dist/hls.min.js"></script>' +
      '<script>(function(){' +
        'var fullUrl=' + fullUrlJson + ';' +
        'var titleText=' + titleJson + ';' +
        'var vid=document.getElementById("video");' +
        'var status=document.getElementById("status");' +
        'var track=document.getElementById("track");' +
        'var prog=document.getElementById("prog");' +
        'var buf=document.getElementById("buf");' +
        'var knob=document.getElementById("knob");' +
        'var t=document.getElementById("t");' +
        'var pp=document.getElementById("pp");' +
        'function fmt(s){if(!isFinite(s))return "0:00";s=Math.max(0,s|0);var m=(s/60)|0,ss=s%60;return m+":"+(ss<10?"0":"")+ss;}' +
        'function setStatus(s){status.textContent=s;}' +
        'setStatus(titleText||"loading...");' +
        'document.getElementById("closeBtn").onclick=function(){window.close();};' +
        'pp.onclick=function(){vid.paused?vid.play():vid.pause();};' +
        'document.querySelectorAll(".seek").forEach(function(b){b.onclick=function(){vid.currentTime=Math.max(0,Math.min(vid.duration||0,vid.currentTime+parseFloat(b.dataset.d)));};});' +
        'function seekFromEvt(e){var r=track.getBoundingClientRect();var cx=e.touches?e.touches[0].clientX:e.clientX;var pct=Math.max(0,Math.min(1,(cx-r.left)/r.width));if(vid.duration)vid.currentTime=pct*vid.duration;}' +
        'var dragging=false;' +
        'track.addEventListener("mousedown",function(e){dragging=true;seekFromEvt(e);e.preventDefault();});' +
        'window.addEventListener("mousemove",function(e){if(dragging)seekFromEvt(e);});' +
        'window.addEventListener("mouseup",function(){dragging=false;});' +
        'track.addEventListener("touchstart",function(e){dragging=true;seekFromEvt(e);},{passive:true});' +
        'window.addEventListener("touchmove",function(e){if(dragging)seekFromEvt(e);},{passive:true});' +
        'window.addEventListener("touchend",function(){dragging=false;});' +
        'function tick(){if(vid.duration){var pct=(vid.currentTime/vid.duration)*100;prog.style.width=pct+"%";knob.style.left=pct+"%";if(vid.buffered.length){var bEnd=vid.buffered.end(vid.buffered.length-1);buf.style.width=(bEnd/vid.duration*100)+"%";}}t.textContent=fmt(vid.currentTime)+" / "+fmt(vid.duration);requestAnimationFrame(tick);}' +
        'tick();' +
        'var hls=new Hls({enableWorker:true});' +
        'hls.on(Hls.Events.MANIFEST_PARSED,function(){var lvl=hls.levels[0]&&hls.levels[0].details;if(lvl)setStatus(titleText+" · "+lvl.fragments.length+" frags · "+fmt(lvl.totalduration));vid.play().catch(function(e){setStatus("play() "+e.message);});});' +
        'hls.on(Hls.Events.FRAG_LOADED,function(_,d){setStatus(titleText+" · frag "+d.frag.sn+" · "+fmt(vid.currentTime)+" / "+fmt(vid.duration));});' +
        'hls.on(Hls.Events.ERROR,function(_,d){setStatus("ERR "+d.type+"/"+d.details+(d.response?" http="+d.response.code:""));console.log("[vg-player:error]",d);});' +
        'hls.loadSource(fullUrl);hls.attachMedia(vid);' +
      '})();</script>' +
      '</body></html>';
  }

  function mountInNewTab(playerWin, rec, sourceNote) {
    if (!playerWin) {
      alert('[vg-player] 新标签页被浏览器拦截了,请允许此站点弹窗后重试');
      return;
    }
    try {
      playerWin.document.open();
      playerWin.document.write(buildPlayerHtml(rec, sourceNote));
      playerWin.document.close();
    } catch (e) {
      try { playerWin.close(); } catch (e2) {}
      alert('[vg-player] 写入新标签页失败: ' + e.message);
    }
  }

  // fullUrl 存的是相对路径(如 /api/app/media/h5/m3u8/...),在原页面里能正常解析;
  // 但写进新标签页的独立文档后,相对路径的解析基准不一定可靠,统一转成绝对
  // URL 再传过去,不依赖浏览器对 window.open 空白页面 baseURI 继承行为的假设。
  function toAbsoluteUrl(url) {
    if (/^https?:\/\//i.test(url)) return url;
    return location.origin + (url.charAt(0) === '/' ? url : '/' + url);
  }

  // ==========================================================================
  // 主流程:纯主动请求,不依赖/不等待任何网络拦截,随时点书签都行。
  // ==========================================================================
  async function resolveRecord() {
    var id = getIdFromUrl();
    var cached = loadCachedRecord();

    if (!isSupportedSite()) {
      if (cached) return { rec: cached, note: 'cached(非目标站点)' };
      throw new Error('当前站点不是 ' + TARGET_HOSTNAME + ',且没有缓存');
    }

    if (id) {
      try {
        var got = await activeFetch(id);
        return { rec: saveRecord(id, got.title, got.fullUrl, got.videoUrl), note: 'active' };
      } catch (e) {
        log('主动请求失败: ' + e.message);
        if (cached && String(cached.id) === String(id)) {
          return { rec: cached, note: 'cached(主动请求失败)' };
        }
        throw e;
      }
    }

    if (cached) return { rec: cached, note: 'cached' };
    throw new Error('当前非详情页(URL 无 ?id=),且没有缓存 — 请先进入视频详情页');
  }

  async function main() {
    // 关键:必须是 main() 里第一行同步执行,不能放在任何 await 之后 —— 一旦
    // 隔着网络请求再调 window.open,浏览器(尤其 Safari)大概率会当成非用户
    // 触发的弹窗直接拦截,见 openBlankPlayerWindow 上方的详细说明。
    var playerWin = openBlankPlayerWindow();
    try {
      startAdCleaner();
      var result = await resolveRecord();
      result.rec.fullUrl = toAbsoluteUrl(result.rec.fullUrl);
      mountInNewTab(playerWin, result.rec, result.note);
    } catch (e) {
      if (playerWin) { try { playerWin.close(); } catch (e2) {} }
      console.error('[vg-player]', e);
      alert('[vg-player] ❌ ' + e.message);
    }
  }

  main();
})();
