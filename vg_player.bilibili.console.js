(function () {
  'use strict';

  // ==========================================================================
  // 哔哩视频书签播放器 (观影导航 #8: nm5s8.com → bilio2.tv)
  // 目标站点: d23qsujlm074se.cloudfront.net (哔哩视频 / 逼哩xv, 成人版B站)
  //
  // 平台: OIO 老代 —— 与 OIO 本体同一套签名体系:
  // - HmacSHA1 签名 key 与 OIO 完全相同 (jR6dO6fT1yD9zY7u), 离线复刻已与
  //   App 抓包逐字符验证一致 (2026-09-14)
  // - 响应解密 interfaceKey 同款 (vEukA&w15z4VAD3kAY#fkL#rBnU!WDhN)
  // - 端点族同款: /login/guest → /media/play → /media/h5/m3u8/<path>
  //
  // 与 OIO 本体的差异:
  // - X-User-Agent 是短格式 (无 Sid/DeviceBrand 后缀):
  //   DevType=...;SysType=h5_ios;Ver=2.1.2;BuildID=<浏览器> <版本>
  //   (逆向自站方 encodeParamToHttpRequest, 服务端不校验 UA 内容,
  //   只要签名消息与请求头一致即可 —— Python 客户端硬编码 UA 已验证)
  // - login/guest 的 body 里 sign 字段可选 (HmacSHA1(devID&affCode, V+guest_skey),
  //   V 来源未定) —— 实测不传也能注册成功, 故省略
  // - 视频详情页 URL 形态: query 带 ?id= 或 ?videoId= (bundle detail 组件证据);
  //   Tiktok 信息流页面 URL 不带 id → 多级提取 + pinia store 兜底
  //
  // 原理 (与 OIO 书签一致): 每次执行时创建全新 guest token (带免费观看额度),
  // 用 token 调 /media/play 拿完整 m3u8 路径, 下载 m3u8 后按 #EXT-X-KEY 声明的
  // URI 动态获取 16 字节 AES-128 密钥, 内联成 data URI, 交给新标签页里的 hls.js。
  //
  // 风控注意: guest 创建有 IP 级软禁形态 (code=200 但 data 为 null、token 不发)
  // —— 持续重试只会延长窗口。若本机被软禁, 书签优先复用页面自己的 token
  // (App 登录成功后存在 localStorage["token"]), 仅在其失败时才尝试全新注册。
  // ==========================================================================

  var TARGET_HOSTNAME = 'd23qsujlm074se.cloudfront.net';
  var API_BASE = '/api/app';
  var REQ_SIGN_KEY = 'jR6dO6fT1yD9zY7u';
  var INTERFACE_KEY = 'vEukA&w15z4VAD3kAY#fkL#rBnU!WDhN';
  var CRYPTO_JS_SRC = 'https://cdn.jsdelivr.net/npm/crypto-js@4.2.0/crypto-js.min.js';
  var HLS_JS_SRC = 'https://cdn.jsdelivr.net/npm/hls.js@1.6.19/dist/hls.min.js';

  var log = function (m) { try { console.log('[vg-bili]', m); } catch (e) {} };

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
  // 视频 id 提取 — 多级: URL query → 路径参数 → pinia store 兜底
  // ==========================================================================

  function getIdFromUrl() {
    // 1) query 参数 (bundle 证据: detail 组件读 query.id / query.videoId)
    var m = location.href.match(/[?&](?:id|videoId)=([^&]+)/);
    if (m) return decodeURIComponent(m[1]);
    // 2) 路径参数 (同族 yms 站路由形态: /play/longVideo/12345)
    m = location.pathname.match(/\/play\/(?:longVideo|shortVideo|video|detail)\/(\d+)/);
    if (m) return m[1];
    // 3) pinia store 兜底 (Tiktok/首页信息流: URL 不带 id)
    return getIdFromPinia();
  }

  function getIdFromPinia() {
    try {
      var el = document.querySelector('#app');
      var app = el && el.__vue_app__;
      var gp = app && app.config && app.config.globalProperties;
      var stores = gp && gp.$pinia && gp.$pinia._s;
      if (!stores) return null;
      var found = null;
      // 在各 store 的 state 里找"当前视频"形态的对象: 数字 id + 视频特征字段。
      // 只扫描普通对象(跳过数组) —— 列表是数组, 当前项通常单独存放。
      var scan = function (obj, depth) {
        if (found || !obj || typeof obj !== 'object' || depth > 3) return;
        if (typeof obj.id === 'number' && obj.id > 0 &&
            (obj.videoUrl || obj.mediaInfo || obj.playUrl || obj.coverUrl ||
             obj.payType !== undefined || obj.duration !== undefined)) {
          found = obj.id;
          return;
        }
        for (var k in obj) {
          if (found) return;
          var v;
          try { v = obj[k]; } catch (e) { continue; }
          if (v && typeof v === 'object' && !Array.isArray(v)) scan(v, depth + 1);
        }
      };
      stores.forEach(function (store) {
        if (found) return;
        try { scan(store.$state || store, 0); } catch (e) {}
      });
      return found;
    } catch (e) { return null; }
  }

  // ==========================================================================
  // 签名 & 解密 — 与 ks/OIO/91p 同族算法, 已离线复刻验证。
  // ==========================================================================

  // 短格式 X-User-Agent (逆向自站方 encodeParamToHttpRequest):
  // SysType 按设备推导 (h5_pc/h5_android/h5_ios), Ver 固定 2.1.2,
  // BuildID 取浏览器名+版本 —— 服务端不校验内容, 只要求签名一致。
  function buildUA() {
    var ua = navigator.userAgent || '';
    var sys = 'h5_pc';
    if (/iPhone|iPad|iPod/i.test(ua)) sys = 'h5_ios';
    else if (/Android/i.test(ua)) sys = 'h5_android';
    var m = ua.match(/(Edg|Chrome|Firefox|Version)\/([\d.]+)/);
    var browser = m ? (m[1] === 'Version' ? 'Safari' : m[1]) + ' ' + m[2] : 'Mobile Safari 17.0';
    return 'DevType=Apple iPhone mobile;SysType=' + sys + ';Ver=2.1.2;BuildID=' + browser;
  }

  function uuid() {
    var hex = '0123456789abcdef';
    var s = '';
    for (var i = 0; i < 32; i++) s += hex[(Math.random() * 16) | 0];
    return s.slice(0, 8) + '-' + s.slice(8, 12) + '-' + s.slice(12, 16) + '-' + s.slice(16, 20) + '-' + s.slice(20);
  }

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

  // ==========================================================================
  // 核心: 拿 token → media/play → 下载 m3u8 → 替换 AES key → 返回 m3u8 文本
  // ==========================================================================

  // 调 /api/app/login/guest 拿全新 guest token。签名时 token 传空字符串;
  // body 的 sign 字段可选(实测省略可注册), 与站方行为一致。
  async function guestLogin() {
    var ua = buildUA();
    var path = API_BASE + '/login/guest';
    var sig = computeSign('', path, ua);

    var resp = await fetch(path, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': '',
        'X-User-Agent': ua,
        'x-api-key': 'timestamp=' + sig.ts + ';sign=' + sig.sign + ';nonce=' + sig.nonce
      },
      body: JSON.stringify({ devID: uuid(), affCode: '{}' })
    });
    if (!resp.ok) throw new Error('guest 登录 HTTP ' + resp.status);
    var j = await resp.json();
    if (!j || !j.data) {
      throw new Error('guest 登录失败 (IP 可能被风控软禁, 稍后再试): ' + JSON.stringify(j).slice(0, 160));
    }
    var plain = qyDecrypt(j.data);
    var data;
    try { data = JSON.parse(plain); } catch (e) { throw new Error('guest 响应解密异常'); }
    if (!data || !data.token) {
      // 站方风控: code=200 但 data 解出 null, token 不发 (IP 级软禁形态)
      throw new Error('guest 登录: 服务端未发 token (IP 风控, 请稍后再试或换网络)');
    }
    log('guest 登录成功, userId=' + (function () {
      try { return JSON.parse(atob(data.token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/'))).userId; } catch (e) { return '?'; }
    })());
    return { token: data.token, ua: ua, fromPage: false };
  }

  // token 两级获取: 页面自己的 token (App 登录成功后存 localStorage["token"])
  // → 失败再全新 guest 注册。规避本机 IP 被软禁时 guest 拿不到的情况。
  async function getAuth() {
    var pageTok = '';
    try { pageTok = localStorage.getItem('token') || ''; } catch (e) {}
    if (pageTok && pageTok !== 'undefined' && pageTok !== 'null' && pageTok.length > 20) {
      log('使用页面已有 token (len=' + pageTok.length + ')');
      return { token: pageTok, ua: buildUA(), fromPage: true };
    }
    return await guestLogin();
  }

  // 调 /api/app/media/play 拿播放信息。
  async function fetchMediaPlay(token, ua, id) {
    var path = API_BASE + '/media/play';
    var sig = computeSign(token, path, ua);

    var resp = await fetch(path, {
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
    if (!j || !j.data) throw new Error('media/play 响应异常: ' + JSON.stringify(j).slice(0, 200));
    var plain = qyDecrypt(j.data);
    var outer = JSON.parse(plain);
    // 与 OIO 同: playable=false 不拦截, 交给 m3u8 fetch 做最终裁决。
    if (!outer.playable) {
      log('警告: playable=false code=' + outer.code + ' msg=' + outer.msg + ' (继续尝试)');
    }
    var info = outer.mediaInfo || outer;
    if (!info.videoUrl) throw new Error('videoUrl 为空 (code=' + outer.code + ' ' + outer.msg + ')');
    log('media/play: playable=' + outer.playable + ' msg=' + outer.msg + ' videoUrl=' + info.videoUrl.slice(0, 50));
    // preFileName 泄露(2026-09-15 抓包证实): 访客未购买时 videoUrl 是广告替代片,
    // 站方自己的播放器实际加载 preFileName 指向的真实路径, 交给 resolveRecord 裁决。
    if (info.preFileName) log('preFileName 泄露: ' + String(info.preFileName).slice(0, 60));
    return { title: info.title || '', videoUrl: info.videoUrl, preFileName: info.preFileName || '' };
  }

  // 构造签名的 m3u8 URL 并下载内容。
  // m3u8 URL 签名时 XUserAgent 传空字符串(逆向自站方 encode_play_url, 同 OIO)。
  // 同时返回绝对 URL(url): 原生 HLS 兜底时直接交给系统播放器, 不受 MSE/Blob
  // 清单限制(WebKit 原生播放器拒绝 Blob 清单, 91p/yms 书签同款问题实测证实)。
  async function fetchM3u8Content(token, videoUrl) {
    var path = API_BASE + '/media/h5/m3u8/' + videoUrl.replace(/^\/+/, '');
    var sig = computeSign(token, path, '');
    var url = path +
      '?token=' + encodeURIComponent(token) +
      '&timestamp=' + sig.ts +
      '&sign=' + sig.sign +
      '&nonce=' + sig.nonce;

    var resp = await fetch(url);
    var text = await resp.text();

    // 服务端无权限时返回 JSON 错误而非 m3u8
    if (text.startsWith('{')) {
      var j = JSON.parse(text);
      throw new Error('m3u8 错误: ' + (j.tip || j.msg || 'code ' + j.code));
    }
    return { text: text, url: location.origin + url };
  }

  // 按 m3u8 里 #EXT-X-KEY 声明的 URI 动态获取 AES-128 密钥。
  // OIO 族不同视频可能用不同 key 端点(enkey/newenkey/lsjenkey) ——
  // 必须按 m3u8 里写的那个取, 不能硬编码。query 签名时空 UA。
  async function fetchKey(token, keyUri) {
    var path = keyUri.split('?')[0];
    var sig = computeSign(token, path, '');
    var url = path + '?token=' + encodeURIComponent(token) +
      '&timestamp=' + sig.ts + '&sign=' + sig.sign + '&nonce=' + sig.nonce;

    var resp = await fetch(url);
    if (!resp.ok) throw new Error('AES key HTTP ' + resp.status + ' (' + path + ')');
    var buf = await resp.arrayBuffer();
    var bytes = new Uint8Array(buf);
    if (bytes.length !== 16) throw new Error('AES key 返回 ' + bytes.length + ' 字节 from ' + path);
    log('AES-128 key 获取成功: ' + bytes.length + ' 字节 from ' + path);
    return bytes;
  }

  // 把 m3u8 里的 #EXT-X-KEY URI 替换成内联 data URI。
  async function injectKey(m3u8Text, token) {
    var keyMatch = m3u8Text.match(/#EXT-X-KEY:METHOD=AES-128,URI="([^"]*)"/);
    if (!keyMatch) {
      log('未找到 #EXT-X-KEY 行(无加密),原样使用');
      return m3u8Text;
    }
    var keyUri = keyMatch[1];
    var keyBytes = await fetchKey(token, keyUri);
    var keyStr = '';
    for (var i = 0; i < keyBytes.length; i++) keyStr += String.fromCharCode(keyBytes[i]);
    var keyBase64 = btoa(keyStr);
    var dataUri = 'data:application/octet-stream;base64,' + keyBase64;
    var replaced = m3u8Text.replace(
      /(#EXT-X-KEY:METHOD=AES-128,URI=")[^"]*(")/,
      '$1' + dataUri + '$2'
    );
    log('已替换 AES-128 key URI (' + keyUri + ') → data URI');
    return replaced;
  }

  // 完整流程: 拿 token → media/play → 下载 m3u8 → 动态获取 key 并注入 → 返回
  async function resolveRecord(id) {
    var auth = await getAuth();
    var media;
    try {
      media = await fetchMediaPlay(auth.token, auth.ua, id);
    } catch (e) {
      if (auth.fromPage) {
        // 页面 token 可能已过期/失效 → 全新 guest 注册重试一次
        log('页面 token 请求失败, 改用全新 guest 重试: ' + e.message);
        auth = await guestLogin();
        media = await fetchMediaPlay(auth.token, auth.ua, id);
      } else {
        throw e;
      }
    }
    // 双候选取最长清单(ks 同款候选法): preFileName 是真实路径, videoUrl 兜底。
    // 分片数用严格 #EXTINF 行计数 —— 站方兜底预告片故意写成 "#  EXTINF:"(带空格),
    // 恰好计 0 片而被自动淘汰。
    var candidates = [];
    if (media.preFileName && media.preFileName !== media.videoUrl) candidates.push(media.preFileName);
    candidates.push(media.videoUrl);
    var picked = null;
    for (var ci = 0; ci < candidates.length; ci++) {
      try {
        var cand = await fetchM3u8Content(auth.token, candidates[ci]);
        var fragCount = (cand.text.match(/^#EXTINF:[\d.]+,$/gm) || []).length;
        log('候选' + (ci + 1) + ': ' + fragCount + ' 片 (' + candidates[ci].slice(0, 46) + '...)');
        if (!picked || fragCount > picked.fragCount) {
          picked = { fragCount: fragCount, m3u8: cand };
        }
      } catch (e) {
        log('候选' + (ci + 1) + ' 失败: ' + e.message);
      }
    }
    if (!picked) throw new Error('所有 m3u8 候选均失败');
    var prepared = await injectKey(picked.m3u8.text, auth.token);
    log('m3u8 准备完成: ' + picked.fragCount + ' 个 ts 片段, 标题=' + media.title.slice(0, 30));

    return { title: media.title, m3u8Text: prepared, realUrl: picked.m3u8.url };
  }

  // ==========================================================================
  // 播放器 UI — 弹出独立窗口,hls.js 从 Blob URL 加载修改后的 m3u8。
  // ==========================================================================

  function openBlankPlayerWindow() {
    try {
      var pre = window.__vg_player_win__;
      if (pre && !pre.closed) return pre;
    } catch (e) {}
    try { return window.open('', '_blank'); } catch (e) { return null; }
  }

  function buildPlayerHtml(title, m3u8Text, realUrl) {
    var titleSafe = (title || 'VG Player Bilibili').replace(/</g, '&lt;');
    var m3u8Json = JSON.stringify(m3u8Text);
    var titleJson = JSON.stringify(title || '');
    var realUrlJson = JSON.stringify(realUrl || '');
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
          '<button id="muteBtn" style="background:#e80;">🔇 声音</button>' +
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
        'var muteBtn=document.getElementById("muteBtn");' +
        'function syncMuteBtn(){muteBtn.textContent=vid.muted?"🔇 声音":"🔊 声音";muteBtn.style.background=vid.muted?"#e80":"#2a7";}' +
        'muteBtn.onclick=function(){vid.muted=!vid.muted;if(!vid.muted){vid.play().catch(function(e){setStatus("play() "+e.message);});}};' +
        'vid.addEventListener("volumechange",syncMuteBtn);' +
        'syncMuteBtn();' +
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
        'function bindUnmuteOnTap(){vid.onclick=function(){vid.muted=false;vid.play().catch(function(e){setStatus("play() "+e.message);});};}' +
        'function tapToPlay(){setStatus("▶ 点🔊声音按钮播放");bindUnmuteOnTap();}' +
        'var nativeStarted=false;' +
        'function tryNative(reason){' +
          'if(nativeStarted||!realUrl)return false;' +
          'nativeStarted=true;' +
          'setStatus(titleText+" · 切换系统播放器(原生 HLS)"+(reason?" ["+reason+"]":"")+"...");' +
          'vid.src=realUrl;' +
          'vid.addEventListener("loadedmetadata",function(){setStatus(titleText+" · "+fmt(vid.duration));});' +
          'vid.play().catch(function(){vid.muted=true;vid.play().then(function(){bindUnmuteOnTap();setStatus(titleText+" · 播放中(静音,点🔊声音按钮恢复)");}).catch(function(){tapToPlay();});});' +
          'return true;' +
        '}' +
        'if(window.Hls&&Hls.isSupported()){' +
          'var hls=new Hls({enableWorker:true});' +
          'hls.on(Hls.Events.MANIFEST_PARSED,function(){var L0=hls.levels[0]||{};var vc=L0.videoCodec||"?";var lvl=L0.details;if(lvl)setStatus(titleText+" · "+lvl.fragments.length+" frags · "+fmt(lvl.totalduration)+" · "+vc);vid.play().catch(function(){vid.muted=true;vid.play().catch(function(){tapToPlay();});});function judge(total){if(vid.currentTime>0.5){diagLock=false;if(vid.muted)bindUnmuteOnTap();setStatus("✅ 播放中 "+fmt(vid.currentTime)+"s · "+(vid.muted?"(静音,点🔊声音按钮恢复)":vc));return;}var bf=vid.buffered.length?vid.buffered.end(vid.buffered.length-1):0;if(total&&vid.paused&&bf>0.5){setStatus("▶ 数据已就绪("+fmt(bf)+"s) 点击画面播放");setTimeout(function(){judge((total||0)+10);},10000);return;}if(total&&vid.networkState!==2){diagLock=true;setStatus("❌ 播放未启动("+total+"s)");console.error("[vg-diag] play-fail codec="+vc);}else{setStatus(total>5?("⏳ 缓冲中 "+total+"s (网络活动中, 大清单首载较慢)..."):"⏳ 缓冲中...");setTimeout(function(){judge((total||0)+10);},10000);}}setTimeout(function(){judge(5);},5000);});' +
          'hls.on(Hls.Events.FRAG_LOADED,function(_,d){if(vid.currentTime>0.5)diagLock=false;if(diagLock)return;setStatus(titleText+" · frag "+d.frag.sn+" · "+fmt(vid.currentTime)+" / "+fmt(vid.duration));});' +
          'hls.on(Hls.Events.ERROR,function(_,d){' +
            'console.log("[vg-bili:error]",d);' +
            'if(!d.fatal)return;' +
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

  function mountInNewTab(playerWin, title, m3u8Text, realUrl) {
    if (!playerWin) {
      alert('[vg-bili] 新标签页被浏览器拦截了,请允许此站点弹窗后重试');
      return;
    }
    try {
      playerWin.document.open();
      playerWin.document.write(buildPlayerHtml(title, m3u8Text, realUrl));
      playerWin.document.close();
    } catch (e) {
      try { playerWin.close(); } catch (e2) {}
      alert('[vg-bili] 写入新标签页失败: ' + e.message);
    }
  }

  // ==========================================================================
  // 主流程
  // ==========================================================================

  function loadingHtml() {
    return '<!DOCTYPE html><html><head><meta charset="utf-8">' +
      '<meta name="viewport" content="width=device-width,initial-scale=1"></head>' +
      '<body style="margin:0;background:#000;color:#fff;font:16px/1.4 -apple-system,sans-serif;' +
      'display:flex;align-items:center;justify-content:center;height:100vh">' +
      '<div style="text-align:center">VG Player Bilibili<br>' +
      '<span style="font-size:13px;opacity:.7">加载中…</span></div></body></html>';
  }

  function errorHtml(msg) {
    var safe = String(msg || '').replace(/</g, '&lt;');
    return '<!DOCTYPE html><html><head><meta charset="utf-8">' +
      '<meta name="viewport" content="width=device-width,initial-scale=1"></head>' +
      '<body style="margin:0;background:#200;color:#fff;font:14px/1.5 -apple-system,sans-serif;' +
      'padding:24px;display:flex;align-items:center;justify-content:center;height:100vh;box-sizing:border-box">' +
      '<div><strong style="color:#f44">VG Player Bilibili ❌</strong><br><br>' + safe + '<br><br>' +
      '<button onclick="window.close()" style="background:#444;color:#fff;border:0;' +
      'padding:10px 20px;border-radius:6px;font-size:14px">关闭</button></div></body></html>';
  }

  async function main() {
    // 必须在第一行(同步上下文),保证 console 手动粘贴场景下弹窗不被拦截。
    // 书签场景下真正保证不被拦截的是 loader 预开的 window.__vg_player_win__。
    var playerWin = openBlankPlayerWindow();
    if (playerWin) {
      try { playerWin.document.open(); playerWin.document.write(loadingHtml()); playerWin.document.close(); }
      catch (e) {}
    }
    try {
      // 站方可能用多个 CloudFront 域名轮换分发同一后端(欲漫涩书签实测确认
      // 有此现象), 硬校验单一域名会在轮换到未覆盖域名时误拦真实用户; API
      // 全走相对路径本身就绑定当前域, 这里只做非阻断提示。
      if (!/\.cloudfront\.net$/.test(location.hostname)) {
        log('⚠ 当前域名(' + location.hostname + ')不是常见 CloudFront 分发, 仍尝试继续');
      }
      var id = getIdFromUrl();
      if (!id) {
        throw new Error('未能从页面获取视频 id — 请进入视频详情页(URL 带 ?id= 或 ?videoId=)后重试; Tiktok 信息流页暂不支持');
      }

      log('加载 CryptoJS...');
      await loadScript(CRYPTO_JS_SRC, 'CryptoJS');
      log('CryptoJS 就绪, 开始处理: id=' + id);
      var result = await resolveRecord(id);
      mountInNewTab(playerWin, result.title, result.m3u8Text, result.realUrl);
    } catch (e) {
      if (playerWin) {
        try { playerWin.document.open(); playerWin.document.write(errorHtml(e.message)); playerWin.document.close(); }
        catch (e2) { try { playerWin.close(); } catch (e3) {} }
      }
      console.error('[vg-bili]', e);
      alert('[vg-bili] ❌ ' + e.message);
    }
  }

  main();
})();
