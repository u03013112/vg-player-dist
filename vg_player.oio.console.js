(function () {
  'use strict';

  // ==========================================================================
  // OIO 禁漫书签播放器
  // 目标站点: d2cjrt5ibwkdp4.cloudfront.net (OIO禁漫)
  //
  // 原理: 每次执行时调 /api/app/login/guest 拿一个全新的 guest token(带 2-3 次
  // 免费观看额度),用新 token 调 /api/app/media/play 拿到完整 m3u8 路径,下载 m3u8
  // 内容后按 #EXT-X-KEY 声明的 URI(enkey 或 newenkey,两个端点返回的 key 不同)
  // 动态获取 16 字节 AES-128 密钥,内联成 data URI 替换进 m3u8,最后把修改后的
  // m3u8 文本传给弹窗里的 hls.js 播放。
  //
  // 和 ks 站的区别:
  // - ks 站 videoUrl=10秒预览, preFileName=真实片段(有设计漏洞可拼接绕过)
  // - OIO 站 videoUrl=完整版(有权限时), preFileName=空(无泄露)
  // - OIO 站 ts 有 AES-128 加密, ks 站没有
  // - OIO 站权限在服务端 m3u8 层检查, ks 站在客户端
  // - OIO 站用 guest 刷免费次数绕过, ks 站用 preFileName 拼接绕过
  //
  // 实测: payType=2 的视频 media/play 返回 playable=false/code=6032,但服务端
  // m3u8 端点不强制 —— 照样返回完整可解密列表,所以不按 playable 拦截,交给
  // m3u8 fetch 做最终裁决。
  // ==========================================================================

  var TARGET_HOSTNAME = 'd2cjrt5ibwkdp4.cloudfront.net';
  var API_BASE = '/api/app';
  var REQ_SIGN_KEY = 'jR6dO6fT1yD9zY7u';
  var INTERFACE_KEY = 'vEukA&w15z4VAD3kAY#fkL#rBnU!WDhN';
  var CRYPTO_JS_SRC = 'https://cdn.jsdelivr.net/npm/crypto-js@4.2.0/crypto-js.min.js';
  var HLS_JS_SRC = 'https://cdn.jsdelivr.net/npm/hls.js@1.5.15/dist/hls.min.js';

  var log = function (m) { try { console.log('[vg-oio]', m); } catch (e) {} };

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
  // 签名 & 解密 — 和 ks/k5 站完全相同的算法,逆向自站方打包 JS。
  // ==========================================================================

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
  // 核心:guest 登录 → media/play → 下载 m3u8 → 替换 AES key → 返回 m3u8 文本
  // ==========================================================================

  // 调 /api/app/login/guest 拿全新 guest token(带免费观看额度)。
  // 签名时 token 传空字符串(首次登录没有旧 token)。
  async function guestLogin() {
    var sid = getSid();
    var ua = buildUA(sid);
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
    if (!j || !j.data) throw new Error('guest 登录失败: ' + JSON.stringify(j).slice(0, 200));
    var plain = qyDecrypt(j.data);
    var data = JSON.parse(plain);
    if (!data.token) throw new Error('guest 登录: 无 token');
    log('guest 登录成功, userId=' + (function () {
      try { return JSON.parse(atob(data.token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/'))).userId; } catch (e) { return '?'; }
    })());
    return { token: data.token, sid: sid, ua: ua };
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
    // 实测: payType=2 的视频 playable=false/code=6032,但服务端 m3u8 端点不强制 ——
    // 照样返回完整可解密列表。所以不在这里 throw,交给 m3u8 fetch 做最终裁决。
    if (!outer.playable) {
      log('警告: playable=false code=' + outer.code + ' msg=' + outer.msg + ' (继续尝试)');
    }
    var info = outer.mediaInfo || outer;
    if (!info.videoUrl) throw new Error('videoUrl 为空 (code=' + outer.code + ' ' + outer.msg + ')');
    log('media/play: playable=' + outer.playable + ' msg=' + outer.msg + ' videoUrl=' + info.videoUrl.slice(0, 50));
    return { title: info.title || '', videoUrl: info.videoUrl };
  }

  // 构造签名的 m3u8 URL 并下载内容。
  // m3u8 URL 签名时 XUserAgent 传空字符串(逆向自 encode_play_url,和 ks 站一致)。
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
    return text;
  }

  // 按 m3u8 里 #EXT-X-KEY 声明的 URI 动态获取 AES-128 密钥。
  // 实测 enkey 和 newenkey 是两个不同端点,返回的 16 字节 key 也不同 ——
  // 必须按 m3u8 里写的那个取,不能硬编码。query 签名时空 UA(和 m3u8 URL 一致)。
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

  // 把 m3u8 里的 #EXT-X-KEY URI 替换成内联 data URI(按 m3u8 声明的端点动态获取的 16 字节密钥)。
  // 这样 hls.js 不需要额外请求 key 端点,播放窗口也不需要 CryptoJS。
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

  // 完整流程:guest 登录 → media/play → 下载 m3u8 → 动态获取 key 并注入 → 返回
  async function resolveRecord(id) {
    var auth = await guestLogin();
    var media = await fetchMediaPlay(auth.token, auth.ua, id);
    var m3u8Text = await fetchM3u8Content(auth.token, media.videoUrl);
    var prepared = await injectKey(m3u8Text, auth.token);

    // 统计片段数
    var tsCount = (m3u8Text.match(/\.ts/g) || []).length;
    log('m3u8 准备完成: ' + tsCount + ' 个 ts 片段, 标题=' + media.title.slice(0, 30));

    return { title: media.title, m3u8Text: prepared };
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

  function buildPlayerHtml(title, m3u8Text) {
    var titleSafe = (title || 'VG Player OIO').replace(/</g, '&lt;');
    var m3u8Json = JSON.stringify(m3u8Text);
    var titleJson = JSON.stringify(title || '');
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
      '<script src="https://cdn.jsdelivr.net/npm/hls.js@1.5.15/dist/hls.min.js"></script>' +
      '<script>(function(){' +
        'var m3u8Text=' + m3u8Json + ';' +
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
        'var hls=new Hls({enableWorker:true});' +
        'hls.on(Hls.Events.MANIFEST_PARSED,function(){var lvl=hls.levels[0]&&hls.levels[0].details;if(lvl)setStatus(titleText+" · "+lvl.fragments.length+" frags · "+fmt(lvl.totalduration));vid.play().catch(function(e){setStatus("play() "+e.message);});});' +
        'hls.on(Hls.Events.FRAG_LOADED,function(_,d){setStatus(titleText+" · frag "+d.frag.sn+" · "+fmt(vid.currentTime)+" / "+fmt(vid.duration));});' +
        'hls.on(Hls.Events.ERROR,function(_,d){' +
          'console.log("[vg-oio:error]",d);' +
          'if(!d.fatal)return;' +
          'retryCount++;' +
          'if(retryCount>MAX_RETRY){setStatus("❌ 播放失败(重试"+MAX_RETRY+"次无效): "+d.type+"/"+d.details+" — 请记录此视频链接反馈");return;}' +
          'setStatus("⚠ "+d.type+"/"+d.details+" 恢复中("+retryCount+"/"+MAX_RETRY+")...");' +
          'try{' +
            'if(d.type===Hls.ErrorTypes.NETWORK_ERROR){hls.startLoad();}' +
            'else if(d.type===Hls.ErrorTypes.MEDIA_ERROR){hls.recoverMediaError();}' +
            'else{hls.destroy();setStatus("❌ 播放失败(无法恢复): "+d.type+"/"+d.details+" — 请记录此视频链接反馈");}' +
          '}catch(e){setStatus("❌ 恢复出错: "+e.message);}' +
        '});' +
        // 用 Blob URL 加载修改后的 m3u8 文本(已内联 AES key)
        'var blob=new Blob([m3u8Text],{type:"application/vnd.apple.mpegurl"});' +
        'var blobUrl=URL.createObjectURL(blob);' +
        'hls.loadSource(blobUrl);' +
        'hls.attachMedia(vid);' +
      '})();</script>' +
      '</body></html>';
  }

  function mountInNewTab(playerWin, title, m3u8Text) {
    if (!playerWin) {
      alert('[vg-oio] 新标签页被浏览器拦截了,请允许此站点弹窗后重试');
      return;
    }
    try {
      playerWin.document.open();
      playerWin.document.write(buildPlayerHtml(title, m3u8Text));
      playerWin.document.close();
    } catch (e) {
      try { playerWin.close(); } catch (e2) {}
      alert('[vg-oio] 写入新标签页失败: ' + e.message);
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
      '<div style="text-align:center">VG Player OIO<br>' +
      '<span style="font-size:13px;opacity:.7">加载中…</span></div></body></html>';
  }

  function errorHtml(msg) {
    var safe = String(msg || '').replace(/</g, '&lt;');
    return '<!DOCTYPE html><html><head><meta charset="utf-8">' +
      '<meta name="viewport" content="width=device-width,initial-scale=1"></head>' +
      '<body style="margin:0;background:#200;color:#fff;font:14px/1.5 -apple-system,sans-serif;' +
      'padding:24px;display:flex;align-items:center;justify-content:center;height:100vh;box-sizing:border-box">' +
      '<div><strong style="color:#f44">VG Player OIO ❌</strong><br><br>' + safe + '<br><br>' +
      '<button onclick="window.close()" style="background:#444;color:#fff;border:0;' +
      'padding:10px 20px;border-radius:6px;font-size:14px">关闭</button></div></body></html>';
  }

  async function main() {
    // 必须在第一行(同步上下文),保证 console 手动粘贴场景下弹窗不被拦截。
    // 书签场景下真正保证不被拦截的是 loader 预开的 window.__vg_player_win__。
    var playerWin = openBlankPlayerWindow();
    // 立即往新标签页写 loading 页,避免在 async 流程中用户看到空白页。
    if (playerWin) {
      try { playerWin.document.open(); playerWin.document.write(loadingHtml()); playerWin.document.close(); }
      catch (e) {}
    }
    try {
      if (location.hostname !== TARGET_HOSTNAME) {
        throw new Error('当前站点不是 ' + TARGET_HOSTNAME + ' (OIO禁漫)');
      }
      var id = getIdFromUrl();
      if (!id) throw new Error('URL 无 ?id= — 请先进入视频详情页');

      // 签名/解密依赖 CryptoJS,站方 JS 不暴露全局 CryptoJS,必须自己加载。
      log('加载 CryptoJS...');
      await loadScript(CRYPTO_JS_SRC, 'CryptoJS');
      log('CryptoJS 就绪, 开始处理: id=' + id);
      var result = await resolveRecord(id);
      mountInNewTab(playerWin, result.title, result.m3u8Text);
    } catch (e) {
      // 出错时把错误写进新标签页(Safari 跨 tab close 不可靠,直接写更稳),
      // 同时在原页面 alert 兜底。
      if (playerWin) {
        try { playerWin.document.open(); playerWin.document.write(errorHtml(e.message)); playerWin.document.close(); }
        catch (e2) { try { playerWin.close(); } catch (e3) {} }
      }
      console.error('[vg-oio]', e);
      alert('[vg-oio] ❌ ' + e.message);
    }
  }

  main();
})();
