(function () {
  'use strict';

  var REQ_SIGN_KEY = 'jR6dO6fT1yD9zY7u';
  var INTERFACE_KEY = 'vEukA&w15z4VAD3kAY#fkL#rBnU!WDhN';
  var API_BASE = '/api/app';
  var CDN_FALLBACK = 'https://s2s1.eaekgu.cn';
  var CRYPTO_JS_SRC = 'https://cdn.jsdelivr.net/npm/crypto-js@4.2.0/crypto-js.min.js';
  var STORAGE_KEY = '__vg_full_url__';

  var log = function (m) { try { console.log('[vg-probe]', m); } catch (e) {} };

  function loadScript(src) {
    return new Promise(function (rs, rj) {
      if (window.CryptoJS) return rs();
      var s = document.createElement('script');
      s.src = src;
      s.onload = function () { rs(); };
      s.onerror = function () { rj(new Error('加载 CryptoJS 失败: ' + src)); };
      document.head.appendChild(s);
    });
  }

  function getIdFromUrl() {
    var m = location.href.match(/[?&]id=([^&]+)/);
    if (!m) throw new Error('URL 无 id 参数,请在视频详情页执行(形如 /movieDetails?id=xxx)');
    return decodeURIComponent(m[1]);
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

  (async function main() {
    try {
      var id = getIdFromUrl();
      log('id=' + id);

      await loadScript(CRYPTO_JS_SRC);
      log('calling /media/play ...');
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

      log('✅ 已保存到 localStorage.' + STORAGE_KEY);
      log('fullUrl = ' + fullUrl);
      alert(
        '[vg-probe] ✅ 成功\n' +
        '标题: ' + (record.title || '(无)') + '\n' +
        'id: ' + id + '\n' +
        '已存入 localStorage.' + STORAGE_KEY + '\n\n' +
        'fullUrl (前 160 字符):\n' + fullUrl.slice(0, 160) + '...'
      );
    } catch (e) {
      console.error('[vg-probe]', e);
      alert('[vg-probe] ❌ 失败\n' + e.message);
    }
  })();
})();
