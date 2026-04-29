(function () {
    'use strict';

    const TAG = '[VGPlayer]';
    const log = (...a) => console.log(TAG, ...a);
    const warn = (...a) => console.warn(TAG, ...a);
    const err = (...a) => console.error(TAG, ...a);

    const INTERFACE_KEY = 'vEukA&w15z4VAD3kAY#fkL#rBnU!WDhN';
    const VIDEO_CDN = 'https://s2s1.eaekgu.cn';
    const ENKEY_ENDPOINT = '/api/app/media/enkey';
    const PLAY_ENDPOINT = '/api/app/media/play';

    const DEPS = [
        { global: 'CryptoJS', src: 'https://cdn.jsdelivr.net/npm/crypto-js@4.2.0/crypto-js.min.js' },
        { global: 'Hls',      src: 'https://cdn.jsdelivr.net/npm/hls.js@1.5.13/dist/hls.min.js' },
        { global: 'Plyr',     src: 'https://cdn.jsdelivr.net/npm/plyr@3.7.8/dist/plyr.polyfilled.min.js' },
    ];
    const PLYR_CSS_URL = 'https://cdn.jsdelivr.net/npm/plyr@3.7.8/dist/plyr.min.css';

    if (window.__vgplayer_started__) {
        log('已启动过,跳过');
        return;
    }
    window.__vgplayer_started__ = true;

    function loadScript(src) {
        return new Promise((resolve, reject) => {
            const s = document.createElement('script');
            s.src = src;
            s.async = false;
            s.crossOrigin = 'anonymous';
            s.onload = () => resolve();
            s.onerror = () => reject(new Error('script load failed: ' + src));
            (document.head || document.documentElement).appendChild(s);
        });
    }

    async function ensureDeps() {
        for (const d of DEPS) {
            if (typeof window[d.global] !== 'undefined') {
                log('dep 已就绪:', d.global);
                continue;
            }
            log('加载:', d.src);
            await loadScript(d.src);
            if (typeof window[d.global] === 'undefined') {
                throw new Error('global ' + d.global + ' 未注入,可能被 CSP 拦截');
            }
        }
    }

    function getVideoId() {
        const sp = new URLSearchParams(location.search);
        const raw = sp.get('id');
        if (!raw) return null;
        const n = parseInt(raw, 10);
        return Number.isFinite(n) && n > 0 ? n : null;
    }

    // qy KDF — 与 Python src/k5j7u_com/decrypt_media_play.py::decrypt_butterfly 逐字节对齐,
    // 任何偏移改动都会让所有 /api/app/* 响应解密失败:
    //   raw = base64(data); salt = raw[:12]; ct = raw[12:]
    //   o = INTERFACE_KEY (32B) + salt (12B) = 44B; n = 22
    //   l = SHA256(o)[8:24]
    //   p = SHA256(l + o[:22])
    //   u = SHA256(o[22:] + l)
    //   key = p[0:8] + u[8:24] + p[24:32]   (32B)
    //   iv  = u[0:4] + p[12:20] + u[28:32]  (16B)
    //   plaintext = AES-256-CBC(ct, key, iv) + PKCS7 unpad
    function wordsConcat(CJS, ...wordArrays) {
        const out = CJS.lib.WordArray.create();
        for (const w of wordArrays) out.concat(w);
        return out;
    }

    function wordsSlice(CJS, wa, start, end) {
        const bytes = [];
        for (let i = start; i < end; i++) {
            bytes.push((wa.words[i >>> 2] >>> (24 - (i & 3) * 8)) & 0xff);
        }
        const words = [];
        for (let i = 0; i < bytes.length; i += 4) {
            const b0 = bytes[i] || 0;
            const b1 = bytes[i + 1] || 0;
            const b2 = bytes[i + 2] || 0;
            const b3 = bytes[i + 3] || 0;
            words.push((b0 << 24) | (b1 << 16) | (b2 << 8) | b3);
        }
        return CJS.lib.WordArray.create(words, bytes.length);
    }

    function qyDecrypt(payloadB64) {
        const CJS = window.CryptoJS;
        const raw = CJS.enc.Base64.parse(payloadB64.trim());
        if (raw.sigBytes < 12) throw new Error('payload too short for salt');

        const salt = wordsSlice(CJS, raw, 0, 12);
        const ct = wordsSlice(CJS, raw, 12, raw.sigBytes);

        const ik = CJS.enc.Utf8.parse(INTERFACE_KEY);
        const o = wordsConcat(CJS, ik.clone(), salt.clone());
        const n = (o.sigBytes / 2) | 0;

        const hO = CJS.SHA256(o);
        const l = wordsSlice(CJS, hO, 8, 24);
        const p = CJS.SHA256(wordsConcat(CJS, l.clone(), wordsSlice(CJS, o, 0, n)));
        const u = CJS.SHA256(wordsConcat(CJS, wordsSlice(CJS, o, n, o.sigBytes), l.clone()));

        const key = wordsConcat(CJS,
            wordsSlice(CJS, p, 0, 8),
            wordsSlice(CJS, u, 8, 24),
            wordsSlice(CJS, p, 24, 32),
        );
        const iv = wordsConcat(CJS,
            wordsSlice(CJS, u, 0, 4),
            wordsSlice(CJS, p, 12, 20),
            wordsSlice(CJS, u, 28, 32),
        );
        if (key.sigBytes !== 32) throw new Error('key len ' + key.sigBytes);
        if (iv.sigBytes !== 16) throw new Error('iv len ' + iv.sigBytes);

        const decrypted = CJS.AES.decrypt(
            CJS.lib.CipherParams.create({ ciphertext: ct }),
            key,
            { iv: iv, mode: CJS.mode.CBC, padding: CJS.pad.Pkcs7 }
        );
        return decrypted.toString(CJS.enc.Utf8);
    }

    async function fetchMediaPlay(id) {
        const resp = await fetch(PLAY_ENDPOINT, {
            method: 'POST',
            credentials: 'include',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
            },
            body: JSON.stringify({ id: id }),
        });
        if (!resp.ok) throw new Error('media/play HTTP ' + resp.status);
        const body = await resp.json();
        if (typeof body.data !== 'string') throw new Error('media/play: no data field');
        const plain = qyDecrypt(body.data);
        const obj = JSON.parse(plain);
        if (!obj.mediaInfo || !obj.mediaInfo.videoUrl) {
            throw new Error('media/play: no mediaInfo.videoUrl');
        }
        return obj;
    }

    function ensurePlyrCss() {
        if (document.querySelector('link[data-vgplayer-plyr]')) return;
        const link = document.createElement('link');
        link.rel = 'stylesheet';
        link.href = PLYR_CSS_URL;
        link.setAttribute('data-vgplayer-plyr', '1');
        document.head.appendChild(link);
    }

    function injectOverlayStyle() {
        if (document.querySelector('style[data-vgplayer-style]')) return;
        const st = document.createElement('style');
        st.setAttribute('data-vgplayer-style', '1');
        st.textContent = `
        .vgp-modal {
            position: fixed; inset: 0;
            z-index: 2147483647;
            background: #000;
            display: flex; align-items: center; justify-content: center;
        }
        .vgp-modal .vgp-close {
            position: absolute; top: 12px; right: 16px;
            width: 36px; height: 36px;
            border: none; border-radius: 50%;
            background: rgba(0,0,0,0.55); color: #fff;
            font-size: 22px; line-height: 36px; text-align: center;
            cursor: pointer; z-index: 2;
        }
        .vgp-modal .vgp-title {
            position: absolute; top: 14px; left: 16px; right: 70px;
            color: #fff; font-size: 15px; line-height: 1.4;
            text-shadow: 0 1px 3px rgba(0,0,0,0.8);
            white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
        }
        .vgp-modal .vgp-stage {
            width: 100%; height: 100%;
            display: flex; align-items: center; justify-content: center;
        }
        .vgp-modal video { width: 100%; height: auto; max-height: 100%; background: #000; }
        .vgp-modal .vgp-status {
            position: absolute; bottom: 20px; left: 50%; transform: translateX(-50%);
            color: #fff; font-size: 13px; background: rgba(0,0,0,0.6);
            padding: 6px 12px; border-radius: 4px; pointer-events: none;
        }
        `;
        document.head.appendChild(st);
    }

    function createOverlay(title) {
        const root = document.createElement('div');
        root.className = 'vgp-modal';
        root.setAttribute('data-vgplayer-root', '1');

        const titleEl = document.createElement('div');
        titleEl.className = 'vgp-title';
        titleEl.textContent = title || '';

        const close = document.createElement('button');
        close.className = 'vgp-close';
        close.textContent = '×';
        close.title = '关闭';

        const stage = document.createElement('div');
        stage.className = 'vgp-stage';

        const video = document.createElement('video');
        video.setAttribute('playsinline', '');
        video.setAttribute('webkit-playsinline', '');
        video.controls = true;
        video.crossOrigin = 'anonymous';
        stage.appendChild(video);

        const status = document.createElement('div');
        status.className = 'vgp-status';
        status.textContent = '加载中…';

        root.appendChild(titleEl);
        root.appendChild(close);
        root.appendChild(stage);
        root.appendChild(status);
        document.body.appendChild(root);

        return { root, video, status, close };
    }

    function destroyOverlay(ctx) {
        try { ctx.hls && ctx.hls.destroy(); } catch (e) {}
        try { ctx.player && ctx.player.destroy(); } catch (e) {}
        try { ctx.root && ctx.root.remove(); } catch (e) {}
        window.__vgplayer_started__ = false;
    }

    // hls.js 的 xhrSetup 会在每次 XHR open 前触发;站点在 CDN m3u8 里写的
    // #EXT-X-KEY URI 是字面占位符 "http://domain/enc.key",必须把它重写到
    // 同源 /api/app/media/enkey 才能拿到真实 AES-128 key。
    function startHls(video, m3u8Url) {
        const Hls = window.Hls;
        if (Hls.isSupported()) {
            const hls = new Hls({
                xhrSetup: function (xhr, url) {
                    if (/\/enc\.key($|\?)/.test(url) || /domain\/enc\.key/i.test(url)) {
                        const target = location.origin + ENKEY_ENDPOINT;
                        xhr.open('GET', target, true);
                        xhr.withCredentials = true;
                    }
                },
            });
            hls.loadSource(m3u8Url);
            hls.attachMedia(video);
            return { hls: hls, native: false };
        }

        // iOS Safari 原生 HLS fallback;若 key URI 仍是占位符会直接失败。
        video.src = m3u8Url;
        return { hls: null, native: true };
    }

    async function main() {
        const id = getVideoId();
        if (!id) {
            warn('URL 里没有 id,跳过');
            alert('[VGPlayer] 当前页面 URL 里没有 id 参数,请在视频详情页运行');
            window.__vgplayer_started__ = false;
            return;
        }
        log('启动,id=', id);

        let ctx = null;
        try {
            await ensureDeps();
            ensurePlyrCss();
            injectOverlayStyle();

            const info = await fetchMediaPlay(id);
            const title = info.mediaInfo.title || ('video ' + id);
            const videoUrl = info.mediaInfo.videoUrl;
            const m3u8 = videoUrl.startsWith('http') ? videoUrl : (VIDEO_CDN + '/' + videoUrl.replace(/^\//, ''));
            log('title=', title, 'm3u8=', m3u8);

            ctx = createOverlay(title);
            ctx.close.addEventListener('click', () => destroyOverlay(ctx));

            const hlsState = startHls(ctx.video, m3u8);
            ctx.hls = hlsState.hls;

            if (typeof window.Plyr !== 'undefined') {
                ctx.player = new window.Plyr(ctx.video, {
                    controls: ['play-large', 'play', 'progress', 'current-time', 'duration',
                               'mute', 'volume', 'settings', 'pip', 'fullscreen'],
                    settings: ['speed'],
                    speed: { selected: 1, options: [0.5, 1, 1.25, 1.5, 2] },
                    keyboard: { focused: true, global: false },
                });
            } else {
                warn('Plyr 未加载,fallback 到原生 controls');
            }

            ctx.video.addEventListener('loadedmetadata', () => {
                ctx.status.textContent = '时长 ' + Math.round(ctx.video.duration) + ' 秒';
                setTimeout(() => { if (ctx.status) ctx.status.style.display = 'none'; }, 2500);
            });
            ctx.video.addEventListener('error', (e) => {
                err('<video> error', e);
                ctx.status.textContent = '播放失败,见控制台';
            });
            if (ctx.hls) {
                ctx.hls.on(window.Hls.Events.ERROR, (event, data) => {
                    err('hls error', data.type, data.details, data);
                    if (data.fatal) ctx.status.textContent = 'HLS 错误: ' + data.details;
                });
            }

            ctx.video.play().catch(() => {});
        } catch (e) {
            err('main 失败:', e);
            if (ctx) {
                ctx.status.textContent = '错误: ' + (e && e.message ? e.message : e);
            } else {
                alert('[VGPlayer] ' + (e && e.message ? e.message : e));
                window.__vgplayer_started__ = false;
            }
        }
    }

    main();
})();
