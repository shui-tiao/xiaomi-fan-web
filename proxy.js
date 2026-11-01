#!/usr/bin/env node
/**
 * 小米云 token 提取本地代理（Web 版）
 *
 * 移植自 PiotrMachowski/Xiaomi-cloud-tokens-extractor（MIT）的账号密码登录流程：
 *   RC4 加密参数、signed_nonce、homeroom/home_device_list、blt_get_beaconkey。
 *
 * 浏览器直连小米云会被 CORS 阻断，且 node 端需要 RC4 / 特殊请求头，
 * 所以由本进程代为请求。账号密码只经过本机 127.0.0.1，不会被记录。
 *
 * 用法：  node proxy.js            (默认 http://127.0.0.1:8765)
 *        PORT=9000 node proxy.js
 */

const http = require("http");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const PORT = Number(process.env.PORT || 8765);
const HOST = "127.0.0.1";
const SERVERS = ["cn", "de", "us", "ru", "tw", "sg", "in", "i2"];
const ALLOWED_ORIGINS = [
  "http://127.0.0.1:8765",
  "http://localhost:8765",
  "http://127.0.0.1:8080",
  "http://localhost:8080",
];

// ---------------------------------------------------------------- 小米云连接器

const b64 = (buf) => Buffer.from(buf).toString("base64");
const randomAgent = () => {
  const id = Array.from({ length: 13 }, () => String.fromCharCode(65 + Math.floor(Math.random() * 5))).join("");
  const txt = Array.from({ length: 18 }, () => String.fromCharCode(97 + Math.floor(Math.random() * 26))).join("");
  return `${txt}-${id} APP/com.xiaomi.mihome APPV/10.5.201`;
};
const randomDeviceId = () =>
  Array.from({ length: 6 }, () => String.fromCharCode(97 + Math.floor(Math.random() * 26))).join("");

function rc4(key, payload) {
  const cipher = crypto.createCipheriv("rc4", key, null);
  cipher.update(Buffer.alloc(1024)); // 丢掉前 1024 字节密钥流，和原项目一致
  return Buffer.concat([cipher.update(payload), cipher.final()]);
}

class XiaomiCloud {
  constructor() {
    this.agent = randomAgent();
    this.deviceId = randomDeviceId();
    this.cookies = new Map();
    this.ssecurity = null;
    this.userId = null;
    this.serviceToken = null;
  }

  // --- cookie 处理
  absorbCookies(res) {
    const list = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
    for (const raw of list) {
      const [pair] = raw.split(";");
      const idx = pair.indexOf("=");
      if (idx > 0) this.cookies.set(pair.slice(0, idx).trim(), pair.slice(idx + 1).trim());
    }
  }
  cookieHeader(extra = {}) {
    const all = Object.fromEntries(this.cookies);
    return Object.entries({ ...all, ...extra })
      .map(([k, v]) => `${k}=${v}`)
      .join("; ");
  }
  async request(url, { method = "GET", body, headers = {}, extraCookies = {}, redirect = "follow" } = {}) {
    const res = await fetch(url, {
      method,
      body,
      headers: { "User-Agent": this.agent, Cookie: this.cookieHeader(extraCookies), ...headers },
      redirect,
    });
    this.absorbCookies(res);
    const text = await res.text();
    return { status: res.status, text, headers: res.headers };
  }

  // --- 登录
  static toJson(text) {
    return JSON.parse(text.replace("&&&START&&&", ""));
  }

  async login(username, password) {
    this.cookies.set("sdkVersion", "accountsdk-18.8.15");
    this.cookies.set("deviceId", this.deviceId);

    // 1. 拿 _sign
    const step1 = await this.request("https://account.xiaomi.com/pass/serviceLogin?sid=xiaomiio&_json=true", {
      extraCookies: { userId: username },
    });
    if (step1.status !== 200) throw new Error(`登录服务不可达 (HTTP ${step1.status})`);
    const j1 = XiaomiCloud.toJson(step1.text);
    const sign = j1._sign;
    if (!sign) throw new Error("无法获取登录签名，请检查账号");

    // 2. 提交账号密码
    const hash = crypto.createHash("md5").update(password, "utf8").digest("hex").toUpperCase();
    const params = new URLSearchParams({
      sid: "xiaomiio",
      hash,
      callback: "https://sts.api.io.mi.com/sts",
      qs: "%3Fsid%3Dxiaomiio%26_json%3Dtrue",
      user: username,
      _sign: sign,
      _json: "true",
    });
    const step2 = await this.request(`https://account.xiaomi.com/pass/serviceLoginAuth2?${params}`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      extraCookies: { userId: username },
      redirect: "manual",
    });
    let j2;
    try {
      j2 = XiaomiCloud.toJson(step2.text);
    } catch {
      throw new Error(`登录响应无法解析 (HTTP ${step2.status})`);
    }
    if (j2.captchaUrl) {
      throw new Error("小米要求输入图形验证码，请先在米家 App 或手机浏览器登录一次账号后再试");
    }
    if (j2.notificationUrl) {
      throw new Error("该账号开启了邮箱二次验证，请先在米家 App 或手机浏览器完成验证后再试");
    }
    if (!j2.ssecurity || String(j2.ssecurity).length <= 4) {
      throw new Error(j2.desc || j2.code ? `登录失败：${j2.desc || j2.code}` : "账号或密码错误");
    }
    this.ssecurity = j2.ssecurity;
    this.userId = j2.userId;
    const location = j2.location;
    if (!location) throw new Error("登录未返回服务票据地址");

    // 3. 换取 serviceToken
    const step3 = await this.request(location, { headers: { "Content-Type": "application/x-www-form-urlencoded" } });
    if (step3.status !== 200) throw new Error(`获取 serviceToken 失败 (HTTP ${step3.status})`);
    this.serviceToken = this.cookies.get("serviceToken");
    if (!this.serviceToken) throw new Error("登录响应中没有 serviceToken");
    return true;
  }

  // --- 云 API（ENCRYPT-RC4）
  static apiUrl(country) {
    return `https://${country === "cn" ? "" : country + "."}api.io.mi.com/app`;
  }
  signedNonce(nonce) {
    return b64(crypto.createHash("sha256").update(Buffer.concat([Buffer.from(this.ssecurity, "base64"), Buffer.from(nonce, "base64")])).digest());
  }
  static encSignature(url, method, signedNonce, params) {
    const parts = [String(method).toUpperCase(), url.split("com")[1].replace("/app/", "/")];
    for (const [k, v] of Object.entries(params)) parts.push(`${k}=${v}`);
    parts.push(signedNonce);
    return b64(crypto.createHash("sha1").update(parts.join("&"), "utf8").digest());
  }

  async api(country, path, dataParams) {
    const url = XiaomiCloud.apiUrl(country) + path;
    const millis = Date.now();
    const nonceBytes = Buffer.concat([crypto.randomBytes(8), Buffer.from(Math.floor(millis / 60000).toString(16).padStart(8, "0"), "hex")]);
    const nonce = b64(nonceBytes);
    const signed = this.signedNonce(nonce);

    const params = { ...dataParams };
    params.rc4_hash__ = XiaomiCloud.encSignature(url, "POST", signed, params);
    for (const k of Object.keys(params)) {
      params[k] = b64(rc4(Buffer.from(signed, "base64"), Buffer.from(params[k], "utf8")));
    }
    params.signature = XiaomiCloud.encSignature(url, "POST", signed, params);
    params.ssecurity = this.ssecurity;
    params._nonce = nonce;

    const qs = new URLSearchParams(params).toString();
    const res = await this.request(`${url}?${qs}`, {
      method: "POST",
      headers: {
        "Accept-Encoding": "identity",
        "Content-Type": "application/x-www-form-urlencoded",
        "x-xiaomi-protocal-flag-cli": "PROTOCAL-HTTP2",
        "MIOT-ENCRYPT-ALGORITHM": "ENCRYPT-RC4",
        "Content-Length": "0",
      },
      extraCookies: {
        userId: String(this.userId),
        serviceToken: this.serviceToken,
        yetAnotherServiceToken: this.serviceToken,
        locale: "en_GB",
        timezone: "GMT+02:00",
        is_daylight: "1",
        dst_offset: "3600000",
        channel: "MI_APP_STORE",
      },
    });
    if (res.status === 401 || res.status === 403) throw new Error("云端登录态已失效，请重新登录");
    if (res.status !== 200) throw new Error(`云端接口 ${path} 返回 HTTP ${res.status}`);
    const plain = rc4(Buffer.from(this.signedNonce(params._nonce), "base64"), Buffer.from(res.text, "base64")).toString("utf8");
    return JSON.parse(plain);
  }

  // --- 业务接口
  async devices(countries) {
    const out = [];
    const seen = new Set();
    for (const server of countries) {
      let homes = [];
      try {
        const r = await this.api(server, "/v2/homeroom/gethome", {
          data: '{"fg": true, "fetch_share": true, "fetch_share_dev": true, "limit": 300, "app_ver": 7}',
        });
        for (const h of r?.result?.homelist || []) homes.push({ home_id: h.id, home_owner: this.userId, shared: false });
      } catch (e) {
        if (/失效/.test(e.message)) throw e;
      }
      try {
        const r = await this.api(server, "/v2/user/get_device_cnt", { data: '{ "fetch_own": true, "fetch_share": true}' });
        for (const h of r?.result?.share?.share_family || []) homes.push({ home_id: h.home_id, home_owner: h.home_owner, shared: true });
      } catch (e) {
        if (/失效/.test(e.message)) throw e;
      }

      for (const home of homes) {
        let r;
        try {
          r = await this.api(server, "/v2/home/home_device_list", {
            data: `{"home_owner": ${home.home_owner}, "home_id": ${home.home_id}, "limit": 200, "get_split_device": true, "support_smart_home": true}`,
          });
        } catch (e) {
          if (/失效/.test(e.message)) throw e;
          continue;
        }
        for (const d of r?.result?.device_info || []) {
          if (!d.mac) continue;
          const mac = String(d.mac).toUpperCase().replace(/-/g, ":");
          const key = `${server}|${mac}`;
          if (seen.has(key)) continue;
          seen.add(key);
          const item = {
            server,
            shared: home.shared,
            name: d.name || "(未命名)",
            mac,
            did: d.did || "",
            model: d.model || "",
            isBle: typeof d.did === "string" && d.did.includes("blt"),
            token: d.token || "",
            beaconkey: "",
            beaconkeyError: "",
          };
          if (item.isBle) {
            try {
              const k = await this.api(server, "/v2/device/blt_get_beaconkey", { data: `{"did":"${item.did}","pdid":1}` });
              const bk = k?.result?.beaconkey || "";
              if (bk.length === 24) item.beaconkey = bk;
              else item.beaconkeyError = "云端未下发 12 字节 BLE 密钥";
            } catch (e) {
              item.beaconkeyError = e.message;
            }
          }
          out.push(item);
        }
      }
    }
    return out;
  }
}

// ---------------------------------------------------------------- HTTP 服务

const sessions = new Map(); // sid -> XiaomiCloud

function cors(req, res) {
  const origin = req.headers.origin;
  if (origin && ALLOWED_ORIGINS.includes(origin)) res.setHeader("Access-Control-Allow-Origin", origin);
  else res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Vary", "Origin");
}

const json = (res, status, payload) => {
  const body = JSON.stringify(payload);
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" });
  res.end(body);
};

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on("data", (c) => {
      size += c.length;
      if (size > 64 * 1024) reject(new Error("请求体过大"));
      else chunks.push(c);
    });
    req.on("end", () => {
      try {
        resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf8")) : {});
      } catch {
        reject(new Error("请求体不是合法 JSON"));
      }
    });
    req.on("error", reject);
  });
}

const server = http.createServer(async (req, res) => {
  cors(req, res);
  if (req.method === "OPTIONS") {
    res.writeHead(204);
    return res.end();
  }

  const url = new URL(req.url, `http://${HOST}:${PORT}`);

  try {
    if (url.pathname === "/health") {
      return json(res, 200, { ok: true, service: "xiaomi-cloud-token-proxy" });
    }

    // 顺带把同目录的 index.html 托管在 localhost 下，Web Bluetooth 在部分
    // 浏览器版本只对 http://localhost 这类安全来源开放（file:// 可能被禁用）
    if (url.pathname === "/" && req.method === "GET") {
      const file = path.join(__dirname, "index.html");
      const html = await fs.promises.readFile(file).catch(() => null);
      if (!html) return json(res, 404, { ok: false, error: "同目录下没有 index.html" });
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
      return res.end(html);
    }

    if (url.pathname === "/api/login" && req.method === "POST") {
      const { username, password } = await readBody(req);
      if (!username || !password) return json(res, 400, { ok: false, error: "请输入账号和密码" });
      const client = new XiaomiCloud();
      await client.login(String(username).trim(), String(password));
      const sid = crypto.randomUUID();
      sessions.set(sid, client);
      return json(res, 200, { ok: true, sid });
    }

    if (url.pathname === "/api/devices") {
      const sid = url.searchParams.get("sid");
      const client = sessions.get(sid);
      if (!client) return json(res, 401, { ok: false, error: "会话不存在，请重新登录" });
      const raw = url.searchParams.get("servers") || "";
      const list = raw ? raw.split(",").filter((s) => SERVERS.includes(s)) : SERVERS;
      const devices = await client.devices(list.length ? list : SERVERS);
      return json(res, 200, { ok: true, devices });
    }

    if (url.pathname === "/api/logout" && req.method === "POST") {
      const { sid } = await readBody(req);
      sessions.delete(sid);
      return json(res, 200, { ok: true });
    }

    return json(res, 404, { ok: false, error: "未知接口" });
  } catch (err) {
    return json(res, 400, { ok: false, error: err && err.message ? err.message : String(err) });
  }
});

server.listen(PORT, HOST, () => {
  console.log(`\n  小米云 Token 代理已启动:  http://${HOST}:${PORT}`);
  console.log(`  浏览器打开 http://${HOST}:${PORT} 即可使用（同目录需有 index.html）`);
  console.log(`  也可以直接双击 index.html，代理地址填 http://${HOST}:${PORT}\n`);
});
