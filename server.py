#!/usr/bin/env python3
"""Local XiaoZhi web console.

Serves an HTML talk page and proxies browser WebSocket traffic to the
official XiaoZhi server, injecting the Device-Id / Client-Id / token
headers that browsers cannot set.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import secrets
import ssl
import sys
import threading
import uuid
from pathlib import Path

import numpy as np
from aiohttp import ClientSession, ClientTimeout, TCPConnector, WSMsgType, web

HERE = Path(__file__).resolve().parent
AGENTS_PATH = HERE / "agents.json"
HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8765"))
INPUT_RATE = 16000
FRAME_MS = 60
FRAME_SAMPLES = INPUT_RATE * FRAME_MS // 1000
DEFAULT_PLAY_RATE = 24000
DEFAULT_WS_URL = "wss://api.tenclass.net/xiaozhi/v1/"
DEFAULT_TOKEN = "test-token"
OTA_URL = "https://api.tenclass.net/xiaozhi/ota/"
ACTIVATE_URL = OTA_URL.rstrip("/") + "/activate"
_STORE_LOCK = threading.RLock()
_ACTIVATE_TASKS: dict[str, asyncio.Task] = {}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("xiaozhi-web")


def setup_opus() -> None:
    import ctypes
    import ctypes.util

    candidates = [
        Path("/opt/homebrew/lib/libopus.dylib"),
        Path("/usr/local/lib/libopus.dylib"),
        Path("/usr/lib/libopus.dylib"),
        Path("/usr/lib/x86_64-linux-gnu/libopus.so.0"),
        Path("/usr/lib/aarch64-linux-gnu/libopus.so.0"),
        Path("/usr/lib64/libopus.so.0"),
        Path("/usr/lib/libopus.so.0"),
    ]
    lib_path = next((p for p in candidates if p.exists()), None)
    if lib_path is None:
        found = ctypes.util.find_library("opus")
        if not found:
            raise RuntimeError(
                "未找到 libopus。macOS 请执行 brew install opus；"
                "Ubuntu / Debian 请执行 sudo apt install libopus0。"
            )
        lib_path = Path(found)
    ctypes.CDLL(str(lib_path))
    original = ctypes.util.find_library

    def patched(name: str):
        return str(lib_path) if name == "opus" else original(name)

    ctypes.util.find_library = patched


setup_opus()
import opuslib  # noqa: E402


def _new_mac(existing: set[str]) -> str:
    while True:
        raw = bytearray(secrets.token_bytes(6))
        raw[0] = (raw[0] | 0x02) & 0xFE
        mac = ":".join(f"{b:02x}" for b in raw)
        if mac not in existing:
            return mac


def ensure_identity(agent: dict) -> dict:
    mac = (agent.get("device_id") or "").lower()
    mac_clean = mac.replace(":", "")
    if not agent.get("serial_number") and mac_clean:
        short_hash = hashlib.md5(mac_clean.encode()).hexdigest()[:8].upper()
        agent["serial_number"] = f"SN-{short_hash}-{mac_clean}"
    if not agent.get("hmac_key"):
        seed = f"{mac}|{agent.get('client_id') or uuid.uuid4()}|{secrets.token_hex(8)}"
        agent["hmac_key"] = hashlib.sha256(seed.encode()).hexdigest()
    return agent


def _public_agent(agent: dict) -> dict:
    return {
        "id": agent["id"],
        "name": agent["name"],
        "bound": bool(agent.get("bound")),
        "activationCode": agent.get("activation_code"),
    }


def _blank_store() -> dict:
    return {"current_id": None, "agents": []}


def load_store() -> dict:
    with _STORE_LOCK:
        if not AGENTS_PATH.exists():
            store = _blank_store()
            AGENTS_PATH.write_text(
                json.dumps(store, ensure_ascii=False, indent=2), encoding="utf-8"
            )
            return store
        store = json.loads(AGENTS_PATH.read_text(encoding="utf-8"))
        store.setdefault("agents", [])
        if not store["agents"]:
            store["current_id"] = None
        elif not any(a["id"] == store.get("current_id") for a in store["agents"]):
            store["current_id"] = store["agents"][0]["id"]
        changed = False
        for agent in store["agents"]:
            before = (agent.get("serial_number"), agent.get("hmac_key"))
            ensure_identity(agent)
            if (agent.get("serial_number"), agent.get("hmac_key")) != before:
                changed = True
        if changed:
            AGENTS_PATH.write_text(
                json.dumps(store, ensure_ascii=False, indent=2), encoding="utf-8"
            )
        return store


def save_store(store: dict) -> None:
    with _STORE_LOCK:
        AGENTS_PATH.write_text(
            json.dumps(store, ensure_ascii=False, indent=2), encoding="utf-8"
        )


def current_agent(store: dict | None = None) -> dict | None:
    store = store or load_store()
    agents = store.get("agents") or []
    if not agents:
        return None
    for agent in agents:
        if agent["id"] == store.get("current_id"):
            return agent
    return agents[0]


def find_agent(agent_id: str, store: dict | None = None) -> dict:
    store = store or load_store()
    for agent in store["agents"]:
        if agent["id"] == agent_id:
            return agent
    raise KeyError(f"没有这个智能体：{agent_id}")


def cfg_from_agent(agent: dict) -> dict:
    return {
        "ws_url": agent.get("ws_url") or DEFAULT_WS_URL,
        "token": agent.get("token") or DEFAULT_TOKEN,
        "device_id": agent["device_id"],
        "client_id": agent["client_id"],
        "agent_id": agent["id"],
        "agent_name": agent["name"],
        "bound": bool(agent.get("bound")),
        "activation_code": agent.get("activation_code"),
    }


def agents_payload(store: dict | None = None) -> dict:
    store = store or load_store()
    agent = current_agent(store)
    return {
        "currentId": store.get("current_id"),
        "agents": [_public_agent(a) for a in store.get("agents") or []],
        "agentId": agent["id"] if agent else None,
        "agentName": agent["name"] if agent else "",
        "bound": bool(agent.get("bound")) if agent else False,
        "activationCode": agent.get("activation_code") if agent else None,
    }


def _ota_headers(agent: dict, version: str = "2") -> dict:
    ensure_identity(agent)
    headers = {
        "Device-Id": agent["device_id"],
        "Client-Id": agent["client_id"],
        "Serial-Number": agent["serial_number"],
        "Activation-Version": version,
        "Content-Type": "application/json",
        "User-Agent": "bread-compact-wifi/py-xiaozhi-2.1.2",
        "Accept-Language": "zh-CN",
    }
    return headers


async def _http_json(method: str, url: str, headers: dict, payload: dict | None = None):
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE
    timeout = ClientTimeout(total=12)
    connector = TCPConnector(ssl=ssl_ctx)
    async with ClientSession(timeout=timeout, connector=connector) as session:
        async with session.request(method, url, headers=headers, json=payload) as resp:
            text = await resp.text()
            data = None
            if text:
                try:
                    data = json.loads(text)
                except json.JSONDecodeError:
                    data = {"raw": text[:300]}
            return resp.status, data


async def fetch_ota(agent: dict) -> dict:
    ensure_identity(agent)
    payload = {
        "application": {
            "version": "2.1.2",
            "elf_sha256": agent["hmac_key"],
        },
        "board": {
            "type": "bread-compact-wifi",
            "name": "py-xiaozhi",
            "ip": "127.0.0.1",
            "mac": agent["device_id"],
        },
    }
    status, data = await _http_json("POST", OTA_URL, _ota_headers(agent), payload)
    if status != 200 or not isinstance(data, dict):
        raise RuntimeError(f"OTA 失败 {status}: {data}")
    return data


async def post_activate(agent: dict) -> int:
    ensure_identity(agent)
    challenge = agent.get("challenge")
    if not challenge:
        return 400
    signature = hmac.new(
        agent["hmac_key"].encode(),
        str(challenge).encode(),
        hashlib.sha256,
    ).hexdigest()
    payload = {
        "Payload": {
            "algorithm": "hmac-sha256",
            "serial_number": agent["serial_number"],
            "challenge": challenge,
            "hmac": signature,
        }
    }
    status, data = await _http_json(
        "POST", ACTIVATE_URL, _ota_headers(agent), payload
    )
    if status not in (200, 202):
        log.info(
            "激活握手 %s status=%s body=%s",
            agent.get("name"),
            status,
            data,
        )
    return status


def start_activate_loop(agent_id: str) -> None:
    old = _ACTIVATE_TASKS.get(agent_id)
    if old and not old.done():
        return
    _ACTIVATE_TASKS[agent_id] = asyncio.create_task(_activate_loop(agent_id))


async def _activate_loop(agent_id: str) -> None:
    for _ in range(60):
        store = load_store()
        try:
            agent = find_agent(agent_id, store)
        except KeyError:
            return
        if agent.get("bound"):
            return
        if not agent.get("challenge"):
            await refresh_agent(agent)
            _write_agent(agent)
        status = await post_activate(agent)
        if status == 200:
            agent["bound"] = True
            agent["activation_code"] = None
            agent["challenge"] = None
            await refresh_agent(agent)
            _write_agent(agent)
            log.info("智能体 %s 已完成官方激活", agent.get("name"))
            return
        if status == 202:
            log.info("官方已收到序列号，等待控制台输入验证码 agent=%s", agent.get("name"))
        await asyncio.sleep(5)


async def refresh_agent(agent: dict) -> dict:
    ensure_identity(agent)
    data = await fetch_ota(agent)
    activation = data.get("activation") or {}
    code = activation.get("code")
    challenge = activation.get("challenge")
    if code:
        agent["bound"] = False
        agent["activation_code"] = str(code)
        if challenge:
            agent["challenge"] = str(challenge)
        start_activate_loop(agent["id"])
    else:
        agent["bound"] = True
        agent["activation_code"] = None
        agent["challenge"] = None
    websocket = data.get("websocket") or {}
    if websocket.get("url"):
        agent["ws_url"] = websocket["url"]
    if websocket.get("token"):
        agent["token"] = websocket["token"]
    return agent


def parse_opus_duration_ms(opus_data: bytes) -> float:
    if not opus_data:
        return FRAME_MS
    toc = opus_data[0]
    config = (toc >> 3) & 0x1F
    code = toc & 0x03
    if config < 12:
        frame_ms = (10, 20, 40, 60)[config % 4]
    elif config < 16:
        frame_ms = (10, 20)[config % 2]
    else:
        frame_ms = (2.5, 5, 10, 20)[config % 4]
    if code == 0:
        num_frames = 1
    elif code <= 2:
        num_frames = 2
    else:
        num_frames = (opus_data[1] & 0x3F) if len(opus_data) >= 2 else 1
    return frame_ms * num_frames


class OpusBridge:
    def __init__(self, play_rate: int = DEFAULT_PLAY_RATE):
        self.play_rate = play_rate
        self.encoder = opuslib.Encoder(INPUT_RATE, 1, opuslib.APPLICATION_VOIP)
        self.decoder = opuslib.Decoder(play_rate, 1)
        self._pcm_buf = np.zeros(0, dtype=np.float32)

    def reset_decoder(self, play_rate: int) -> None:
        self.play_rate = play_rate
        self.decoder = opuslib.Decoder(play_rate, 1)

    def encode_pcm16(self, pcm16: bytes) -> list[bytes]:
        if not pcm16:
            return []
        samples = np.frombuffer(pcm16, dtype=np.int16).astype(np.float32) / 32768.0
        if samples.size == 0:
            return []
        self._pcm_buf = np.concatenate([self._pcm_buf, samples])
        frames: list[bytes] = []
        while self._pcm_buf.size >= FRAME_SAMPLES:
            chunk = self._pcm_buf[:FRAME_SAMPLES]
            self._pcm_buf = self._pcm_buf[FRAME_SAMPLES:]
            frames.append(self.encoder.encode_float(chunk.tobytes(), FRAME_SAMPLES))
        return frames

    def flush(self) -> list[bytes]:
        if self._pcm_buf.size == 0:
            return []
        padded = np.zeros(FRAME_SAMPLES, dtype=np.float32)
        padded[: self._pcm_buf.size] = self._pcm_buf
        self._pcm_buf = np.zeros(0, dtype=np.float32)
        return [self.encoder.encode_float(padded.tobytes(), FRAME_SAMPLES)]

    def decode_opus(self, opus_data: bytes) -> bytes:
        duration_ms = parse_opus_duration_ms(opus_data)
        frame_size = max(int(self.play_rate * duration_ms / 1000), 1)
        pcm = self.decoder.decode_float(opus_data, frame_size, decode_fec=False)
        f32 = np.frombuffer(pcm, dtype=np.float32)
        return np.clip(f32 * 32767.0, -32768, 32767).astype(np.int16).tobytes()


class OfficialSession:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.upstream = None
        self.session_id = ""
        self.play_rate = DEFAULT_PLAY_RATE
        self.opus = OpusBridge(self.play_rate)
        self.listening = False
        self.speaking = False
        self.powered = False
        self._browser = None
        self._pump = None

    def attach_browser(self, browser: web.WebSocketResponse) -> None:
        self._browser = browser

    def start_pump(self) -> None:
        if self._pump and not self._pump.done():
            self._pump.cancel()
        if self._browser is not None and self.upstream is not None:
            self._pump = asyncio.create_task(pump_upstream(self, self._browser))

    async def connect(self):
        import websockets

        ssl_ctx = ssl._create_unverified_context()
        headers = {
            "Authorization": f"Bearer {self.cfg['token']}",
            "Protocol-Version": "1",
            "Device-Id": self.cfg["device_id"],
            "Client-Id": self.cfg["client_id"],
        }
        try:
            self.upstream = await websockets.connect(
                uri=self.cfg["ws_url"],
                ssl=ssl_ctx,
                additional_headers=headers,
                ping_interval=20,
                ping_timeout=20,
                close_timeout=8,
                open_timeout=8,
                max_size=10 * 1024 * 1024,
                compression=None,
                proxy=None,
            )
        except TypeError:
            self.upstream = await websockets.connect(
                self.cfg["ws_url"],
                ssl=ssl_ctx,
                extra_headers=headers,
                ping_interval=20,
                ping_timeout=20,
                close_timeout=8,
                open_timeout=8,
                max_size=10 * 1024 * 1024,
                compression=None,
            )

        hello = {
            "type": "hello",
            "version": 1,
            "features": {"mcp": False},
            "transport": "websocket",
            "audio_params": {
                "format": "opus",
                "sample_rate": INPUT_RATE,
                "channels": 1,
                "frame_duration": FRAME_MS,
            },
        }
        await self.upstream.send(json.dumps(hello))
        raw = await asyncio.wait_for(self.upstream.recv(), timeout=10)
        data = json.loads(raw)
        if data.get("type") != "hello":
            raise RuntimeError(f"服务端握手失败: {data}")
        self.session_id = data.get("session_id") or ""
        params = data.get("audio_params") or {}
        play_rate = int(params.get("sample_rate") or DEFAULT_PLAY_RATE)
        if play_rate != self.play_rate:
            self.play_rate = play_rate
            self.opus.reset_decoder(play_rate)
        log.info(
            "已连接官方服务 agent=%s session=%s play_rate=%s",
            self.cfg.get("agent_name") or self.cfg["device_id"],
            self.session_id,
            self.play_rate,
        )

    async def close(self):
        if self._pump and not self._pump.done():
            self._pump.cancel()
            try:
                await self._pump
            except (Exception, asyncio.CancelledError):
                pass
        self._pump = None
        if self.upstream is not None:
            try:
                await self.upstream.close()
            except Exception:
                pass
            self.upstream = None
        self.listening = False
        self.speaking = False

    def is_open(self) -> bool:
        return self.upstream is not None and self.upstream.close_code is None

    async def ensure(self):
        if not self.is_open():
            await self.connect()
            self.start_pump()

    async def send_json(self, payload: dict):
        await self.ensure()
        if self.session_id and "session_id" not in payload:
            payload = {**payload, "session_id": self.session_id}
        try:
            await self.upstream.send(json.dumps(payload))
        except Exception as exc:
            log.info("发送官方消息失败: %s", exc)
            await self._mark_upstream_closed()
            raise

    async def send_audio_pcm(self, pcm16: bytes):
        if not self.listening or not self.is_open():
            return
        try:
            for frame in self.opus.encode_pcm16(pcm16):
                await self.upstream.send(frame)
        except Exception as exc:
            log.info("发送音频失败: %s", exc)
            await self._mark_upstream_closed()

    async def _mark_upstream_closed(self) -> None:
        self.listening = False
        self.speaking = False
        if self.upstream is not None:
            try:
                await self.upstream.close()
            except Exception:
                pass
            self.upstream = None
        if self._browser is not None and not self._browser.closed:
            await self._browser.send_str(
                json.dumps({"type": "status", "state": "upstream_closed"})
            )

    async def start_listen(self):
        await self.ensure()
        self.listening = True
        self.speaking = False
        await self.send_json({"type": "listen", "state": "start", "mode": "manual"})

    async def stop_listen(self):
        if not self.is_open():
            self.listening = False
            return
        for frame in self.opus.flush():
            await self.upstream.send(frame)
        self.listening = False
        await self.send_json({"type": "listen", "state": "stop"})

    async def send_text(self, text: str):
        await self.ensure()
        if self.speaking:
            await self.send_json({"type": "abort"})
            self.speaking = False
        await self.send_json({"type": "listen", "state": "start", "mode": "manual"})
        await self.send_json({"type": "listen", "state": "detect", "text": text})

    async def abort(self):
        if self.is_open():
            await self.send_json({"type": "abort"})
        self.listening = False
        self.speaking = False

    async def use_agent(self, agent: dict) -> None:
        await self.close()
        self.cfg = cfg_from_agent(agent)
        self.session_id = ""
        self.play_rate = DEFAULT_PLAY_RATE
        self.opus = OpusBridge(self.play_rate)


def status_message(state: str, session: OfficialSession | None = None, **extra) -> str:
    payload = {"type": "status", "state": state, **agents_payload(), **extra}
    if session is not None:
        payload["playSampleRate"] = session.play_rate
        payload["deviceId"] = session.cfg.get("device_id")
    return json.dumps(payload, ensure_ascii=False)


async def pump_upstream(session: OfficialSession, browser: web.WebSocketResponse):
    try:
        async for message in session.upstream:
            if browser.closed:
                break
            if isinstance(message, bytes):
                try:
                    pcm = session.opus.decode_opus(message)
                    await browser.send_bytes(pcm)
                except Exception as exc:
                    log.info("解码官方音频失败: %s", exc)
                continue
            try:
                data = json.loads(message)
            except json.JSONDecodeError:
                continue
            msg_type = data.get("type")
            if msg_type == "tts" and data.get("state") == "start":
                session.speaking = True
                session.listening = False
            elif msg_type == "tts" and data.get("state") == "stop":
                session.speaking = False
            await browser.send_str(json.dumps(data, ensure_ascii=False))
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        log.info("官方连接结束: %s", exc)
    finally:
        session.listening = False
        session.speaking = False
        session.upstream = None
        if not browser.closed:
            try:
                await browser.send_str(json.dumps({"type": "status", "state": "upstream_closed"}))
            except Exception:
                pass


def _write_agent(agent: dict) -> dict:
    store = load_store()
    for item in store["agents"]:
        if item["id"] == agent["id"]:
            item.update(agent)
            break
    save_store(store)
    return store


async def apply_power_on(session: OfficialSession, browser: web.WebSocketResponse) -> None:
    agent = current_agent()
    if agent is None:
        await browser.send_str(
            json.dumps({"type": "error", "message": "先添加一个智能体，再用验证码绑定"}, ensure_ascii=False)
        )
        return
    if not agent.get("bound"):
        await refresh_agent(agent)
        _write_agent(agent)
        session.cfg = cfg_from_agent(agent)
        if not agent.get("bound"):
            session.powered = True
            await browser.send_str(status_message("need_bind", session))
            return
    session.powered = True
    if session.cfg.get("agent_id") != agent["id"]:
        await session.use_agent(agent)
    else:
        session.cfg = cfg_from_agent(agent)
    await session.ensure()
    await browser.send_str(status_message("ready", session))


async def apply_switch(session: OfficialSession, browser: web.WebSocketResponse, agent_id: str) -> None:
    store = load_store()
    agent = find_agent(agent_id, store)
    store["current_id"] = agent["id"]
    save_store(store)
    await session.use_agent(agent)
    if session.powered:
        await apply_power_on(session, browser)
    else:
        await browser.send_str(status_message("off", session))


async def ws_handler(request: web.Request):
    browser = web.WebSocketResponse(max_msg_size=10 * 1024 * 1024, heartbeat=20)
    await browser.prepare(request)
    agent = current_agent()
    session = OfficialSession(cfg_from_agent(agent)) if agent else None
    if session is not None:
        session.attach_browser(browser)
    try:
        if session is None:
            await browser.send_str(status_message("empty"))
        else:
            await browser.send_str(status_message("off", session))
        async for msg in browser:
            try:
                if msg.type == WSMsgType.TEXT:
                    data = json.loads(msg.data)
                    kind = data.get("type")
                    if kind == "ping":
                        await browser.send_str(json.dumps({"type": "pong"}))
                    elif kind == "power":
                        if session is None:
                            await browser.send_str(
                                json.dumps(
                                    {"type": "error", "message": "先添加一个智能体，再用验证码绑定"},
                                    ensure_ascii=False,
                                )
                            )
                            continue
                        if data.get("on"):
                            await apply_power_on(session, browser)
                        else:
                            session.powered = False
                            try:
                                await session.abort()
                            except Exception:
                                pass
                            await session.close()
                            await browser.send_str(status_message("off", session))
                    elif kind == "switch":
                        agent_id = str(data.get("id") or "")
                        if session is None:
                            picked = find_agent(agent_id)
                            session = OfficialSession(cfg_from_agent(picked))
                            session.attach_browser(browser)
                        await apply_switch(session, browser, agent_id)
                    elif kind == "refresh_agent":
                        store = load_store()
                        agent = current_agent(store)
                        if agent is None or session is None:
                            await browser.send_str(status_message("empty"))
                            continue
                        await refresh_agent(agent)
                        _write_agent(agent)
                        session.cfg = cfg_from_agent(agent)
                        if session.powered and agent.get("bound"):
                            await apply_power_on(session, browser)
                        elif session.powered:
                            await browser.send_str(status_message("need_bind", session))
                        else:
                            await browser.send_str(status_message("off", session))
                    elif kind == "listen" and data.get("state") == "start":
                        if session is None or not session.powered:
                            await browser.send_str(json.dumps({"type": "error", "message": "小智已关闭"}))
                            continue
                        if not session.cfg.get("bound"):
                            await browser.send_str(status_message("need_bind", session))
                            continue
                        await session.start_listen()
                        await browser.send_str(status_message("listening", session))
                    elif kind == "listen" and data.get("state") == "stop":
                        if session is None:
                            continue
                        await session.stop_listen()
                        await browser.send_str(status_message("idle", session))
                    elif kind == "text":
                        if session is None or not session.powered:
                            await browser.send_str(json.dumps({"type": "error", "message": "小智已关闭"}))
                            continue
                        if not session.cfg.get("bound"):
                            await browser.send_str(status_message("need_bind", session))
                            continue
                        text = (data.get("text") or "").strip()
                        if text:
                            await session.send_text(text)
                    elif kind == "abort":
                        if session is None:
                            continue
                        await session.abort()
                        await browser.send_str(status_message("idle", session))
                elif msg.type == WSMsgType.BINARY:
                    if session is not None:
                        await session.send_audio_pcm(msg.data)
                elif msg.type in (WSMsgType.CLOSE, WSMsgType.ERROR):
                    break
            except Exception as exc:
                log.exception("处理网页消息失败")
                if not browser.closed:
                    await browser.send_str(
                        json.dumps({"type": "error", "message": f"这一轮失败，连接仍在：{exc}"})
                    )
    except Exception as exc:
        log.exception("网页会话失败")
        if not browser.closed:
            await browser.send_str(json.dumps({"type": "error", "message": str(exc)}))
    finally:
        if session is not None:
            await session.close()
        if not browser.closed:
            await browser.close()
    return browser


def json_ok(data: dict, status: int = 200) -> web.Response:
    return web.json_response(data, status=status, headers={"Cache-Control": "no-store"})


async def list_agents_handler(_request: web.Request):
    return json_ok(agents_payload())


async def create_agent_handler(request: web.Request):
    body = await request.json()
    name = str(body.get("name") or "").strip()
    if not name:
        return json_ok({"error": "请填写智能体名称"}, 400)
    if len(name) > 40:
        return json_ok({"error": "名称不要超过 40 个字"}, 400)
    store = load_store()
    if any(item["name"] == name for item in store["agents"]):
        return json_ok({"error": "已经有同名智能体"}, 400)
    existing = {item["device_id"] for item in store["agents"]}
    agent = {
        "id": "a-" + secrets.token_hex(4),
        "name": name,
        "device_id": _new_mac(existing),
        "client_id": str(uuid.uuid4()),
        "bound": False,
        "activation_code": None,
        "ws_url": None,
        "token": None,
    }
    ensure_identity(agent)
    await refresh_agent(agent)
    store["agents"].append(agent)
    store["current_id"] = agent["id"]
    save_store(store)
    log.info("已添加智能体 %s device=%s bound=%s", agent["name"], agent["device_id"], agent["bound"])
    return json_ok(agents_payload(store), 201)


async def patch_agent_handler(request: web.Request):
    agent_id = request.match_info["agent_id"]
    body = await request.json()
    try:
        store = load_store()
        agent = find_agent(agent_id, store)
    except KeyError as exc:
        return json_ok({"error": str(exc)}, 404)
    name = str(body.get("name") or "").strip()
    if name:
        if len(name) > 40:
            return json_ok({"error": "名称不要超过 40 个字"}, 400)
        if any(item["name"] == name and item["id"] != agent_id for item in store["agents"]):
            return json_ok({"error": "已经有同名智能体"}, 400)
        agent["name"] = name
    save_store(store)
    return json_ok(agents_payload(store))


def rotate_identity(agent: dict, existing_macs: set[str]) -> dict:
    task = _ACTIVATE_TASKS.pop(agent["id"], None)
    if task and not task.done():
        task.cancel()
    agent["device_id"] = _new_mac(existing_macs)
    agent["client_id"] = str(uuid.uuid4())
    agent["serial_number"] = None
    agent["hmac_key"] = None
    agent["challenge"] = None
    agent["activation_code"] = None
    agent["bound"] = False
    agent["ws_url"] = None
    agent["token"] = None
    ensure_identity(agent)
    return agent


async def reissue_agent_handler(request: web.Request):
    agent_id = request.match_info["agent_id"]
    try:
        store = load_store()
        agent = find_agent(agent_id, store)
    except KeyError as exc:
        return json_ok({"error": str(exc)}, 404)
    if agent.get("bound"):
        return json_ok({"error": "已经绑定的智能体不用重新取码"}, 400)
    existing = {item["device_id"] for item in store["agents"] if item["id"] != agent_id}
    rotate_identity(agent, existing)
    await refresh_agent(agent)
    save_store(store)
    log.info("已为 %s 重新取码 device=%s", agent["name"], agent["device_id"])
    return json_ok(agents_payload(store))


async def refresh_agent_handler(request: web.Request):
    agent_id = request.match_info["agent_id"]
    try:
        store = load_store()
        agent = find_agent(agent_id, store)
    except KeyError as exc:
        return json_ok({"error": str(exc)}, 404)
    await refresh_agent(agent)
    save_store(store)
    return json_ok(agents_payload(store))


async def delete_agent_handler(request: web.Request):
    agent_id = request.match_info["agent_id"]
    store = load_store()
    if not any(item["id"] == agent_id for item in store["agents"]):
        return json_ok({"error": f"没有这个智能体：{agent_id}"}, 404)
    remaining = [item for item in store["agents"] if item["id"] != agent_id]
    if not remaining:
        store["current_id"] = None
    elif store["current_id"] == agent_id:
        store["current_id"] = remaining[0]["id"]
    store["agents"] = remaining
    save_store(store)
    return json_ok(agents_payload(store))


async def index_handler(_request: web.Request):
    return web.FileResponse(
        HERE / "index.html",
        headers={"Cache-Control": "no-store"},
    )


def main() -> int:
    app = web.Application()
    app.router.add_get("/", index_handler)
    app.router.add_get("/ws", ws_handler)
    app.router.add_get("/api/agents", list_agents_handler)
    app.router.add_post("/api/agents", create_agent_handler)
    app.router.add_patch("/api/agents/{agent_id}", patch_agent_handler)
    app.router.add_post("/api/agents/{agent_id}/refresh", refresh_agent_handler)
    app.router.add_post("/api/agents/{agent_id}/reissue", reissue_agent_handler)
    app.router.add_delete("/api/agents/{agent_id}", delete_agent_handler)
    log.info("网页对话页: http://%s:%s/", HOST, PORT)
    log.info("只在本机打开。每个使用者用自己的 xiaozhi.me 账号绑定智能体")
    web.run_app(app, host=HOST, port=PORT, print=None)
    return 0


if __name__ == "__main__":
    sys.exit(main())
