/**
 * Trojan protocol inbound header parsing
 * Header: sha224(password) hex(56) + CRLF + cmd(1) + atyp(1) + addr + port(2 BE) + CRLF + payload
 */

// 复用 TextDecoder：decode() 非流模式下每次调用独立、无残留状态，可安全跨调用复用
const TEXT_DECODER = new TextDecoder();

/**
 * sha224 hex（纯 JS 实现，FIPS 180-4 SHA-224）
 * 注意：WebCrypto 标准套件不支持 SHA-224（仅 SHA-1/256/384/512），
 * CF Workers 的 crypto.subtle.digest({name:'SHA-224'}) 会抛 NotSupportedError，
 * 导致 trojan 密码校验必然失败——早期实现因此全传输不可用。必须纯 JS 计算。
 */
const SHA224_K = new Uint32Array([
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]);
const SHA224_H = new Uint32Array([0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4]);
const rotr = (x, n) => (x >>> n) | (x << (32 - n));

function sha224HexSync(str) {
	const data = new TextEncoder().encode(str);
	const bitLenHi = Math.floor(data.length / 0x20000000); // data.length*8 的 high 32
	const bitLenLo = (data.length * 8) >>> 0;
	const tail = (data.length + 9) % 64;
	const pad = tail === 0 ? 0 : 64 - tail;
	const paddedLen = data.length + 1 + pad + 8;
	const msg = new Uint8Array(paddedLen);
	msg.set(data);
	msg[data.length] = 0x80;
	const dv = new DataView(msg.buffer);
	dv.setUint32(paddedLen - 8, bitLenHi);
	dv.setUint32(paddedLen - 4, bitLenLo);

	const h = SHA224_H.slice();
	const w = new Uint32Array(64);
	for (let off = 0; off < paddedLen; off += 64) {
		for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4);
		for (let i = 16; i < 64; i++) {
			const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
			const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
			w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
		}
		let a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
		for (let i = 0; i < 64; i++) {
			const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
			const ch = (e & f) ^ (~e & g);
			const t1 = (hh + S1 + ch + SHA224_K[i] + w[i]) >>> 0;
			const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
			const maj = (a & b) ^ (a & c) ^ (b & c);
			const t2 = (S0 + maj) >>> 0;
			hh = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
		}
		h[0] = (h[0] + a) >>> 0; h[1] = (h[1] + b) >>> 0; h[2] = (h[2] + c) >>> 0; h[3] = (h[3] + d) >>> 0;
		h[4] = (h[4] + e) >>> 0; h[5] = (h[5] + f) >>> 0; h[6] = (h[6] + g) >>> 0; h[7] = (h[7] + hh) >>> 0;
	}
	let out = '';
	for (let i = 0; i < 7; i++) out += h[i].toString(16).padStart(8, '0');
	return out;
}

/**
 * sha224 hex（async 兼容接口，内部纯 JS 同步计算）
 * @param {string} str
 * @returns {Promise<string>}
 */
export async function sha224Hex(str) {
	return sha224HexSync(str);
}

/** 同步版 sha224 十六进制（纯 JS，无 WebCrypto 依赖） */
const sha224Cache = new Map();
/** 反向索引：sha224 hex -> 明文密码。任一密码首次计算后回填，后续连接 O(1) 命中，免去多密码循环比对 */
const sha224Reverse = new Map();
export function sha224Sync(str) {
	if (sha224Cache.has(str)) return sha224Cache.get(str);
	const h = sha224HexSync(str);
	sha224Cache.set(str, h);
	sha224Reverse.set(h, str);
	return h;
}

/**
 * 判断是否是 trojan 协议（仅检查 CRLF 位置，密码校验在 process 中）
 * @param {ArrayBuffer} buffer
 */
export function isTrojanLike(buffer) {
	if (buffer.byteLength < 60) return false;
	// Uint8Array 视图零拷贝：new Uint8Array(typedArray) 是拷贝构造，每连接省 2 次 60 字节拷贝
	const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
	// VLESS 首字节必为 version=0x00；首字节为 0 时不可能为 trojan（hash hex 首字符非 0）
	if (bytes[0] === 0x00) return false;
	return bytes[56] === 0x0d && bytes[57] === 0x0a;
}

/**
 * 解析 trojan 入站头（异步：密码哈希比对）
 * @param {ArrayBuffer} protocolBuffer
 * @param {Set<string>} passwordSet 明文密码集合
 * @returns {Promise<{hasError:boolean,message?:string,userPassword?:string,addressRemote?:string,addressType?:number,portRemote?:number,rawDataIndex?:number,isUDP?:boolean}>}
 */
export async function processTrojanHeader(protocolBuffer, passwordSet) {
	if (protocolBuffer.byteLength < 60) {
		return { hasError: true, message: 'Invalid Trojan data: too short' };
	}
	const bytes = protocolBuffer instanceof Uint8Array ? protocolBuffer : new Uint8Array(protocolBuffer);
	// createWsIO 归一化为 Uint8Array，需取其底层 buffer 构造 DataView
	const dataView = protocolBuffer instanceof Uint8Array
		? new DataView(protocolBuffer.buffer, protocolBuffer.byteOffset, protocolBuffer.byteLength)
		: new DataView(protocolBuffer);

	if (bytes[56] !== 0x0d || bytes[57] !== 0x0a) {
		return { hasError: true, message: 'Invalid Trojan header: missing CRLF' };
	}

	const receivedHash = TEXT_DECODER.decode(bytes.subarray(0, 56));
	let matchedPassword = null;
	// 先查反向索引（O(1)）：同一 hash 已被任一密码回填时直接命中，免去多密码循环比对
	const reverseHit = sha224Reverse.get(receivedHash);
	// 反向索引为进程级全局缓存，命中后必须复核密码仍在本连接作用域集合内，
	// 防止密码已删除/停用后旧 hash 仍能通过校验（自定义路径 scope 限定凭据时尤其关键）
	if (reverseHit !== undefined && passwordSet.has(reverseHit)) {
		matchedPassword = reverseHit;
	} else {
		// 多密码：逐一比对 sha224（首次连接回填反向索引，后续连接走 O(1) 命中）
		for (const password of passwordSet) {
			try {
				const h = await sha224Sync(password);
				if (h === receivedHash) { matchedPassword = password; break; }
			} catch (e) { /* ignore */ }
		}
	}
	if (!matchedPassword) {
		return { hasError: true, message: 'Invalid Trojan password' };
	}

	// Trojan 协议头两种真实布局（兼容，以真实客户端字节为准）：
	//   A) trojan-gfw 官方规范：hex 56B + CRLF 2B + CMD 1B + CRLF 2B + ATYP + ADDR + PORT 2B + CRLF
	//   B) xray/v2ray 实现（v2fly trojan 出站，实测 xray 26.7.28 线上抓包确认）：
	//      hex 56B + CRLF 2B + CMD 1B + ATYP + ADDR + PORT 2B + CRLF（CMD 后无 CRLF）
	// 判定：bytes[59..60] 为 0x0d 0x0a 时按 A（ATYP 在 61），否则按 B（ATYP 在 59）。
	// 早前实现仅支持 A，导致 xray 客户端（无 CMD 后 CRLF）被误判
	// 'missing CRLF after command' 拒绝，trojan 全传输不可用。
	const command = bytes[58];
	if (command !== 0x01 && command !== 0x03) {
		return { hasError: true, message: `Unsupported Trojan command: ${command}` };
	}
	const cmdCrlf = bytes[59] === 0x0d && bytes[60] === 0x0a;
	const atypIndex = cmdCrlf ? 61 : 59;
	if (protocolBuffer.byteLength < atypIndex + 1) {
		return { hasError: true, message: 'Invalid Trojan header: too short' };
	}

	const addressType = bytes[atypIndex];
	let addressValue, addressLength, addressValueIndex;

	switch (addressType) {
		case 1: // IPv4
			addressLength = 4;
			addressValueIndex = atypIndex + 1;
			if (protocolBuffer.byteLength < addressValueIndex + addressLength + 2) {
				return { hasError: true, message: 'Invalid Trojan header: IPv4 truncated' };
			}
			addressValue = `${dataView.getUint8(addressValueIndex)}.${dataView.getUint8(addressValueIndex + 1)}.${dataView.getUint8(addressValueIndex + 2)}.${dataView.getUint8(addressValueIndex + 3)}`;
			break;
		case 3: // Domain
			addressLength = bytes[atypIndex + 1];
			addressValueIndex = atypIndex + 2;
			if (protocolBuffer.byteLength < addressValueIndex + addressLength + 2) {
				return { hasError: true, message: 'Invalid Trojan header: domain truncated' };
			}
			addressValue = TEXT_DECODER.decode(bytes.subarray(addressValueIndex, addressValueIndex + addressLength));
			break;
		case 4: // IPv6
			addressLength = 16;
			addressValueIndex = atypIndex + 1;
			if (protocolBuffer.byteLength < addressValueIndex + addressLength + 2) {
				return { hasError: true, message: 'Invalid Trojan header: IPv6 truncated' };
			}
			addressValue = `${dataView.getUint16(addressValueIndex).toString(16)}:${dataView.getUint16(addressValueIndex + 2).toString(16)}:${dataView.getUint16(addressValueIndex + 4).toString(16)}:${dataView.getUint16(addressValueIndex + 6).toString(16)}:${dataView.getUint16(addressValueIndex + 8).toString(16)}:${dataView.getUint16(addressValueIndex + 10).toString(16)}:${dataView.getUint16(addressValueIndex + 12).toString(16)}:${dataView.getUint16(addressValueIndex + 14).toString(16)}`;
			break;
		default:
			return { hasError: true, message: `Invalid Trojan address type: ${addressType}` };
	}

	const portIndex = addressValueIndex + addressLength;
	if (protocolBuffer.byteLength < portIndex + 2) {
		return { hasError: true, message: 'Invalid Trojan header: port truncated' };
	}
	const portRemote = dataView.getUint16(portIndex);

	const crlfIndex = portIndex + 2;
	if (protocolBuffer.byteLength < crlfIndex + 2) {
		return { hasError: true, message: 'Invalid Trojan header: missing final CRLF' };
	}
	if (bytes[crlfIndex] !== 0x0d || bytes[crlfIndex + 1] !== 0x0a) {
		return { hasError: true, message: 'Invalid Trojan header: invalid final CRLF' };
	}

	return {
		hasError: false,
		userPassword: matchedPassword,
		addressRemote: addressValue,
		addressType: addressType === 3 ? 2 : (addressType === 4 ? 3 : addressType), // 映射到 VLESS 语义（2=domain，3=IPv6；Trojan atyp=4 为 IPv6）
		portRemote,
		rawDataIndex: crlfIndex + 2,
		isUDP: command === 0x03
	};
}
