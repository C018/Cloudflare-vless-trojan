/**
 * Trojan protocol inbound header parsing
 * Header: sha224(password) hex(56) + CRLF + cmd(1) + atyp(1) + addr + port(2 BE) + CRLF + payload
 */

/**
 * sha224 hex (WebCrypto 实现)
 * @param {string} str
 * @returns {Promise<string>}
 */
export async function sha224Hex(str) {
	const data = new TextEncoder().encode(str);
	const digest = await crypto.subtle.digest({ name: 'SHA-224' }, data);
	return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** 同步版 sha224 十六进制（Worker 无同步 SHA-224，这里用缓存方案） */
const sha224Cache = new Map();
export function sha224Sync(str) {
	if (sha224Cache.has(str)) return sha224Cache.get(str);
	// 返回 promise 包装结果，调用方需 await
	const p = sha224Hex(str);
	sha224Cache.set(str, p);
	return p;
}

/**
 * 判断是否是 trojan 协议（仅检查 CRLF 位置，密码校验在 process 中）
 * @param {ArrayBuffer} buffer
 */
export function isTrojanLike(buffer) {
	if (buffer.byteLength < 60) return false;
	const bytes = new Uint8Array(buffer);
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
	const bytes = new Uint8Array(protocolBuffer);
	// createWsIO 归一化为 Uint8Array，需取其底层 buffer 构造 DataView
	const dataView = protocolBuffer instanceof Uint8Array
		? new DataView(protocolBuffer.buffer, protocolBuffer.byteOffset, protocolBuffer.byteLength)
		: new DataView(protocolBuffer);

	if (bytes[56] !== 0x0d || bytes[57] !== 0x0a) {
		return { hasError: true, message: 'Invalid Trojan header: missing CRLF' };
	}

	const receivedHash = new TextDecoder().decode(bytes.slice(0, 56));
	let matchedPassword = null;
	// 多密码：逐一比对 sha224
	for (const password of passwordSet) {
		try {
			const h = await sha224Sync(password);
			if (h === receivedHash) { matchedPassword = password; break; }
		} catch (e) { /* ignore */ }
	}
	if (!matchedPassword) {
		return { hasError: true, message: 'Invalid Trojan password' };
	}

	const command = bytes[58];
	if (command !== 0x01 && command !== 0x03) {
		return { hasError: true, message: `Unsupported Trojan command: ${command}` };
	}

	const addressType = bytes[59];
	let addressValue, addressLength, addressValueIndex;

	switch (addressType) {
		case 1: // IPv4
			addressLength = 4;
			addressValueIndex = 60;
			if (protocolBuffer.byteLength < addressValueIndex + addressLength + 2) {
				return { hasError: true, message: 'Invalid Trojan header: IPv4 truncated' };
			}
			addressValue = Array.from(bytes.slice(addressValueIndex, addressValueIndex + addressLength)).join('.');
			break;
		case 3: // Domain
			addressLength = bytes[60];
			addressValueIndex = 61;
			if (protocolBuffer.byteLength < addressValueIndex + addressLength + 2) {
				return { hasError: true, message: 'Invalid Trojan header: domain truncated' };
			}
			addressValue = new TextDecoder().decode(bytes.slice(addressValueIndex, addressValueIndex + addressLength));
			break;
		case 4: // IPv6
			addressLength = 16;
			addressValueIndex = 60;
			if (protocolBuffer.byteLength < addressValueIndex + addressLength + 2) {
				return { hasError: true, message: 'Invalid Trojan header: IPv6 truncated' };
			}
			addressValue = Array.from({ length: 8 }, (_, i) => dataView.getUint16(addressValueIndex + i * 2).toString(16)).join(':');
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
		addressType: addressType === 3 ? 2 : addressType, // 映射到 VLESS 语义（2=domain）
		portRemote,
		rawDataIndex: crlfIndex + 2,
		isUDP: command === 0x03
	};
}
