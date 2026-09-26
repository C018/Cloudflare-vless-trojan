/**
 * VLESS protocol inbound header parsing
 * Header: version(1) + uuid(16) + optLen(1) + [opt] + cmd(1) + port(2 BE) + atyp(1) + addr
 */

import { byteToHex } from '../config/constants.js';

// 复用 TextDecoder：decode() 非流模式下每次调用独立、无残留状态，可安全跨调用复用
const TEXT_DECODER = new TextDecoder();

// uuid 字符串 -> 16 字节 缓存：同一出站 uuid 每次建连都重复 replace + 16 次 parseInt，
// 缓存后 O(1) 命中（出站 uuid 数量极少，64 项上限足够；到达上限清空重建，避免无限增长）
const uuidBytesCache = new Map();
const UUID_CACHE_MAX = 64;
function uuidToBytes(uuid) {
	let b = uuidBytesCache.get(uuid);
	if (b) return b;
	const s = uuid.replace(/-/g, '');
	b = new Uint8Array(16);
	for (let i = 0; i < 16; i++) b[i] = parseInt(s.substr(i * 2, 2), 16);
	if (uuidBytesCache.size >= UUID_CACHE_MAX) uuidBytesCache.clear();
	uuidBytesCache.set(uuid, b);
	return b;
}

/** @param {Uint8Array} bytes */
function bytesToUuid(bytes) {
	// byteToHex 已为小写十六进制，toLowerCase() 属冗余的全串扫描分配（uuidSet/vlessIndex 均按小写建索引）
	const h = (i) => byteToHex[bytes[i]];
	return `${h(0)}${h(1)}${h(2)}${h(3)}-${h(4)}${h(5)}-${h(6)}${h(7)}-${h(8)}${h(9)}-${h(10)}${h(11)}${h(12)}${h(13)}${h(14)}${h(15)}`;
}

/**
 * 解析 VLESS 入站头
 * @param {ArrayBuffer} protocolBuffer
 * @param {Set<string>} uuidSet 有效 uuid 集合
 * @returns {{hasError:boolean,message?:string,userUuid?:string,addressRemote?:string,addressType?:number,portRemote?:number,rawDataIndex?:number,isUDP?:boolean}}
 */
export function processVlessHeader(protocolBuffer, uuidSet) {
	if (protocolBuffer.byteLength < 24) {
		return { hasError: true, message: 'invalid data' };
	}
	// createWsIO 归一化为 Uint8Array；统一视图后 subarray 零拷贝读取
	const view = protocolBuffer instanceof Uint8Array ? protocolBuffer : new Uint8Array(protocolBuffer);
	const dataView = new DataView(view.buffer, view.byteOffset, view.byteLength);
	const uuid = bytesToUuid(view.subarray(1, 17));

	if (!uuidSet.has(uuid)) {
		return { hasError: true, message: 'invalid user' };
	}

	const optLength = dataView.getUint8(17);
	const cmdIndex = 18 + optLength;
	if (protocolBuffer.byteLength < cmdIndex + 4) {
		return { hasError: true, message: 'invalid data' };
	}
	const command = dataView.getUint8(cmdIndex);
	if (command !== 1 && command !== 2) {
		return { hasError: true, message: `command ${command} is not supported` };
	}

	const portIndex = cmdIndex + 1;
	const portRemote = dataView.getUint16(portIndex);
	const addressType = dataView.getUint8(portIndex + 2);
	let addressValue, addressLength, addressValueIndex;

	switch (addressType) {
		case 1: // IPv4
			addressLength = 4;
			addressValueIndex = portIndex + 3;
			addressValue = `${dataView.getUint8(addressValueIndex)}.${dataView.getUint8(addressValueIndex + 1)}.${dataView.getUint8(addressValueIndex + 2)}.${dataView.getUint8(addressValueIndex + 3)}`;
			break;
		case 2: // Domain
			if (protocolBuffer.byteLength < portIndex + 4) {
				return { hasError: true, message: 'invalid data' };
			}
			addressLength = dataView.getUint8(portIndex + 3);
			addressValueIndex = portIndex + 4;
			addressValue = TEXT_DECODER.decode(view.subarray(addressValueIndex, addressValueIndex + addressLength));
			break;
		case 3: // IPv6
			addressLength = 16;
			addressValueIndex = portIndex + 3;
			addressValue = `${dataView.getUint16(addressValueIndex).toString(16)}:${dataView.getUint16(addressValueIndex + 2).toString(16)}:${dataView.getUint16(addressValueIndex + 4).toString(16)}:${dataView.getUint16(addressValueIndex + 6).toString(16)}:${dataView.getUint16(addressValueIndex + 8).toString(16)}:${dataView.getUint16(addressValueIndex + 10).toString(16)}:${dataView.getUint16(addressValueIndex + 12).toString(16)}:${dataView.getUint16(addressValueIndex + 14).toString(16)}`;
			break;
		default:
			return { hasError: true, message: `invalid addressType: ${addressType}` };
	}

	if (!addressValue) {
		return { hasError: true, message: 'addressValue is empty' };
	}

	return {
		hasError: false,
		userUuid: uuid,
		addressRemote: addressValue,
		addressType,
		portRemote,
		rawDataIndex: addressValueIndex + addressLength,
		isUDP: command === 2
	};
}

/**
 * 构造 VLESS 出站请求头
 * @param {number} command 1=TCP 2=UDP
 * @param {number} addressType
 * @param {string} addressRemote
 * @param {number} portRemote
 * @param {string} uuid
 */
export function makeVlessRequestHeader(command, addressType, addressRemote, portRemote, uuid) {
	let addressFieldLength;
	let addressEncoded;
	let addrBytes = [];

	switch (addressType) {
		case 1:
			addressFieldLength = 4;
			addrBytes = addressRemote.split('.').map(Number);
			break;
		case 2:
			addressEncoded = new TextEncoder().encode(addressRemote);
			addressFieldLength = addressEncoded.length + 1;
			break;
		case 3:
			addressFieldLength = 16;
			addrBytes = expandIPv6(addressRemote).split(':').map((g) => [parseInt(g.slice(0, 2), 16), parseInt(g.slice(2), 16)]).flat();
			break;
		default:
			throw new Error(`Unknown address type: ${addressType}`);
	}

	const header = new Uint8Array(22 + addressFieldLength);
	header[0] = 0x00;
	header.set(uuidToBytes(uuid), 1); // 缓存命中 O(1)，避免每次建连重复 replace + 16 次 parseInt
	header[17] = 0x00; // additional info length
	header[18] = command;
	header[19] = portRemote >> 8;
	header[20] = portRemote & 0xff;
	header[21] = addressType;
	if (addressType === 2) {
		header[22] = addressEncoded.length;
		header.set(addressEncoded, 23);
	} else {
		header.set(addrBytes, 22);
	}
	return header;
}

/** @param {string} ipv6 */
export function expandIPv6(ipv6) {
	ipv6 = ipv6.replace(/^\[|\]$/g, '');
	if (ipv6.includes('::')) {
		const parts = ipv6.split('::');
		const left = parts[0] ? parts[0].split(':') : [];
		const right = parts[1] ? parts[1].split(':') : [];
		const missing = 8 - left.length - right.length;
		const middle = Array(Math.max(0, missing)).fill('0');
		return [...left, ...middle, ...right].map((g) => g.padStart(4, '0')).join(':');
	}
	return ipv6.split(':').map((g) => g.padStart(4, '0')).join(':');
}
