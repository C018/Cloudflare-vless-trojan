/**
 * VLESS protocol inbound header parsing
 * Header: version(1) + uuid(16) + optLen(1) + [opt] + cmd(1) + port(2 BE) + atyp(1) + addr
 */

import { byteToHex } from '../config/constants.js';

/** @param {Uint8Array} bytes */
function bytesToUuid(bytes) {
	const h = (i) => byteToHex[bytes[i]];
	return `${h(0)}${h(1)}${h(2)}${h(3)}-${h(4)}${h(5)}-${h(6)}${h(7)}-${h(8)}${h(9)}-${h(10)}${h(11)}${h(12)}${h(13)}${h(14)}${h(15)}`.toLowerCase();
}

/**
 * 解析 VLESS 入站头
 * @param {ArrayBuffer} protocolBuffer
 * @param {Set<string>} uuidSet 有效 uuid 集合
 * @returns {{hasError:boolean,message?:string,userUuid?:string,addressRemote?:string,addressType?:number,portRemote?:number,rawDataIndex?:number,protocolVersion?:Uint8Array,isUDP?:boolean}}
 */
export function processVlessHeader(protocolBuffer, uuidSet) {
	if (protocolBuffer.byteLength < 24) {
		return { hasError: true, message: 'invalid data' };
	}
	// createWsIO 归一化为 Uint8Array，需取其底层 buffer 构造 DataView
	const dataView = protocolBuffer instanceof Uint8Array
		? new DataView(protocolBuffer.buffer, protocolBuffer.byteOffset, protocolBuffer.byteLength)
		: new DataView(protocolBuffer);
	const version = dataView.getUint8(0);
	const uuid = bytesToUuid(new Uint8Array(protocolBuffer.slice(1, 17)));

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
			addressValue = Array.from(new Uint8Array(protocolBuffer.slice(addressValueIndex, addressValueIndex + addressLength))).join('.');
			break;
		case 2: // Domain
			if (protocolBuffer.byteLength < portIndex + 4) {
				return { hasError: true, message: 'invalid data' };
			}
			addressLength = dataView.getUint8(portIndex + 3);
			addressValueIndex = portIndex + 4;
			addressValue = new TextDecoder().decode(protocolBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
			break;
		case 3: // IPv6
			addressLength = 16;
			addressValueIndex = portIndex + 3;
			addressValue = Array.from({ length: 8 }, (_, i) => dataView.getUint16(addressValueIndex + i * 2).toString(16)).join(':');
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
		protocolVersion: new Uint8Array([version]),
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

	const uuidString = uuid.replace(/-/g, '');
	const header = new Uint8Array(22 + addressFieldLength);
	header[0] = 0x00;
	for (let i = 0; i < uuidString.length; i += 2) {
		header[1 + i / 2] = parseInt(uuidString.substr(i, 2), 16);
	}
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
