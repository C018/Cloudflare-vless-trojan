/**
 * HTTP CONNECT outbound proxy
 */

/**
 * HTTP CONNECT 隧道建立
 * @param {number} addressType
 * @param {string} addressRemote
 * @param {number} portRemote
 * @param {Function} log
 * @param {{username?:string,password?:string,hostname:string,port:number}} parsedAddr
 * @param {Function} connect
 * @param {Uint8Array} initialData 隧道建立后立即发送的初始数据
 * @returns {Promise<import('@cloudflare/workers-types').Socket|undefined>}
 */
export async function httpConnect(addressType, addressRemote, portRemote, log, parsedAddr, connect, initialData = new Uint8Array(0)) {
	const { username, password, hostname, port } = parsedAddr;
	const socket = connect({ hostname, port });
	const writer = socket.writable.getWriter();
	const reader = socket.readable.getReader();

	try {
		const auth = username && password ? `Proxy-Authorization: Basic ${btoa(`${username}:${password}`)}\r\n` : '';
		const request = `CONNECT ${addressRemote}:${portRemote} HTTP/1.1\r\nHost: ${addressRemote}:${portRemote}\r\n${auth}User-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n`;
		await writer.write(new TextEncoder().encode(request));

		let responseBuffer = new Uint8Array(0);
		let headerEndIndex = -1;
		let bytesRead = 0;
		while (headerEndIndex === -1 && bytesRead < 8192) {
			const { done, value } = await reader.read();
			if (done) throw new Error('Connection closed before HTTP response');
			const merged = new Uint8Array(responseBuffer.length + value.length);
			merged.set(responseBuffer, 0);
			merged.set(value, responseBuffer.length);
			responseBuffer = merged;
			bytesRead = responseBuffer.length;
			for (let i = 0; i < responseBuffer.length - 3; i++) {
				if (responseBuffer[i] === 0x0d && responseBuffer[i + 1] === 0x0a &&
					responseBuffer[i + 2] === 0x0d && responseBuffer[i + 3] === 0x0a) {
					headerEndIndex = i + 4;
					break;
				}
			}
		}
		if (headerEndIndex === -1) throw new Error('Invalid HTTP response');

		const headerText = new TextDecoder().decode(responseBuffer.slice(0, headerEndIndex));
		const statusMatch = headerText.split('\r\n')[0].match(/HTTP\/\d\.\d\s+(\d+)/);
		if (!statusMatch) throw new Error('Invalid HTTP response format');
		const statusCode = parseInt(statusMatch[1]);
		if (statusCode < 200 || statusCode >= 300) {
			throw new Error(`HTTP CONNECT failed: HTTP ${statusCode}`);
		}

		if (initialData.length > 0) {
			await writer.write(initialData);
		}

		writer.releaseLock();
		reader.releaseLock();
		return socket;
	} catch (error) {
		log(`http connect error: ${error.message}`);
		try { writer.releaseLock(); } catch (e) { /* ignore */ }
		try { reader.releaseLock(); } catch (e) { /* ignore */ }
		try { socket.close(); } catch (e) { /* ignore */ }
		return undefined;
	}
}

/**
 * 解析 http 代理地址字符串 'user:pass@host:port' 或 'host:port'；
 * 支持通过 credentials 传入外部凭据（后台 username/password 字段，优先于地址内嵌）
 */
export function parseHttpAddress(address, credentials = {}) {
	let [latter, former] = String(address || '').trim().split('@').reverse();
	let username, password, hostname, port;
	if (former) {
		const formers = former.split(':');
		if (formers.length !== 2) throw new Error('Invalid HTTP address format');
		[username, password] = formers;
	}
	const latters = latter.split(':');
	port = Number(latters[latters.length - 1]);
	if (isNaN(port)) {
		// address 仅主机（面板分字段保存：port 在独立字段），用 credentials.port 兜底
		if (credentials && credentials.port !== undefined && credentials.port !== null && credentials.port !== '') {
			port = Number(credentials.port);
			hostname = latter;
		} else {
			throw new Error('Invalid HTTP address format');
		}
	} else {
		hostname = latters.slice(0, -1).join(':');
	}
	if (isNaN(port) || !hostname) throw new Error('Invalid HTTP address format');
	if (credentials && credentials.username !== undefined && credentials.username !== null && credentials.username !== '') {
		username = credentials.username;
	}
	if (credentials && credentials.password !== undefined && credentials.password !== null && credentials.password !== '') {
		password = credentials.password;
	}
	return { username, password, hostname, port };
}
