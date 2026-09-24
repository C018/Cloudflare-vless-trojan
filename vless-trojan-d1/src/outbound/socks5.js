/**
 * SOCKS5 outbound proxy
 */

/**
 * 使用可变缓冲实现精确读取：TCP 分片场景下累积到满足 minBytes，
 * 多余字节保留在 holder.buf 中，握手完成后合并进隧道流。
 * @param {ReadableStreamDefaultReader} reader
 * @param {{buf: Uint8Array}} holder
 * @param {number} minBytes
 */
async function readExact(reader, holder, minBytes) {
	while (holder.buf.length < minBytes) {
		const { done, value } = await reader.read();
		if (done) return null;
		if (!value || value.byteLength === 0) continue;
		const merged = new Uint8Array(holder.buf.length + value.byteLength);
		merged.set(holder.buf, 0);
		merged.set(value, holder.buf.length);
		holder.buf = merged;
	}
	const out = holder.buf.slice(0, minBytes);
	holder.buf = holder.buf.slice(minBytes);
	return out;
}

/**
 * SOCKS5 握手并建立隧道
 * @param {number} addressType 1=IPv4 2=Domain 3=IPv6
 * @param {string} addressRemote
 * @param {number} portRemote
 * @param {Function} log
 * @param {{username?:string,password?:string,hostname:string,port:number}} parsedAddr
 * @param {Function} connect Cloudflare connect
 * @returns {Promise<import('@cloudflare/workers-types').Socket|undefined>}
 */
export async function socks5Connect(addressType, addressRemote, portRemote, log, parsedAddr, connect) {
	const { username, password, hostname, port } = parsedAddr;
	const socket = connect({ hostname, port });
	const writer = socket.writable.getWriter();
	const reader = socket.readable.getReader();
	const encoder = new TextEncoder();
	const holder = { buf: new Uint8Array(0) };

	try {
		// greeting: VER=5, NMETHODS=2, [0x00 no-auth, 0x02 user/pass]
		await writer.write(new Uint8Array([5, 2, 0, 2]));
		let res = await readExact(reader, holder, 2);
		if (!res || res[0] !== 0x05) {
			log('socks version error');
			return undefined;
		}
		if (res[1] === 0xff) {
			log('no acceptable methods');
			return undefined;
		}
		if (res[1] === 0x02) {
			if (!username || !password) {
				log('socks server requires auth but no credentials');
				return undefined;
			}
			const authRequest = new Uint8Array([
				1, username.length, ...encoder.encode(username),
				password.length, ...encoder.encode(password)
			]);
			await writer.write(authRequest);
			res = await readExact(reader, holder, 2);
			if (!res || res[0] !== 0x01 || res[1] !== 0x00) {
				log('socks auth failed');
				return undefined;
			}
		}

		// request: VER=5 CMD=1(CONNECT) RSV=0 ATYP=...
		let DSTADDR;
		switch (addressType) {
			case 1:
				DSTADDR = new Uint8Array([1, ...addressRemote.split('.').map(Number)]);
				break;
			case 2:
				DSTADDR = new Uint8Array([3, addressRemote.length, ...encoder.encode(addressRemote)]);
				break;
			case 3:
				DSTADDR = new Uint8Array([4, ...addressRemote.split(':').flatMap((x) => [parseInt(x.slice(0, 2), 16), parseInt(x.slice(2), 16)])]);
				break;
			default:
				log(`invalid addressType ${addressType}`);
				return undefined;
		}
		const socksRequest = new Uint8Array([5, 1, 0, ...DSTADDR, portRemote >> 8, portRemote & 0xff]);
		await writer.write(socksRequest);

		// CONNECT 响应：VER REP RSV ATYP BND.ADDR BND.PORT（完整消费，避免残留污染隧道）
		const head = await readExact(reader, holder, 4);
		if (!head || head[0] !== 0x05) {
			log('socks version error');
			return undefined;
		}
		if (head[1] !== 0x00) {
			log(`socks connect failed rep=${head[1]}`);
			return undefined;
		}
		let rest = 0;
		switch (head[3]) { // ATYP
			case 1: rest = 4 + 2; break;  // IPv4 + port
			case 3: rest = 1 + 2; break;  // domain 长度需再读
			case 4: rest = 16 + 2; break; // IPv6 + port
			default: log(`socks invalid ATYP ${head[3]}`); return undefined;
		}
		if (head[3] === 3) {
			const lenByte = await readExact(reader, holder, 1);
			if (!lenByte) return undefined;
			rest += lenByte[0];
		}
		const tail = await readExact(reader, holder, rest);
		if (!tail) return undefined;

		writer.releaseLock();
		// 握手期读多的字节（隧道早期数据）合并进返回流，避免丢失
		if (holder.buf.length > 0) {
			let bufLeft = holder.buf.slice();
			const merged = new ReadableStream({
				pull(controller) {
					if (bufLeft.length > 0) {
						const chunk = bufLeft;
						bufLeft = new Uint8Array(0);
						controller.enqueue(chunk);
						return;
					}
					return reader.read().then(({ done, value }) => {
						if (done) controller.close();
						else if (value && value.byteLength > 0) controller.enqueue(value);
					});
				},
				cancel() { try { reader.cancel(); } catch (e) { /* ignore */ } }
			});
			return { readable: merged, writable: socket.writable, closed: socket.closed || Promise.resolve() };
		}
		reader.releaseLock();
		return socket;
	} catch (error) {
		log(`socks5 error: ${error.message}`);
		try { writer.releaseLock(); } catch (e) { /* ignore */ }
		try { reader.releaseLock(); } catch (e) { /* ignore */ }
		try { socket.close(); } catch (e) { /* ignore */ }
		return undefined;
	}
}

/**
 * 解析 socks5 地址字符串 'user:pass@host:port' 或 'host:port'；
 * 支持通过 credentials 传入外部凭据（后台 username/password 字段，优先于地址内嵌）
 */
export function parseSocks5Address(address, credentials = {}) {
	// 容错：剥离常见 scheme 前缀（socks5://、socks://），用户可能从订阅/客户端直接粘贴完整地址
	let addr = String(address || '').trim().replace(/^socks5?:\/\//i, '');
	let [latter, former] = addr.split('@').reverse();
	let username, password, hostname, port;
	if (former) {
		const formers = former.split(':');
		if (formers.length !== 2) throw new Error('Invalid SOCKS address format');
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
			throw new Error('Invalid SOCKS address format');
		}
	} else {
		hostname = latters.slice(0, -1).join(':');
	}
	if (isNaN(port) || !hostname) throw new Error('Invalid SOCKS address format');
	if (credentials && credentials.username !== undefined && credentials.username !== null && credentials.username !== '') {
		username = credentials.username;
	}
	if (credentials && credentials.password !== undefined && credentials.password !== null && credentials.password !== '') {
		password = credentials.password;
	}
	return { username, password, hostname, port };
}
