/**
 * SOCKS5 outbound proxy
 */

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

	try {
		// greeting: VER=5, NMETHODS=2, [0x00 no-auth, 0x02 user/pass]
		await writer.write(new Uint8Array([5, 2, 0, 2]));
		let res = (await reader.read()).value;
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
			res = (await reader.read()).value;
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
		res = (await reader.read()).value;
		if (!res || res[1] !== 0x00) {
			log(`socks connect failed rep=${res ? res[1] : 'none'}`);
			return undefined;
		}

		writer.releaseLock();
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
	let [latter, former] = address.split('@').reverse();
	let username, password, hostname, port;
	if (former) {
		const formers = former.split(':');
		if (formers.length !== 2) throw new Error('Invalid SOCKS address format');
		[username, password] = formers;
	}
	const latters = latter.split(':');
	port = Number(latters.pop());
	if (isNaN(port)) throw new Error('Invalid SOCKS address format');
	hostname = latters.join(':');
	if (credentials && credentials.username !== undefined && credentials.username !== null && credentials.username !== '') {
		username = credentials.username;
	}
	if (credentials && credentials.password !== undefined && credentials.password !== null && credentials.password !== '') {
		password = credentials.password;
	}
	return { username, password, hostname, port };
}
