/**
 * Admin auth: PBKDF2 password hashing + HMAC signed cookie
 */

import { ADMIN_COOKIE_NAME, ADMIN_COOKIE_MAX_AGE } from '../config/constants.js';

const PBKDF2_ITERATIONS = 100000;

function toHex(bytes) {
	return Array.from(new Uint8Array(bytes)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

function randomSalt() {
	const arr = new Uint8Array(16);
	crypto.getRandomValues(arr);
	return toHex(arr);
}

async function pbkdf2(password, salt, iterations) {
	const keyMaterial = await crypto.subtle.importKey(
		'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']
	);
	const bits = await crypto.subtle.deriveBits(
		{ name: 'PBKDF2', salt: new TextEncoder().encode(salt), iterations, hash: 'SHA-256' },
		keyMaterial, 256
	);
	return toHex(bits);
}

/**
 * 生成密码哈希，格式 salt:iterations:hex
 */
export async function hashPassword(password) {
	const salt = randomSalt();
	const hash = await pbkdf2(password, salt, PBKDF2_ITERATIONS);
	return `${salt}:${PBKDF2_ITERATIONS}:${hash}`;
}

/**
 * 校验密码
 */
export async function verifyPassword(password, stored) {
	if (!stored || !password) return false;
	const parts = String(stored).split(':');
	if (parts.length !== 3) return false;
	const [salt, iterStr, hash] = parts;
	const iterations = parseInt(iterStr, 10) || PBKDF2_ITERATIONS;
	const computed = await pbkdf2(password, salt, iterations);
	return computed === hash;
}

async function hmacSign(secret, message) {
	const key = await crypto.subtle.importKey(
		'raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
	);
	const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message));
	return toHex(sig);
}

/**
 * 创建会话 cookie 值
 */
export async function createSessionValue(secret) {
	const expires = Math.floor(Date.now() / 1000) + ADMIN_COOKIE_MAX_AGE;
	const payload = `admin.${expires}`;
	const sig = await hmacSign(secret, payload);
	return `${payload}.${sig}`;
}

/**
 * 校验会话 cookie 值
 */
export async function verifySessionValue(value, secret) {
	if (!value || !secret) return false;
	const parts = String(value).split('.');
	if (parts.length !== 3) return false;
	const [who, expStr, sig] = parts;
	if (who !== 'admin') return false;
	const exp = Number(expStr);
	if (!Number.isFinite(exp) || exp < Date.now() / 1000) return false;
	const expected = await hmacSign(secret, `${who}.${expStr}`);
	if (expected.length !== sig.length) return false;
	// constant-time compare
	let diff = 0;
	for (let i = 0; i < expected.length; i++) diff |= expected.charCodeAt(i) ^ sig.charCodeAt(i);
	return diff === 0;
}

export { ADMIN_COOKIE_NAME };

/**
 * 从 cookie header 提取指定 cookie
 */
export function parseCookies(header) {
	const result = {};
	if (!header) return result;
	for (const part of header.split(';')) {
		const idx = part.indexOf('=');
		if (idx < 0) continue;
		const key = part.slice(0, idx).trim();
		const value = part.slice(idx + 1).trim();
		result[key] = decodeURIComponent(value);
	}
	return result;
}
