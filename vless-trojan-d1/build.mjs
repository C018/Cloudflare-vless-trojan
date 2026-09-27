// vless-trojan-d1 自包含构建：esbuild JS API + javascript-obfuscator（依赖安装于项目 node_modules）
// 用法: node build.mjs  （或 npm run build）
// 注意：Windows cmd 下命令行传中文文件名（_worker明.js）会乱码，
//       因此 esbuild/obfuscator 均使用 ASCII 临时名，最后用 Node rename 还原。
import { build } from 'esbuild';
import { execFileSync } from 'child_process';
import path from 'path';
import { fileURLToPath } from 'url';
import { renameSync, statSync, readFileSync, writeFileSync } from 'fs';

// 项目根目录：由本文件所在位置推导，严禁写死本机路径
const root = path.dirname(fileURLToPath(import.meta.url));
const plainTmp = path.join(root, '_worker_plain_tmp.js');
const outObf = path.join(root, '_worker.js');
const outPlain = path.join(root, '_worker' + String.fromCharCode(0x660E) + '.js'); // _worker明.js

// ---- 版本号自动重写：1.0.x-yyyyMMdd-HHmm（每次构建递增 x）----
const versionFile = path.join(root, 'src/version.js');
const verSrc = readFileSync(versionFile, 'utf8');
const m = verSrc.match(/VERSION\s*=\s*'([^']+)'/);
const cur = m ? m[1] : '1.0.0';
const mm = cur.match(/^1\.0\.(\d+)/);
const nextX = mm ? (Number(mm[1]) + 1) : 1;
const now = new Date();
const pad = n => String(n).padStart(2, '0');
const stamp = `${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}-${pad(now.getHours())}${pad(now.getMinutes())}`;
const newVersion = `1.0.${nextX}-${stamp}`;
const newVerSrc = verSrc.replace(/(VERSION\s*=\s*')([^']+)(')/, `$1${newVersion}$3`);
writeFileSync(versionFile, newVerSrc, 'utf8');
console.log(`[build] version: ${cur} -> ${newVersion}`);

await build({
	entryPoints: [path.join(root, 'src/index.js')],
	bundle: true,
	format: 'esm',
	target: 'es2022',
	outfile: plainTmp,
	minify: true,
	legalComments: 'none',
	external: ['cloudflare:sockets'],
	plugins: [
		{
			name: 'fflate-alias',
			setup(b) {
				b.onResolve({ filter: /^fflate$/ }, () => ({
					path: path.join(root, 'node_modules/fflate/esm/browser.js')
				}));
			}
		}
	],
	logLevel: 'silent'
});
console.log('[build] esbuild ok');

const obfCli = path.join(root, 'node_modules/javascript-obfuscator/bin/javascript-obfuscator');
execFileSync(process.execPath, [
	obfCli, plainTmp, '--output', outObf,
	'--compact', 'true',
	'--self-defending', 'false'
	// 混淆降档（1.0.50）：关闭 string-array 字符串数组混淆（原 threshold 0.5 + base64 解码
	// 是冷启动最大开销源），仅保留 compact 压缩，显著加快 Worker 冷启动/首个请求建连
], { stdio: 'inherit', timeout: 300000 });
console.log('[build] obfuscator ok (low obfuscation: string-array disabled)');

renameSync(plainTmp, outPlain);
console.log('[build] renamed to _worker明.js');

for (const f of [outPlain, outObf]) {
	const s = statSync(f);
	console.log(`[build] ${s.size} B  ${s.mtime.toLocaleTimeString()}  ${f}`);
}
