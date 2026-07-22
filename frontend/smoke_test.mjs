import { JSDOM } from 'jsdom';
import { readFileSync, readdirSync } from 'fs';

const dom = new JSDOM('<!DOCTYPE html><html><body><div id="root"></div></body></html>', {
  url: 'http://localhost/',
  runScripts: 'dangerously',
  resources: 'usable',
});

global.window = dom.window;
global.document = dom.window.document;

Object.defineProperty(global, 'navigator', {
  value: dom.window.navigator,
  configurable: true,
});


dom.window.fetch = async () => ({ ok: false, status: 0, json: async () => ({}) });

const errors = [];
dom.window.addEventListener('error', (e) => errors.push(e.error?.message ?? e.message));
dom.window.onerror = (msg) => errors.push(String(msg));

const jsFile = readdirSync('dist/assets').find((f) => f.endsWith('.js'));
const bundle = readFileSync('dist/assets/' + jsFile, 'utf-8');

try {
  const script = dom.window.document.createElement('script');
  script.textContent = bundle;
  dom.window.document.body.appendChild(script);
} catch (e) {
  errors.push(String(e));
}

await new Promise((r) => setTimeout(r, 500));

console.log('Root innerHTML length:', dom.window.document.getElementById('root').innerHTML.length);
console.log('Errors:', errors.length ? errors : 'none');
console.log('Contains "DriftGuard" text:', dom.window.document.body.textContent.includes('DriftGuard'));
console.log('Contains hero headline:', dom.window.document.body.textContent.includes('Your state file says one thing'));
process.exit(0);
