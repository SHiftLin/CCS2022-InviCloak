"use strict";

async function EncryptMsg(message, K, IV) {
    return await crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: IV,
            tagLength: cloak_tag_BYTES << 3,
        },
        K,
        message
    ); // tag attached at the end
}

async function DecryptMsg(ciphertext, K, IV) {
    return await crypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv: IV,
            tagLength: cloak_tag_BYTES << 3,
        },
        K,
        ciphertext,
    );
}

async function ExportCryptoKey(key, isPrivate) {
    const buf = await crypto.subtle.exportKey(isPrivate ? "pkcs8" : "spki", key);
    const bytes = ArrayToBytes(buf);
    // const pem = `-----BEGIN ${title} KEY-----\n${base64}\n-----END ${title} KEY-----`;
    return btoa(bytes);;
}

async function ImportVerifyKey(hex) {
    return await crypto.subtle.importKey(
        "spki",
        HexToArray(hex),
        {
            name: "ECDSA",
            namedCurve: "P-256", //can be "P-256", "P-384", or "P-521"
        },
        false,
        ['verify']
    );
}

async function GenerateECDHKeyPair() {
    return await crypto.subtle.generateKey(
        {
            name: "ECDH",
            namedCurve: "P-256",
        },
        false,
        ["deriveBits"]
    );
}

async function ImportECDHKey(pemContent, isPrivate) {
    return await crypto.subtle.importKey(
        isPrivate ? "pkcs8" : "spki",
        BytesToArray(atob(pemContent)),
        {
            name: "ECDH",
            namedCurve: "P-256", //can be "P-256", "P-384", or "P-521"
        },
        false,
        isPrivate ? ["deriveBits"] : []
    );
}

async function ImportSecretKey(key) {
    return await crypto.subtle.importKey(
        "raw",
        key,
        "AES-GCM",
        false,
        ["encrypt", "decrypt"]
    );
}

async function DeriveSymmKey(a, gb) {
    let gab = await crypto.subtle.deriveBits(
        {
            name: "ECDH",
            namedCurve: "P-256", //can be "P-256", "P-384", or "P-521"
            public: gb,
        },
        a,
        cloak_key_BYTES << 3
    );
    let gab_key = await crypto.subtle.importKey(
        "raw",
        gab,
        { name: "HKDF" },
        false,
        ["deriveKey", "deriveBits"]
    );
    let K = await crypto.subtle.deriveBits(
        {
            name: "HKDF",
            hash: "SHA-256",
            salt: new Uint8Array([]),
            info: new TextEncoder().encode("ap traffic")
        },
        gab_key,
        cloak_key_BYTES << 3
    );
    return K;
}

var Dec2Hex = ["00", "01", "02", "03", "04", "05", "06", "07", "08", "09", "0a", "0b", "0c", "0d", "0e", "0f", "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "1a", "1b", "1c", "1d", "1e", "1f", "20", "21", "22", "23", "24", "25", "26", "27", "28", "29", "2a", "2b", "2c", "2d", "2e", "2f", "30", "31", "32", "33", "34", "35", "36", "37", "38", "39", "3a", "3b", "3c", "3d", "3e", "3f", "40", "41", "42", "43", "44", "45", "46", "47", "48", "49", "4a", "4b", "4c", "4d", "4e", "4f", "50", "51", "52", "53", "54", "55", "56", "57", "58", "59", "5a", "5b", "5c", "5d", "5e", "5f", "60", "61", "62", "63", "64", "65", "66", "67", "68", "69", "6a", "6b", "6c", "6d", "6e", "6f", "70", "71", "72", "73", "74", "75", "76", "77", "78", "79", "7a", "7b", "7c", "7d", "7e", "7f", "80", "81", "82", "83", "84", "85", "86", "87", "88", "89", "8a", "8b", "8c", "8d", "8e", "8f", "90", "91", "92", "93", "94", "95", "96", "97", "98", "99", "9a", "9b", "9c", "9d", "9e", "9f", "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "a8", "a9", "aa", "ab", "ac", "ad", "ae", "af", "b0", "b1", "b2", "b3", "b4", "b5", "b6", "b7", "b8", "b9", "ba", "bb", "bc", "bd", "be", "bf", "c0", "c1", "c2", "c3", "c4", "c5", "c6", "c7", "c8", "c9", "ca", "cb", "cc", "cd", "ce", "cf", "d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7", "d8", "d9", "da", "db", "dc", "dd", "de", "df", "e0", "e1", "e2", "e3", "e4", "e5", "e6", "e7", "e8", "e9", "ea", "eb", "ec", "ed", "ee", "ef", "f0", "f1", "f2", "f3", "f4", "f5", "f6", "f7", "f8", "f9", "fa", "fb", "fc", "fd", "fe", "ff"]

/*
function BytesToHex(str) {
    let len = str.length;
    let hex = "";
    for (let i = 0; i < len; i++)
        hex += Dec2Hex[str.charCodeAt(i)]
    return hex;
}

function HexToBytes(hex) {
    let len = hex.length;
    let str = "";
    for (let i = 0; i < len; i += 2)
        str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
    return str;
}
*/

function HexToArray(hex) {
    let len = hex.length;
    let array = new Uint8Array(len / 2);
    for (let i = 0, j = 0; i < len; i += 2, j++)
        array[j] = parseInt(hex.substr(i, 2), 16);
    return array;
}

function ArrayToHex(array) {
    if (array instanceof ArrayBuffer)
        array = new Uint8Array(array);
    let hex = '';
    for (let i = 0; i < array.length; ++i)
        hex += Dec2Hex[array[i]]
    return hex;
}

function BytesToArray(str) {
    let len = str.length;
    let array = new Uint8Array(len);
    for (let i = 0; i < len; i++)
        array[i] = str.charCodeAt(i);
    return array;
}

function ArrayToBytes(array) { // array: Uint8Array | ArrayBuffer
    if (array instanceof ArrayBuffer) return String.fromCharCode.apply(null, new Uint8Array(array));
    else return String.fromCharCode.apply(null, array);
}

function UintToArray(x, array, offset) { // x: unsigned integer, Array: small end 
    for (let i = 0; i < 4; i++, offset++, x >>= 8)
        array[offset] = x & 0xff
}

function ArrayToUint(array) {
    let x = 0;
    if (typeof array === "string")
        for (let i = 0; i < array.length; i++)
            x = (x << 8) + str.charCodeAt(i);
    else {
        for (let i = 0; i < array.length; i++)
            x = (x << 8) + array[i];
    }
    return x;
}

function JSONURLEncode(json) {
    let res = [];
    for (let key in json)
        res.push(key + "=" + encodeURIComponent(json[key]));
    return res.join("&");
}


function UpdateURL(request, url) {
    let {
        cache, credentials, headers, integrity, method, mode, redirect, referrer, referrerPolicy, originUrl, body
    } = request;
    if (mode = 'navigate')
        mode = 'cors';
    return new Request(url, {
        cache, credentials, headers, integrity, method, mode, redirect, referrer, referrerPolicy, body
    });
}

function ParseURL(url) {
    let res = new URL(url);
    let params = res.search;
    if (params.length > 0) params = params.substr(1); //?a=1 --> a=1
    let pathname = res.pathname;
    // if (pathname.length > 1 && pathname.charAt(pathname.length - 1) == '/')
    //     pathname = pathname.substr(0, pathname.length - 1); // /login/ -> /login
    return {
        protocol: res.protocol, //"https:"
        hostname: res.hostname, //"www.shiftlin.top"
        pathname: pathname, //"/login" ("/")
        origin: res.origin + pathname, //"https://www.shiftlin.top/login"
        params: params //"userid=lsh"
    };
}
"use strict";

var cacheName = "credential";
var secretName = "secret";
// const cloak_sessionID_BYTES = 16;
const cloak_key_BYTES = 32;
const cloak_IV_BYTES = 16;
const cloak_tag_BYTES = 16;
const cloak_sign_BYTES = 64;
const cloak_blksize_BYTES = 8;
const cloak_record_default_BYTES = 32 * 1024;

async function saveSecretInCache({ K, rID, ticket }) { //for const K
    K = ArrayToHex(K);
    let cache = await caches.open(cacheName);
    return await cache.put('/' + secretName, new Response(JSON.stringify({ K, rID, ticket })));
}

async function getSecretFromCache() {
    try {
        let cache = await caches.open(cacheName);
        let secret = await cache.match(secretName);
        secret = await secret.json();
        secret.K = HexToArray(secret.K);
        // if (!('sID' in secret)) return null;
        return secret;
    } catch (error) {
        return null;
    }
}

async function deleteSecretFromCache() {
    let cache = await caches.open(cacheName);
    return await cache.delete('/' + secretName, { ignoreSearch: true });
}

let PubKeys = {};

async function getPubKey(domain, noCache) {
    let items = domain.split('.');
    let keydomain = '_pubkey.' + domain;
    if (items.length > 2) {
        items[0] = items[0] + '_pubkey';
        keydomain = items.join('.');
    }

    if (!noCache && keydomain in PubKeys)
        return { pubS: PubKeys[keydomain], fromCache: true };

    // replace the key when evaluation
    let key = "3059301306072a8648ce3d020106082a8648ce3d03010703420004522016fd796bb1a94ee5243a25630e7d237122452c8e0479ec4db1cbc3d05bbee81de318ea9c05c64f63ef499ba0fefe3d711a9cc87cbf28216beac28ca995ab";

    // let key = null;
    // let dnsres = await fetch('https://dns.google.com/resolve?name=' + keydomain + '&type=TLSA&dnssec=true', { method: 'GET' });
    // dnsres = await dnsres.json();
    // if (!("Answer" in dnsres)) return { pubS: null, fromCache: false };
    // for (let item of dnsres.Answer)
    //     if (item.type == dnsres.Question[0].type) {
    //         let data = item.data.replace(/[\s]/g, '');
    //         if (data.length < 5 || data.substr(0, 5) != '25410') continue;
    //         key = data.substr(5);
    //         break;
    //     }

    if (key) {
        key = await ImportVerifyKey(key);
        // PubKeys[keydomain] = key;
    }

    PubKeys[keydomain] = key;

    return { pubS: key, fromCache: false };
}

async function KeyExchange(domain) {
    let keypair = await GenerateECDHKeyPair();
    let ga_pem = await ExportCryptoKey(keypair.publicKey, false);
    let noCache = false;
    let ticket;

    for (let i = 0; i < 2; i++) {
        let results = await Promise.all([
            getPubKey(domain, noCache),
            fetch(new Request(config.clientHelloURL, {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: JSONURLEncode({ ga: ga_pem })
            }))
        ])

        // let { pubS, fromCache } = await getPubKey(domain, noCache);

        // let res = await fetch(new Request(config.clientHelloURL, {
        //     method: 'POST',
        //     headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        //     body: JSONURLEncode({ ga: ga_pem })
        // }));
        let { pubS, fromCache } = results[0];
        let res = results[1];
        ticket = res.headers.get("cloakparams");
        res = await res.text();

        let sign = HexToArray(res.substr(0, 2 * cloak_sign_BYTES));
        var gb_pem = res.substr(2 * cloak_sign_BYTES);

        res = await crypto.subtle.verify(
            {
                name: "ECDSA",
                hash: { name: "SHA-256" }
            },
            pubS,
            sign,
            BytesToArray(ga_pem + gb_pem)
        );

        if (ticket && res) break;
        if (fromCache) noCache = true;
        else return null;
    }

    let gb = await ImportECDHKey(gb_pem, false);
    let K = await DeriveSymmKey(keypair.privateKey, gb)
    let rID = Math.trunc(Math.random() * 0xffff);
    let secret = { K, rID, ticket };
    await saveSecretInCache(secret);
    return secret;
}

async function Encapsulate(data, GET, secret) {
    if (GET)
        data = BytesToArray(data);
    let message = new Uint8Array(data.byteLength + 8);
    UintToArray(Math.trunc(Date.now() / 1000), message, 0);
    let rID = (secret.rID++) * 0x7fff + Math.trunc(Math.random() * 0x7fff);
    UintToArray(rID, message, 4);
    message.set(new Uint8Array(data), 8);

    await saveSecretInCache(secret);

    let IV = crypto.getRandomValues(new Uint8Array(cloak_IV_BYTES));
    let K = await ImportSecretKey(secret.K);
    let ciphertext = await EncryptMsg(message, K, IV);

    if (GET) {
        let cipherhex = ArrayToHex(ciphertext);
        let cipherlen = cipherhex.length - 2 * cloak_tag_BYTES;
        return {
            params: ArrayToHex(IV) + secret.ticket,
            cachekey: secret.ticket,
            // cipherquery: "ciphertext=" + cipherhex.substring(0, cipherlen) + '-' +
            //     cipherhex.substring(cipherlen, cipherlen + 2 * cloak_tag_BYTES),
            ciphertext: "null",
            cipherquery: cipherhex.substring(0, cipherlen) + '-' +
                cipherhex.substring(cipherlen, cipherlen + 2 * cloak_tag_BYTES),
            K: K
        }
    } else {
        return {
            params: ArrayToHex(IV) + secret.ticket,
            cachekey: secret.ticket,
            ciphertext: ciphertext,
            cipherquery: "null",
            K: K
        }
    }
}

function parseCloakparams(cloakparams, hasHeader) {
    if (hasHeader) {
        // parse from header
        return {
            record_bytes: ArrayToUint(HexToArray(cloakparams.substring(0, 2 * cloak_blksize_BYTES))),
            IV: HexToArray(cloakparams.substring(2 * cloak_blksize_BYTES, 2 * (cloak_blksize_BYTES + cloak_IV_BYTES)))
        };
    } else {
        // parse from leading
        return {
            record_bytes: ArrayToUint(cloakparams.slice(0, cloak_blksize_BYTES)),
            IV: cloakparams.slice(cloak_blksize_BYTES, cloak_blksize_BYTES + cloak_IV_BYTES)
        };
    }
}

function Decapsulate(response, K) {
    if (!response.ok) return response;

    var IV, blocksize, blockcnt = 0, block;
    let header = response.headers.get('cloakparams');
    if (header == null) {
        // parse from leading
        blocksize = cloak_record_default_BYTES + cloak_tag_BYTES;
        block = new Uint8Array(0);
    } else {
        // parse from headers
        let params = parseCloakparams(header, true);
        IV = params.IV;
        blocksize = params.record_bytes + cloak_tag_BYTES;
        block = new Uint8Array(blocksize);
    }

    const reader = response.body.getReader();
    var leadcnt = 0, leadlen = cloak_blksize_BYTES + cloak_IV_BYTES;
    var leading = new Uint8Array(leadlen);
    let stream = new ReadableStream({
        async start(controller) {
            while (true) {
                let { done, value } = await reader.read();
                if (done) {
                    if (blockcnt > 0) {
                        let plaintext = await DecryptMsg(block.slice(0, blockcnt).buffer, K, IV); // arrayBuffer
                        controller.enqueue(new Uint8Array(plaintext));
                        blockcnt = 0;
                    }
                    break;
                }
                let used = 0;
                if (leadcnt < leadlen) {
                    let len = Math.min(leadlen - leadcnt, value.length);
                    leading.set(value.slice(0, len), leadcnt);
                    used += len;
                    leadcnt += len;
                    if (leadcnt == len && header == null) {
                        // parse from leading 
                        let params = parseCloakparams(leading, false);
                        IV = params.IV;
                        // blocksize = params.record_bytes + cloak_tag_BYTES; // TODO: enable record_bytes for leading
                        blockcnt = 0;
                        block = new Uint8Array(blocksize);
                    }
                }
                while (used < value.length) {
                    let len = Math.min(blocksize - blockcnt, value.length - used);
                    block.set(value.slice(used, used + len), blockcnt);
                    used += len;
                    blockcnt += len;
                    if (blockcnt == blocksize) {
                        let plaintext = await DecryptMsg(block.buffer, K, IV); // arrayBuffer    
                        controller.enqueue(new Uint8Array(plaintext));
                        blockcnt = 0;
                    }
                }
            }
            controller.close();
        },
        pull(controller) {
        },
        cancel(controller) {
            controller.close();
        }
    });

    let headers = new Headers(response.headers);
    let content_length = parseInt(response.headers.get('Content-Length'));
    content_length -= leadlen;
    if (content_length) {
        let tagbytes = Math.trunc(content_length / blocksize) * cloak_tag_BYTES;
        if (content_length % blocksize > 0)
            tagbytes += cloak_tag_BYTES;
        content_length -= tagbytes;
        headers.set('Content-Length', content_length);
    }

    return new Response(stream, {
        status: response.status,
        statusText: response.statusText,
        headers: headers
    });
}
