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
