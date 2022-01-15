"use strict";

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

function HexToArray(hex) {
    let len = hex.length;
    let array = new Uint8Array(len / 2);
    for (let i = 0, j = 0; i < len; i += 2, j++)
        array[j] = parseInt(hex.substr(i, 2), 16);
    return array;
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

async function Verify(message, sign, pubKey) {
    return await crypto.subtle.verify(
        {
            name: "ECDSA",
            hash: { name: "SHA-256" }
        },
        pubKey,
        HexToArray(sign),
        message
    );
}


var PubKeys = {};
var DNSDomain = "dns.google.com";

async function getPubKey(url) {
    let items = url.hostname.split('.');
    let keydomain = '_pubkey.' + url.hostname;
    if (items.length > 2) {
        items[0] = items[0] + '_pubkey';
        keydomain = items.join('.');
    }

    if (keydomain in PubKeys)
        return PubKeys[keydomain];


    let key = null;
    let dnsres = null;
    try {
        dnsres = await fetch('https://' + DNSDomain + '/resolve?name=' + keydomain + '&type=TLSA&dnssec=true', { method: 'GET' });
        dnsres = await dnsres.json();
        if (!("Answer" in dnsres)) return null;
    } catch (error) {
        return null;
    }
    for (let item of dnsres.Answer)
        if (item.type == dnsres.Question[0].type) {
            let data = item.data.replace(/[\s]/g, '');
            if (data.length < 5 || data.substr(0, 5) != '25410') continue;
            key = data.substr(5);
            break;
        }
    // let key = "3059301306072a8648ce3d020106082a8648ce3d03010703420004522016fd796bb1a94ee5243a25630e7d237122452c8e0479ec4db1cbc3d05bbee81de318ea9c05c64f63ef499ba0fefe3d711a9cc87cbf28216beac28ca995ab";

    if (key) {
        key = await ImportVerifyKey(key);
    }
    PubKeys[keydomain] = key;

    return key;
}

function getSignature(response, contentType) {
    let patterng;
    let pattern;
    if (contentType == 1) {
        patterng = /<!-{2,}\s*cloaksign:\s*(\w*?)\s*-{2,}>/g;
        pattern = /<!-{2,}\s*cloaksign:\s*(\w*?)\s*-{2,}>/;
    }
    else {
        patterng = /\/\*\s*cloaksign:\s*(\w*?)\s*\*\//g;
        pattern = /\/\*\s*cloaksign:\s*(\w*?)\s*\*\//;
    }
    let res = response.match(patterng);
    if (res == null) return null;
    return res[res.length - 1].match(pattern); //return the last one
}

async function IntegrityVerification(data, contentType, pubKey, details) {
    let start = window.performance.now();
    let response = '';
    for (let i = 0; i < data.length; i++)
        response += ArrayToBytes(data[i]);

    let sign = getSignature(response, contentType);
    let res = false;
    if (sign) {
        let message = BytesToArray(response.replace(sign[0], ''));
        res = await Verify(message, sign[1], pubKey);
    }
    let end = window.performance.now();
    let time = (end - start) * 1000;
    console.log(res);
    if (res) {
        browser.tabs.executeScript(details.tabId, {
            code: 'console.log("time: ' + time + '");'
        });;
        // browser.browserAction.setIcon({ path: "icons/true.svg" });
        // alert users
    }
}


var PublicReq = new Set();

function getRequestHeaders(details) { //Note this function is in onBeforeSendHeaders
    for (let header of details.requestHeaders) {
        if (header.name.toLowerCase() === "cloakparams")
            return;
    }
    PublicReq.add(details.requestId);
}

async function addResponseFilter(details) {
    let flag = 0;
    if (details.statusCode == 200)
        for (let header of details.responseHeaders) {
            if (header.name.toLowerCase() == "content-type") {
                let value = header.value.toLowerCase();
                if (value.indexOf("javascript") != -1) flag = 2;
                else if (value.indexOf("html") != -1) flag = 1;
                break;
            }
        }
    if (flag == 0) return;

    if (!PublicReq.has(details.requestId))
        return;
    PublicReq.delete(details.requestId);

    let url = new URL(details.url);
    if (url.hostname == DNSDomain)
        return;

    let pubKey = await getPubKey(url);
    if (!pubKey) return;

    let size;
    for (let header of details.responseHeaders) {
        if (header.name.toLowerCase() == "content-length") {
            size = parseInt(header.value.toLowerCase());
        }
    }
    let data = [];
    let filter = browser.webRequest.filterResponseData(details.requestId);

    filter.ondata = event => {
        filter.write(event.data);
        data.push(event.data); //ArrayBuffer
    };

    filter.onstop = event => {
        filter.close();
        IntegrityVerification(data, flag, pubKey, details); //not await
    };

}


browser.webRequest.onBeforeSendHeaders.addListener(
    getRequestHeaders,
    { urls: ["https://www.dukesec.net/plt_sign_size/*"], types: ["main_frame", "sub_frame", "script", "xmlhttprequest"] },
    ["requestHeaders"]
);

browser.webRequest.onHeadersReceived.addListener(
    addResponseFilter,
    { urls: ["https://www.dukesec.net/plt_sign_size/*"], types: ["main_frame", "sub_frame", "script", "xmlhttprequest"] },
    ["responseHeaders", "blocking"]
);



