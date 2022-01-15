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

async function IntegrityVerification(response, contentType, pubKey, details) {
    let start = window.performance.now();
    let sign = getSignature(response, contentType);
    let res = false;
    if (sign) {
        let message = BytesToArray(response.replace(sign[0], ''));
        res = await Verify(message, sign[1], pubKey);
    }
    let end = window.performance.now();
    let time = (end - start) * 1000;
    // console.log(res);
    if (res) {
        // chrome.tabs.executeScript(details.tabId, {
        //     code: 'console.log("time: ' + time + '");'
        // });;
        // browser.browserAction.setIcon({ path: "icons/true.svg" });
        // alert users
    } else {
        console.log(res, details.url);
    }
}

function filterByRequest(details) { //Note this function is in onBeforeSendHeaders
    for (let header of details.requestHeaders) {
        if (header.name.toLowerCase() === "cloakparams")
            return false;
    }
    let url = new URL(details.url);
    if (url.hostname == DNSDomain)
        return false;
    // console.log(details.requestId, "onBeforeSendHeaders");
    return true;
}

async function filterByResponseHeaders(details) {
    let contentType = 0;
    if (details.statusCode == 200)
        for (let header of details.responseHeaders) {
            if (header.name.toLowerCase() == "content-type") {
                let value = header.value.toLowerCase();
                if (value.indexOf("javascript") != -1) contentType = 2;
                else if (value.indexOf("html") != -1) contentType = 1;
                break;
            }
        }
    if (contentType == 0)
        return { contentType: 0, pubKey: null };

    let pubKey = await getPubKey(new URL(details.url));
    if (!pubKey)
        return { contentType: 0, pubKey: null };

    // console.log(details.requestId, "onHeadersReceived");
    return { contentType, pubKey };
}

function getResponseBody(details, contentType, pubKey) {
    let response = '';
    for (let i = 0; i < details[i].responseData.length; i++)
        response += ArrayToBytes(details[i].responseData);
    // console.log(details[0].requestId, "onDataReceived");
    IntegrityVerification(response, contentType, pubKey, details[0]);
}

var Events = {};
var totalEvents = 3;

async function Run(requestId) {
    let events = Events[requestId];
    let flag = filterByRequest(events["BeforeSendHeader"][0]);
    if (!flag) return;
    let res = await filterByResponseHeaders(events["HeadersReceived"][0]);
    if (res.contentType == 0) return;
    getResponseBody(events["DataReceived"], res.contentType, res.pubKey);
}

async function addEvents(event, details, step) {
    if (!(details.requestId in Events))
        Events[details.requestId] = { cnt: 0 }
    if (!(event in Events[details.requestId]))
        Events[details.requestId][event] = [];
    Events[details.requestId][event].push(details);
    Events[details.requestId]["cnt"] += step;
    if (Events[details.requestId]["cnt"] == totalEvents) {
        await Run(details.requestId);
        delete Event[details.requestId];
    }
}

function addBeforeSendHeaderEvent(details) {
    addEvents("BeforeSendHeader", details, 1);
}

function addHeadersReceivedEvent(details) {
    addEvents("HeadersReceived", details, 1);
}

function addDataReceivedEvent(details) {
    let data = new Uint8Array(details.responseData);
    details.responseData = data;
    addEvents("DataReceived", details, data.length == 0);
}

chrome.webRequest.onBeforeSendHeaders.addListener(
    addBeforeSendHeaderEvent,
    {
        urls: ["http://*/*", "https://*/*"],
        types: ["main_frame", "sub_frame", "script", "xmlhttprequest"]
    },
    ["requestHeaders"]
);

chrome.webRequest.onHeadersReceived.addListener(
    addHeadersReceivedEvent,
    {
        urls: ["http://*/*", "https://*/*"],
        types: ["main_frame", "sub_frame", "script", "xmlhttprequest"]
    },
    ["responseHeaders"]
);

chrome.webRequest.onDataReceived.addListener(
    addDataReceivedEvent,
    {
        urls: ["http://*/*", "https://*/*"],
        types: ["main_frame", "sub_frame", "script", "xmlhttprequest"]
    },
    ["responseData"]
);



//For evaluation only, must be removed for release

/*
const lastReq = {
    "card.discover.com": ["www.facebook.com/tr/*"],
    "ihprd.siss.duke.edu": ["ihprd.siss.duke.edu/cs/IHPRD01/cache/DataTables-1.10.16/images/sort_asc.png*", "ihprd.siss.duke.edu/psp/IHPRD01/EMPLOYEE/EMPL/h/*"],
    "console.aws.amazon.com": ["console.aws.amazon.com/billing/rest/v1.0/taxinvoice/newmetadata*"]
}

var urlFilters = [];
for (let domain in lastReq) {
    for (let url of lastReq[domain]) {
        urlFilters.push("https://" + url);
    }
}

function checkOne(details) {
    let end = parseInt(details.timeStamp);
    chrome.tabs.executeScript(details.tabId, {
        code: `console.log("end: ` + end + `");`
    });
}

chrome.webRequest.onCompleted.addListener(
    checkOne,
    {
        urls: urlFilters,
        types: ["sub_frame", "image", "xmlhttprequest", "script", "object", "other"]
    }
);
*/
