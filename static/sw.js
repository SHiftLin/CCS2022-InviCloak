"use strict";
importScripts('/swjs/batch.js');
importScripts('/swjs/configure.js');

var secret = null;

self.addEventListener('activate', async event => {
    Handshake(self.location.hostname);
});

self.addEventListener('fetch', event => {
    if (event.request.method == 'OPTIONS')
        return;
    let url = ParseURL(event.request.url);
    if (MatchURL(url))
        event.respondWith(requestHandler(event, url));
    /* event.respondWith has to be called synchronously */
});

async function requestHandler(event, url) {
    if (secret == "pending") {
        return new Promise(function pend(resolve, reject) {
            setTimeout(async () => {
                if (secret == "pending") pend(resolve, reject);
                else if (secret == null) resolve(new Response('', { status: 500 }));
                else resolve(InviCloak(event, url));
            }, 50);
        });
    } else {
        let res = await Handshake(url.hostname);
        if (res == -1)
            return new Response('', { status: 500 });
        return InviCloak(event, url);
    }
}


async function Handshake(hostname) {
    if (secret == null)
        secret = await getSecretFromCache();
    if (secret == null) {
        secret = "pending"
        try {
            secret = await KeyExchange(hostname);
        } catch (error) {
            secret = null;
        }
        if (secret == null) return -1;
    }
    return 0;
}

async function InviCloak(event, url) {
    let request = event.request.clone();
    let env;
    if (request.method == 'POST' || request.method == 'PUT') {
        env = await Encapsulate(await request.arrayBuffer(), false, secret);
        request = new Request(event.request, { body: env.ciphertext });
    } else {
        env = await Encapsulate(url.params, true, secret);
        request = UpdateURL(event.request, url.origin);
        // request = UpdateURL(event.request, url.origin + '?' + env.ciphertext);
    }
    let response = Decapsulate(await fetch(request, {
        credentials: 'include',
        headers: {
            'cloakparams': env.params,
            'cachekey': env.cachekey,
            'cipherquery': env.cipherquery,
        }
    }), env.K);
    if (response.status == 403) {
        await deleteSecretFromCache();
        secret = null;
    }

    return response;
}

function Match(pattern, str) {
    if (pattern instanceof RegExp)
        return pattern.test(str);
    return pattern == str;
}

function MatchURL(url) {
    for (let exp of config.sensitiveURLs) {
        if (exp instanceof Array) {
            if (exp.length == 0) continue;
            if (exp.length == 1) {
                if (Match(exp[0], url.pathname)) return true;
            } else if (exp.length == 2) {
                if (Match(exp[0], url.hostname) && Match(exp[1], url.pathname)) return true;
            } else {
                if (Match(exp[0], url.hostname) && Match(exp[1], url.pathname) && Match(exp[2], url.params)) return true;
            }
        } else {
            if (Match(exp, url.pathname)) return true;
        }
    }
    return false;
}
