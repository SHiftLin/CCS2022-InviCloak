"use strict";
var config = {
    sensitiveURLs: [
        /^\/privacy\/.*/,
        /^\/dynamic\/.*/,
        '/blk_sw'
    ],
    clientHelloURL: '/clientHello' // should start with '/' to force absolute path
};
