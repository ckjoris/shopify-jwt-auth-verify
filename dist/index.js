"use strict";
exports.__esModule = true;
// Node crypto & bufferFrom
var buffer_1 = require("buffer");
var url_1 = require("url");
var crypto = require("crypto");
// Utils
var atob = function (a) {
    if (a === void 0) { a = ""; }
    return buffer_1.Buffer.from(a, "base64").toString("binary");
};
var base64UrlEncode = function (buffer) {
    return buffer
        .toString("base64")
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/g, "");
};
// is Verified and not expired
function isVerified(authorization, secret, key) {
    // Early return for missing params
    if (!authorization || !secret || !key) {
        return {
            verified: false,
            message: "authorization or app secret or app key missing"
        };
    }
    // probably could be cleaned up this is dirty, straight string replace to remove the stragglers and split it.
    var auth = authorization.replace("Bearer ", "").split(".");
    // will be passed to the optional call back
    var authObject = {
        header: atob(auth[0]),
        payload: atob(auth[1]),
        signature: auth[2]
    };
    var headerPayload = [auth[0], auth[1]].join(".");
    var signedBuffer = crypto
        .createHmac("sha256", secret)
        .update(headerPayload)
        .digest();
    var isVerified = authObject.signature === base64UrlEncode(signedBuffer);
    if (!isVerified) {
        return {
            verified: false,
            message: "Token is invalid"
        };
    }
    // validate not expired
    var payload = JSON.parse(authObject.payload);
    var time = new Date().getTime() / 1000;
    var isExpired = payload.exp <= time;
    var isValidAfter = payload.nbf <= time;
    var iss = new url_1.URL(payload.iss).hostname;
    var dest = new url_1.URL(payload.dest).hostname;
    // still valid
    if (isExpired) {
        return {
            verified: false,
            message: "Token is expired"
        };
    }
    // valid from
    if (!isValidAfter) {
        return {
            verified: false,
            message: "Token is not yet valid"
        };
    }
    if (iss != dest) {
        return {
            verified: false,
            message: "Token issuer " + iss + " does not match the destination " + dest
        };
    }
    if (payload.aud != key) {
        return {
            verified: false,
            message: "Token does not match the Shopify API Key"
        };
    }
    return {
        verified: true,
        message: "Token is valid",
        payload: payload,
        authObject: authObject
    };
}
exports["default"] = isVerified;
//# sourceMappingURL=index.js.map