// Node crypto & bufferFrom
import { Buffer } from "buffer";
import { URL } from "url";
import * as crypto from "crypto";

export type TResult = {
  verified: boolean;
  message: string;
  payload?: IPayload;
  authObject?: Record<"header" | "payload" | "signature", string>;
};

export type TUtils = (a: string) => string;
export type TB64UrlEncode = (a: Buffer) => string;
export interface IPayload {
  iss: string;
  dest: string;
  aud: string;
  sub: string;
  exp: number;
  nbf: number;
  iat: number;
  jti: string;
}

// Utils
const atob: TUtils = (a = "") => Buffer.from(a, "base64").toString("binary");
const base64UrlEncode: TB64UrlEncode = (buffer) =>
  buffer
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");

// is Verified and not expired
export default function isVerified(
  authorization: string,
  secret: string,
  key: string,
): TResult {
  // Early return for missing params
  if (!authorization || !secret || !key) {
    return {
      verified: false,
      message: "authorization or app secret or app key missing",
    };
  }
  // probably could be cleaned up this is dirty, straight string replace to remove the stragglers and split it.
  const auth: string[] = authorization.replace("Bearer ", "").split(".");
  // will be passed to the optional call back
  const authObject: Record<"header" | "payload" | "signature", string> = {
    header: atob(auth[0]),
    payload: atob(auth[1]),
    signature: auth[2],
  };

  const headerPayload: string = [auth[0], auth[1]].join(".");
  const signedBuffer: Buffer = crypto
    .createHmac("sha256", secret)
    .update(headerPayload)
    .digest();
  const isVerified: boolean =
    authObject.signature === base64UrlEncode(signedBuffer);

  if (!isVerified) {
    return {
      verified: false,
      message: "Token is invalid",
    };
  }
  // validate not expired
  const payload: IPayload = JSON.parse(authObject.payload);
  const time = new Date().getTime() / 1000;
  const isExpired: boolean = payload.exp <= time;
  const isValidAfter: boolean = payload.nbf <= time;
  const iss = new URL(payload.iss).hostname;
  const dest = new URL(payload.dest).hostname;

  // still valid
  if (isExpired) {
    return {
      verified: false,
      message: "Token is expired",
    };
  }

  // valid from
  if (!isValidAfter) {
    return {
      verified: false,
      message: "Token is not yet valid",
    };
  }

  if (iss != dest) {
    return {
      verified: false,
      message: `Token issuer ${iss} does not match the destination ${dest}`,
    };
  }

  if (payload.aud != key) {
    return {
      verified: false,
      message: "Token does not match the Shopify API Key",
    };
  }

  return {
    verified: true,
    message: "Token is valid",
    payload,
    authObject,
  };
}
