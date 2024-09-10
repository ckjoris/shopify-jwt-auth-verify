/// <reference types="node" />
export declare type TResult = {
    verified: boolean;
    message: string;
    payload?: IPayload;
    authObject?: Record<"header" | "payload" | "signature", string>;
};
export declare type TUtils = (a: string) => string;
export declare type TB64UrlEncode = (a: Buffer) => string;
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
export default function isVerified(authorization: string, secret: string, key: string): TResult;
