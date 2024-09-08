import isVerified from "../src/index";
import createMock from "../utils/createMock";

test("Expect false when no params are parsed to the function", () => {
  // @ts-ignore
  const result = isVerified();
  expect(result).toBeInstanceOf(Object);
  expect(result.verified).toBe(false);
});

test("a valid request both authenticity & not expired", () => {
  // @ts-ignore
  const { bearer, signature, secret, key, headerPayload } = createMock();
  const result = isVerified(bearer, secret, key);
  expect(result.verified).toBe(true);
});

test("Test expired or incorrect tbf", () => {
  // @ts-ignore
  const { builtExpiredAuth, signature, secret, key } = createMock();
  const result = isVerified(builtExpiredAuth, secret, key);
  expect(result.verified).toBe(false);
});

test("a valid request with a token direct from the session token request ( EG : minus Bearer )", () => {
  // @ts-ignore
  const { secret, sessionToken, key } = createMock();
  const result = isVerified(sessionToken, secret, key);
  expect(result.verified).toBe(true);
});

test("a fradulent request", () => {
  // @ts-ignore
  const { bearer, signature, secret, key, headerPayload } = createMock(
    60000,
    true,
  );
  const result = isVerified(bearer, secret, key);
  expect(result.verified).toBe(false);
});

test("a fradulent request where the expirey is correct but the hashes are invalid", () => {
  // @ts-ignore
  const { bearer, signature, secret, key, headerPayload } = createMock(
    null,
    true,
  );
  const result = isVerified(bearer, secret, key);
  expect(result.verified).toBe(false);
});

test("an expired token should fail the verification", () => {
  // @ts-ignore
  const { bearer, signature, secret, key, headerPayload } = createMock(-100);
  const result = isVerified(bearer, secret, key);
  expect(result.verified).toBe(false);
});

test("returns payload", () => {
  // @ts-ignore
  const {
    bearer,
    encodedSignature,
    secret,
    key,
    headerPayload,
    mockHeader,
    mockPayload,
  } = createMock();
  const result = isVerified(bearer, secret, key);
  expect(result.verified).toBe(true);
  expect(JSON.parse(result.authObject.header)).toEqual(mockHeader);
  expect(JSON.parse(result.authObject.payload)).toEqual(
    mockPayload,
  );
  expect(result.authObject.signature).toEqual(encodedSignature);
});
