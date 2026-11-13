import crypto from 'node:crypto';

import { hash, randomToken } from './security.js';

export function createDeviceToken() {
  return randomToken(32);
}

export function hashDeviceToken(token) {
  return hash(token);
}

export function isValidDeviceToken(token) {
  return (
    typeof token === 'string' &&
    token.length >= 32 &&
    token.length <= 128 &&
    /^[A-Za-z0-9_-]+$/.test(token)
  );
}

export function safeCompare(a, b) {
  const left = Buffer.from(a);
  const right = Buffer.from(b);

  return (
    left.length === right.length &&
    crypto.timingSafeEqual(left, right)
  );
}
