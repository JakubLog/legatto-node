import { describe, expect, it } from 'vitest';
import { rateLimitBucket, sanitizeUserAgent } from '../../src/client';

describe('rateLimitBucket (ported from public-submit-case)', () => {
  it.each([
    ['203.0.113.7', '203.0.113.7'],
    ['::ffff:203.0.113.7', '203.0.113.7'],
    ['[2001:db8::1]', '2001:0db8:0000:0000::/64'],
    ['2001:DB8:1:2:3:4:5:6', '2001:0db8:0001:0002::/64'],
    ['fe80::1%eth0', 'fe80:0000:0000:0000::/64'],
    ['64:ff9b::192.0.2.1', '0064:ff9b:0000:0000::/64'],
    ['not-an-ip', 'not-an-ip'],
  ])('%s -> %s', (input, expected) => {
    expect(rateLimitBucket(input)).toBe(expected);
  });
});

describe('sanitizeUserAgent', () => {
  it('keeps printable ASCII, replaces the rest and caps at 256 bytes', () => {
    expect(sanitizeUserAgent('Mozilla/5.0 Zażółć\u0000')).toBe('Mozilla/5.0 Za?????');
    expect(sanitizeUserAgent('ą'.repeat(400))).toHaveLength(256);
    expect(new TextEncoder().encode(sanitizeUserAgent('ą'.repeat(400))).length).toBe(256);
    expect(sanitizeUserAgent(null)).toBe('');
  });
});
