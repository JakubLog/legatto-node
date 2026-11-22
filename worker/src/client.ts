// Client identity for rate limiting. Ported 1:1 from legatto-app
// supabase/functions/public-submit-case (rateLimitBucket): IPv4 as is,
// IPv4-mapped IPv6 as IPv4, other IPv6 collapsed to its /64.

export function rateLimitBucket(ip: string): string {
  const addr = ip.trim().toLowerCase().replace(/^\[|\]$/g, '').replace(/%.*$/, '');
  if (!addr.includes(':')) return addr;

  // Trailing dotted IPv4 (::ffff:1.2.3.4, 64:ff9b::1.2.3.4) -> two hextets.
  let text = addr;
  const v4Tail = /(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(text);
  if (v4Tail) {
    const octets = v4Tail.slice(1).map(Number);
    if (octets.some((n) => n > 255)) return addr;
    const [a, b, c, d] = octets;
    text = text.slice(0, v4Tail.index) + `${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
  }

  // Expand '::' to 8 groups.
  const halves = text.split('::');
  if (halves.length > 2) return addr;
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const fill = 8 - head.length - tail.length;
  if (halves.length === 1 ? fill !== 0 : fill < 1) return addr;
  const groups = [...head, ...new Array<string>(halves.length === 2 ? fill : 0).fill('0'), ...tail];
  if (groups.some((g) => !/^[0-9a-f]{1,4}$/.test(g))) return addr;
  const words = groups.map((g) => parseInt(g, 16));

  // IPv4-mapped (::ffff:a.b.c.d) = IPv4 client.
  if (words.slice(0, 5).every((w) => w === 0) && words[5] === 0xffff) {
    return [words[6] >> 8, words[6] & 0xff, words[7] >> 8, words[7] & 0xff].join('.');
  }

  return `${words.slice(0, 4).map((w) => w.toString(16).padStart(4, '0')).join(':')}::/64`;
}

/**
 * User-Agent reduced to printable ASCII (anything else becomes '?') and at
 * most 256 bytes, so the meta plaintext always fits its 512-byte pad.
 */
export function sanitizeUserAgent(value: string | null): string {
  return (value ?? '').replace(/[^\x20-\x7e]/g, '?').slice(0, 256);
}
