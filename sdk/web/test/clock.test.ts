import { describe, expect, test } from 'vitest';
import { ServerClock, parseHttpDate } from '../src/clock.js';

describe('parseHttpDate', () => {
  test('parses IMF-fixdate', () => {
    expect(parseHttpDate('Sun, 06 Nov 1994 08:49:37 GMT')).toBe(Date.UTC(1994, 10, 6, 8, 49, 37));
  });

  test.each([
    null,
    '',
    'Sunday, 06-Nov-94 08:49:37 GMT', // obsolete RFC 850 form
    'Sun Nov  6 08:49:37 1994', // asctime
    '1994-11-06T08:49:37Z',
    'Sun, 06 Nov 1994 08:49:37 UTC',
    'Sun, 6 Nov 1994 08:49:37 GMT',
  ])('ignores %j', (value) => {
    expect(parseHttpDate(value)).toBeUndefined();
  });
});

describe('ServerClock', () => {
  test('starts uncorrected', () => {
    const clock = new ServerClock(() => 1_000_000);
    expect(clock.offsetMs).toBe(0);
    expect(clock.nowSeconds()).toBe(1000);
  });

  test('estimates the offset from Date and the round trip midpoint', () => {
    let local = 1_700_000_000_000;
    const clock = new ServerClock(() => local);
    // Server is one hour ahead; request took 200 ms.
    const serverAtResponse = local + 3_600_000 + 100;
    const date = new Date(Math.floor(serverAtResponse / 1000) * 1000).toUTCString();
    const delta = clock.observe(date, local, local + 200);
    expect(Math.abs(clock.offsetMs - 3_600_000)).toBeLessThanOrEqual(1000);
    expect(delta).toBe(clock.offsetMs);
    local += 10_000;
    expect(
      Math.abs(clock.nowSeconds() - Math.floor((local + 3_600_000) / 1000)),
    ).toBeLessThanOrEqual(1);
  });

  test('handles a client clock that is behind', () => {
    const local = 1_700_000_000_000;
    const clock = new ServerClock(() => local);
    const date = new Date(local - 86_400_000).toUTCString();
    clock.observe(date, local, local);
    expect(Math.abs(clock.offsetMs + 86_400_000)).toBeLessThanOrEqual(1000);
  });

  test('ignores missing or malformed Date headers and inverted timings', () => {
    const clock = new ServerClock(() => 0);
    expect(clock.observe(null, 0, 1)).toBe(0);
    expect(clock.observe('garbage', 0, 1)).toBe(0);
    expect(clock.observe(new Date(5_000_000).toUTCString(), 10, 5)).toBe(0);
    expect(clock.offsetMs).toBe(0);
  });
});
