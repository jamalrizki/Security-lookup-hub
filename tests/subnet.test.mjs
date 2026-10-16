import { test } from 'node:test';
import assert from 'node:assert/strict';
import { subnetInfo, inRange, formatIPv6, parseCidr } from '../js/analyze/subnet.js';

test('IPv4 /24 with host bits set', () => {
  const r = subnetInfo('192.168.1.77/24');
  assert.equal(r.network, '192.168.1.0/24');
  assert.equal(r.netmask, '255.255.255.0');
  assert.equal(r.wildcard, '0.0.0.255');
  assert.equal(r.broadcast, '192.168.1.255');
  assert.equal(r.firstHost, '192.168.1.1');
  assert.equal(r.lastHost, '192.168.1.254');
  assert.equal(r.usable, '254');
  assert.equal(r.hostBitsSet, true);
});

test('IPv4 edge prefixes: /0, /31 (RFC 3021), /32', () => {
  const zero = subnetInfo('8.8.8.8/0');
  assert.equal(zero.network, '0.0.0.0/0');
  assert.equal(zero.total, '4294967296');
  assert.equal(zero.usable, '4294967294');
  assert.equal(zero.broadcast, '255.255.255.255');

  const p2p = subnetInfo('10.0.0.1/31');
  assert.equal(p2p.network, '10.0.0.0/31');
  assert.equal(p2p.broadcast, null);
  assert.equal(p2p.firstHost, '10.0.0.0');
  assert.equal(p2p.lastHost, '10.0.0.1');
  assert.equal(p2p.usable, '2');

  const host = subnetInfo('10.0.0.1/32');
  assert.equal(host.usable, '1');
  assert.equal(host.firstHost, '10.0.0.1');
  assert.equal(host.lastHost, '10.0.0.1');
  assert.equal(host.broadcast, null);
  assert.equal(subnetInfo('10.0.0.1').prefix, 32, 'no prefix means a single host');
});

test('IPv4 dotted netmasks, and bad input', () => {
  assert.equal(subnetInfo('172.16.5.4/255.255.240.0').network, '172.16.0.0/20');
  assert.match(subnetInfo('10.0.0.0/255.0.255.0').error, /gaps/);
  assert.match(subnetInfo('10.0.0.0/33').error, /0 to 32/);
  assert.match(subnetInfo('10.0.0.0/-1').error, /0 to 32/);
  assert.match(subnetInfo('banana/24').error, /not an IPv4 or IPv6/);
  assert.match(subnetInfo('10.0.0.0/8/9').error, /one "\/"/);
});

test('IPv6 edge prefixes: /0, /64, /127, /128 with BigInt counts', () => {
  const zero = subnetInfo('2001:db8::1/0');
  assert.equal(zero.network, '::/0');
  assert.equal(zero.last, 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff');
  assert.equal(zero.count, (2n ** 128n).toString());

  const lan = subnetInfo('2001:db8:abcd:12::99/64');
  assert.equal(lan.network, '2001:db8:abcd:12::/64');
  assert.equal(lan.first, '2001:db8:abcd:12::');
  assert.equal(lan.last, '2001:db8:abcd:12:ffff:ffff:ffff:ffff');
  assert.equal(lan.count, '18446744073709551616');

  const p2p = subnetInfo('2001:db8::1/127');
  assert.equal(p2p.first, '2001:db8::');
  assert.equal(p2p.last, '2001:db8::1');
  assert.equal(p2p.count, '2');

  const one = subnetInfo('fe80::1/128');
  assert.equal(one.first, 'fe80::1');
  assert.equal(one.count, '1');
  assert.match(subnetInfo('::1/129').error, /0 to 128/);
});

test('RFC 5952 formatting', () => {
  const p = (s) => parseCidr(s).addr;
  assert.equal(formatIPv6(p('2001:0db8:0000:0000:0001:0000:0000:0001')), '2001:db8::1:0:0:1', 'first longest run');
  assert.equal(formatIPv6(p('2001:db8:0:1:1:1:1:1')), '2001:db8:0:1:1:1:1:1', 'a single zero group is not shortened');
  assert.equal(formatIPv6(0n), '::');
});

test('is this IP in this range?', () => {
  assert.equal(inRange('10.0.0.0/8', '10.255.1.2'), true);
  assert.equal(inRange('10.0.0.0/8', '11.0.0.1'), false);
  assert.equal(inRange('192.168.1.0/31', '192.168.1.1'), true);
  assert.equal(inRange('2001:db8::/32', '2001:db8:ffff::1'), true);
  assert.equal(inRange('2001:db8::/32', '2001:db9::1'), false);
  assert.match(inRange('10.0.0.0/8', '::1').error, /Mixing/);
  assert.equal(inRange('0.0.0.0/0', '203.0.113.9'), true);
});
