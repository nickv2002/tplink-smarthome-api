import { expect } from 'chai';

import {
  generateAuthHash,
  handshake1SeedAuthHash,
  handshake2SeedAuthHash,
  KlapEncryptionSession,
  matchHandshake1Auth,
} from '../../src/network/klap';
import {
  getKlapHttpPort,
  isIotKlapDiscovery,
  isKlapV2Scheme,
  parseNewDiscoveryMessage,
} from '../../src/network/klap-discovery';

describe('KLAP', function () {
  const creds = { username: 'foo', password: 'bar' };
  const localSeed = Buffer.alloc(16, 0x00);
  const remoteSeed = Buffer.alloc(16, 0x11);

  describe('hashes (KlapTransportV2 / python-kasa)', function () {
    it('should match python-kasa v2 auth hash', function () {
      expect(generateAuthHash(creds, 2).toString('hex')).to.equal(
        'fbafbfc0b0166ca060c19b4b429f8d51bdf90b61395ca5b14e127d1533c7b1a2',
      );
    });

    it('should match python-kasa v1 auth hash', function () {
      expect(generateAuthHash(creds, 1).toString('hex')).to.equal(
        '0105fcbc9eea8193de8e1834677b6c6b',
      );
    });

    it('should match python-kasa v2 handshake1 hash', function () {
      const auth = generateAuthHash(creds, 2);
      expect(
        handshake1SeedAuthHash(localSeed, remoteSeed, auth, 2).toString('hex'),
      ).to.equal(
        'b07aa0ae54eb6b03cfd841088af5f2041fb82d32035ab757919917a0a188aa29',
      );
    });

    it('should match python-kasa v2 handshake2 hash', function () {
      const auth = generateAuthHash(creds, 2);
      expect(
        handshake2SeedAuthHash(localSeed, remoteSeed, auth, 2).toString('hex'),
      ).to.equal(
        'd07d2d3eafdd06f0b53e32fcc508cd8609439138243a4aa0e54801c1c6b84b58',
      );
    });
  });

  describe('matchHandshake1Auth', function () {
    it('should select KLAP v2 when the device uses v2 hashing', function () {
      const auth = generateAuthHash(creds, 2);
      const serverHash = handshake1SeedAuthHash(localSeed, remoteSeed, auth, 2);
      const matched = matchHandshake1Auth(
        localSeed,
        remoteSeed,
        serverHash,
        creds,
      );
      expect(matched).to.not.equal(undefined);
      expect(matched?.version).to.equal(2);
      expect(matched?.authHash.equals(auth)).to.equal(true);
    });

    it('should select KLAP v1 when the device uses v1 hashing', function () {
      const auth = generateAuthHash(creds, 1);
      const serverHash = handshake1SeedAuthHash(localSeed, remoteSeed, auth, 1);
      const matched = matchHandshake1Auth(
        localSeed,
        remoteSeed,
        serverHash,
        creds,
      );
      expect(matched).to.not.equal(undefined);
      expect(matched?.version).to.equal(1);
    });

    it('should return undefined for mismatched credentials', function () {
      const auth = generateAuthHash(creds, 2);
      const serverHash = handshake1SeedAuthHash(localSeed, remoteSeed, auth, 2);
      const matched = matchHandshake1Auth(localSeed, remoteSeed, serverHash, {
        username: 'wrong',
        password: 'wrong',
      });
      expect(matched).to.equal(undefined);
    });
  });

  describe('KlapEncryptionSession', function () {
    it('should encrypt and decrypt a round-trip matching python-kasa', function () {
      const auth = generateAuthHash(creds, 2);
      const session = new KlapEncryptionSession(localSeed, remoteSeed, auth);
      const { payload, seq } = session.encrypt('{"system":{"get_sysinfo":{}}}');
      expect(seq).to.equal(753086691);
      expect(payload.toString('hex')).to.equal(
        'e9b96cdc01bbc5eaa6294d23773c1c0765b4c96ccf80e47f53d8ada32d36e94bd5de7d502199d4e9b4cc7c0c92e146be82f4a5cb3c0dfa786f00c1a40b71dc3a',
      );
      expect(session.decrypt(payload)).to.equal(
        '{"system":{"get_sysinfo":{}}}',
      );
    });
  });

  describe('discovery', function () {
    const iotKlapPayload = {
      result: {
        device_type: 'IOT.SMARTBULB',
        device_model: 'KL125(US)',
        device_id: 'abc',
        ip: '192.168.1.35',
        mac: '98-25-4A-BC-5A-6A',
        mgt_encrypt_schm: {
          is_support_https: false,
          encrypt_type: 'KLAP',
          http_port: 80,
          lv: 2,
          new_klap: 1,
        },
      },
      error_code: 0,
    };

    it('should parse a 20002 discovery datagram', function () {
      const body = Buffer.from(JSON.stringify(iotKlapPayload));
      const msg = Buffer.concat([Buffer.alloc(16), body]);
      const result = parseNewDiscoveryMessage(msg);
      expect(result?.device_type).to.equal('IOT.SMARTBULB');
      expect(result?.device_model).to.equal('KL125(US)');
    });

    it('should detect IOT KLAP devices and skip Tapo/SMART', function () {
      const parsed = parseNewDiscoveryMessage(
        Buffer.concat([
          Buffer.alloc(16),
          Buffer.from(JSON.stringify(iotKlapPayload)),
        ]),
      );
      expect(parsed).to.not.equal(undefined);
      if (parsed == null) return;
      expect(isIotKlapDiscovery(parsed)).to.equal(true);
      expect(getKlapHttpPort(parsed)).to.equal(80);

      const tapo = {
        ...iotKlapPayload.result,
        device_type: 'SMART.TAPOBULB',
        mgt_encrypt_schm: {
          ...iotKlapPayload.result.mgt_encrypt_schm,
          encrypt_type: 'KLAP',
        },
      };
      expect(isIotKlapDiscovery(tapo)).to.equal(false);
    });

    it('should treat new_klap as login_version 2', function () {
      expect(
        isKlapV2Scheme({
          encrypt_type: 'KLAP',
          http_port: 80,
          new_klap: 1,
        }),
      ).to.equal(true);
      expect(
        isKlapV2Scheme({
          encrypt_type: 'KLAP',
          lv: 2,
        }),
      ).to.equal(true);
      expect(
        isKlapV2Scheme({
          encrypt_type: 'KLAP',
          lv: 1,
        }),
      ).to.equal(false);
    });
  });
});
