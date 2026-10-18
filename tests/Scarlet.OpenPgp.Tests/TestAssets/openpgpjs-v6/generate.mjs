// Generates v6 (RFC 9580) fixtures with OpenPGP.js, an independent implementation, for
// Scarlet.OpenPgp's interop tests. Usage: node generate.mjs <output folder>
import * as openpgp from 'openpgp';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const out = process.argv[2];
const created = new Date(Date.UTC(2026, 0, 1));
const signedAt = new Date(Date.UTC(2026, 0, 2));
const config = { v6Keys: true, aeadProtect: true };
const text = 'OpenPGP.js v6 interop fixture.\nSecond line with trailing spaces   \n- a line starting with a dash\n';

const variants = [
  { name: 'v6-ed25519', options: { type: 'curve25519' } },
  { name: 'v6-ed448', options: { type: 'curve448' } },
  { name: 'v6-ed25519-signing-subkey', options: { type: 'curve25519', subkeys: [{ sign: true }] }, signWithSubkey: true },
  { name: 'v6-rsa3072', options: { type: 'rsa', rsaBits: 3072 } },
  { name: 'v6-ecdsa-nistp256', options: { type: 'ecc', curve: 'nistP256' } },
];

for (const variant of variants) {
  try {
    const { privateKey, publicKey } = await openpgp.generateKey({
      ...variant.options,
      userIDs: [{ name: 'Interop', email: 'interop@example.test' }],
      date: created,
      format: 'object',
      config,
    });
    const folder = join(out, variant.name);
    mkdirSync(folder, { recursive: true });
    writeFileSync(join(folder, 'public-key.asc'), publicKey.armor(config));
    writeFileSync(join(folder, 'data.txt'), text);

    const signingKeyIDs = variant.signWithSubkey ? (await privateKey.getSigningKey(undefined, signedAt)).getKeyID() : undefined;
    const common = { signingKeys: privateKey, signingKeyIDs, date: signedAt, config };

    const binary = await openpgp.createMessage({ binary: new TextEncoder().encode(text) });
    writeFileSync(join(folder, 'data.txt.sig'), await openpgp.sign({ ...common, message: binary, detached: true, format: 'binary' }));

    const textMessage = await openpgp.createMessage({ text });
    writeFileSync(join(folder, 'data.txt.textmode.asc'), await openpgp.sign({ ...common, message: textMessage, detached: true }));

    const cleartext = await openpgp.createCleartextMessage({ text });
    writeFileSync(join(folder, 'data.txt.clearsign.asc'), await openpgp.sign({ ...common, message: cleartext }));

    const signer = variant.signWithSubkey ? (await privateKey.getSigningKey(undefined, signedAt)) : privateKey;
    console.log(variant.name + ': ok, signed by ' + signer.getFingerprint().toUpperCase() + ', primary ' + publicKey.getFingerprint().toUpperCase() + ', version ' + publicKey.keyPacket.version);
  } catch (error) {
    console.log(variant.name + ': skipped - ' + error.message);
  }
}
