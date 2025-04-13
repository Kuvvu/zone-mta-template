const fs = require('fs');
const { spawn } = require('child_process');
const path = require('path');

module.exports = function (plugin) {
  plugin.registerHook('message:body', async (message, content, stream) => {
    const envelopeFrom = message.envelope.mailFrom.address.toLowerCase();
    const headerFromRaw = message.header.get('From');

    if (!headerFromRaw) {
      plugin.loginfo(`Missing From header, skipping signing`);
      return;
    }

    const headerFromMatch = headerFromRaw.match(/<([^>]+)>/);
    const headerFrom = (headerFromMatch ? headerFromMatch[1] : headerFromRaw).toLowerCase();

    if (headerFrom !== envelopeFrom) {
      plugin.loginfo(`Header-From (${headerFrom}) ≠ Envelope-From (${envelopeFrom}) – skipping signing`);
      return;
    }

    const allowedEmails = (plugin.cfg.allowed_emails || []).map(e => e.toLowerCase());
    if (!allowedEmails.includes(envelopeFrom)) {
      plugin.loginfo(`Envelope-From (${envelopeFrom}) not in allowed_emails – skipping plugin`);
      return;
    }

    const certDirectory = plugin.cfg.cert_dir || '/var/lib/zone-mta/smime-certs';
    const certFilename = envelopeFrom.replace(/[@.]/g, '_') + '.p12';
    const certPath = path.join(certDirectory, certFilename);

    if (!fs.existsSync(certPath)) {
      plugin.loginfo(`No certificate found at ${certPath} for ${envelopeFrom}, skipping signing`);
      return;
    }

    plugin.loginfo(`Using certificate from ${certPath} for ${envelopeFrom}`);

    return new Promise((resolve, reject) => {
      const args = [
        'smime', '-sign',
        '-signer', certPath,
        '-inkey', certPath,
        '-outform', 'pem',
        '-nodetach'
      ];

      const openssl = spawn('openssl', args);

      let signed = Buffer.alloc(0);
      let error = '';

      openssl.stdout.on('data', (data) => {
        signed = Buffer.concat([signed, data]);
      });

      openssl.stderr.on('data', (data) => {
        error += data.toString();
      });

      openssl.on('close', (code) => {
        if (code !== 0) {
          plugin.logerror(`OpenSSL failed: ${error}`);
          return reject(new Error(`OpenSSL failed: ${error}`));
        }
        plugin.loginfo(`SIGNING ${signed}`);
        resolve(signed);
      });

      openssl.stdin.write(content);
      openssl.stdin.end();
    });
  });
};
