const fs = require('fs');
const forge = require('node-forge');
const jws = require('jws');
const https = require('https');
const crypto = require('crypto');
const express = require("express");
require('dotenv').config();
const cookieParser = require('cookie-parser');
const rp = require("request-promise");

const port = 5001;
const app = express();
app.use(cookieParser());
app.use(express.json({ extended: true, limit: '1mb' }))

app.post('/', function (req, res) {
    let data = JSON.stringify({
        "id": process.env.FAYDA_ID,
        "version": "1.0",
        "requesttime": new Date().toISOString(),
        "metadata": {},
        "request": {
            "clientId": process.env.CLIENT_ID,
            "secretKey": process.env.SECRET_KEY,
            "appId": process.env.APP_ID
        }
    });

    var options = {
        url: process.env.DOMAIN_URI + process.env.AUTH_PATH,
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        resolveWithFullResponse: true,
        body: data,
        strictSSL: false,
        proxy:
            "http://brd-customer-hl_135f35dc-zone-fayda:x1pqeo4xo75h@brd.superproxy.io:22225"
    };

    rp(options)
        .then((response) => {
            const cookies = response.headers.authorization;
            res.cookie("Authorization", cookies);
            res.send(response.body)
        })
        .catch((error) => {
            console.error("Show the error", error.message);
        })
        .finally(() => {
            console.log("Request Done");
        });


});

app.post("/sendotp", function (req, res) {
    const { individual_id } = req.body

    // Read the PKCS12 file into a buffer
    const p12File = fs.readFileSync('./testorg.p12');

    // Convert the PKCS12 buffer to a PKCS12 object
    const pkcs12Asn1 = forge.asn1.fromDer(p12File.toString('binary'));
    const pkcs12 = forge.pkcs12.pkcs12FromAsn1(pkcs12Asn1, 'testorg2');

    // Extract the private key and certificate from the PKCS12 object
    const privateKey = pkcs12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[forge.pki.oids.pkcs8ShroudedKeyBag][0].key;
    const cert = pkcs12.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag][0].cert;

    // Convert the private key to PEM format
    const keyPem = forge.pki.privateKeyToPem(privateKey);

    // Convert the certificate to PEM format
    const certPem = forge.pki.certificateToPem(cert);

    // Using their key

    const pKey = fs.readFileSync('./testorg2-key.pem', { encoding: "utf8" });
    const pCert = fs.readFileSync('./testorg2-cert.pem', { encoding: "utf8" });

    const payloadStream = JSON.stringify({ "requestTime": new Date().toISOString(), "env": "Developer", "domainUri": "https://dev.fayda.et", "transactionID": "1231231234", "individualId": `${individual_id}`, "individualType": "UIN", "otpChannel": ["PHONE"], "id": "fayda.identity.otp", "version": "1.0" });

    const publicCert = pCert.replace(`-----BEGIN CERTIFICATE-----\n`, "").replace("\n-----END CERTIFICATE-----\n", "");

    const signature = jws.sign({
        header: { alg: "RS256", x5c: [publicCert] },
        privateKey: { key: pKey, passphrase: process.env.PASSPHRASE },
        payload: payloadStream,
    });


    var options = {
        url: process.env.DOMAIN_URI + process.env.OTP_REQUEST_PATH,
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            "Authorization": req.cookies,
            "Signature": signature
        },
        resolveWithFullResponse: true,
        body: payloadStream,
        strictSSL: false,
        proxy:
            "http://brd-customer-hl_135f35dc-zone-fayda:x1pqeo4xo75h@brd.superproxy.io:22225",
    };


    rp(options)
        .then((response) => {
            res.send(response.body)
            // res.send("otp send successfully");
        })
        .catch((error) => {
            console.error("Show the error", error.message);
        })
        .finally(() => {
            console.log("Request Done");
        });

});



app.post("/votp", function (req, res) {

    const { otpCode, individual_id } = req.body;
    const pKey = fs.readFileSync('./testorg2-key.pem', { encoding: "utf8" });
    const pCert = fs.readFileSync('./testorg2-cert.pem', { encoding: "utf8" });
    const publicCert = pCert.replace(`-----BEGIN CERTIFICATE-----\n`, "").replace("\n-----END CERTIFICATE-----\n", "");

    const requestBody = JSON.stringify({ "timestamp": new Date().toISOString(), "otp": `${otpCode}` })

    function base64UrlEncode(buffer) {
        let base64Url = buffer.toString('base64')
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
        return base64Url;
    }
    function generateSecretKey(keyLen) {
        const key = crypto.randomBytes(keyLen);
        return key;
    }

    function getCertificate(path) {
        const certData = fs.readFileSync(path);
        const cert = new crypto.X509Certificate(certData);
        const pubCert = cert.publicKey.export({ type: 'spki', format: 'pem' });
        return { publicKey: pubCert, certificate: cert };
    }

    function generateHash(data) {
        const hash = crypto.createHash('sha256');
        hash.update(data);
        return hash.digest();
    }


    function encryptSymmetricKey(data, publicKey) {
        const encryptedSymKey = crypto.publicEncrypt({
            key: publicKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: 'sha256',
            mgf1: {
                hash: 'sha256'
            }
        }, data);

        const encryptedSymKeyBase64Url = base64UrlEncode(encryptedSymKey); // Base64-URL-encode the encrypted symmetric key

        return encryptedSymKeyBase64Url;
    };

    function symmetricEncrypt(key, data, aad) {
        try {
            const randomIV = crypto.randomBytes(16);
            const cipher = crypto.createCipheriv('aes-256-gcm', key, randomIV, { authTagLength: 16 });
            cipher.setAAD(aad);
            const encryptedData = Buffer.concat([cipher.update(data), cipher.final()]);
            const authTag = cipher.getAuthTag();
            const output = Buffer.concat([encryptedData, authTag, randomIV]);
            return output.toString('base64url');
        } catch (error) {
            console.error(error);
            return null;
        }
    };

    function generateThumbprint(data) {
        // Get raw DER certificate data
        const certDER = data.raw;
        // Generate SHA-256 thumbprint 
        const thumbprint = crypto.createHash('sha256').update(certDER).digest('base64url');
        return thumbprint;
    }

    const SecretKeyTemp = generateSecretKey(32);
    const SecretKey = SecretKeyTemp.toString('base64url');

    const pubKey = getCertificate('./fayda.crt').publicKey;
    const pubCertificate = getCertificate("./fayda.crt").certificate;
    const requestSessionKey = encryptSymmetricKey(Buffer.from(SecretKey, 'base64url'), pubKey);
    const hashOfRequestBody = generateHash(requestBody).toString('hex');
    const requestHMAC = symmetricEncrypt(Buffer.from(SecretKey, 'base64url'), hashOfRequestBody.toUpperCase(), "");
    const encryptedRequestBody = symmetricEncrypt(Buffer.from(SecretKey, 'base64url'), requestBody, "");
    const thumbprint = generateThumbprint(pubCertificate);

    const payload = JSON.stringify({ "requestTime": new Date().toISOString(), "env": "Developer", "domainUri": "https://dev.fayda.et", "transactionID": "1231231234", "requestedAuth": { "otp": true, "demo": false, "bio": false }, "consentObtained": true, "individualId": `${individual_id}`, "individualIdType": "UIN", "thumbprint": thumbprint, "requestSessionKey": requestSessionKey, "requestHMAC": requestHMAC, "request": encryptedRequestBody, "id": "fayda.identity.auth", "version": "1.0" });



    // Send Request to end point

    const signature = jws.sign({
        header: { alg: "RS256", x5c: [publicCert] },
        privateKey: { key: pKey, passphrase: process.env.PASSPHRASE },
        payload: payload,
    });


    var options = {
        url: process.env.DOMAIN_URI + process.env.AUTH_REQUEST_PATH,
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            "Authorization": req.cookies,
            "Signature": signature
        },
        resolveWithFullResponse: true,
        body: payload,
        strictSSL: false,
        proxy:
            "http://brd-customer-hl_135f35dc-zone-fayda:x1pqeo4xo75h@brd.superproxy.io:22225",
    };

    rp(options)
        .then((response) => {
            res.send(response.body)
            // res.send("fayda otp verified successfully");
        })
        .catch((error) => {
            console.error("Show the error", error.message);
        })
        .finally(() => {
            console.log("Request Done");
        });

});



app.listen(port, () => {
    console.log(`Test app listening on port ${port}`);
});
