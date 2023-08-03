const fs = require('fs');
const forge = require('node-forge');
const jws = require('jws');
const https = require('https');
const crypto = require('crypto');
const express = require("express");
const cookieParser = require('cookie-parser');

const port = 5001;
const app = express();
app.use(cookieParser());

app.post('/', function (req, res) {
    let data = JSON.stringify({
        "id": process.env.FAYDA_ID,
        "version": "1",
        "requesttime": new Date().toISOString(),
        "metadata": {},
        "request": {
            "clientId": process.env.CLIENT_ID,
            "secretKey": process.env.SECRET_KEY,
            "appId": process.env.APP_ID
        }
    });

    var options = {
        host: process.env.HOST,
        path: process.env.AUTH_PATH,
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        // rejectUnauthorized: false,
    };

    var request = https.request(options, function (resp) {
        let tempChunk = ""
        resp.setEncoding('utf8');
        resp.on('data', function (chunk) {
            tempChunk += chunk;
        });
        resp.on('end', function () {
            if (resp.statusCode !== 200) {
                res.status(resp.statusCode).res.send(tempChunk);
            } else {
                res.cookie("Authorization", resp.headers.authorization);
                res.send(tempChunk);
            }
        })
    });

    request.on('error', (error) => {
        console.error('show the error', error);
    });
    request.write(data);  // add a body to the request
    request.end(() => {
        console.log('Request Sent successfully');
    });
});

app.post("/sendotp", function (req, res) {
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

    const payloadStream = JSON.stringify({
        "id": process.env.FAYDA_ID,
        "version": "1.0",
        "requestTime": new Date().toISOString(),
        "env": process.env.ENV_TYPE,
        "domainUri": process.env.DOMAIN_URI,
        "transactionID": process.env.TRANSICTION_ID,
        "individualId": process.env.INDIVIDUAL_ID,
        "individualIdType": process.env.INDIVIDUAL_ID_TYPE,
        "otpChannel": ["PHONE"]
    });
    console.log('the certificate', pCert);


    const publicCert = pCert.replace(`-----BEGIN CERTIFICATE-----\n`, "").replace("\n-----END CERTIFICATE-----\n", "");

    const signature = jws.sign({
        header: { alg: "RS256", typ: "JWS", x5c: [publicCert] },
        privateKey: { key: pKey, passphrase: process.env.PASSPHRASE },
        payload: payloadStream,
    });


    var options = {
        host: process.env.HOST,
        path: process.env.OTP_REQUEST_PATH,
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            "Authorization": req.cookies,
            "Signature": signature
        },
        rejectUnauthorized: false,
    };


    var request = https.request(options, function (resp) {
        let tempChunk = ""
        resp.setEncoding('utf8');
        resp.on('data', function (chunk) {
            tempChunk += chunk;
        });
        resp.on('end', function () {
            if (resp.statusCode !== 200) {
                res.status(resp.statusCode).res.send(tempChunk);
            } else {
                // res.cookie("Authorization", resp.headers.authorization);
                res.send(tempChunk);
            }
        })
    });

    request.on('error', (error) => {
        console.error('show the error', error);
    });
    request.write(payloadStream);  // add a body to the request
    request.end(() => {
        console.log('Request Sent successfully');
    });


    // res.send(req.cookies);
});

app.post("/authotp", function (req, res) {

    const pKey = fs.readFileSync('./testorg2-key.pem', { encoding: "utf8" });
    const pCert = fs.readFileSync('./testorg2-cert.pem', { encoding: "utf8" });
    const publicCert = pCert.replace(`-----BEGIN CERTIFICATE-----\n`, "").replace("\n-----END CERTIFICATE-----\n", "");
    // Generate secret Key
    function generateSecretKey() {
        const secretKey = crypto.randomBytes(32); // 256 bits
        return secretKey;
    }

    function base64UrlEncode(buffer) {
        let base64Url = buffer.toString('base64')
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
        return base64Url;
    }

    const secretKey = generateSecretKey().toString('hex');
    const key = crypto.randomBytes(32); // 256-bit key
    const faydaCrt = fs.readFileSync('./fayda.crt', { encoding: "utf8" });
    const iv = crypto.randomBytes(128);

    const keyLength = crypto.publicEncrypt(faydaCrt, Buffer.from(''));
    console.log("Public key length", keyLength.length);


    // Encrypt symmetricKey or generate requestSessionKey using aes-256-gcm but not compatable with public certificate
    function encryptSymmetricKeyAES(secretKey, fPublicKey) {
        const cipher = crypto.createCipheriv('aes-256-gcm', fPublicKey, iv);
        const encryptedKey = Buffer.concat([cipher.update(secretKey, 'utf8'), cipher.final()]);
        return encryptedKey.toString('base64url');
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

    const requestSessionKey = encryptSymmetricKey(secretKey, faydaCrt);
    console.log(requestSessionKey);

    // Generate SHA256 hash of certificate
    const sha256 = crypto.createHash('sha256');
    sha256.update(faydaCrt);
    const thumbprint = base64UrlEncode(sha256.digest().toString('base64'));


    const requestBody = JSON.stringify({
        "id": process.env.FAYDA_ID,
        "version": "1.0",
        "requkeyGen.generateKeyestTime": new Date().toISOString(),
        "env": process.env.ENV_TYPE,
        "domainUri": process.env.DOMAIN_URI,
        "transactionID": process.env.TRANSICTION_ID,
        "consentObtained": true,
        "individualId": process.env.INDIVIDUAL_ID,
        "individualIdType": process.env.INDIVIDUAL_ID_TYPE,
        "requestedAuth": {
            "otp": true,
            "demo": false,
            "bio": false
        },
        "thumbprint": thumbprint,
        "requestSessionKey": requestSessionKey,
        "requestHMAC": "<SHA-256 of request block before encryption and then hash is encrypted using the requestSessionKey>",
        //Encrypted with session key and base-64-URL encoded
        "request": {
            "timestamp": new Date().toISOString(),
            "otp": "111111"
        }
    });

    const signature = jws.sign({
        header: { alg: "RS256", typ: "JWS", x5c: [publicCert] },
        privateKey: { key: pKey, passphrase: process.env.PASSPHRASE },
        payload: payloadStream,
    });


    res.send(requestBody);
})



app.listen(port, () => {
    console.log(`Test app listening on port ${port}`);
});