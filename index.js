const fs = require('fs');
const forge = require('node-forge');
const jws = require('jws');
const https = require('https');
const crypto = require('crypto');
const express = require("express");
require('dotenv').config();
const cookieParser = require('cookie-parser');
const { parse } = require('path');

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
        host: process.env.HOST,
        path: process.env.AUTH_PATH,
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
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
                res.cookie("Authorization", resp.headers.authorization);
                res.send(tempChunk);
            }
        })
    });

    request.on('error', (error) => {
        res.send(error);
        console.error('show the error', error);
    });
    request.write(data);  // add a body to the request
    request.end(() => {
        console.log('Request Sent successfully');
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
        res.send(error)
        // console.error('show the error', error);
    });
    request.write(payloadStream);  // add a body to the request
    request.end(() => {
        // console.log('Request Sent successfully');
    });


    // res.send(req.cookies);
});

app.post("/authotp", function (req, res) {
    const { otpCode } = req.body;

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

    const secretKey = generateSecretKey();
    // const secretKey = generateSecretKey().toString('hex');
    const key = crypto.randomBytes(32); // 256-bit key
    const faydaCrt = fs.readFileSync('./fayda.crt', { encoding: "utf8" });
    // const faydaPub = fs.readFileSync('./fayda.pub', { encoding: 'utf8' });
    const iv = crypto.randomBytes(16);
    // console.log('normal', key.length);
    // console.log('crt', faydaCrt.length);
    // console.log('crt', faydaPub.length);



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
    // console.log(requestSessionKey);

    // Generate HASH
    function generateSHA256Hash(data, type) {
        const hash = crypto.createHash('sha256');
        hash.update(data);
        return hash.digest(`${type}`);
    }

    // Generate Thumbprint from SHA256 hash of certificate
    const thumbprint = base64UrlEncode(generateSHA256Hash(faydaCrt, 'base64'));
    // console.log('thumbpring', thumbprint)


    // Generate HMAC 
    const requestBody = {
        "timestamp": new Date().toISOString(),
        "otp": otpCode
    };

    function generateMHAC(body, secKey) {
        const hmac = generateSHA256Hash(JSON.stringify(body), 'hex');
        const hmacLength = Buffer.byteLength(hmac, 'hex')

        const iv = crypto.randomBytes(hmacLength);
        const cipher = crypto.createCipheriv('aes-256-gcm', secKey, iv);

        const encrypted = Buffer.concat([cipher.update(hmac), cipher.final()]);
        return base64UrlEncode(encrypted.toString('base64'));
    }

    const Hmac = generateMHAC(requestBody, secretKey);
    // console.log('the hmac', Hmac);


    const payload = JSON.stringify({
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
        "requestHMAC": Hmac,
        //Encrypted with session key and base-64-URL encoded
        "request": {
            "timestamp": new Date().toISOString(),
            "otp": "111111"
        }
    });

    const signature = jws.sign({
        header: { alg: "RS256", typ: "JWS", x5c: [publicCert] },
        privateKey: { key: pKey, passphrase: process.env.PASSPHRASE },
        payload: payload,
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
        res.send(error)
        console.error('show the error', error);
    });
    request.write(payload);  // add a body to the request
    request.end(() => {
        console.log('Request Sent successfully');
    });


    // res.send({ Signature: signature, payload: payload });
})

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
        host: process.env.HOST,
        path: process.env.AUTH_REQUEST_PATH,
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
        res.send(error)
        console.error('show the error', error);
    });
    request.write(payload);  // add a body to the request
    request.end(() => {
        console.log('Request Sent successfully');
    });

});

app.post("/thumbprint", function (req, res) {
    function getCertificate(path) {
        const certData = fs.readFileSync(path);
        const cert = new crypto.X509Certificate(certData);
        const pubCert = cert.publicKey.export({ type: 'spki', format: 'pem' });
        return { publicKey: pubCert, certificate: cert };
    }
    function generateThumbprint(data) {
        // Get raw DER certificate data
        const certDER = data.raw;
        // Generate SHA-256 thumbprint 
        const thumbprint = crypto.createHash('sha256').update(certDER).digest('base64url');
        return thumbprint;
    }
    const pubCertificate = getCertificate("./fayda.crt").certificate
    const thumbprint = generateThumbprint(pubCertificate);

    res.send(thumbprint);
});



app.post("/hmac", function (req, res) {

    function generateSecretKey(keyLen) {
        const key = crypto.randomBytes(keyLen);
        // return key.toString('hex');
        return key;
    }
    function generateHash(data) {
        const hash = crypto.createHash('sha256');
        hash.update(data);
        return hash.digest();
    }

    function symmetricEncrypt(key, data, aad) {
        try {
            // const ogRandIv = "2jt8jsHkCKltos-exBLY3g";
            // const randomIV = Buffer.from(ogRandIv, 'base64url');
            const randomIV = crypto.randomBytes(16);
            const cipher = crypto.createCipheriv('aes-256-gcm', key, randomIV, { authTagLength: 16 });
            cipher.setAAD(aad);
            const encryptedData = Buffer.concat([cipher.update(data), cipher.final()]);
            const authTag = cipher.getAuthTag();
            const output = Buffer.concat([encryptedData, authTag, randomIV]);
            console.log('encrypted:', encryptedData.toString('base64url'));
            return output.toString('base64url');
        } catch (error) {
            console.error(error);
            return null;
        }
    };


    const requestBody = JSON.stringify({ "timestamp": "2023-08-07T08:43:27.504Z", "otp": "111111" })
    const hashOfRequestBody = generateHash(requestBody).toString('hex');
    console.log('hash of req body', hashOfRequestBody);
    const ogSecret = "G1iAX-SJr6475Zot7rPzXNsjyPOqszw6izO8_XWZgOE";
    const SecretKey = Buffer.from(ogSecret, 'base64url');
    const requestHMAC = symmetricEncrypt(SecretKey, hashOfRequestBody.toUpperCase(), "");
    res.send(requestHMAC);
});


app.post("/request", function (req, res) {

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

    function base64UrlDecode(base64Url) {
        // Convert Base64-URL to Base64 by replacing '-' with '+' and '_' with '/'
        const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');

        // Add padding characters if necessary
        const paddingLength = 4 - (base64.length % 4);
        const paddedBase64 = base64 + '==='.slice(0, paddingLength);

        // Decode the Base64 string to binary
        const decodedData = Buffer.from(paddedBase64, 'base64');

        return decodedData;
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

    function decryptSymmetricKey(encryptedSymKeyBase64Url, privateKey) {
        const encryptedSymKey = base64UrlDecode(encryptedSymKeyBase64Url);

        const decryptedSymKey = crypto.privateDecrypt({
            key: privateKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: 'sha256',
            mgf1: {
                hash: 'sha256'
            }
        }, encryptedSymKey);

        return decryptedSymKey;
    }

    function urlSafePublicKey(publicKey) {
        const publicKeyBuffer = crypto.createPublicKey(publicKey).export({ format: 'der', type: 'spki' });
        const publicKeyUrlSafeBase64 = publicKeyBuffer.toString('base64')
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/, '');

        return publicKeyUrlSafeBase64;
    }

    function getCertificate(path) {
        const certData = fs.readFileSync(path);
        const cert = new crypto.X509Certificate(certData);
        const pubCert = cert.publicKey.export({ type: 'spki', format: 'pem' });
        return { publicKey: pubCert, certificate: cert };
    }

    const pKey = fs.readFileSync('./testorg2-key.pem', { encoding: "utf8" });
    const publicKey = getCertificate('./fayda.crt').publicKey;
    console.log('Show public key:', publicKey);
    const secretKey = generateSecretKey();
    const requestSessionKey = encryptSymmetricKey(secretKey, publicKey);
    // const decryptSessionKey = decryptSymmetricKey(requestSessionKey, pKey);
    console.log("The secret Key:", secretKey);
    // console.log("The decrypted Secret Key:", decryptSessionKey);

    res.send(requestSessionKey);
});


app.post("/testEncryption", function (req, res) {

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

    function getCertificate(path) {
        const certData = fs.readFileSync(path);
        const cert = new crypto.X509Certificate(certData);
        const pubCert = cert.publicKey.export({ type: 'spki', format: 'pem' });
        return { publicKey: pubCert, certificate: cert };
    }

});




app.listen(port, () => {
    console.log(`Test app listening on port ${port}`);
});
