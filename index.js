const fs = require('fs');
const forge = require('node-forge');
const jws = require('jws');
const https = require('https');
const crypto = require('crypto');
const express = require("express");
require('dotenv').config();
const cookieParser = require('cookie-parser');

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

    const payloadStream = JSON.stringify({
        "id": process.env.FAYDA_ID,
        "version": "1.0",
        "requestTime": new Date().toISOString(),
        "env": process.env.ENV_TYPE,
        "domainUri": process.env.DOMAIN_URI,
        "transactionID": process.env.TRANSICTION_ID,
        // "individualId": process.env.INDIVIDUAL_ID,
        "individualId": individual_id,
        "individualIdType": process.env.INDIVIDUAL_ID_TYPE,
        "otpChannel": ["PHONE"]
    });

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

app.post("/genSecret", function (req, res) {

    const { otpCode } = req.body;
    const pKey = fs.readFileSync('./testorg2-key.pem', { encoding: "utf8" });
    const pCert = fs.readFileSync('./testorg2-cert.pem', { encoding: "utf8" });
    const publicCert = pCert.replace(`-----BEGIN CERTIFICATE-----\n`, "").replace("\n-----END CERTIFICATE-----\n", "");

    const requestBody = JSON.stringify({
        "timestamp": new Date().toISOString(),
        "otp": otpCode
    });

    function base64UrlEncode(buffer) {
        let base64Url = buffer.toString('base64')
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
        return base64Url;
    }
    function generateSecretKey(keyLen) {
        const key = crypto.randomBytes(keyLen);
        // return key.toString('hex');
        return key;
    }

    function getCertificate(path) {
        const certData = fs.readFileSync(path);
        const cert = new crypto.X509Certificate(certData);
        const pubCert = cert.publicKey.export({ type: 'spki', format: 'pem' });
        return { publicKey: pubCert, certificate: cert };
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


    function encryptAESGCMNOPadding(data, secretKey) {
        const algorithm = 'aes-256-gcm';
        const iv = crypto.randomBytes(16); // Generate a random IV

        const cipher = crypto.createCipheriv(algorithm, secretKey, iv);
        const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
        const tag = cipher.getAuthTag();

        const output = Buffer.concat([encrypted, iv, tag]);
        return output.toString('base64url');
    }

    function generateHash(data) {
        const hash = crypto.createHash('sha256');
        hash.update(data);
        return hash.digest();
    }


    function symmetricEncrypt(key, data, aad) {
        try {
            const randomIV = crypto.randomBytes(16);
            const cipher = crypto.createCipheriv('aes-256-gcm', key, randomIV);
            cipher.setAAD(aad);
            const encryptedData = Buffer.concat([cipher.update(data), cipher.final()]);
            const authTag = cipher.getAuthTag();
            const output = Buffer.concat([encryptedData, randomIV, authTag]);
            console.log('the output',);
            return output.toString('base64url');
        } catch (error) {
            console.error(error);
            return null;
        }
    }

    function generateThumbprint(data) {
        // Get raw DER certificate data
        const certDER = data.raw;
        // Generate SHA-256 thumbprint 
        const thumbprint = crypto.createHash('sha256').update(certDER).digest('hex');
        return thumbprint;
    }

    const SecretKey = generateSecretKey(32);

    const pubKey = getCertificate("./fayda.crt").publicKey;
    const pubCertificate = getCertificate("./fayda.crt").certificate
    const requestSessionKey = encryptSymmetricKey(SecretKey, pubKey);
    const encryptedRequestBody = encryptAESGCMNOPadding(Buffer.from(requestBody), SecretKey);
    const hashOfRequestBody = generateHash(requestBody).toString('base64url');
    const requestHMAC = symmetricEncrypt(SecretKey, hashOfRequestBody, "");
    const thumbprint = generateThumbprint(pubCertificate);

    console.log('thumbprint', thumbprint);
    console.log("requestSessionKey", requestSessionKey);
    console.log("requestHMAC", requestHMAC);
    console.log("encryt body", encryptedRequestBody);
    console.log("hash of req", hashOfRequestBody);


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
        "requestHMAC": requestHMAC,
        //Encrypted with session key and base-64-URL encoded
        "request": encryptedRequestBody
    });


    // Send Request to end point

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

});



app.listen(port, () => {
    console.log(`Test app listening on port ${port}`);
});