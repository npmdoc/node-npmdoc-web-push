# api documentation for  [web-push (v3.2.2)](https://github.com/web-push-libs/web-push#readme)  [![npm package](https://img.shields.io/npm/v/npmdoc-web-push.svg?style=flat-square)](https://www.npmjs.org/package/npmdoc-web-push) [![travis-ci.org build-status](https://api.travis-ci.org/npmdoc/node-npmdoc-web-push.svg)](https://travis-ci.org/npmdoc/node-npmdoc-web-push)
#### Web Push library for Node.js

[![NPM](https://nodei.co/npm/web-push.png?downloads=true)](https://www.npmjs.com/package/web-push)

[![apidoc](https://npmdoc.github.io/node-npmdoc-web-push/build/screenCapture.buildNpmdoc.browser._2Fhome_2Ftravis_2Fbuild_2Fnpmdoc_2Fnode-npmdoc-web-push_2Ftmp_2Fbuild_2Fapidoc.html.png)](https://npmdoc.github.io/node-npmdoc-web-push/build/apidoc.html)

![npmPackageListing](https://npmdoc.github.io/node-npmdoc-web-push/build/screenCapture.npmPackageListing.svg)

![npmPackageDependencyTree](https://npmdoc.github.io/node-npmdoc-web-push/build/screenCapture.npmPackageDependencyTree.svg)



# package.json

```json

{
    "author": {
        "name": "Marco Castelluccio"
    },
    "bin": {
        "web-push": "src/cli.js"
    },
    "bugs": {
        "url": "https://github.com/web-push-libs/web-push/issues"
    },
    "dependencies": {
        "asn1.js": "^4.8.1",
        "http_ece": "^0.5.2",
        "jws": "^3.1.3",
        "minimist": "^1.2.0",
        "urlsafe-base64": "^1.0.0"
    },
    "description": "Web Push library for Node.js",
    "devDependencies": {
        "chalk": "^1.1.3",
        "chromedriver": "2.24.1",
        "del": "^2.2.1",
        "eslint": "^3.5.0",
        "eslint-config-airbnb": "^11.1.0",
        "eslint-plugin-import": "^1.16.0",
        "geckodriver": "1.1.3",
        "istanbul": "^0.4.2",
        "mkdirp": "^0.5.1",
        "mocha": "^3.0.2",
        "portfinder": "^1.0.2",
        "selenium-assistant": "1.0.0",
        "selenium-webdriver": "3.0.0-beta-2",
        "semver": "^5.1.0",
        "which": "^1.2.11"
    },
    "directories": {},
    "dist": {
        "shasum": "d2f7c5590a3037cb50e4442b5117edd6475768a5",
        "tarball": "https://registry.npmjs.org/web-push/-/web-push-3.2.2.tgz"
    },
    "engines": {
        "node": ">= 4"
    },
    "gitHead": "720b34454ea61af7cca22f3a36e038d1304c31e1",
    "homepage": "https://github.com/web-push-libs/web-push#readme",
    "keywords": [
        "web push",
        "push",
        "notifications",
        "push notifications"
    ],
    "license": "MPL-2.0",
    "main": "src/index.js",
    "maintainers": [
        {
            "name": "marco-c",
            "email": "mar.castelluccio@studenti.unina.it"
        }
    ],
    "name": "web-push",
    "optionalDependencies": {},
    "readme": "ERROR: No README data found!",
    "repository": {
        "type": "git",
        "url": "git+https://github.com/web-push-libs/web-push.git"
    },
    "scripts": {
        "download-browser": "node --harmony ./test/helpers/download-test-browsers.js",
        "lint": "node ./node_modules/eslint/bin/eslint --ignore-path .gitignore '.'",
        "pretest": "npm run lint && npm run download-browser",
        "test": "node --harmony node_modules/.bin/istanbul cover node_modules/.bin/_mocha -- --ui tdd test/test*"
    },
    "version": "3.2.2"
}
```



# <a name="apidoc.tableOfContents"></a>[table of contents](#apidoc.tableOfContents)

#### [module web-push](#apidoc.module.web-push)
1.  [function <span class="apidocSignatureSpan">web-push.</span>encrypt (userPublicKey, userAuth, payload)](#apidoc.element.web-push.encrypt)
1.  [function <span class="apidocSignatureSpan">web-push.</span>generateRequestDetails (subscription, payload, options)](#apidoc.element.web-push.generateRequestDetails)
1.  [function <span class="apidocSignatureSpan">web-push.</span>generateVAPIDKeys ()](#apidoc.element.web-push.generateVAPIDKeys)
1.  [function <span class="apidocSignatureSpan">web-push.</span>getVapidHeaders (audience, subject, publicKey, privateKey, expiration)](#apidoc.element.web-push.getVapidHeaders)
1.  [function <span class="apidocSignatureSpan">web-push.</span>sendNotification (subscription, payload, options)](#apidoc.element.web-push.sendNotification)
1.  [function <span class="apidocSignatureSpan">web-push.</span>setGCMAPIKey (apiKey)](#apidoc.element.web-push.setGCMAPIKey)
1.  [function <span class="apidocSignatureSpan">web-push.</span>setVapidDetails (subject, publicKey, privateKey)](#apidoc.element.web-push.setVapidDetails)
1.  [function <span class="apidocSignatureSpan">web-push.</span>web_push_error (message, statusCode, headers, body, endpoint)](#apidoc.element.web-push.web_push_error)
1.  [function <span class="apidocSignatureSpan">web-push.</span>web_push_js ()](#apidoc.element.web-push.web_push_js)
1.  object <span class="apidocSignatureSpan">web-push.</span>encryption_helper
1.  object <span class="apidocSignatureSpan">web-push.</span>vapid_helper
1.  object <span class="apidocSignatureSpan">web-push.</span>web_push_js.prototype

#### [module web-push.encryption_helper](#apidoc.module.web-push.encryption_helper)
1.  [function <span class="apidocSignatureSpan">web-push.encryption_helper.</span>encrypt (userPublicKey, userAuth, payload)](#apidoc.element.web-push.encryption_helper.encrypt)

#### [module web-push.vapid_helper](#apidoc.module.web-push.vapid_helper)
1.  [function <span class="apidocSignatureSpan">web-push.vapid_helper.</span>generateVAPIDKeys ()](#apidoc.element.web-push.vapid_helper.generateVAPIDKeys)
1.  [function <span class="apidocSignatureSpan">web-push.vapid_helper.</span>getVapidHeaders (audience, subject, publicKey, privateKey, expiration)](#apidoc.element.web-push.vapid_helper.getVapidHeaders)
1.  [function <span class="apidocSignatureSpan">web-push.vapid_helper.</span>validatePrivateKey (privateKey)](#apidoc.element.web-push.vapid_helper.validatePrivateKey)
1.  [function <span class="apidocSignatureSpan">web-push.vapid_helper.</span>validatePublicKey (publicKey)](#apidoc.element.web-push.vapid_helper.validatePublicKey)
1.  [function <span class="apidocSignatureSpan">web-push.vapid_helper.</span>validateSubject (subject)](#apidoc.element.web-push.vapid_helper.validateSubject)

#### [module web-push.web_push_error](#apidoc.module.web-push.web_push_error)
1.  [function <span class="apidocSignatureSpan">web-push.</span>web_push_error (message, statusCode, headers, body, endpoint)](#apidoc.element.web-push.web_push_error.web_push_error)
1.  [function <span class="apidocSignatureSpan">web-push.web_push_error.</span>super_ ()](#apidoc.element.web-push.web_push_error.super_)

#### [module web-push.web_push_js](#apidoc.module.web-push.web_push_js)
1.  [function <span class="apidocSignatureSpan">web-push.</span>web_push_js ()](#apidoc.element.web-push.web_push_js.web_push_js)

#### [module web-push.web_push_js.prototype](#apidoc.module.web-push.web_push_js.prototype)
1.  [function <span class="apidocSignatureSpan">web-push.web_push_js.prototype.</span>generateRequestDetails (subscription, payload, options)](#apidoc.element.web-push.web_push_js.prototype.generateRequestDetails)
1.  [function <span class="apidocSignatureSpan">web-push.web_push_js.prototype.</span>sendNotification (subscription, payload, options)](#apidoc.element.web-push.web_push_js.prototype.sendNotification)
1.  [function <span class="apidocSignatureSpan">web-push.web_push_js.prototype.</span>setGCMAPIKey (apiKey)](#apidoc.element.web-push.web_push_js.prototype.setGCMAPIKey)
1.  [function <span class="apidocSignatureSpan">web-push.web_push_js.prototype.</span>setVapidDetails (subject, publicKey, privateKey)](#apidoc.element.web-push.web_push_js.prototype.setVapidDetails)



# <a name="apidoc.module.web-push"></a>[module web-push](#apidoc.module.web-push)

#### <a name="apidoc.element.web-push.encrypt"></a>[function <span class="apidocSignatureSpan">web-push.</span>encrypt (userPublicKey, userAuth, payload)](#apidoc.element.web-push.encrypt)
- description and source-code
```javascript
encrypt = function (userPublicKey, userAuth, payload) {
  if (!userPublicKey) {
    throw new Error('No user public key provided for encryption.');
  }

  if (typeof userPublicKey !== 'string') {
    throw new Error('The subscription p256dh value must be a string.');
  }

  if (urlBase64.decode(userPublicKey).length !== 65) {
    throw new Error('The subscription p256dh value should be 65 bytes long.');
  }

  if (!userAuth) {
    throw new Error('No user auth provided for encryption.');
  }

  if (typeof userAuth !== 'string') {
    throw new Error('The subscription auth key must be a string.');
  }

  if (urlBase64.decode(userAuth).length < 16) {
    throw new Error('The subscription auth key should be at least 16 ' +
      'bytes long');
  }

  if (typeof payload !== 'string' && !Buffer.isBuffer(payload)) {
    throw new Error('Payload must be either a string or a Node Buffer.');
  }

  if (typeof payload === 'string' || payload instanceof String) {
    payload = new Buffer(payload);
  }

  const localCurve = crypto.createECDH('prime256v1');
  const localPublicKey = localCurve.generateKeys();

  const salt = urlBase64.encode(crypto.randomBytes(16));

  ece.saveKey('webpushKey', localCurve, 'P-256');

  const cipherText = ece.encrypt(payload, {
    keyid: 'webpushKey',
    dh: userPublicKey,
    salt: salt,
    authSecret: userAuth,
    padSize: 2
  });

  return {
    localPublicKey: localPublicKey,
    salt: salt,
    cipherText: cipherText
  };
}
```
- example usage
```shell
...
const pushSubscription = {
  endpoint: 'https://....',
  keys: {
    p256dh: '.....',
    auth: '.....'
  }
};
webPush.encrypt(
  pushSubscription.keys.p256dh,
  pushSubscription.keys.auth,
  'My Payload'
)
.then(encryptionDetails => {

});
...
```

#### <a name="apidoc.element.web-push.generateRequestDetails"></a>[function <span class="apidocSignatureSpan">web-push.</span>generateRequestDetails (subscription, payload, options)](#apidoc.element.web-push.generateRequestDetails)
- description and source-code
```javascript
generateRequestDetails = function (subscription, payload, options) {
  if (!subscription || !subscription.endpoint) {
    throw new Error('You must pass in a subscription with at least ' +
      'an endpoint.');
  }

  if (typeof subscription.endpoint !== 'string' ||
    subscription.endpoint.length === 0) {
    throw new Error('The subscription endpoint must be a string with ' +
      'a valid URL.');
  }

  if (payload) {
    // Validate the subscription keys
    if (!subscription.keys || !subscription.keys.p256dh ||
      !subscription.keys.auth) {
      throw new Error('To send a message with a payload, the ' +
        'subscription must have \'auth\' and \'p256dh\' keys.');
    }
  }

  let currentGCMAPIKey = gcmAPIKey;
  let currentVapidDetails = vapidDetails;
  let timeToLive = DEFAULT_TTL;
  let extraHeaders = {};

  if (options) {
    const validOptionKeys = [
      'headers',
      'gcmAPIKey',
      'vapidDetails',
      'TTL'
    ];
    const optionKeys = Object.keys(options);
    for (let i = 0; i < optionKeys.length; i += 1) {
      const optionKey = optionKeys[i];
      if (validOptionKeys.indexOf(optionKey) === -1) {
        throw new Error('\'' + optionKey + '\' is an invalid option. ' +
          'The valid options are [\'' + validOptionKeys.join('\', \'') +
          '\'].');
      }
    }

    if (options.headers) {
      extraHeaders = options.headers;
      let duplicates = Object.keys(extraHeaders)
          .filter(function (header) {
            return typeof options[header] !== 'undefined';
          });

      if (duplicates.length > 0) {
        throw new Error('Duplicated headers defined [' +
          duplicates.join(',') + ']. Please either define the header in the' +
          'top level options OR in the \'headers\' key.');
      }
    }

    if (options.gcmAPIKey) {
      currentGCMAPIKey = options.gcmAPIKey;
    }

    if (options.vapidDetails) {
      currentVapidDetails = options.vapidDetails;
    }

    if (options.TTL) {
      timeToLive = options.TTL;
    }
  }

  if (typeof timeToLive === 'undefined') {
    timeToLive = DEFAULT_TTL;
  }

  const requestDetails = {
    method: 'POST',
    headers: {
      TTL: timeToLive
    }
  };
  Object.keys(extraHeaders).forEach(function (header) {
    requestDetails.headers[header] = extraHeaders[header];
  });
  let requestPayload = null;

  if (payload) {
    if (!subscription.keys ||
      typeof subscription !== 'object' ||
      !subscription.keys.p256dh ||
      !subscription.keys.auth) {
      throw new Error(new Error('Unable to send a message with ' +
        'payload to this subscription since it doesn\'t have the ' +
        'required encryption keys'));
    }

    const encrypted = encryptionHelper.encrypt(
      subscription.keys.p256dh, subscription.keys.auth, payload);

    requestDetails.headers['Content-Length'] = encrypted.cipherText.length;
    requestDetails.headers['Content-Type'] = 'application/octet-stream';
    requestDetails.headers['Content-Encoding'] = 'aesgcm';
    requestDetails.headers.Encryption = 'salt=' + encrypted.salt;
    requestDetails.headers['Crypto-Key'] = 'dh=' + urlBase64.encode(encrypted.localPublicKey);

    requestPayload = encrypted.cipherText;
  } else {
    requestDetails.headers['Content-Length'] = 0;
  }

  const isGCM = subscription.endpoint.indexOf(
    'https://android.googleapis.com/gcm/send') === 0;
  // VAPID isn't supported by GCM hence the if, else if.
  if (isGCM) {
    if (!currentGCMAPIKey) {
      console.warn('Attempt to send push notification to GCM endpoint, ' +
        'but no GCM key is defined. Please use setGCMApiKey() or add ' +
        '\'gcmAPIKey\' as an option.');
    } else {
      requestDetails.headers.Authorization = 'key=' + currentGCMAPIKey;
    }
  } else if (currentVapidDetails) {
    const parsedUrl = url.parse(subscription.endpoint);
    const audience = parsedUrl.protocol + '//' +
      parsedUrl.hostname;

    const vapidHeaders = vapidHelper.getVapidHeaders(
      audience,
      currentVapidDetails.subject,
      currentVapidDetails.publicKey,
      currentVapidDetails.privateKey ...
```
- example usage
```shell
...
  TTL: <Number>,
  headers: {
    '< header name >': '< header value >'
  }
}

try {
  const details = webpush.generateRequestDetails(
    pushSubscription,
    payload,
    options
  );
} catch (err) {
  console.error(err);
}
...
```

#### <a name="apidoc.element.web-push.generateVAPIDKeys"></a>[function <span class="apidocSignatureSpan">web-push.</span>generateVAPIDKeys ()](#apidoc.element.web-push.generateVAPIDKeys)
- description and source-code
```javascript
function generateVAPIDKeys() {
  const curve = crypto.createECDH('prime256v1');
  curve.generateKeys();

  return {
    publicKey: urlBase64.encode(curve.getPublicKey()),
    privateKey: urlBase64.encode(curve.getPrivateKey())
  };
}
```
- example usage
```shell
...
The common use case for this library is an application server using
a GCM API key and VAPID keys.

'''javascript
const webpush = require('web-push');

// VAPID keys should only be generated only once.
const vapidKeys = webpush.generateVAPIDKeys();

webpush.setGCMAPIKey('<Your GCM API Key Here>');
webpush.setVapidDetails(
  'mailto:example@yourdomain.org',
  vapidKeys.publicKey,
  vapidKeys.privateKey
);
...
```

#### <a name="apidoc.element.web-push.getVapidHeaders"></a>[function <span class="apidocSignatureSpan">web-push.</span>getVapidHeaders (audience, subject, publicKey, privateKey, expiration)](#apidoc.element.web-push.getVapidHeaders)
- description and source-code
```javascript
function getVapidHeaders(audience, subject, publicKey, privateKey, expiration) {
  if (!audience) {
    throw new Error('No audience could be generated for VAPID.');
  }

  if (typeof audience !== 'string' || audience.length === 0) {
    throw new Error('The audience value must be a string containing the ' +
      'origin of a push service. ' + audience);
  }

  const audienceParseResult = url.parse(audience);
  if (!audienceParseResult.hostname) {
    throw new Error('VAPID audience is not a url. ' + audience);
  }

  validateSubject(subject);
  validatePublicKey(publicKey);
  validatePrivateKey(privateKey);

  publicKey = urlBase64.decode(publicKey);
  privateKey = urlBase64.decode(privateKey);

  const DEFAULT_EXPIRATION = Math.floor(Date.now() / 1000) + 43200;

  if (expiration) {
    // TODO: Check if expiration is valid and use it in place of the hard coded
    // expiration of 24hours.
  }

  const header = {
    typ: 'JWT',
    alg: 'ES256'
  };

  const jwtPayload = {
    aud: audience,
    exp: DEFAULT_EXPIRATION,
    sub: subject
  };

  const jwt = jws.sign({
    header: header,
    payload: jwtPayload,
    privateKey: toPEM(privateKey)
  });

  return {
    Authorization: 'WebPush ' + jwt,
    'Crypto-Key': 'p256ecdsa=' + urlBase64.encode(publicKey)
  };
}
```
- example usage
```shell
...
## getVapidHeaders(audience, subject, publicKey, privateKey, expiration)

'''javascript
const parsedUrl = url.parse(subscription.endpoint);
const audience = parsedUrl.protocol + '//' +
  parsedUrl.hostname;

const vapidHeaders = vapidHelper.getVapidHeaders(
  audience,
  'mailto: example@web-push-node.org',
  vapidDetails.publicKey,
  vapidDetails.privateKey
);
'''
...
```

#### <a name="apidoc.element.web-push.sendNotification"></a>[function <span class="apidocSignatureSpan">web-push.</span>sendNotification (subscription, payload, options)](#apidoc.element.web-push.sendNotification)
- description and source-code
```javascript
sendNotification = function (subscription, payload, options) {
  let requestDetails;
  try {
    requestDetails = this.generateRequestDetails(
      subscription, payload, options);
  } catch (err) {
    return Promise.reject(err);
  }

  return new Promise(function(resolve, reject) {
    const httpsOptions = {};
    const urlParts = url.parse(requestDetails.endpoint);
    httpsOptions.hostname = urlParts.hostname;
    httpsOptions.port = urlParts.port;
    httpsOptions.path = urlParts.path;

    httpsOptions.headers = requestDetails.headers;
    httpsOptions.method = requestDetails.method;

    const pushRequest = https.request(httpsOptions, function(pushResponse) {
      let responseText = '';

      pushResponse.on('data', function(chunk) {
        responseText += chunk;
      });

      pushResponse.on('end', function() {
        if (pushResponse.statusCode !== 201) {
          reject(new WebPushError('Received unexpected response code',
            pushResponse.statusCode, pushResponse.headers, responseText, subscription.endpoint));
        } else {
          resolve({
            statusCode: pushResponse.statusCode,
            body: responseText,
            headers: pushResponse.headers
          });
        }
      });
    });

    pushRequest.on('error', function(e) {
      reject(e);
    });

    if (requestDetails.body) {
      pushRequest.write(requestDetails.body);
    }

    pushRequest.end();
  });
}
```
- example usage
```shell
...
  endpoint: '.....',
  keys: {
    auth: '.....',
    p256dh: '.....'
  }
};

webpush.sendNotification(pushSubscription, 'Your Push Payload Text');
'''

## Using VAPID Key for applicationServerKey

When using your VAPID key in your web app, you'll need to convert the
URL safe base64 string to a Uint8Array to pass into the subscribe call,
which you can do like so:
...
```

#### <a name="apidoc.element.web-push.setGCMAPIKey"></a>[function <span class="apidocSignatureSpan">web-push.</span>setGCMAPIKey (apiKey)](#apidoc.element.web-push.setGCMAPIKey)
- description and source-code
```javascript
setGCMAPIKey = function (apiKey) {
  if (apiKey === null) {
    gcmAPIKey = null;
    return;
  }

  if (typeof apiKey === 'undefined' || typeof apiKey !== 'string' ||
    apiKey.length === 0) {
    throw new Error('The GCM API Key should be a non-empty string or null.');
  }

  gcmAPIKey = apiKey;
}
```
- example usage
```shell
...

'''javascript
const webpush = require('web-push');

// VAPID keys should only be generated only once.
const vapidKeys = webpush.generateVAPIDKeys();

webpush.setGCMAPIKey('<Your GCM API Key Here>');
webpush.setVapidDetails(
  'mailto:example@yourdomain.org',
  vapidKeys.publicKey,
  vapidKeys.privateKey
);

// This is the same output of calling JSON.stringify on a PushSubscription
...
```

#### <a name="apidoc.element.web-push.setVapidDetails"></a>[function <span class="apidocSignatureSpan">web-push.</span>setVapidDetails (subject, publicKey, privateKey)](#apidoc.element.web-push.setVapidDetails)
- description and source-code
```javascript
setVapidDetails = function (subject, publicKey, privateKey) {
  if (arguments.length === 1 && arguments[0] === null) {
    vapidDetails = null;
    return;
  }

  vapidHelper.validateSubject(subject);
  vapidHelper.validatePublicKey(publicKey);
  vapidHelper.validatePrivateKey(privateKey);

  vapidDetails = {
    subject: subject,
    publicKey: publicKey,
    privateKey: privateKey
  };
}
```
- example usage
```shell
...
'''javascript
const webpush = require('web-push');

// VAPID keys should only be generated only once.
const vapidKeys = webpush.generateVAPIDKeys();

webpush.setGCMAPIKey('<Your GCM API Key Here>');
webpush.setVapidDetails(
  'mailto:example@yourdomain.org',
  vapidKeys.publicKey,
  vapidKeys.privateKey
);

// This is the same output of calling JSON.stringify on a PushSubscription
const pushSubscription = {
...
```

#### <a name="apidoc.element.web-push.web_push_error"></a>[function <span class="apidocSignatureSpan">web-push.</span>web_push_error (message, statusCode, headers, body, endpoint)](#apidoc.element.web-push.web_push_error)
- description and source-code
```javascript
function WebPushError(message, statusCode, headers, body, endpoint) {
  Error.captureStackTrace(this, this.constructor);

  this.name = this.constructor.name;
  this.message = message;
  this.statusCode = statusCode;
  this.headers = headers;
  this.body = body;
  this.endpoint = endpoint;
}
```
- example usage
```shell
n/a
```

#### <a name="apidoc.element.web-push.web_push_js"></a>[function <span class="apidocSignatureSpan">web-push.</span>web_push_js ()](#apidoc.element.web-push.web_push_js)
- description and source-code
```javascript
function WebPushLib() {

}
```
- example usage
```shell
n/a
```



# <a name="apidoc.module.web-push.encryption_helper"></a>[module web-push.encryption_helper](#apidoc.module.web-push.encryption_helper)

#### <a name="apidoc.element.web-push.encryption_helper.encrypt"></a>[function <span class="apidocSignatureSpan">web-push.encryption_helper.</span>encrypt (userPublicKey, userAuth, payload)](#apidoc.element.web-push.encryption_helper.encrypt)
- description and source-code
```javascript
encrypt = function (userPublicKey, userAuth, payload) {
  if (!userPublicKey) {
    throw new Error('No user public key provided for encryption.');
  }

  if (typeof userPublicKey !== 'string') {
    throw new Error('The subscription p256dh value must be a string.');
  }

  if (urlBase64.decode(userPublicKey).length !== 65) {
    throw new Error('The subscription p256dh value should be 65 bytes long.');
  }

  if (!userAuth) {
    throw new Error('No user auth provided for encryption.');
  }

  if (typeof userAuth !== 'string') {
    throw new Error('The subscription auth key must be a string.');
  }

  if (urlBase64.decode(userAuth).length < 16) {
    throw new Error('The subscription auth key should be at least 16 ' +
      'bytes long');
  }

  if (typeof payload !== 'string' && !Buffer.isBuffer(payload)) {
    throw new Error('Payload must be either a string or a Node Buffer.');
  }

  if (typeof payload === 'string' || payload instanceof String) {
    payload = new Buffer(payload);
  }

  const localCurve = crypto.createECDH('prime256v1');
  const localPublicKey = localCurve.generateKeys();

  const salt = urlBase64.encode(crypto.randomBytes(16));

  ece.saveKey('webpushKey', localCurve, 'P-256');

  const cipherText = ece.encrypt(payload, {
    keyid: 'webpushKey',
    dh: userPublicKey,
    salt: salt,
    authSecret: userAuth,
    padSize: 2
  });

  return {
    localPublicKey: localPublicKey,
    salt: salt,
    cipherText: cipherText
  };
}
```
- example usage
```shell
...
const pushSubscription = {
  endpoint: 'https://....',
  keys: {
    p256dh: '.....',
    auth: '.....'
  }
};
webPush.encrypt(
  pushSubscription.keys.p256dh,
  pushSubscription.keys.auth,
  'My Payload'
)
.then(encryptionDetails => {

});
...
```



# <a name="apidoc.module.web-push.vapid_helper"></a>[module web-push.vapid_helper](#apidoc.module.web-push.vapid_helper)

#### <a name="apidoc.element.web-push.vapid_helper.generateVAPIDKeys"></a>[function <span class="apidocSignatureSpan">web-push.vapid_helper.</span>generateVAPIDKeys ()](#apidoc.element.web-push.vapid_helper.generateVAPIDKeys)
- description and source-code
```javascript
function generateVAPIDKeys() {
  const curve = crypto.createECDH('prime256v1');
  curve.generateKeys();

  return {
    publicKey: urlBase64.encode(curve.getPublicKey()),
    privateKey: urlBase64.encode(curve.getPrivateKey())
  };
}
```
- example usage
```shell
...
The common use case for this library is an application server using
a GCM API key and VAPID keys.

'''javascript
const webpush = require('web-push');

// VAPID keys should only be generated only once.
const vapidKeys = webpush.generateVAPIDKeys();

webpush.setGCMAPIKey('<Your GCM API Key Here>');
webpush.setVapidDetails(
  'mailto:example@yourdomain.org',
  vapidKeys.publicKey,
  vapidKeys.privateKey
);
...
```

#### <a name="apidoc.element.web-push.vapid_helper.getVapidHeaders"></a>[function <span class="apidocSignatureSpan">web-push.vapid_helper.</span>getVapidHeaders (audience, subject, publicKey, privateKey, expiration)](#apidoc.element.web-push.vapid_helper.getVapidHeaders)
- description and source-code
```javascript
function getVapidHeaders(audience, subject, publicKey, privateKey, expiration) {
  if (!audience) {
    throw new Error('No audience could be generated for VAPID.');
  }

  if (typeof audience !== 'string' || audience.length === 0) {
    throw new Error('The audience value must be a string containing the ' +
      'origin of a push service. ' + audience);
  }

  const audienceParseResult = url.parse(audience);
  if (!audienceParseResult.hostname) {
    throw new Error('VAPID audience is not a url. ' + audience);
  }

  validateSubject(subject);
  validatePublicKey(publicKey);
  validatePrivateKey(privateKey);

  publicKey = urlBase64.decode(publicKey);
  privateKey = urlBase64.decode(privateKey);

  const DEFAULT_EXPIRATION = Math.floor(Date.now() / 1000) + 43200;

  if (expiration) {
    // TODO: Check if expiration is valid and use it in place of the hard coded
    // expiration of 24hours.
  }

  const header = {
    typ: 'JWT',
    alg: 'ES256'
  };

  const jwtPayload = {
    aud: audience,
    exp: DEFAULT_EXPIRATION,
    sub: subject
  };

  const jwt = jws.sign({
    header: header,
    payload: jwtPayload,
    privateKey: toPEM(privateKey)
  });

  return {
    Authorization: 'WebPush ' + jwt,
    'Crypto-Key': 'p256ecdsa=' + urlBase64.encode(publicKey)
  };
}
```
- example usage
```shell
...
## getVapidHeaders(audience, subject, publicKey, privateKey, expiration)

'''javascript
const parsedUrl = url.parse(subscription.endpoint);
const audience = parsedUrl.protocol + '//' +
  parsedUrl.hostname;

const vapidHeaders = vapidHelper.getVapidHeaders(
  audience,
  'mailto: example@web-push-node.org',
  vapidDetails.publicKey,
  vapidDetails.privateKey
);
'''
...
```

#### <a name="apidoc.element.web-push.vapid_helper.validatePrivateKey"></a>[function <span class="apidocSignatureSpan">web-push.vapid_helper.</span>validatePrivateKey (privateKey)](#apidoc.element.web-push.vapid_helper.validatePrivateKey)
- description and source-code
```javascript
function validatePrivateKey(privateKey) {
  if (!privateKey) {
    throw new Error('No key set in vapidDetails.privateKey');
  }

  if (typeof privateKey !== 'string') {
    throw new Error('Vapid private key must be a URL safe Base 64 ' +
      'encoded string.');
  }

  privateKey = urlBase64.decode(privateKey);

  if (privateKey.length !== 32) {
    throw new Error('Vapid private key should be 32 bytes long when decoded.');
  }
}
```
- example usage
```shell
...
  if (arguments.length === 1 && arguments[0] === null) {
    vapidDetails = null;
    return;
  }

  vapidHelper.validateSubject(subject);
  vapidHelper.validatePublicKey(publicKey);
  vapidHelper.validatePrivateKey(privateKey);

  vapidDetails = {
    subject: subject,
    publicKey: publicKey,
    privateKey: privateKey
  };
};
...
```

#### <a name="apidoc.element.web-push.vapid_helper.validatePublicKey"></a>[function <span class="apidocSignatureSpan">web-push.vapid_helper.</span>validatePublicKey (publicKey)](#apidoc.element.web-push.vapid_helper.validatePublicKey)
- description and source-code
```javascript
function validatePublicKey(publicKey) {
  if (!publicKey) {
    throw new Error('No key set vapidDetails.publicKey');
  }

  if (typeof publicKey !== 'string') {
    throw new Error('Vapid public key is must be a URL safe Base 64 ' +
      'encoded string.');
  }

  publicKey = urlBase64.decode(publicKey);

  if (publicKey.length !== 65) {
    throw new Error('Vapid public key should be 65 bytes long when decoded.');
  }
}
```
- example usage
```shell
...
  function(subject, publicKey, privateKey) {
if (arguments.length === 1 && arguments[0] === null) {
  vapidDetails = null;
  return;
}

vapidHelper.validateSubject(subject);
vapidHelper.validatePublicKey(publicKey);
vapidHelper.validatePrivateKey(privateKey);

vapidDetails = {
  subject: subject,
  publicKey: publicKey,
  privateKey: privateKey
};
...
```

#### <a name="apidoc.element.web-push.vapid_helper.validateSubject"></a>[function <span class="apidocSignatureSpan">web-push.vapid_helper.</span>validateSubject (subject)](#apidoc.element.web-push.vapid_helper.validateSubject)
- description and source-code
```javascript
function validateSubject(subject) {
  if (!subject) {
    throw new Error('No subject set in vapidDetails.subject.');
  }

  if (typeof subject !== 'string' || subject.length === 0) {
    throw new Error('The subject value must be a string containing a URL or ' +
      'mailto: address. ' + subject);
  }

  if (subject.indexOf('mailto:') !== 0) {
    const subjectParseResult = url.parse(subject);
    if (!subjectParseResult.hostname) {
      throw new Error('Vapid subject is not a url or mailto url. ' + subject);
    }
  }
}
```
- example usage
```shell
...
WebPushLib.prototype.setVapidDetails =
  function(subject, publicKey, privateKey) {
if (arguments.length === 1 && arguments[0] === null) {
  vapidDetails = null;
  return;
}

vapidHelper.validateSubject(subject);
vapidHelper.validatePublicKey(publicKey);
vapidHelper.validatePrivateKey(privateKey);

vapidDetails = {
  subject: subject,
  publicKey: publicKey,
  privateKey: privateKey
...
```



# <a name="apidoc.module.web-push.web_push_error"></a>[module web-push.web_push_error](#apidoc.module.web-push.web_push_error)

#### <a name="apidoc.element.web-push.web_push_error.web_push_error"></a>[function <span class="apidocSignatureSpan">web-push.</span>web_push_error (message, statusCode, headers, body, endpoint)](#apidoc.element.web-push.web_push_error.web_push_error)
- description and source-code
```javascript
function WebPushError(message, statusCode, headers, body, endpoint) {
  Error.captureStackTrace(this, this.constructor);

  this.name = this.constructor.name;
  this.message = message;
  this.statusCode = statusCode;
  this.headers = headers;
  this.body = body;
  this.endpoint = endpoint;
}
```
- example usage
```shell
n/a
```

#### <a name="apidoc.element.web-push.web_push_error.super_"></a>[function <span class="apidocSignatureSpan">web-push.web_push_error.</span>super_ ()](#apidoc.element.web-push.web_push_error.super_)
- description and source-code
```javascript
function Error() { [native code] }
```
- example usage
```shell
n/a
```



# <a name="apidoc.module.web-push.web_push_js"></a>[module web-push.web_push_js](#apidoc.module.web-push.web_push_js)

#### <a name="apidoc.element.web-push.web_push_js.web_push_js"></a>[function <span class="apidocSignatureSpan">web-push.</span>web_push_js ()](#apidoc.element.web-push.web_push_js.web_push_js)
- description and source-code
```javascript
function WebPushLib() {

}
```
- example usage
```shell
n/a
```



# <a name="apidoc.module.web-push.web_push_js.prototype"></a>[module web-push.web_push_js.prototype](#apidoc.module.web-push.web_push_js.prototype)

#### <a name="apidoc.element.web-push.web_push_js.prototype.generateRequestDetails"></a>[function <span class="apidocSignatureSpan">web-push.web_push_js.prototype.</span>generateRequestDetails (subscription, payload, options)](#apidoc.element.web-push.web_push_js.prototype.generateRequestDetails)
- description and source-code
```javascript
generateRequestDetails = function (subscription, payload, options) {
  if (!subscription || !subscription.endpoint) {
    throw new Error('You must pass in a subscription with at least ' +
      'an endpoint.');
  }

  if (typeof subscription.endpoint !== 'string' ||
    subscription.endpoint.length === 0) {
    throw new Error('The subscription endpoint must be a string with ' +
      'a valid URL.');
  }

  if (payload) {
    // Validate the subscription keys
    if (!subscription.keys || !subscription.keys.p256dh ||
      !subscription.keys.auth) {
      throw new Error('To send a message with a payload, the ' +
        'subscription must have \'auth\' and \'p256dh\' keys.');
    }
  }

  let currentGCMAPIKey = gcmAPIKey;
  let currentVapidDetails = vapidDetails;
  let timeToLive = DEFAULT_TTL;
  let extraHeaders = {};

  if (options) {
    const validOptionKeys = [
      'headers',
      'gcmAPIKey',
      'vapidDetails',
      'TTL'
    ];
    const optionKeys = Object.keys(options);
    for (let i = 0; i < optionKeys.length; i += 1) {
      const optionKey = optionKeys[i];
      if (validOptionKeys.indexOf(optionKey) === -1) {
        throw new Error('\'' + optionKey + '\' is an invalid option. ' +
          'The valid options are [\'' + validOptionKeys.join('\', \'') +
          '\'].');
      }
    }

    if (options.headers) {
      extraHeaders = options.headers;
      let duplicates = Object.keys(extraHeaders)
          .filter(function (header) {
            return typeof options[header] !== 'undefined';
          });

      if (duplicates.length > 0) {
        throw new Error('Duplicated headers defined [' +
          duplicates.join(',') + ']. Please either define the header in the' +
          'top level options OR in the \'headers\' key.');
      }
    }

    if (options.gcmAPIKey) {
      currentGCMAPIKey = options.gcmAPIKey;
    }

    if (options.vapidDetails) {
      currentVapidDetails = options.vapidDetails;
    }

    if (options.TTL) {
      timeToLive = options.TTL;
    }
  }

  if (typeof timeToLive === 'undefined') {
    timeToLive = DEFAULT_TTL;
  }

  const requestDetails = {
    method: 'POST',
    headers: {
      TTL: timeToLive
    }
  };
  Object.keys(extraHeaders).forEach(function (header) {
    requestDetails.headers[header] = extraHeaders[header];
  });
  let requestPayload = null;

  if (payload) {
    if (!subscription.keys ||
      typeof subscription !== 'object' ||
      !subscription.keys.p256dh ||
      !subscription.keys.auth) {
      throw new Error(new Error('Unable to send a message with ' +
        'payload to this subscription since it doesn\'t have the ' +
        'required encryption keys'));
    }

    const encrypted = encryptionHelper.encrypt(
      subscription.keys.p256dh, subscription.keys.auth, payload);

    requestDetails.headers['Content-Length'] = encrypted.cipherText.length;
    requestDetails.headers['Content-Type'] = 'application/octet-stream';
    requestDetails.headers['Content-Encoding'] = 'aesgcm';
    requestDetails.headers.Encryption = 'salt=' + encrypted.salt;
    requestDetails.headers['Crypto-Key'] = 'dh=' + urlBase64.encode(encrypted.localPublicKey);

    requestPayload = encrypted.cipherText;
  } else {
    requestDetails.headers['Content-Length'] = 0;
  }

  const isGCM = subscription.endpoint.indexOf(
    'https://android.googleapis.com/gcm/send') === 0;
  // VAPID isn't supported by GCM hence the if, else if.
  if (isGCM) {
    if (!currentGCMAPIKey) {
      console.warn('Attempt to send push notification to GCM endpoint, ' +
        'but no GCM key is defined. Please use setGCMApiKey() or add ' +
        '\'gcmAPIKey\' as an option.');
    } else {
      requestDetails.headers.Authorization = 'key=' + currentGCMAPIKey;
    }
  } else if (currentVapidDetails) {
    const parsedUrl = url.parse(subscription.endpoint);
    const audience = parsedUrl.protocol + '//' +
      parsedUrl.hostname;

    const vapidHeaders = vapidHelper.getVapidHeaders(
      audience,
      currentVapidDetails.subject,
      currentVapidDetails.publicKey,
      currentVapidDetails.privateKey ...
```
- example usage
```shell
...
  TTL: <Number>,
  headers: {
    '< header name >': '< header value >'
  }
}

try {
  const details = webpush.generateRequestDetails(
    pushSubscription,
    payload,
    options
  );
} catch (err) {
  console.error(err);
}
...
```

#### <a name="apidoc.element.web-push.web_push_js.prototype.sendNotification"></a>[function <span class="apidocSignatureSpan">web-push.web_push_js.prototype.</span>sendNotification (subscription, payload, options)](#apidoc.element.web-push.web_push_js.prototype.sendNotification)
- description and source-code
```javascript
sendNotification = function (subscription, payload, options) {
  let requestDetails;
  try {
    requestDetails = this.generateRequestDetails(
      subscription, payload, options);
  } catch (err) {
    return Promise.reject(err);
  }

  return new Promise(function(resolve, reject) {
    const httpsOptions = {};
    const urlParts = url.parse(requestDetails.endpoint);
    httpsOptions.hostname = urlParts.hostname;
    httpsOptions.port = urlParts.port;
    httpsOptions.path = urlParts.path;

    httpsOptions.headers = requestDetails.headers;
    httpsOptions.method = requestDetails.method;

    const pushRequest = https.request(httpsOptions, function(pushResponse) {
      let responseText = '';

      pushResponse.on('data', function(chunk) {
        responseText += chunk;
      });

      pushResponse.on('end', function() {
        if (pushResponse.statusCode !== 201) {
          reject(new WebPushError('Received unexpected response code',
            pushResponse.statusCode, pushResponse.headers, responseText, subscription.endpoint));
        } else {
          resolve({
            statusCode: pushResponse.statusCode,
            body: responseText,
            headers: pushResponse.headers
          });
        }
      });
    });

    pushRequest.on('error', function(e) {
      reject(e);
    });

    if (requestDetails.body) {
      pushRequest.write(requestDetails.body);
    }

    pushRequest.end();
  });
}
```
- example usage
```shell
...
  endpoint: '.....',
  keys: {
    auth: '.....',
    p256dh: '.....'
  }
};

webpush.sendNotification(pushSubscription, 'Your Push Payload Text');
'''

## Using VAPID Key for applicationServerKey

When using your VAPID key in your web app, you'll need to convert the
URL safe base64 string to a Uint8Array to pass into the subscribe call,
which you can do like so:
...
```

#### <a name="apidoc.element.web-push.web_push_js.prototype.setGCMAPIKey"></a>[function <span class="apidocSignatureSpan">web-push.web_push_js.prototype.</span>setGCMAPIKey (apiKey)](#apidoc.element.web-push.web_push_js.prototype.setGCMAPIKey)
- description and source-code
```javascript
setGCMAPIKey = function (apiKey) {
  if (apiKey === null) {
    gcmAPIKey = null;
    return;
  }

  if (typeof apiKey === 'undefined' || typeof apiKey !== 'string' ||
    apiKey.length === 0) {
    throw new Error('The GCM API Key should be a non-empty string or null.');
  }

  gcmAPIKey = apiKey;
}
```
- example usage
```shell
...

'''javascript
const webpush = require('web-push');

// VAPID keys should only be generated only once.
const vapidKeys = webpush.generateVAPIDKeys();

webpush.setGCMAPIKey('<Your GCM API Key Here>');
webpush.setVapidDetails(
  'mailto:example@yourdomain.org',
  vapidKeys.publicKey,
  vapidKeys.privateKey
);

// This is the same output of calling JSON.stringify on a PushSubscription
...
```

#### <a name="apidoc.element.web-push.web_push_js.prototype.setVapidDetails"></a>[function <span class="apidocSignatureSpan">web-push.web_push_js.prototype.</span>setVapidDetails (subject, publicKey, privateKey)](#apidoc.element.web-push.web_push_js.prototype.setVapidDetails)
- description and source-code
```javascript
setVapidDetails = function (subject, publicKey, privateKey) {
  if (arguments.length === 1 && arguments[0] === null) {
    vapidDetails = null;
    return;
  }

  vapidHelper.validateSubject(subject);
  vapidHelper.validatePublicKey(publicKey);
  vapidHelper.validatePrivateKey(privateKey);

  vapidDetails = {
    subject: subject,
    publicKey: publicKey,
    privateKey: privateKey
  };
}
```
- example usage
```shell
...
'''javascript
const webpush = require('web-push');

// VAPID keys should only be generated only once.
const vapidKeys = webpush.generateVAPIDKeys();

webpush.setGCMAPIKey('<Your GCM API Key Here>');
webpush.setVapidDetails(
  'mailto:example@yourdomain.org',
  vapidKeys.publicKey,
  vapidKeys.privateKey
);

// This is the same output of calling JSON.stringify on a PushSubscription
const pushSubscription = {
...
```



# misc
- this document was created with [utility2](https://github.com/kaizhu256/node-utility2)
