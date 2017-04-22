# npmdoc-web-push

#### api documentation for  [web-push (v3.2.2)](https://github.com/web-push-libs/web-push#readme)  [![npm package](https://img.shields.io/npm/v/npmdoc-web-push.svg?style=flat-square)](https://www.npmjs.org/package/npmdoc-web-push) [![travis-ci.org build-status](https://api.travis-ci.org/npmdoc/node-npmdoc-web-push.svg)](https://travis-ci.org/npmdoc/node-npmdoc-web-push)

#### Web Push library for Node.js

[![NPM](https://nodei.co/npm/web-push.png?downloads=true&downloadRank=true&stars=true)](https://www.npmjs.com/package/web-push)

- [https://npmdoc.github.io/node-npmdoc-web-push/build/apidoc.html](https://npmdoc.github.io/node-npmdoc-web-push/build/apidoc.html)

[![apidoc](https://npmdoc.github.io/node-npmdoc-web-push/build/screenCapture.buildCi.browser.%252Ftmp%252Fbuild%252Fapidoc.html.png)](https://npmdoc.github.io/node-npmdoc-web-push/build/apidoc.html)

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
            "name": "marco-c"
        }
    ],
    "name": "web-push",
    "optionalDependencies": {},
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



# misc
- this document was created with [utility2](https://github.com/kaizhu256/node-utility2)
