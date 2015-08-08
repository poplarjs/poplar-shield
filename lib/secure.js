var crypto = require('crypto');

module.exports = Secure;

function Secure(options) {
  options = options || {};

  this.vendorPrefix = options.vendorPrefix || 'Bearer';
  this.publicKey = options.publicKey || '';
  this.privateKey = options.privateKey || '';
  this.joinBy = options.joinBy || ';';
  this.seperator = options.seperator || ':';

  // Hmac options
  this.hmac = options.hmac || {};
  this.hmac.algorithm = this.hmac.algorithm || 'sha256';
  this.hmac.encoding = this.hmac.encoding || 'base64';
}

//   Secure: [this.vendorPrefix, this.publicKey, signature].join(this.seperator)
Secure.prototype.sign = function(httpVerb, requestPath, timestamp, params) {
  var paramsString = this.joinValues(this.sortByAscendingKeys(params));
  var stringToSign = [
    httpVerb, requestPath, timestamp, paramsString
  ].join(this.joinBy);
  var signature = crypto.createHmac(this.hmac.algorithm, this.privateKey)
                        .update(stringToSign, 'utf8')
                        .digest(this.hmac.encoding);
  return [this.vendorPrefix, this.publicKey, signature].join(this.seperator);
};

// constant-time comparison algorithm to prevent timing attacks
Secure.prototype.compare = function(a, b) {
  if (!a || !b || a.length != b.length) return false;
  var res = 0;
  var aBytes = this.unpack(a);
  var bBytes = this.unpack(b);
  bBytes.forEach(function(byte) {
    res |= byte ^ aBytes.shift();
  });
  return res === 0;
};

// unpack string to its char code array
Secure.prototype.unpack = function(str) {
  return (String(str) || '').split('').map(function(letter) {
    return letter.charCodeAt(0);
  });
};

// sort object by key in ascending order
Secure.prototype.sortByAscendingKeys = function(obj) {
  var newObj = {};
  keys = Object.keys(obj).sort(function(a, b) {
    if (a > b) return 1;
    if (a == b) return 0;
    return -1;
  });
  keys.forEach(function(key) {
    newObj[key] = obj[key];
  });
  return newObj;
};

// join values
Secure.prototype.joinValues = function(obj) {
  return Object.keys(obj).map(function(key) {
    return String(obj[key]);
  }).join(this.joinBy);
};

// validate timestamp and return ISOString
Secure.prototype.validateTimestamp = function(timestamp) {
  var date;
  var isValid = false;
  try {
    date = new Date(timestamp);
    isValid = true;
  } catch (e) { /* Do nothing */ }
  if (isValid) {
    return date.toISOString();
  } else {
    return false;
  }
};