var crypto = require('crypto');

module.exports = Secure;

function Secure(options) {
  options = options || {};

  this.vendorPrefix = options.vendorPrefix || 'Bearer';
  this.publicKey = options.publicKey || '';
  this.privateKey = options.privateKey || '';
  this.joinBy = options.joinBy || ';';
  this.seperator = options.seperator || ':';
  this.encoding = options.encoding || 'utf8';
  this.timeWindow = options.timeWindow || 15 * 60 * 1000;
  this.includePublicKey = options.includePublicKey !== false;

  // Hmac options
  this.hmac = options.hmac || {};
  this.hmac.algorithm = this.hmac.algorithm || 'sha256';
  this.hmac.encoding = this.hmac.encoding || 'base64';
}

// Generate public and secret keys
Secure.generateKeys = function(seed) {
  var _seed = function() {
    return String(seed || '') || Math.random().toString();
  };

  var _simpleHash = function(algorithm) {
    algorithm = algorithm || 'sha1';
    return crypto
            .createHash(algorithm)
            .update(_seed())
            .digest('base64')
            .replace(/[\/\+\=]/g, 't');
  };

  return { publicKey: _simpleHash(), privateKey: _simpleHash('sha256') };
};

//   Secure: [this.vendorPrefix, this.publicKey, signature].join(this.seperator)
Secure.prototype.sign = function(httpVerb, requestPath, timestamp, params) {
  var paramsString = this.joinValues(params);
  var stringToSign = [
    httpVerb, requestPath, timestamp, paramsString
  ].join(this.joinBy);
  var signature = crypto.createHmac(this.hmac.algorithm, this.privateKey)
                        .update(new Buffer(stringToSign, this.encoding))
                        .digest(this.hmac.encoding);
  var stringsArray = [signature];
  if (this.includePublicKey) stringsArray.unshift(this.publicKey);
  stringsArray.unshift(this.vendorPrefix);
  return stringsArray.join(this.seperator);
};

// constant-time comparison algorithm to prevent timing attacks
Secure.prototype.compare = function(a, b) {
  if (!a || !b || a.length != b.length) return false;
  var res = 0;
  var aCharCodes = this.unpack(a);
  var bCharCodes = this.unpack(b);
  bCharCodes.forEach(function(charCode) {
    res |= charCode ^ aCharCodes.shift();
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
  var keys = Object.keys(obj).sort(function(a, b) {
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
  var self = this;
  if (Array.isArray(obj)) {
    // if obj is an array, then join it directly
    return obj.map(self.joinValues).join(self.joinBy);
  } else if (Object.prototype.toString.call(obj) === '[object Object]') {
    // if obj is a plain object
    obj = self.sortByAscendingKeys(obj);
    return Object.keys(obj).map(function(k) {
      return self.joinValues(obj[k]);
    }).join(self.joinBy);
  } else {
    // return String format
    return String(obj).valueOf();
  }
};

// parse timestamp as ISOString
Secure.prototype.toISOString = function(timestamp) {
  var date;
  var isValidTimestamp = false;
  try {
    date = new Date(timestamp);
    isValidTimestamp = true;
  } catch (e) { /* Do nothing */ }
  if (isValidTimestamp) {
    return date.toISOString();
  } else {
    return '';
  }
};

// check if a timestamp is valid
Secure.prototype.isValidTimestamp = function(timestamp) {
  var target;
  var now = +new Date();
  try {
    target = +new Date(timestamp);
  } catch(e) { /* Do nothing */ }
  if (target) {
    var interval = target - now;
    return interval >= -this.timeWindow && interval <= this.timeWindow;
  } else {
    return false;
  }
};
