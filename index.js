"use strict";
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __esm = (fn, res) => function __init() {
  return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
};
var __commonJS = (cb, mod) => function __require() {
  return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// node_modules/@actions/core/lib/utils.js
var require_utils = __commonJS({
  "node_modules/@actions/core/lib/utils.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.toCommandProperties = exports.toCommandValue = void 0;
    function toCommandValue(input) {
      if (input === null || input === void 0) {
        return "";
      } else if (typeof input === "string" || input instanceof String) {
        return input;
      }
      return JSON.stringify(input);
    }
    exports.toCommandValue = toCommandValue;
    function toCommandProperties(annotationProperties) {
      if (!Object.keys(annotationProperties).length) {
        return {};
      }
      return {
        title: annotationProperties.title,
        file: annotationProperties.file,
        line: annotationProperties.startLine,
        endLine: annotationProperties.endLine,
        col: annotationProperties.startColumn,
        endColumn: annotationProperties.endColumn
      };
    }
    exports.toCommandProperties = toCommandProperties;
  }
});

// node_modules/@actions/core/lib/command.js
var require_command = __commonJS({
  "node_modules/@actions/core/lib/command.js"(exports) {
    "use strict";
    var __createBinding = exports && exports.__createBinding || (Object.create ? function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      Object.defineProperty(o, k2, { enumerable: true, get: function() {
        return m[k];
      } });
    } : function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      o[k2] = m[k];
    });
    var __setModuleDefault = exports && exports.__setModuleDefault || (Object.create ? function(o, v) {
      Object.defineProperty(o, "default", { enumerable: true, value: v });
    } : function(o, v) {
      o["default"] = v;
    });
    var __importStar = exports && exports.__importStar || function(mod) {
      if (mod && mod.__esModule)
        return mod;
      var result = {};
      if (mod != null) {
        for (var k in mod)
          if (k !== "default" && Object.hasOwnProperty.call(mod, k))
            __createBinding(result, mod, k);
      }
      __setModuleDefault(result, mod);
      return result;
    };
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.issue = exports.issueCommand = void 0;
    var os = __importStar(require("os"));
    var utils_1 = require_utils();
    function issueCommand(command, properties, message) {
      const cmd = new Command(command, properties, message);
      process.stdout.write(cmd.toString() + os.EOL);
    }
    exports.issueCommand = issueCommand;
    function issue(name, message = "") {
      issueCommand(name, {}, message);
    }
    exports.issue = issue;
    var CMD_STRING = "::";
    var Command = class {
      constructor(command, properties, message) {
        if (!command) {
          command = "missing.command";
        }
        this.command = command;
        this.properties = properties;
        this.message = message;
      }
      toString() {
        let cmdStr = CMD_STRING + this.command;
        if (this.properties && Object.keys(this.properties).length > 0) {
          cmdStr += " ";
          let first = true;
          for (const key in this.properties) {
            if (this.properties.hasOwnProperty(key)) {
              const val = this.properties[key];
              if (val) {
                if (first) {
                  first = false;
                } else {
                  cmdStr += ",";
                }
                cmdStr += `${key}=${escapeProperty(val)}`;
              }
            }
          }
        }
        cmdStr += `${CMD_STRING}${escapeData(this.message)}`;
        return cmdStr;
      }
    };
    function escapeData(s) {
      return utils_1.toCommandValue(s).replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
    }
    function escapeProperty(s) {
      return utils_1.toCommandValue(s).replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A").replace(/:/g, "%3A").replace(/,/g, "%2C");
    }
  }
});

// node_modules/uuid/dist/esm-node/rng.js
function rng() {
  if (poolPtr > rnds8Pool.length - 16) {
    import_crypto.default.randomFillSync(rnds8Pool);
    poolPtr = 0;
  }
  return rnds8Pool.slice(poolPtr, poolPtr += 16);
}
var import_crypto, rnds8Pool, poolPtr;
var init_rng = __esm({
  "node_modules/uuid/dist/esm-node/rng.js"() {
    import_crypto = __toESM(require("crypto"));
    rnds8Pool = new Uint8Array(256);
    poolPtr = rnds8Pool.length;
  }
});

// node_modules/uuid/dist/esm-node/regex.js
var regex_default;
var init_regex = __esm({
  "node_modules/uuid/dist/esm-node/regex.js"() {
    regex_default = /^(?:[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}|00000000-0000-0000-0000-000000000000)$/i;
  }
});

// node_modules/uuid/dist/esm-node/validate.js
function validate(uuid) {
  return typeof uuid === "string" && regex_default.test(uuid);
}
var validate_default;
var init_validate = __esm({
  "node_modules/uuid/dist/esm-node/validate.js"() {
    init_regex();
    validate_default = validate;
  }
});

// node_modules/uuid/dist/esm-node/stringify.js
function stringify(arr, offset = 0) {
  const uuid = (byteToHex[arr[offset + 0]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + "-" + byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + "-" + byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + "-" + byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + "-" + byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] + byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]).toLowerCase();
  if (!validate_default(uuid)) {
    throw TypeError("Stringified UUID is invalid");
  }
  return uuid;
}
var byteToHex, stringify_default;
var init_stringify = __esm({
  "node_modules/uuid/dist/esm-node/stringify.js"() {
    init_validate();
    byteToHex = [];
    for (let i = 0; i < 256; ++i) {
      byteToHex.push((i + 256).toString(16).substr(1));
    }
    stringify_default = stringify;
  }
});

// node_modules/uuid/dist/esm-node/v1.js
function v1(options, buf, offset) {
  let i = buf && offset || 0;
  const b = buf || new Array(16);
  options = options || {};
  let node = options.node || _nodeId;
  let clockseq = options.clockseq !== void 0 ? options.clockseq : _clockseq;
  if (node == null || clockseq == null) {
    const seedBytes = options.random || (options.rng || rng)();
    if (node == null) {
      node = _nodeId = [seedBytes[0] | 1, seedBytes[1], seedBytes[2], seedBytes[3], seedBytes[4], seedBytes[5]];
    }
    if (clockseq == null) {
      clockseq = _clockseq = (seedBytes[6] << 8 | seedBytes[7]) & 16383;
    }
  }
  let msecs = options.msecs !== void 0 ? options.msecs : Date.now();
  let nsecs = options.nsecs !== void 0 ? options.nsecs : _lastNSecs + 1;
  const dt = msecs - _lastMSecs + (nsecs - _lastNSecs) / 1e4;
  if (dt < 0 && options.clockseq === void 0) {
    clockseq = clockseq + 1 & 16383;
  }
  if ((dt < 0 || msecs > _lastMSecs) && options.nsecs === void 0) {
    nsecs = 0;
  }
  if (nsecs >= 1e4) {
    throw new Error("uuid.v1(): Can't create more than 10M uuids/sec");
  }
  _lastMSecs = msecs;
  _lastNSecs = nsecs;
  _clockseq = clockseq;
  msecs += 122192928e5;
  const tl = ((msecs & 268435455) * 1e4 + nsecs) % 4294967296;
  b[i++] = tl >>> 24 & 255;
  b[i++] = tl >>> 16 & 255;
  b[i++] = tl >>> 8 & 255;
  b[i++] = tl & 255;
  const tmh = msecs / 4294967296 * 1e4 & 268435455;
  b[i++] = tmh >>> 8 & 255;
  b[i++] = tmh & 255;
  b[i++] = tmh >>> 24 & 15 | 16;
  b[i++] = tmh >>> 16 & 255;
  b[i++] = clockseq >>> 8 | 128;
  b[i++] = clockseq & 255;
  for (let n = 0; n < 6; ++n) {
    b[i + n] = node[n];
  }
  return buf || stringify_default(b);
}
var _nodeId, _clockseq, _lastMSecs, _lastNSecs, v1_default;
var init_v1 = __esm({
  "node_modules/uuid/dist/esm-node/v1.js"() {
    init_rng();
    init_stringify();
    _lastMSecs = 0;
    _lastNSecs = 0;
    v1_default = v1;
  }
});

// node_modules/uuid/dist/esm-node/parse.js
function parse(uuid) {
  if (!validate_default(uuid)) {
    throw TypeError("Invalid UUID");
  }
  let v;
  const arr = new Uint8Array(16);
  arr[0] = (v = parseInt(uuid.slice(0, 8), 16)) >>> 24;
  arr[1] = v >>> 16 & 255;
  arr[2] = v >>> 8 & 255;
  arr[3] = v & 255;
  arr[4] = (v = parseInt(uuid.slice(9, 13), 16)) >>> 8;
  arr[5] = v & 255;
  arr[6] = (v = parseInt(uuid.slice(14, 18), 16)) >>> 8;
  arr[7] = v & 255;
  arr[8] = (v = parseInt(uuid.slice(19, 23), 16)) >>> 8;
  arr[9] = v & 255;
  arr[10] = (v = parseInt(uuid.slice(24, 36), 16)) / 1099511627776 & 255;
  arr[11] = v / 4294967296 & 255;
  arr[12] = v >>> 24 & 255;
  arr[13] = v >>> 16 & 255;
  arr[14] = v >>> 8 & 255;
  arr[15] = v & 255;
  return arr;
}
var parse_default;
var init_parse = __esm({
  "node_modules/uuid/dist/esm-node/parse.js"() {
    init_validate();
    parse_default = parse;
  }
});

// node_modules/uuid/dist/esm-node/v35.js
function stringToBytes(str) {
  str = unescape(encodeURIComponent(str));
  const bytes2 = [];
  for (let i = 0; i < str.length; ++i) {
    bytes2.push(str.charCodeAt(i));
  }
  return bytes2;
}
function v35_default(name, version2, hashfunc) {
  function generateUUID(value, namespace, buf, offset) {
    if (typeof value === "string") {
      value = stringToBytes(value);
    }
    if (typeof namespace === "string") {
      namespace = parse_default(namespace);
    }
    if (namespace.length !== 16) {
      throw TypeError("Namespace must be array-like (16 iterable integer values, 0-255)");
    }
    let bytes2 = new Uint8Array(16 + value.length);
    bytes2.set(namespace);
    bytes2.set(value, namespace.length);
    bytes2 = hashfunc(bytes2);
    bytes2[6] = bytes2[6] & 15 | version2;
    bytes2[8] = bytes2[8] & 63 | 128;
    if (buf) {
      offset = offset || 0;
      for (let i = 0; i < 16; ++i) {
        buf[offset + i] = bytes2[i];
      }
      return buf;
    }
    return stringify_default(bytes2);
  }
  try {
    generateUUID.name = name;
  } catch (err) {
  }
  generateUUID.DNS = DNS;
  generateUUID.URL = URL2;
  return generateUUID;
}
var DNS, URL2;
var init_v35 = __esm({
  "node_modules/uuid/dist/esm-node/v35.js"() {
    init_stringify();
    init_parse();
    DNS = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
    URL2 = "6ba7b811-9dad-11d1-80b4-00c04fd430c8";
  }
});

// node_modules/uuid/dist/esm-node/md5.js
function md5(bytes2) {
  if (Array.isArray(bytes2)) {
    bytes2 = Buffer.from(bytes2);
  } else if (typeof bytes2 === "string") {
    bytes2 = Buffer.from(bytes2, "utf8");
  }
  return import_crypto2.default.createHash("md5").update(bytes2).digest();
}
var import_crypto2, md5_default;
var init_md5 = __esm({
  "node_modules/uuid/dist/esm-node/md5.js"() {
    import_crypto2 = __toESM(require("crypto"));
    md5_default = md5;
  }
});

// node_modules/uuid/dist/esm-node/v3.js
var v3, v3_default;
var init_v3 = __esm({
  "node_modules/uuid/dist/esm-node/v3.js"() {
    init_v35();
    init_md5();
    v3 = v35_default("v3", 48, md5_default);
    v3_default = v3;
  }
});

// node_modules/uuid/dist/esm-node/v4.js
function v4(options, buf, offset) {
  options = options || {};
  const rnds = options.random || (options.rng || rng)();
  rnds[6] = rnds[6] & 15 | 64;
  rnds[8] = rnds[8] & 63 | 128;
  if (buf) {
    offset = offset || 0;
    for (let i = 0; i < 16; ++i) {
      buf[offset + i] = rnds[i];
    }
    return buf;
  }
  return stringify_default(rnds);
}
var v4_default;
var init_v4 = __esm({
  "node_modules/uuid/dist/esm-node/v4.js"() {
    init_rng();
    init_stringify();
    v4_default = v4;
  }
});

// node_modules/uuid/dist/esm-node/sha1.js
function sha1(bytes2) {
  if (Array.isArray(bytes2)) {
    bytes2 = Buffer.from(bytes2);
  } else if (typeof bytes2 === "string") {
    bytes2 = Buffer.from(bytes2, "utf8");
  }
  return import_crypto3.default.createHash("sha1").update(bytes2).digest();
}
var import_crypto3, sha1_default;
var init_sha1 = __esm({
  "node_modules/uuid/dist/esm-node/sha1.js"() {
    import_crypto3 = __toESM(require("crypto"));
    sha1_default = sha1;
  }
});

// node_modules/uuid/dist/esm-node/v5.js
var v5, v5_default;
var init_v5 = __esm({
  "node_modules/uuid/dist/esm-node/v5.js"() {
    init_v35();
    init_sha1();
    v5 = v35_default("v5", 80, sha1_default);
    v5_default = v5;
  }
});

// node_modules/uuid/dist/esm-node/nil.js
var nil_default;
var init_nil = __esm({
  "node_modules/uuid/dist/esm-node/nil.js"() {
    nil_default = "00000000-0000-0000-0000-000000000000";
  }
});

// node_modules/uuid/dist/esm-node/version.js
function version(uuid) {
  if (!validate_default(uuid)) {
    throw TypeError("Invalid UUID");
  }
  return parseInt(uuid.substr(14, 1), 16);
}
var version_default;
var init_version = __esm({
  "node_modules/uuid/dist/esm-node/version.js"() {
    init_validate();
    version_default = version;
  }
});

// node_modules/uuid/dist/esm-node/index.js
var esm_node_exports = {};
__export(esm_node_exports, {
  NIL: () => nil_default,
  parse: () => parse_default,
  stringify: () => stringify_default,
  v1: () => v1_default,
  v3: () => v3_default,
  v4: () => v4_default,
  v5: () => v5_default,
  validate: () => validate_default,
  version: () => version_default
});
var init_esm_node = __esm({
  "node_modules/uuid/dist/esm-node/index.js"() {
    init_v1();
    init_v3();
    init_v4();
    init_v5();
    init_nil();
    init_version();
    init_validate();
    init_stringify();
    init_parse();
  }
});

// node_modules/@actions/core/lib/file-command.js
var require_file_command = __commonJS({
  "node_modules/@actions/core/lib/file-command.js"(exports) {
    "use strict";
    var __createBinding = exports && exports.__createBinding || (Object.create ? function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      Object.defineProperty(o, k2, { enumerable: true, get: function() {
        return m[k];
      } });
    } : function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      o[k2] = m[k];
    });
    var __setModuleDefault = exports && exports.__setModuleDefault || (Object.create ? function(o, v) {
      Object.defineProperty(o, "default", { enumerable: true, value: v });
    } : function(o, v) {
      o["default"] = v;
    });
    var __importStar = exports && exports.__importStar || function(mod) {
      if (mod && mod.__esModule)
        return mod;
      var result = {};
      if (mod != null) {
        for (var k in mod)
          if (k !== "default" && Object.hasOwnProperty.call(mod, k))
            __createBinding(result, mod, k);
      }
      __setModuleDefault(result, mod);
      return result;
    };
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.prepareKeyValueMessage = exports.issueFileCommand = void 0;
    var fs2 = __importStar(require("fs"));
    var os = __importStar(require("os"));
    var uuid_1 = (init_esm_node(), __toCommonJS(esm_node_exports));
    var utils_1 = require_utils();
    function issueFileCommand(command, message) {
      const filePath = process.env[`GITHUB_${command}`];
      if (!filePath) {
        throw new Error(`Unable to find environment variable for file command ${command}`);
      }
      if (!fs2.existsSync(filePath)) {
        throw new Error(`Missing file at path: ${filePath}`);
      }
      fs2.appendFileSync(filePath, `${utils_1.toCommandValue(message)}${os.EOL}`, {
        encoding: "utf8"
      });
    }
    exports.issueFileCommand = issueFileCommand;
    function prepareKeyValueMessage(key, value) {
      const delimiter = `ghadelimiter_${uuid_1.v4()}`;
      const convertedValue = utils_1.toCommandValue(value);
      if (key.includes(delimiter)) {
        throw new Error(`Unexpected input: name should not contain the delimiter "${delimiter}"`);
      }
      if (convertedValue.includes(delimiter)) {
        throw new Error(`Unexpected input: value should not contain the delimiter "${delimiter}"`);
      }
      return `${key}<<${delimiter}${os.EOL}${convertedValue}${os.EOL}${delimiter}`;
    }
    exports.prepareKeyValueMessage = prepareKeyValueMessage;
  }
});

// node_modules/@actions/http-client/lib/proxy.js
var require_proxy = __commonJS({
  "node_modules/@actions/http-client/lib/proxy.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.checkBypass = exports.getProxyUrl = void 0;
    function getProxyUrl(reqUrl) {
      const usingSsl = reqUrl.protocol === "https:";
      if (checkBypass(reqUrl)) {
        return void 0;
      }
      const proxyVar = (() => {
        if (usingSsl) {
          return process.env["https_proxy"] || process.env["HTTPS_PROXY"];
        } else {
          return process.env["http_proxy"] || process.env["HTTP_PROXY"];
        }
      })();
      if (proxyVar) {
        return new URL(proxyVar);
      } else {
        return void 0;
      }
    }
    exports.getProxyUrl = getProxyUrl;
    function checkBypass(reqUrl) {
      if (!reqUrl.hostname) {
        return false;
      }
      const reqHost = reqUrl.hostname;
      if (isLoopbackAddress(reqHost)) {
        return true;
      }
      const noProxy = process.env["no_proxy"] || process.env["NO_PROXY"] || "";
      if (!noProxy) {
        return false;
      }
      let reqPort;
      if (reqUrl.port) {
        reqPort = Number(reqUrl.port);
      } else if (reqUrl.protocol === "http:") {
        reqPort = 80;
      } else if (reqUrl.protocol === "https:") {
        reqPort = 443;
      }
      const upperReqHosts = [reqUrl.hostname.toUpperCase()];
      if (typeof reqPort === "number") {
        upperReqHosts.push(`${upperReqHosts[0]}:${reqPort}`);
      }
      for (const upperNoProxyItem of noProxy.split(",").map((x) => x.trim().toUpperCase()).filter((x) => x)) {
        if (upperNoProxyItem === "*" || upperReqHosts.some((x) => x === upperNoProxyItem || x.endsWith(`.${upperNoProxyItem}`) || upperNoProxyItem.startsWith(".") && x.endsWith(`${upperNoProxyItem}`))) {
          return true;
        }
      }
      return false;
    }
    exports.checkBypass = checkBypass;
    function isLoopbackAddress(host) {
      const hostLower = host.toLowerCase();
      return hostLower === "localhost" || hostLower.startsWith("127.") || hostLower.startsWith("[::1]") || hostLower.startsWith("[0:0:0:0:0:0:0:1]");
    }
  }
});

// node_modules/tunnel/lib/tunnel.js
var require_tunnel = __commonJS({
  "node_modules/tunnel/lib/tunnel.js"(exports) {
    "use strict";
    var net = require("net");
    var tls = require("tls");
    var http = require("http");
    var https = require("https");
    var events = require("events");
    var assert2 = require("assert");
    var util = require("util");
    exports.httpOverHttp = httpOverHttp;
    exports.httpsOverHttp = httpsOverHttp;
    exports.httpOverHttps = httpOverHttps;
    exports.httpsOverHttps = httpsOverHttps;
    function httpOverHttp(options) {
      var agent = new TunnelingAgent(options);
      agent.request = http.request;
      return agent;
    }
    function httpsOverHttp(options) {
      var agent = new TunnelingAgent(options);
      agent.request = http.request;
      agent.createSocket = createSecureSocket;
      agent.defaultPort = 443;
      return agent;
    }
    function httpOverHttps(options) {
      var agent = new TunnelingAgent(options);
      agent.request = https.request;
      return agent;
    }
    function httpsOverHttps(options) {
      var agent = new TunnelingAgent(options);
      agent.request = https.request;
      agent.createSocket = createSecureSocket;
      agent.defaultPort = 443;
      return agent;
    }
    function TunnelingAgent(options) {
      var self2 = this;
      self2.options = options || {};
      self2.proxyOptions = self2.options.proxy || {};
      self2.maxSockets = self2.options.maxSockets || http.Agent.defaultMaxSockets;
      self2.requests = [];
      self2.sockets = [];
      self2.on("free", function onFree(socket, host, port, localAddress) {
        var options2 = toOptions(host, port, localAddress);
        for (var i = 0, len = self2.requests.length; i < len; ++i) {
          var pending = self2.requests[i];
          if (pending.host === options2.host && pending.port === options2.port) {
            self2.requests.splice(i, 1);
            pending.request.onSocket(socket);
            return;
          }
        }
        socket.destroy();
        self2.removeSocket(socket);
      });
    }
    util.inherits(TunnelingAgent, events.EventEmitter);
    TunnelingAgent.prototype.addRequest = function addRequest(req, host, port, localAddress) {
      var self2 = this;
      var options = mergeOptions({ request: req }, self2.options, toOptions(host, port, localAddress));
      if (self2.sockets.length >= this.maxSockets) {
        self2.requests.push(options);
        return;
      }
      self2.createSocket(options, function(socket) {
        socket.on("free", onFree);
        socket.on("close", onCloseOrRemove);
        socket.on("agentRemove", onCloseOrRemove);
        req.onSocket(socket);
        function onFree() {
          self2.emit("free", socket, options);
        }
        function onCloseOrRemove(err) {
          self2.removeSocket(socket);
          socket.removeListener("free", onFree);
          socket.removeListener("close", onCloseOrRemove);
          socket.removeListener("agentRemove", onCloseOrRemove);
        }
      });
    };
    TunnelingAgent.prototype.createSocket = function createSocket(options, cb) {
      var self2 = this;
      var placeholder = {};
      self2.sockets.push(placeholder);
      var connectOptions = mergeOptions({}, self2.proxyOptions, {
        method: "CONNECT",
        path: options.host + ":" + options.port,
        agent: false,
        headers: {
          host: options.host + ":" + options.port
        }
      });
      if (options.localAddress) {
        connectOptions.localAddress = options.localAddress;
      }
      if (connectOptions.proxyAuth) {
        connectOptions.headers = connectOptions.headers || {};
        connectOptions.headers["Proxy-Authorization"] = "Basic " + new Buffer(connectOptions.proxyAuth).toString("base64");
      }
      debug("making CONNECT request");
      var connectReq = self2.request(connectOptions);
      connectReq.useChunkedEncodingByDefault = false;
      connectReq.once("response", onResponse);
      connectReq.once("upgrade", onUpgrade);
      connectReq.once("connect", onConnect);
      connectReq.once("error", onError);
      connectReq.end();
      function onResponse(res) {
        res.upgrade = true;
      }
      function onUpgrade(res, socket, head) {
        process.nextTick(function() {
          onConnect(res, socket, head);
        });
      }
      function onConnect(res, socket, head) {
        connectReq.removeAllListeners();
        socket.removeAllListeners();
        if (res.statusCode !== 200) {
          debug(
            "tunneling socket could not be established, statusCode=%d",
            res.statusCode
          );
          socket.destroy();
          var error = new Error("tunneling socket could not be established, statusCode=" + res.statusCode);
          error.code = "ECONNRESET";
          options.request.emit("error", error);
          self2.removeSocket(placeholder);
          return;
        }
        if (head.length > 0) {
          debug("got illegal response body from proxy");
          socket.destroy();
          var error = new Error("got illegal response body from proxy");
          error.code = "ECONNRESET";
          options.request.emit("error", error);
          self2.removeSocket(placeholder);
          return;
        }
        debug("tunneling connection has established");
        self2.sockets[self2.sockets.indexOf(placeholder)] = socket;
        return cb(socket);
      }
      function onError(cause) {
        connectReq.removeAllListeners();
        debug(
          "tunneling socket could not be established, cause=%s\n",
          cause.message,
          cause.stack
        );
        var error = new Error("tunneling socket could not be established, cause=" + cause.message);
        error.code = "ECONNRESET";
        options.request.emit("error", error);
        self2.removeSocket(placeholder);
      }
    };
    TunnelingAgent.prototype.removeSocket = function removeSocket(socket) {
      var pos = this.sockets.indexOf(socket);
      if (pos === -1) {
        return;
      }
      this.sockets.splice(pos, 1);
      var pending = this.requests.shift();
      if (pending) {
        this.createSocket(pending, function(socket2) {
          pending.request.onSocket(socket2);
        });
      }
    };
    function createSecureSocket(options, cb) {
      var self2 = this;
      TunnelingAgent.prototype.createSocket.call(self2, options, function(socket) {
        var hostHeader = options.request.getHeader("host");
        var tlsOptions = mergeOptions({}, self2.options, {
          socket,
          servername: hostHeader ? hostHeader.replace(/:.*$/, "") : options.host
        });
        var secureSocket = tls.connect(0, tlsOptions);
        self2.sockets[self2.sockets.indexOf(socket)] = secureSocket;
        cb(secureSocket);
      });
    }
    function toOptions(host, port, localAddress) {
      if (typeof host === "string") {
        return {
          host,
          port,
          localAddress
        };
      }
      return host;
    }
    function mergeOptions(target) {
      for (var i = 1, len = arguments.length; i < len; ++i) {
        var overrides = arguments[i];
        if (typeof overrides === "object") {
          var keys = Object.keys(overrides);
          for (var j = 0, keyLen = keys.length; j < keyLen; ++j) {
            var k = keys[j];
            if (overrides[k] !== void 0) {
              target[k] = overrides[k];
            }
          }
        }
      }
      return target;
    }
    var debug;
    if (process.env.NODE_DEBUG && /\btunnel\b/.test(process.env.NODE_DEBUG)) {
      debug = function() {
        var args = Array.prototype.slice.call(arguments);
        if (typeof args[0] === "string") {
          args[0] = "TUNNEL: " + args[0];
        } else {
          args.unshift("TUNNEL:");
        }
        console.error.apply(console, args);
      };
    } else {
      debug = function() {
      };
    }
    exports.debug = debug;
  }
});

// node_modules/tunnel/index.js
var require_tunnel2 = __commonJS({
  "node_modules/tunnel/index.js"(exports, module2) {
    module2.exports = require_tunnel();
  }
});

// node_modules/@actions/http-client/lib/index.js
var require_lib = __commonJS({
  "node_modules/@actions/http-client/lib/index.js"(exports) {
    "use strict";
    var __createBinding = exports && exports.__createBinding || (Object.create ? function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      Object.defineProperty(o, k2, { enumerable: true, get: function() {
        return m[k];
      } });
    } : function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      o[k2] = m[k];
    });
    var __setModuleDefault = exports && exports.__setModuleDefault || (Object.create ? function(o, v) {
      Object.defineProperty(o, "default", { enumerable: true, value: v });
    } : function(o, v) {
      o["default"] = v;
    });
    var __importStar = exports && exports.__importStar || function(mod) {
      if (mod && mod.__esModule)
        return mod;
      var result = {};
      if (mod != null) {
        for (var k in mod)
          if (k !== "default" && Object.hasOwnProperty.call(mod, k))
            __createBinding(result, mod, k);
      }
      __setModuleDefault(result, mod);
      return result;
    };
    var __awaiter = exports && exports.__awaiter || function(thisArg, _arguments, P, generator) {
      function adopt(value) {
        return value instanceof P ? value : new P(function(resolve) {
          resolve(value);
        });
      }
      return new (P || (P = Promise))(function(resolve, reject) {
        function fulfilled(value) {
          try {
            step(generator.next(value));
          } catch (e) {
            reject(e);
          }
        }
        function rejected(value) {
          try {
            step(generator["throw"](value));
          } catch (e) {
            reject(e);
          }
        }
        function step(result) {
          result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected);
        }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
      });
    };
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.HttpClient = exports.isHttps = exports.HttpClientResponse = exports.HttpClientError = exports.getProxyUrl = exports.MediaTypes = exports.Headers = exports.HttpCodes = void 0;
    var http = __importStar(require("http"));
    var https = __importStar(require("https"));
    var pm = __importStar(require_proxy());
    var tunnel = __importStar(require_tunnel2());
    var HttpCodes;
    (function(HttpCodes2) {
      HttpCodes2[HttpCodes2["OK"] = 200] = "OK";
      HttpCodes2[HttpCodes2["MultipleChoices"] = 300] = "MultipleChoices";
      HttpCodes2[HttpCodes2["MovedPermanently"] = 301] = "MovedPermanently";
      HttpCodes2[HttpCodes2["ResourceMoved"] = 302] = "ResourceMoved";
      HttpCodes2[HttpCodes2["SeeOther"] = 303] = "SeeOther";
      HttpCodes2[HttpCodes2["NotModified"] = 304] = "NotModified";
      HttpCodes2[HttpCodes2["UseProxy"] = 305] = "UseProxy";
      HttpCodes2[HttpCodes2["SwitchProxy"] = 306] = "SwitchProxy";
      HttpCodes2[HttpCodes2["TemporaryRedirect"] = 307] = "TemporaryRedirect";
      HttpCodes2[HttpCodes2["PermanentRedirect"] = 308] = "PermanentRedirect";
      HttpCodes2[HttpCodes2["BadRequest"] = 400] = "BadRequest";
      HttpCodes2[HttpCodes2["Unauthorized"] = 401] = "Unauthorized";
      HttpCodes2[HttpCodes2["PaymentRequired"] = 402] = "PaymentRequired";
      HttpCodes2[HttpCodes2["Forbidden"] = 403] = "Forbidden";
      HttpCodes2[HttpCodes2["NotFound"] = 404] = "NotFound";
      HttpCodes2[HttpCodes2["MethodNotAllowed"] = 405] = "MethodNotAllowed";
      HttpCodes2[HttpCodes2["NotAcceptable"] = 406] = "NotAcceptable";
      HttpCodes2[HttpCodes2["ProxyAuthenticationRequired"] = 407] = "ProxyAuthenticationRequired";
      HttpCodes2[HttpCodes2["RequestTimeout"] = 408] = "RequestTimeout";
      HttpCodes2[HttpCodes2["Conflict"] = 409] = "Conflict";
      HttpCodes2[HttpCodes2["Gone"] = 410] = "Gone";
      HttpCodes2[HttpCodes2["TooManyRequests"] = 429] = "TooManyRequests";
      HttpCodes2[HttpCodes2["InternalServerError"] = 500] = "InternalServerError";
      HttpCodes2[HttpCodes2["NotImplemented"] = 501] = "NotImplemented";
      HttpCodes2[HttpCodes2["BadGateway"] = 502] = "BadGateway";
      HttpCodes2[HttpCodes2["ServiceUnavailable"] = 503] = "ServiceUnavailable";
      HttpCodes2[HttpCodes2["GatewayTimeout"] = 504] = "GatewayTimeout";
    })(HttpCodes = exports.HttpCodes || (exports.HttpCodes = {}));
    var Headers;
    (function(Headers2) {
      Headers2["Accept"] = "accept";
      Headers2["ContentType"] = "content-type";
    })(Headers = exports.Headers || (exports.Headers = {}));
    var MediaTypes;
    (function(MediaTypes2) {
      MediaTypes2["ApplicationJson"] = "application/json";
    })(MediaTypes = exports.MediaTypes || (exports.MediaTypes = {}));
    function getProxyUrl(serverUrl) {
      const proxyUrl = pm.getProxyUrl(new URL(serverUrl));
      return proxyUrl ? proxyUrl.href : "";
    }
    exports.getProxyUrl = getProxyUrl;
    var HttpRedirectCodes = [
      HttpCodes.MovedPermanently,
      HttpCodes.ResourceMoved,
      HttpCodes.SeeOther,
      HttpCodes.TemporaryRedirect,
      HttpCodes.PermanentRedirect
    ];
    var HttpResponseRetryCodes = [
      HttpCodes.BadGateway,
      HttpCodes.ServiceUnavailable,
      HttpCodes.GatewayTimeout
    ];
    var RetryableHttpVerbs = ["OPTIONS", "GET", "DELETE", "HEAD"];
    var ExponentialBackoffCeiling = 10;
    var ExponentialBackoffTimeSlice = 5;
    var HttpClientError = class extends Error {
      constructor(message, statusCode) {
        super(message);
        this.name = "HttpClientError";
        this.statusCode = statusCode;
        Object.setPrototypeOf(this, HttpClientError.prototype);
      }
    };
    exports.HttpClientError = HttpClientError;
    var HttpClientResponse = class {
      constructor(message) {
        this.message = message;
      }
      readBody() {
        return __awaiter(this, void 0, void 0, function* () {
          return new Promise((resolve) => __awaiter(this, void 0, void 0, function* () {
            let output2 = Buffer.alloc(0);
            this.message.on("data", (chunk) => {
              output2 = Buffer.concat([output2, chunk]);
            });
            this.message.on("end", () => {
              resolve(output2.toString());
            });
          }));
        });
      }
    };
    exports.HttpClientResponse = HttpClientResponse;
    function isHttps(requestUrl) {
      const parsedUrl = new URL(requestUrl);
      return parsedUrl.protocol === "https:";
    }
    exports.isHttps = isHttps;
    var HttpClient = class {
      constructor(userAgent, handlers, requestOptions) {
        this._ignoreSslError = false;
        this._allowRedirects = true;
        this._allowRedirectDowngrade = false;
        this._maxRedirects = 50;
        this._allowRetries = false;
        this._maxRetries = 1;
        this._keepAlive = false;
        this._disposed = false;
        this.userAgent = userAgent;
        this.handlers = handlers || [];
        this.requestOptions = requestOptions;
        if (requestOptions) {
          if (requestOptions.ignoreSslError != null) {
            this._ignoreSslError = requestOptions.ignoreSslError;
          }
          this._socketTimeout = requestOptions.socketTimeout;
          if (requestOptions.allowRedirects != null) {
            this._allowRedirects = requestOptions.allowRedirects;
          }
          if (requestOptions.allowRedirectDowngrade != null) {
            this._allowRedirectDowngrade = requestOptions.allowRedirectDowngrade;
          }
          if (requestOptions.maxRedirects != null) {
            this._maxRedirects = Math.max(requestOptions.maxRedirects, 0);
          }
          if (requestOptions.keepAlive != null) {
            this._keepAlive = requestOptions.keepAlive;
          }
          if (requestOptions.allowRetries != null) {
            this._allowRetries = requestOptions.allowRetries;
          }
          if (requestOptions.maxRetries != null) {
            this._maxRetries = requestOptions.maxRetries;
          }
        }
      }
      options(requestUrl, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
          return this.request("OPTIONS", requestUrl, null, additionalHeaders || {});
        });
      }
      get(requestUrl, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
          return this.request("GET", requestUrl, null, additionalHeaders || {});
        });
      }
      del(requestUrl, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
          return this.request("DELETE", requestUrl, null, additionalHeaders || {});
        });
      }
      post(requestUrl, data, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
          return this.request("POST", requestUrl, data, additionalHeaders || {});
        });
      }
      patch(requestUrl, data, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
          return this.request("PATCH", requestUrl, data, additionalHeaders || {});
        });
      }
      put(requestUrl, data, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
          return this.request("PUT", requestUrl, data, additionalHeaders || {});
        });
      }
      head(requestUrl, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
          return this.request("HEAD", requestUrl, null, additionalHeaders || {});
        });
      }
      sendStream(verb, requestUrl, stream, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
          return this.request(verb, requestUrl, stream, additionalHeaders);
        });
      }
      /**
       * Gets a typed object from an endpoint
       * Be aware that not found returns a null.  Other errors (4xx, 5xx) reject the promise
       */
      getJson(requestUrl, additionalHeaders = {}) {
        return __awaiter(this, void 0, void 0, function* () {
          additionalHeaders[Headers.Accept] = this._getExistingOrDefaultHeader(additionalHeaders, Headers.Accept, MediaTypes.ApplicationJson);
          const res = yield this.get(requestUrl, additionalHeaders);
          return this._processResponse(res, this.requestOptions);
        });
      }
      postJson(requestUrl, obj, additionalHeaders = {}) {
        return __awaiter(this, void 0, void 0, function* () {
          const data = JSON.stringify(obj, null, 2);
          additionalHeaders[Headers.Accept] = this._getExistingOrDefaultHeader(additionalHeaders, Headers.Accept, MediaTypes.ApplicationJson);
          additionalHeaders[Headers.ContentType] = this._getExistingOrDefaultHeader(additionalHeaders, Headers.ContentType, MediaTypes.ApplicationJson);
          const res = yield this.post(requestUrl, data, additionalHeaders);
          return this._processResponse(res, this.requestOptions);
        });
      }
      putJson(requestUrl, obj, additionalHeaders = {}) {
        return __awaiter(this, void 0, void 0, function* () {
          const data = JSON.stringify(obj, null, 2);
          additionalHeaders[Headers.Accept] = this._getExistingOrDefaultHeader(additionalHeaders, Headers.Accept, MediaTypes.ApplicationJson);
          additionalHeaders[Headers.ContentType] = this._getExistingOrDefaultHeader(additionalHeaders, Headers.ContentType, MediaTypes.ApplicationJson);
          const res = yield this.put(requestUrl, data, additionalHeaders);
          return this._processResponse(res, this.requestOptions);
        });
      }
      patchJson(requestUrl, obj, additionalHeaders = {}) {
        return __awaiter(this, void 0, void 0, function* () {
          const data = JSON.stringify(obj, null, 2);
          additionalHeaders[Headers.Accept] = this._getExistingOrDefaultHeader(additionalHeaders, Headers.Accept, MediaTypes.ApplicationJson);
          additionalHeaders[Headers.ContentType] = this._getExistingOrDefaultHeader(additionalHeaders, Headers.ContentType, MediaTypes.ApplicationJson);
          const res = yield this.patch(requestUrl, data, additionalHeaders);
          return this._processResponse(res, this.requestOptions);
        });
      }
      /**
       * Makes a raw http request.
       * All other methods such as get, post, patch, and request ultimately call this.
       * Prefer get, del, post and patch
       */
      request(verb, requestUrl, data, headers) {
        return __awaiter(this, void 0, void 0, function* () {
          if (this._disposed) {
            throw new Error("Client has already been disposed.");
          }
          const parsedUrl = new URL(requestUrl);
          let info = this._prepareRequest(verb, parsedUrl, headers);
          const maxTries = this._allowRetries && RetryableHttpVerbs.includes(verb) ? this._maxRetries + 1 : 1;
          let numTries = 0;
          let response;
          do {
            response = yield this.requestRaw(info, data);
            if (response && response.message && response.message.statusCode === HttpCodes.Unauthorized) {
              let authenticationHandler;
              for (const handler of this.handlers) {
                if (handler.canHandleAuthentication(response)) {
                  authenticationHandler = handler;
                  break;
                }
              }
              if (authenticationHandler) {
                return authenticationHandler.handleAuthentication(this, info, data);
              } else {
                return response;
              }
            }
            let redirectsRemaining = this._maxRedirects;
            while (response.message.statusCode && HttpRedirectCodes.includes(response.message.statusCode) && this._allowRedirects && redirectsRemaining > 0) {
              const redirectUrl = response.message.headers["location"];
              if (!redirectUrl) {
                break;
              }
              const parsedRedirectUrl = new URL(redirectUrl);
              if (parsedUrl.protocol === "https:" && parsedUrl.protocol !== parsedRedirectUrl.protocol && !this._allowRedirectDowngrade) {
                throw new Error("Redirect from HTTPS to HTTP protocol. This downgrade is not allowed for security reasons. If you want to allow this behavior, set the allowRedirectDowngrade option to true.");
              }
              yield response.readBody();
              if (parsedRedirectUrl.hostname !== parsedUrl.hostname) {
                for (const header in headers) {
                  if (header.toLowerCase() === "authorization") {
                    delete headers[header];
                  }
                }
              }
              info = this._prepareRequest(verb, parsedRedirectUrl, headers);
              response = yield this.requestRaw(info, data);
              redirectsRemaining--;
            }
            if (!response.message.statusCode || !HttpResponseRetryCodes.includes(response.message.statusCode)) {
              return response;
            }
            numTries += 1;
            if (numTries < maxTries) {
              yield response.readBody();
              yield this._performExponentialBackoff(numTries);
            }
          } while (numTries < maxTries);
          return response;
        });
      }
      /**
       * Needs to be called if keepAlive is set to true in request options.
       */
      dispose() {
        if (this._agent) {
          this._agent.destroy();
        }
        this._disposed = true;
      }
      /**
       * Raw request.
       * @param info
       * @param data
       */
      requestRaw(info, data) {
        return __awaiter(this, void 0, void 0, function* () {
          return new Promise((resolve, reject) => {
            function callbackForResult(err, res) {
              if (err) {
                reject(err);
              } else if (!res) {
                reject(new Error("Unknown error"));
              } else {
                resolve(res);
              }
            }
            this.requestRawWithCallback(info, data, callbackForResult);
          });
        });
      }
      /**
       * Raw request with callback.
       * @param info
       * @param data
       * @param onResult
       */
      requestRawWithCallback(info, data, onResult) {
        if (typeof data === "string") {
          if (!info.options.headers) {
            info.options.headers = {};
          }
          info.options.headers["Content-Length"] = Buffer.byteLength(data, "utf8");
        }
        let callbackCalled = false;
        function handleResult(err, res) {
          if (!callbackCalled) {
            callbackCalled = true;
            onResult(err, res);
          }
        }
        const req = info.httpModule.request(info.options, (msg) => {
          const res = new HttpClientResponse(msg);
          handleResult(void 0, res);
        });
        let socket;
        req.on("socket", (sock) => {
          socket = sock;
        });
        req.setTimeout(this._socketTimeout || 3 * 6e4, () => {
          if (socket) {
            socket.end();
          }
          handleResult(new Error(`Request timeout: ${info.options.path}`));
        });
        req.on("error", function(err) {
          handleResult(err);
        });
        if (data && typeof data === "string") {
          req.write(data, "utf8");
        }
        if (data && typeof data !== "string") {
          data.on("close", function() {
            req.end();
          });
          data.pipe(req);
        } else {
          req.end();
        }
      }
      /**
       * Gets an http agent. This function is useful when you need an http agent that handles
       * routing through a proxy server - depending upon the url and proxy environment variables.
       * @param serverUrl  The server URL where the request will be sent. For example, https://api.github.com
       */
      getAgent(serverUrl) {
        const parsedUrl = new URL(serverUrl);
        return this._getAgent(parsedUrl);
      }
      _prepareRequest(method, requestUrl, headers) {
        const info = {};
        info.parsedUrl = requestUrl;
        const usingSsl = info.parsedUrl.protocol === "https:";
        info.httpModule = usingSsl ? https : http;
        const defaultPort = usingSsl ? 443 : 80;
        info.options = {};
        info.options.host = info.parsedUrl.hostname;
        info.options.port = info.parsedUrl.port ? parseInt(info.parsedUrl.port) : defaultPort;
        info.options.path = (info.parsedUrl.pathname || "") + (info.parsedUrl.search || "");
        info.options.method = method;
        info.options.headers = this._mergeHeaders(headers);
        if (this.userAgent != null) {
          info.options.headers["user-agent"] = this.userAgent;
        }
        info.options.agent = this._getAgent(info.parsedUrl);
        if (this.handlers) {
          for (const handler of this.handlers) {
            handler.prepareRequest(info.options);
          }
        }
        return info;
      }
      _mergeHeaders(headers) {
        if (this.requestOptions && this.requestOptions.headers) {
          return Object.assign({}, lowercaseKeys(this.requestOptions.headers), lowercaseKeys(headers || {}));
        }
        return lowercaseKeys(headers || {});
      }
      _getExistingOrDefaultHeader(additionalHeaders, header, _default) {
        let clientHeader;
        if (this.requestOptions && this.requestOptions.headers) {
          clientHeader = lowercaseKeys(this.requestOptions.headers)[header];
        }
        return additionalHeaders[header] || clientHeader || _default;
      }
      _getAgent(parsedUrl) {
        let agent;
        const proxyUrl = pm.getProxyUrl(parsedUrl);
        const useProxy = proxyUrl && proxyUrl.hostname;
        if (this._keepAlive && useProxy) {
          agent = this._proxyAgent;
        }
        if (this._keepAlive && !useProxy) {
          agent = this._agent;
        }
        if (agent) {
          return agent;
        }
        const usingSsl = parsedUrl.protocol === "https:";
        let maxSockets = 100;
        if (this.requestOptions) {
          maxSockets = this.requestOptions.maxSockets || http.globalAgent.maxSockets;
        }
        if (proxyUrl && proxyUrl.hostname) {
          const agentOptions = {
            maxSockets,
            keepAlive: this._keepAlive,
            proxy: Object.assign(Object.assign({}, (proxyUrl.username || proxyUrl.password) && {
              proxyAuth: `${proxyUrl.username}:${proxyUrl.password}`
            }), { host: proxyUrl.hostname, port: proxyUrl.port })
          };
          let tunnelAgent;
          const overHttps = proxyUrl.protocol === "https:";
          if (usingSsl) {
            tunnelAgent = overHttps ? tunnel.httpsOverHttps : tunnel.httpsOverHttp;
          } else {
            tunnelAgent = overHttps ? tunnel.httpOverHttps : tunnel.httpOverHttp;
          }
          agent = tunnelAgent(agentOptions);
          this._proxyAgent = agent;
        }
        if (this._keepAlive && !agent) {
          const options = { keepAlive: this._keepAlive, maxSockets };
          agent = usingSsl ? new https.Agent(options) : new http.Agent(options);
          this._agent = agent;
        }
        if (!agent) {
          agent = usingSsl ? https.globalAgent : http.globalAgent;
        }
        if (usingSsl && this._ignoreSslError) {
          agent.options = Object.assign(agent.options || {}, {
            rejectUnauthorized: false
          });
        }
        return agent;
      }
      _performExponentialBackoff(retryNumber) {
        return __awaiter(this, void 0, void 0, function* () {
          retryNumber = Math.min(ExponentialBackoffCeiling, retryNumber);
          const ms = ExponentialBackoffTimeSlice * Math.pow(2, retryNumber);
          return new Promise((resolve) => setTimeout(() => resolve(), ms));
        });
      }
      _processResponse(res, options) {
        return __awaiter(this, void 0, void 0, function* () {
          return new Promise((resolve, reject) => __awaiter(this, void 0, void 0, function* () {
            const statusCode = res.message.statusCode || 0;
            const response = {
              statusCode,
              result: null,
              headers: {}
            };
            if (statusCode === HttpCodes.NotFound) {
              resolve(response);
            }
            function dateTimeDeserializer(key, value) {
              if (typeof value === "string") {
                const a = new Date(value);
                if (!isNaN(a.valueOf())) {
                  return a;
                }
              }
              return value;
            }
            let obj;
            let contents;
            try {
              contents = yield res.readBody();
              if (contents && contents.length > 0) {
                if (options && options.deserializeDates) {
                  obj = JSON.parse(contents, dateTimeDeserializer);
                } else {
                  obj = JSON.parse(contents);
                }
                response.result = obj;
              }
              response.headers = res.message.headers;
            } catch (err) {
            }
            if (statusCode > 299) {
              let msg;
              if (obj && obj.message) {
                msg = obj.message;
              } else if (contents && contents.length > 0) {
                msg = contents;
              } else {
                msg = `Failed request: (${statusCode})`;
              }
              const err = new HttpClientError(msg, statusCode);
              err.result = response.result;
              reject(err);
            } else {
              resolve(response);
            }
          }));
        });
      }
    };
    exports.HttpClient = HttpClient;
    var lowercaseKeys = (obj) => Object.keys(obj).reduce((c, k) => (c[k.toLowerCase()] = obj[k], c), {});
  }
});

// node_modules/@actions/http-client/lib/auth.js
var require_auth = __commonJS({
  "node_modules/@actions/http-client/lib/auth.js"(exports) {
    "use strict";
    var __awaiter = exports && exports.__awaiter || function(thisArg, _arguments, P, generator) {
      function adopt(value) {
        return value instanceof P ? value : new P(function(resolve) {
          resolve(value);
        });
      }
      return new (P || (P = Promise))(function(resolve, reject) {
        function fulfilled(value) {
          try {
            step(generator.next(value));
          } catch (e) {
            reject(e);
          }
        }
        function rejected(value) {
          try {
            step(generator["throw"](value));
          } catch (e) {
            reject(e);
          }
        }
        function step(result) {
          result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected);
        }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
      });
    };
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.PersonalAccessTokenCredentialHandler = exports.BearerCredentialHandler = exports.BasicCredentialHandler = void 0;
    var BasicCredentialHandler = class {
      constructor(username, password) {
        this.username = username;
        this.password = password;
      }
      prepareRequest(options) {
        if (!options.headers) {
          throw Error("The request has no headers");
        }
        options.headers["Authorization"] = `Basic ${Buffer.from(`${this.username}:${this.password}`).toString("base64")}`;
      }
      // This handler cannot handle 401
      canHandleAuthentication() {
        return false;
      }
      handleAuthentication() {
        return __awaiter(this, void 0, void 0, function* () {
          throw new Error("not implemented");
        });
      }
    };
    exports.BasicCredentialHandler = BasicCredentialHandler;
    var BearerCredentialHandler = class {
      constructor(token) {
        this.token = token;
      }
      // currently implements pre-authorization
      // TODO: support preAuth = false where it hooks on 401
      prepareRequest(options) {
        if (!options.headers) {
          throw Error("The request has no headers");
        }
        options.headers["Authorization"] = `Bearer ${this.token}`;
      }
      // This handler cannot handle 401
      canHandleAuthentication() {
        return false;
      }
      handleAuthentication() {
        return __awaiter(this, void 0, void 0, function* () {
          throw new Error("not implemented");
        });
      }
    };
    exports.BearerCredentialHandler = BearerCredentialHandler;
    var PersonalAccessTokenCredentialHandler = class {
      constructor(token) {
        this.token = token;
      }
      // currently implements pre-authorization
      // TODO: support preAuth = false where it hooks on 401
      prepareRequest(options) {
        if (!options.headers) {
          throw Error("The request has no headers");
        }
        options.headers["Authorization"] = `Basic ${Buffer.from(`PAT:${this.token}`).toString("base64")}`;
      }
      // This handler cannot handle 401
      canHandleAuthentication() {
        return false;
      }
      handleAuthentication() {
        return __awaiter(this, void 0, void 0, function* () {
          throw new Error("not implemented");
        });
      }
    };
    exports.PersonalAccessTokenCredentialHandler = PersonalAccessTokenCredentialHandler;
  }
});

// node_modules/@actions/core/lib/oidc-utils.js
var require_oidc_utils = __commonJS({
  "node_modules/@actions/core/lib/oidc-utils.js"(exports) {
    "use strict";
    var __awaiter = exports && exports.__awaiter || function(thisArg, _arguments, P, generator) {
      function adopt(value) {
        return value instanceof P ? value : new P(function(resolve) {
          resolve(value);
        });
      }
      return new (P || (P = Promise))(function(resolve, reject) {
        function fulfilled(value) {
          try {
            step(generator.next(value));
          } catch (e) {
            reject(e);
          }
        }
        function rejected(value) {
          try {
            step(generator["throw"](value));
          } catch (e) {
            reject(e);
          }
        }
        function step(result) {
          result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected);
        }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
      });
    };
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.OidcClient = void 0;
    var http_client_1 = require_lib();
    var auth_1 = require_auth();
    var core_1 = require_core();
    var OidcClient = class {
      static createHttpClient(allowRetry = true, maxRetry = 10) {
        const requestOptions = {
          allowRetries: allowRetry,
          maxRetries: maxRetry
        };
        return new http_client_1.HttpClient("actions/oidc-client", [new auth_1.BearerCredentialHandler(OidcClient.getRequestToken())], requestOptions);
      }
      static getRequestToken() {
        const token = process.env["ACTIONS_ID_TOKEN_REQUEST_TOKEN"];
        if (!token) {
          throw new Error("Unable to get ACTIONS_ID_TOKEN_REQUEST_TOKEN env variable");
        }
        return token;
      }
      static getIDTokenUrl() {
        const runtimeUrl = process.env["ACTIONS_ID_TOKEN_REQUEST_URL"];
        if (!runtimeUrl) {
          throw new Error("Unable to get ACTIONS_ID_TOKEN_REQUEST_URL env variable");
        }
        return runtimeUrl;
      }
      static getCall(id_token_url) {
        var _a;
        return __awaiter(this, void 0, void 0, function* () {
          const httpclient = OidcClient.createHttpClient();
          const res = yield httpclient.getJson(id_token_url).catch((error) => {
            throw new Error(`Failed to get ID Token. 
 
        Error Code : ${error.statusCode}
 
        Error Message: ${error.result.message}`);
          });
          const id_token = (_a = res.result) === null || _a === void 0 ? void 0 : _a.value;
          if (!id_token) {
            throw new Error("Response json body do not have ID Token field");
          }
          return id_token;
        });
      }
      static getIDToken(audience) {
        return __awaiter(this, void 0, void 0, function* () {
          try {
            let id_token_url = OidcClient.getIDTokenUrl();
            if (audience) {
              const encodedAudience = encodeURIComponent(audience);
              id_token_url = `${id_token_url}&audience=${encodedAudience}`;
            }
            core_1.debug(`ID token url is ${id_token_url}`);
            const id_token = yield OidcClient.getCall(id_token_url);
            core_1.setSecret(id_token);
            return id_token;
          } catch (error) {
            throw new Error(`Error message: ${error.message}`);
          }
        });
      }
    };
    exports.OidcClient = OidcClient;
  }
});

// node_modules/@actions/core/lib/summary.js
var require_summary = __commonJS({
  "node_modules/@actions/core/lib/summary.js"(exports) {
    "use strict";
    var __awaiter = exports && exports.__awaiter || function(thisArg, _arguments, P, generator) {
      function adopt(value) {
        return value instanceof P ? value : new P(function(resolve) {
          resolve(value);
        });
      }
      return new (P || (P = Promise))(function(resolve, reject) {
        function fulfilled(value) {
          try {
            step(generator.next(value));
          } catch (e) {
            reject(e);
          }
        }
        function rejected(value) {
          try {
            step(generator["throw"](value));
          } catch (e) {
            reject(e);
          }
        }
        function step(result) {
          result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected);
        }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
      });
    };
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.summary = exports.markdownSummary = exports.SUMMARY_DOCS_URL = exports.SUMMARY_ENV_VAR = void 0;
    var os_1 = require("os");
    var fs_1 = require("fs");
    var { access, appendFile, writeFile: writeFile2 } = fs_1.promises;
    exports.SUMMARY_ENV_VAR = "GITHUB_STEP_SUMMARY";
    exports.SUMMARY_DOCS_URL = "https://docs.github.com/actions/using-workflows/workflow-commands-for-github-actions#adding-a-job-summary";
    var Summary = class {
      constructor() {
        this._buffer = "";
      }
      /**
       * Finds the summary file path from the environment, rejects if env var is not found or file does not exist
       * Also checks r/w permissions.
       *
       * @returns step summary file path
       */
      filePath() {
        return __awaiter(this, void 0, void 0, function* () {
          if (this._filePath) {
            return this._filePath;
          }
          const pathFromEnv = process.env[exports.SUMMARY_ENV_VAR];
          if (!pathFromEnv) {
            throw new Error(`Unable to find environment variable for $${exports.SUMMARY_ENV_VAR}. Check if your runtime environment supports job summaries.`);
          }
          try {
            yield access(pathFromEnv, fs_1.constants.R_OK | fs_1.constants.W_OK);
          } catch (_a) {
            throw new Error(`Unable to access summary file: '${pathFromEnv}'. Check if the file has correct read/write permissions.`);
          }
          this._filePath = pathFromEnv;
          return this._filePath;
        });
      }
      /**
       * Wraps content in an HTML tag, adding any HTML attributes
       *
       * @param {string} tag HTML tag to wrap
       * @param {string | null} content content within the tag
       * @param {[attribute: string]: string} attrs key-value list of HTML attributes to add
       *
       * @returns {string} content wrapped in HTML element
       */
      wrap(tag, content, attrs = {}) {
        const htmlAttrs = Object.entries(attrs).map(([key, value]) => ` ${key}="${value}"`).join("");
        if (!content) {
          return `<${tag}${htmlAttrs}>`;
        }
        return `<${tag}${htmlAttrs}>${content}</${tag}>`;
      }
      /**
       * Writes text in the buffer to the summary buffer file and empties buffer. Will append by default.
       *
       * @param {SummaryWriteOptions} [options] (optional) options for write operation
       *
       * @returns {Promise<Summary>} summary instance
       */
      write(options) {
        return __awaiter(this, void 0, void 0, function* () {
          const overwrite = !!(options === null || options === void 0 ? void 0 : options.overwrite);
          const filePath = yield this.filePath();
          const writeFunc = overwrite ? writeFile2 : appendFile;
          yield writeFunc(filePath, this._buffer, { encoding: "utf8" });
          return this.emptyBuffer();
        });
      }
      /**
       * Clears the summary buffer and wipes the summary file
       *
       * @returns {Summary} summary instance
       */
      clear() {
        return __awaiter(this, void 0, void 0, function* () {
          return this.emptyBuffer().write({ overwrite: true });
        });
      }
      /**
       * Returns the current summary buffer as a string
       *
       * @returns {string} string of summary buffer
       */
      stringify() {
        return this._buffer;
      }
      /**
       * If the summary buffer is empty
       *
       * @returns {boolen} true if the buffer is empty
       */
      isEmptyBuffer() {
        return this._buffer.length === 0;
      }
      /**
       * Resets the summary buffer without writing to summary file
       *
       * @returns {Summary} summary instance
       */
      emptyBuffer() {
        this._buffer = "";
        return this;
      }
      /**
       * Adds raw text to the summary buffer
       *
       * @param {string} text content to add
       * @param {boolean} [addEOL=false] (optional) append an EOL to the raw text (default: false)
       *
       * @returns {Summary} summary instance
       */
      addRaw(text, addEOL = false) {
        this._buffer += text;
        return addEOL ? this.addEOL() : this;
      }
      /**
       * Adds the operating system-specific end-of-line marker to the buffer
       *
       * @returns {Summary} summary instance
       */
      addEOL() {
        return this.addRaw(os_1.EOL);
      }
      /**
       * Adds an HTML codeblock to the summary buffer
       *
       * @param {string} code content to render within fenced code block
       * @param {string} lang (optional) language to syntax highlight code
       *
       * @returns {Summary} summary instance
       */
      addCodeBlock(code, lang) {
        const attrs = Object.assign({}, lang && { lang });
        const element = this.wrap("pre", this.wrap("code", code), attrs);
        return this.addRaw(element).addEOL();
      }
      /**
       * Adds an HTML list to the summary buffer
       *
       * @param {string[]} items list of items to render
       * @param {boolean} [ordered=false] (optional) if the rendered list should be ordered or not (default: false)
       *
       * @returns {Summary} summary instance
       */
      addList(items, ordered = false) {
        const tag = ordered ? "ol" : "ul";
        const listItems = items.map((item) => this.wrap("li", item)).join("");
        const element = this.wrap(tag, listItems);
        return this.addRaw(element).addEOL();
      }
      /**
       * Adds an HTML table to the summary buffer
       *
       * @param {SummaryTableCell[]} rows table rows
       *
       * @returns {Summary} summary instance
       */
      addTable(rows) {
        const tableBody = rows.map((row) => {
          const cells = row.map((cell) => {
            if (typeof cell === "string") {
              return this.wrap("td", cell);
            }
            const { header, data, colspan, rowspan } = cell;
            const tag = header ? "th" : "td";
            const attrs = Object.assign(Object.assign({}, colspan && { colspan }), rowspan && { rowspan });
            return this.wrap(tag, data, attrs);
          }).join("");
          return this.wrap("tr", cells);
        }).join("");
        const element = this.wrap("table", tableBody);
        return this.addRaw(element).addEOL();
      }
      /**
       * Adds a collapsable HTML details element to the summary buffer
       *
       * @param {string} label text for the closed state
       * @param {string} content collapsable content
       *
       * @returns {Summary} summary instance
       */
      addDetails(label, content) {
        const element = this.wrap("details", this.wrap("summary", label) + content);
        return this.addRaw(element).addEOL();
      }
      /**
       * Adds an HTML image tag to the summary buffer
       *
       * @param {string} src path to the image you to embed
       * @param {string} alt text description of the image
       * @param {SummaryImageOptions} options (optional) addition image attributes
       *
       * @returns {Summary} summary instance
       */
      addImage(src, alt, options) {
        const { width, height } = options || {};
        const attrs = Object.assign(Object.assign({}, width && { width }), height && { height });
        const element = this.wrap("img", null, Object.assign({ src, alt }, attrs));
        return this.addRaw(element).addEOL();
      }
      /**
       * Adds an HTML section heading element
       *
       * @param {string} text heading text
       * @param {number | string} [level=1] (optional) the heading level, default: 1
       *
       * @returns {Summary} summary instance
       */
      addHeading(text, level) {
        const tag = `h${level}`;
        const allowedTag = ["h1", "h2", "h3", "h4", "h5", "h6"].includes(tag) ? tag : "h1";
        const element = this.wrap(allowedTag, text);
        return this.addRaw(element).addEOL();
      }
      /**
       * Adds an HTML thematic break (<hr>) to the summary buffer
       *
       * @returns {Summary} summary instance
       */
      addSeparator() {
        const element = this.wrap("hr", null);
        return this.addRaw(element).addEOL();
      }
      /**
       * Adds an HTML line break (<br>) to the summary buffer
       *
       * @returns {Summary} summary instance
       */
      addBreak() {
        const element = this.wrap("br", null);
        return this.addRaw(element).addEOL();
      }
      /**
       * Adds an HTML blockquote to the summary buffer
       *
       * @param {string} text quote text
       * @param {string} cite (optional) citation url
       *
       * @returns {Summary} summary instance
       */
      addQuote(text, cite) {
        const attrs = Object.assign({}, cite && { cite });
        const element = this.wrap("blockquote", text, attrs);
        return this.addRaw(element).addEOL();
      }
      /**
       * Adds an HTML anchor tag to the summary buffer
       *
       * @param {string} text link text/content
       * @param {string} href hyperlink
       *
       * @returns {Summary} summary instance
       */
      addLink(text, href) {
        const element = this.wrap("a", text, { href });
        return this.addRaw(element).addEOL();
      }
    };
    var _summary = new Summary();
    exports.markdownSummary = _summary;
    exports.summary = _summary;
  }
});

// node_modules/@actions/core/lib/path-utils.js
var require_path_utils = __commonJS({
  "node_modules/@actions/core/lib/path-utils.js"(exports) {
    "use strict";
    var __createBinding = exports && exports.__createBinding || (Object.create ? function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      Object.defineProperty(o, k2, { enumerable: true, get: function() {
        return m[k];
      } });
    } : function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      o[k2] = m[k];
    });
    var __setModuleDefault = exports && exports.__setModuleDefault || (Object.create ? function(o, v) {
      Object.defineProperty(o, "default", { enumerable: true, value: v });
    } : function(o, v) {
      o["default"] = v;
    });
    var __importStar = exports && exports.__importStar || function(mod) {
      if (mod && mod.__esModule)
        return mod;
      var result = {};
      if (mod != null) {
        for (var k in mod)
          if (k !== "default" && Object.hasOwnProperty.call(mod, k))
            __createBinding(result, mod, k);
      }
      __setModuleDefault(result, mod);
      return result;
    };
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.toPlatformPath = exports.toWin32Path = exports.toPosixPath = void 0;
    var path2 = __importStar(require("path"));
    function toPosixPath(pth) {
      return pth.replace(/[\\]/g, "/");
    }
    exports.toPosixPath = toPosixPath;
    function toWin32Path(pth) {
      return pth.replace(/[/]/g, "\\");
    }
    exports.toWin32Path = toWin32Path;
    function toPlatformPath(pth) {
      return pth.replace(/[/\\]/g, path2.sep);
    }
    exports.toPlatformPath = toPlatformPath;
  }
});

// node_modules/@actions/core/lib/core.js
var require_core = __commonJS({
  "node_modules/@actions/core/lib/core.js"(exports) {
    "use strict";
    var __createBinding = exports && exports.__createBinding || (Object.create ? function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      Object.defineProperty(o, k2, { enumerable: true, get: function() {
        return m[k];
      } });
    } : function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      o[k2] = m[k];
    });
    var __setModuleDefault = exports && exports.__setModuleDefault || (Object.create ? function(o, v) {
      Object.defineProperty(o, "default", { enumerable: true, value: v });
    } : function(o, v) {
      o["default"] = v;
    });
    var __importStar = exports && exports.__importStar || function(mod) {
      if (mod && mod.__esModule)
        return mod;
      var result = {};
      if (mod != null) {
        for (var k in mod)
          if (k !== "default" && Object.hasOwnProperty.call(mod, k))
            __createBinding(result, mod, k);
      }
      __setModuleDefault(result, mod);
      return result;
    };
    var __awaiter = exports && exports.__awaiter || function(thisArg, _arguments, P, generator) {
      function adopt(value) {
        return value instanceof P ? value : new P(function(resolve) {
          resolve(value);
        });
      }
      return new (P || (P = Promise))(function(resolve, reject) {
        function fulfilled(value) {
          try {
            step(generator.next(value));
          } catch (e) {
            reject(e);
          }
        }
        function rejected(value) {
          try {
            step(generator["throw"](value));
          } catch (e) {
            reject(e);
          }
        }
        function step(result) {
          result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected);
        }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
      });
    };
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.getIDToken = exports.getState = exports.saveState = exports.group = exports.endGroup = exports.startGroup = exports.info = exports.notice = exports.warning = exports.error = exports.debug = exports.isDebug = exports.setFailed = exports.setCommandEcho = exports.setOutput = exports.getBooleanInput = exports.getMultilineInput = exports.getInput = exports.addPath = exports.setSecret = exports.exportVariable = exports.ExitCode = void 0;
    var command_1 = require_command();
    var file_command_1 = require_file_command();
    var utils_1 = require_utils();
    var os = __importStar(require("os"));
    var path2 = __importStar(require("path"));
    var oidc_utils_1 = require_oidc_utils();
    var ExitCode;
    (function(ExitCode2) {
      ExitCode2[ExitCode2["Success"] = 0] = "Success";
      ExitCode2[ExitCode2["Failure"] = 1] = "Failure";
    })(ExitCode = exports.ExitCode || (exports.ExitCode = {}));
    function exportVariable(name, val) {
      const convertedVal = utils_1.toCommandValue(val);
      process.env[name] = convertedVal;
      const filePath = process.env["GITHUB_ENV"] || "";
      if (filePath) {
        return file_command_1.issueFileCommand("ENV", file_command_1.prepareKeyValueMessage(name, val));
      }
      command_1.issueCommand("set-env", { name }, convertedVal);
    }
    exports.exportVariable = exportVariable;
    function setSecret(secret) {
      command_1.issueCommand("add-mask", {}, secret);
    }
    exports.setSecret = setSecret;
    function addPath(inputPath) {
      const filePath = process.env["GITHUB_PATH"] || "";
      if (filePath) {
        file_command_1.issueFileCommand("PATH", inputPath);
      } else {
        command_1.issueCommand("add-path", {}, inputPath);
      }
      process.env["PATH"] = `${inputPath}${path2.delimiter}${process.env["PATH"]}`;
    }
    exports.addPath = addPath;
    function getInput2(name, options) {
      const val = process.env[`INPUT_${name.replace(/ /g, "_").toUpperCase()}`] || "";
      if (options && options.required && !val) {
        throw new Error(`Input required and not supplied: ${name}`);
      }
      if (options && options.trimWhitespace === false) {
        return val;
      }
      return val.trim();
    }
    exports.getInput = getInput2;
    function getMultilineInput(name, options) {
      const inputs = getInput2(name, options).split("\n").filter((x) => x !== "");
      if (options && options.trimWhitespace === false) {
        return inputs;
      }
      return inputs.map((input) => input.trim());
    }
    exports.getMultilineInput = getMultilineInput;
    function getBooleanInput(name, options) {
      const trueValue = ["true", "True", "TRUE"];
      const falseValue = ["false", "False", "FALSE"];
      const val = getInput2(name, options);
      if (trueValue.includes(val))
        return true;
      if (falseValue.includes(val))
        return false;
      throw new TypeError(`Input does not meet YAML 1.2 "Core Schema" specification: ${name}
Support boolean input list: \`true | True | TRUE | false | False | FALSE\``);
    }
    exports.getBooleanInput = getBooleanInput;
    function setOutput(name, value) {
      const filePath = process.env["GITHUB_OUTPUT"] || "";
      if (filePath) {
        return file_command_1.issueFileCommand("OUTPUT", file_command_1.prepareKeyValueMessage(name, value));
      }
      process.stdout.write(os.EOL);
      command_1.issueCommand("set-output", { name }, utils_1.toCommandValue(value));
    }
    exports.setOutput = setOutput;
    function setCommandEcho(enabled) {
      command_1.issue("echo", enabled ? "on" : "off");
    }
    exports.setCommandEcho = setCommandEcho;
    function setFailed(message) {
      process.exitCode = ExitCode.Failure;
      error(message);
    }
    exports.setFailed = setFailed;
    function isDebug() {
      return process.env["RUNNER_DEBUG"] === "1";
    }
    exports.isDebug = isDebug;
    function debug(message) {
      command_1.issueCommand("debug", {}, message);
    }
    exports.debug = debug;
    function error(message, properties = {}) {
      command_1.issueCommand("error", utils_1.toCommandProperties(properties), message instanceof Error ? message.toString() : message);
    }
    exports.error = error;
    function warning(message, properties = {}) {
      command_1.issueCommand("warning", utils_1.toCommandProperties(properties), message instanceof Error ? message.toString() : message);
    }
    exports.warning = warning;
    function notice(message, properties = {}) {
      command_1.issueCommand("notice", utils_1.toCommandProperties(properties), message instanceof Error ? message.toString() : message);
    }
    exports.notice = notice;
    function info(message) {
      process.stdout.write(message + os.EOL);
    }
    exports.info = info;
    function startGroup(name) {
      command_1.issue("group", name);
    }
    exports.startGroup = startGroup;
    function endGroup() {
      command_1.issue("endgroup");
    }
    exports.endGroup = endGroup;
    function group(name, fn) {
      return __awaiter(this, void 0, void 0, function* () {
        startGroup(name);
        let result;
        try {
          result = yield fn();
        } finally {
          endGroup();
        }
        return result;
      });
    }
    exports.group = group;
    function saveState(name, value) {
      const filePath = process.env["GITHUB_STATE"] || "";
      if (filePath) {
        return file_command_1.issueFileCommand("STATE", file_command_1.prepareKeyValueMessage(name, value));
      }
      command_1.issueCommand("save-state", { name }, utils_1.toCommandValue(value));
    }
    exports.saveState = saveState;
    function getState(name) {
      return process.env[`STATE_${name}`] || "";
    }
    exports.getState = getState;
    function getIDToken(aud) {
      return __awaiter(this, void 0, void 0, function* () {
        return yield oidc_utils_1.OidcClient.getIDToken(aud);
      });
    }
    exports.getIDToken = getIDToken;
    var summary_1 = require_summary();
    Object.defineProperty(exports, "summary", { enumerable: true, get: function() {
      return summary_1.summary;
    } });
    var summary_2 = require_summary();
    Object.defineProperty(exports, "markdownSummary", { enumerable: true, get: function() {
      return summary_2.markdownSummary;
    } });
    var path_utils_1 = require_path_utils();
    Object.defineProperty(exports, "toPosixPath", { enumerable: true, get: function() {
      return path_utils_1.toPosixPath;
    } });
    Object.defineProperty(exports, "toWin32Path", { enumerable: true, get: function() {
      return path_utils_1.toWin32Path;
    } });
    Object.defineProperty(exports, "toPlatformPath", { enumerable: true, get: function() {
      return path_utils_1.toPlatformPath;
    } });
  }
});

// node_modules/drand-client/version.js
var require_version = __commonJS({
  "node_modules/drand-client/version.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.LIB_VERSION = void 0;
    exports.LIB_VERSION = "1.1.0";
  }
});

// node_modules/drand-client/util.js
var require_util = __commonJS({
  "node_modules/drand-client/util.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.retryOnError = exports.jsonOrError = exports.defaultHttpOptions = exports.roundTime = exports.roundAt = exports.sleep = void 0;
    var version_1 = require_version();
    function sleep(timeMs) {
      return new Promise((resolve) => {
        if (timeMs <= 0) {
          resolve();
        }
        setTimeout(resolve, timeMs);
      });
    }
    exports.sleep = sleep;
    function roundAt(time, chain) {
      if (!Number.isFinite(time)) {
        throw new Error("Cannot use Infinity or NaN as a beacon time");
      }
      if (time < chain.genesis_time * 1e3) {
        throw Error("Cannot request a round before the genesis time");
      }
      return Math.floor((time - chain.genesis_time * 1e3) / (chain.period * 1e3)) + 1;
    }
    exports.roundAt = roundAt;
    function roundTime(chain, round) {
      if (!Number.isFinite(round)) {
        throw new Error("Cannot use Infinity or NaN as a round number");
      }
      round = round < 0 ? 0 : round;
      return (chain.genesis_time + (round - 1) * chain.period) * 1e3;
    }
    exports.roundTime = roundTime;
    exports.defaultHttpOptions = {
      userAgent: `drand-client-${version_1.LIB_VERSION}`
    };
    async function jsonOrError(url, options = exports.defaultHttpOptions) {
      const headers = { ...options.headers };
      if (options.userAgent) {
        headers["User-Agent"] = options.userAgent;
      }
      const response = await fetch(url, { headers });
      if (!response.ok) {
        throw Error(`Error response fetching ${url} - got ${response.status}`);
      }
      return await response.json();
    }
    exports.jsonOrError = jsonOrError;
    async function retryOnError(fn, times) {
      try {
        return await fn();
      } catch (err) {
        if (times === 0) {
          throw err;
        }
        return retryOnError(fn, times - 1);
      }
    }
    exports.retryOnError = retryOnError;
  }
});

// node_modules/drand-client/http-caching-chain.js
var require_http_caching_chain = __commonJS({
  "node_modules/drand-client/http-caching-chain.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.HttpChain = void 0;
    var index_1 = require_drand_client();
    var util_1 = require_util();
    var HttpChain = class {
      baseUrl;
      options;
      httpOptions;
      constructor(baseUrl, options = index_1.defaultChainOptions, httpOptions = {}) {
        this.baseUrl = baseUrl;
        this.options = options;
        this.httpOptions = httpOptions;
      }
      async info() {
        const chainInfo = await (0, util_1.jsonOrError)(`${this.baseUrl}/info`, this.httpOptions);
        if (!!this.options.chainVerificationParams && !isValidInfo(chainInfo, this.options.chainVerificationParams)) {
          throw Error(`The chain info retrieved from ${this.baseUrl} did not match the verification params!`);
        }
        return chainInfo;
      }
    };
    exports.HttpChain = HttpChain;
    function isValidInfo(chainInfo, validParams) {
      return chainInfo.hash === validParams.chainHash && chainInfo.public_key === validParams.publicKey;
    }
    var HttpCachingChain2 = class {
      baseUrl;
      options;
      chain;
      cachedInfo;
      constructor(baseUrl, options = index_1.defaultChainOptions) {
        this.baseUrl = baseUrl;
        this.options = options;
        this.chain = new HttpChain(baseUrl, options);
      }
      async info() {
        if (!this.cachedInfo) {
          this.cachedInfo = await this.chain.info();
        }
        return this.cachedInfo;
      }
    };
    exports.default = HttpCachingChain2;
  }
});

// node_modules/drand-client/http-chain-client.js
var require_http_chain_client = __commonJS({
  "node_modules/drand-client/http-chain-client.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    var index_1 = require_drand_client();
    var util_1 = require_util();
    var HttpChainClient2 = class {
      someChain;
      options;
      httpOptions;
      constructor(someChain, options = index_1.defaultChainOptions, httpOptions = util_1.defaultHttpOptions) {
        this.someChain = someChain;
        this.options = options;
        this.httpOptions = httpOptions;
      }
      async get(roundNumber) {
        const url = withCachingParams(`${this.someChain.baseUrl}/public/${roundNumber}`, this.options);
        return await (0, util_1.jsonOrError)(url, this.httpOptions);
      }
      async latest() {
        const url = withCachingParams(`${this.someChain.baseUrl}/public/latest`, this.options);
        return await (0, util_1.jsonOrError)(url, this.httpOptions);
      }
      chain() {
        return this.someChain;
      }
    };
    function withCachingParams(url, config) {
      if (config.noCache) {
        return `${url}?${Date.now()}`;
      }
      return url;
    }
    exports.default = HttpChainClient2;
  }
});

// node_modules/drand-client/speedtest.js
var require_speedtest = __commonJS({
  "node_modules/drand-client/speedtest.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.createSpeedTest = void 0;
    function createSpeedTest(test, frequencyMs, samples = 5) {
      let queue = new DroppingQueue(samples);
      let intervalId = null;
      const executeSpeedTest = async () => {
        const startTime = Date.now();
        try {
          await test();
          queue.add(Date.now() - startTime);
        } catch (err) {
          queue.add(Number.MAX_SAFE_INTEGER);
        }
      };
      return {
        start: () => {
          if (intervalId != null) {
            console.warn("Attempted to start a speed test, but it had already been started!");
            return;
          }
          intervalId = setInterval(executeSpeedTest, frequencyMs);
        },
        stop: () => {
          if (intervalId !== null) {
            clearInterval(intervalId);
            intervalId = null;
            queue = new DroppingQueue(samples);
          }
        },
        average: () => {
          const values = queue.get();
          if (values.length === 0) {
            return Number.MAX_SAFE_INTEGER;
          }
          const total = values.reduce((acc, next) => acc + next, 0);
          return total / values.length;
        }
      };
    }
    exports.createSpeedTest = createSpeedTest;
    var DroppingQueue = class {
      capacity;
      values = [];
      constructor(capacity) {
        this.capacity = capacity;
      }
      add(value) {
        this.values.push(value);
        if (this.values.length > this.capacity) {
          this.values.pop();
        }
      }
      get() {
        return this.values;
      }
    };
  }
});

// node_modules/drand-client/fastest-node-client.js
var require_fastest_node_client = __commonJS({
  "node_modules/drand-client/fastest-node-client.js"(exports) {
    "use strict";
    var __createBinding = exports && exports.__createBinding || (Object.create ? function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      var desc = Object.getOwnPropertyDescriptor(m, k);
      if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
        desc = { enumerable: true, get: function() {
          return m[k];
        } };
      }
      Object.defineProperty(o, k2, desc);
    } : function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      o[k2] = m[k];
    });
    var __setModuleDefault = exports && exports.__setModuleDefault || (Object.create ? function(o, v) {
      Object.defineProperty(o, "default", { enumerable: true, value: v });
    } : function(o, v) {
      o["default"] = v;
    });
    var __importStar = exports && exports.__importStar || function(mod) {
      if (mod && mod.__esModule)
        return mod;
      var result = {};
      if (mod != null) {
        for (var k in mod)
          if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k))
            __createBinding(result, mod, k);
      }
      __setModuleDefault(result, mod);
      return result;
    };
    var __importDefault = exports && exports.__importDefault || function(mod) {
      return mod && mod.__esModule ? mod : { "default": mod };
    };
    Object.defineProperty(exports, "__esModule", { value: true });
    var index_1 = require_drand_client();
    var http_caching_chain_1 = __importStar(require_http_caching_chain());
    var speedtest_1 = require_speedtest();
    var http_chain_client_1 = __importDefault(require_http_chain_client());
    var defaultSpeedTestInterval = 1e3 * 60 * 5;
    var FastestNodeClient = class {
      baseUrls;
      options;
      speedTestIntervalMs;
      speedTests = [];
      speedTestHttpOptions = { userAgent: "drand-web-client-speedtest" };
      constructor(baseUrls, options = index_1.defaultChainOptions, speedTestIntervalMs = defaultSpeedTestInterval) {
        this.baseUrls = baseUrls;
        this.options = options;
        this.speedTestIntervalMs = speedTestIntervalMs;
        if (baseUrls.length === 0) {
          throw Error("Can't optimise an empty `baseUrls` array!");
        }
      }
      async latest() {
        return new http_chain_client_1.default(this.current(), this.options).latest();
      }
      async get(roundNumber) {
        return new http_chain_client_1.default(this.current(), this.options).get(roundNumber);
      }
      chain() {
        return this.current();
      }
      start() {
        if (this.baseUrls.length === 1) {
          console.warn("There was only a single base URL in the `FastestNodeClient` - not running speed testing");
          return;
        }
        this.speedTests = this.baseUrls.map((url) => {
          const testFn = async () => {
            await new http_caching_chain_1.HttpChain(url, this.options, this.speedTestHttpOptions).info();
            return;
          };
          const test = (0, speedtest_1.createSpeedTest)(testFn, this.speedTestIntervalMs);
          test.start();
          return { test, url };
        });
      }
      current() {
        if (this.speedTests.length === 0) {
          console.warn("You are not currently running speed tests to choose the fastest client. Run `.start()` to speed test");
        }
        const fastestEntry = this.speedTests.slice().sort((entry1, entry2) => entry1.test.average() - entry2.test.average()).shift();
        if (!fastestEntry) {
          throw Error("Somehow there were no entries to optimise! This should be impossible by now");
        }
        return new http_caching_chain_1.default(fastestEntry.url, this.options);
      }
      stop() {
        this.speedTests.forEach((entry) => entry.test.stop());
        this.speedTests = [];
      }
    };
    exports.default = FastestNodeClient;
  }
});

// node_modules/drand-client/multi-beacon-node.js
var require_multi_beacon_node = __commonJS({
  "node_modules/drand-client/multi-beacon-node.js"(exports) {
    "use strict";
    var __importDefault = exports && exports.__importDefault || function(mod) {
      return mod && mod.__esModule ? mod : { "default": mod };
    };
    Object.defineProperty(exports, "__esModule", { value: true });
    var index_1 = require_drand_client();
    var http_caching_chain_1 = __importDefault(require_http_caching_chain());
    var util_1 = require_util();
    var MultiBeaconNode = class {
      baseUrl;
      options;
      constructor(baseUrl, options = index_1.defaultChainOptions) {
        this.baseUrl = baseUrl;
        this.options = options;
      }
      async chains() {
        const chains = await (0, util_1.jsonOrError)(`${this.baseUrl}/chains`);
        if (!Array.isArray(chains)) {
          throw Error(`Expected an array from the chains endpoint but got: ${chains}`);
        }
        return chains.map((chainHash) => new http_caching_chain_1.default(`${this.baseUrl}/${chainHash}`), this.options);
      }
      async health() {
        const response = await fetch(`${this.baseUrl}/health`);
        if (!response.ok) {
          return {
            status: response.status,
            current: -1,
            expected: -1
          };
        }
        const json = await response.json();
        return {
          status: response.status,
          current: json.current ?? -1,
          expected: json.expected ?? -1
        };
      }
    };
    exports.default = MultiBeaconNode;
  }
});

// node_modules/@noble/bls12-381/lib/math.js
var require_math = __commonJS({
  "node_modules/@noble/bls12-381/lib/math.js"(exports) {
    "use strict";
    var _a;
    var _b;
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.psi2 = exports.psi = exports.millerLoop = exports.calcPairingPrecomputes = exports.isogenyMapG1 = exports.isogenyMapG2 = exports.map_to_curve_simple_swu_3mod4 = exports.map_to_curve_simple_swu_9mod16 = exports.ProjectivePoint = exports.Fp12 = exports.Fp6 = exports.Fp2 = exports.Fr = exports.Fp = exports.concatBytes = exports.bytesToNumberBE = exports.bytesToHex = exports.numberToBytesBE = exports.hexToBytes = exports.powMod = exports.mod = exports.CURVE = void 0;
    exports.CURVE = {
      P: 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaabn,
      r: 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n,
      h: 0x396c8c005555e1568c00aaab0000aaabn,
      Gx: 0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bbn,
      Gy: 0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1n,
      b: 4n,
      P2: 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaabn ** 2n - 1n,
      h2: 0x5d543a95414e7f1091d50792876a202cd91de4547085abaa68a205b2e5a7ddfa628f1cb4d9e82ef21537e293a6691ae1616ec6e786f0c70cf1c38e31c7238e5n,
      G2x: [
        0x024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8n,
        0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7en
      ],
      G2y: [
        0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801n,
        0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79ben
      ],
      b2: [4n, 4n],
      x: 0xd201000000010000n,
      h2Eff: 0xbc69f08f2ee75b3584c6a0ea91b352888e2a8e9145ad7689986ff031508ffe1329c2f178731db956d82bf015d1212b02ec0ec69d7477c1ae954cbc06689f6a359894c0adebbf6b4e8020005aaa95551n
    };
    var BLS_X_LEN = bitLen(exports.CURVE.x);
    function mod(a, b) {
      const res = a % b;
      return res >= 0n ? res : b + res;
    }
    exports.mod = mod;
    function powMod(num, power, modulo) {
      if (modulo <= 0n || power < 0n)
        throw new Error("Expected power/modulo > 0");
      if (modulo === 1n)
        return 0n;
      let res = 1n;
      while (power > 0n) {
        if (power & 1n)
          res = res * num % modulo;
        num = num * num % modulo;
        power >>= 1n;
      }
      return res;
    }
    exports.powMod = powMod;
    function genInvertBatch(cls, nums) {
      const tmp = new Array(nums.length);
      const lastMultiplied = nums.reduce((acc, num, i) => {
        if (num.isZero())
          return acc;
        tmp[i] = acc;
        return acc.multiply(num);
      }, cls.ONE);
      const inverted = lastMultiplied.invert();
      nums.reduceRight((acc, num, i) => {
        if (num.isZero())
          return acc;
        tmp[i] = acc.multiply(tmp[i]);
        return acc.multiply(num);
      }, inverted);
      return tmp;
    }
    function bitLen(n) {
      let len;
      for (len = 0; n > 0n; n >>= 1n, len += 1)
        ;
      return len;
    }
    function bitGet(n, pos) {
      return n >> BigInt(pos) & 1n;
    }
    function invert(number2, modulo = exports.CURVE.P) {
      const _0n = 0n;
      const _1n = 1n;
      if (number2 === _0n || modulo <= _0n) {
        throw new Error(`invert: expected positive integers, got n=${number2} mod=${modulo}`);
      }
      let a = mod(number2, modulo);
      let b = modulo;
      let x = _0n, y = _1n, u = _1n, v = _0n;
      while (a !== _0n) {
        const q = b / a;
        const r = b % a;
        const m = x - u * q;
        const n = y - v * q;
        b = a, a = r, x = u, y = v, u = m, v = n;
      }
      const gcd = b;
      if (gcd !== _1n)
        throw new Error("invert: does not exist");
      return mod(x, modulo);
    }
    function hexToBytes(hex) {
      if (typeof hex !== "string") {
        throw new TypeError("hexToBytes: expected string, got " + typeof hex);
      }
      if (hex.length % 2)
        throw new Error("hexToBytes: received invalid unpadded hex");
      const array = new Uint8Array(hex.length / 2);
      for (let i = 0; i < array.length; i++) {
        const j = i * 2;
        const hexByte = hex.slice(j, j + 2);
        if (hexByte.length !== 2)
          throw new Error("Invalid byte sequence");
        const byte = Number.parseInt(hexByte, 16);
        if (Number.isNaN(byte) || byte < 0)
          throw new Error("Invalid byte sequence");
        array[i] = byte;
      }
      return array;
    }
    exports.hexToBytes = hexToBytes;
    function numberToHex(num, byteLength) {
      if (!byteLength)
        throw new Error("byteLength target must be specified");
      const hex = num.toString(16);
      const p1 = hex.length & 1 ? `0${hex}` : hex;
      return p1.padStart(byteLength * 2, "0");
    }
    function numberToBytesBE(num, byteLength) {
      const res = hexToBytes(numberToHex(num, byteLength));
      if (res.length !== byteLength)
        throw new Error("numberToBytesBE: wrong byteLength");
      return res;
    }
    exports.numberToBytesBE = numberToBytesBE;
    var hexes2 = Array.from({ length: 256 }, (v, i) => i.toString(16).padStart(2, "0"));
    function bytesToHex(uint8a) {
      let hex = "";
      for (let i = 0; i < uint8a.length; i++) {
        hex += hexes2[uint8a[i]];
      }
      return hex;
    }
    exports.bytesToHex = bytesToHex;
    function bytesToNumberBE(bytes2) {
      return BigInt("0x" + bytesToHex(bytes2));
    }
    exports.bytesToNumberBE = bytesToNumberBE;
    function concatBytes(...arrays) {
      if (arrays.length === 1)
        return arrays[0];
      const length = arrays.reduce((a, arr) => a + arr.length, 0);
      const result = new Uint8Array(length);
      for (let i = 0, pad = 0; i < arrays.length; i++) {
        const arr = arrays[i];
        result.set(arr, pad);
        pad += arr.length;
      }
      return result;
    }
    exports.concatBytes = concatBytes;
    var Fp = class {
      constructor(value) {
        this.value = mod(value, Fp.ORDER);
      }
      isZero() {
        return this.value === 0n;
      }
      equals(rhs) {
        return this.value === rhs.value;
      }
      negate() {
        return new Fp(-this.value);
      }
      invert() {
        return new Fp(invert(this.value, Fp.ORDER));
      }
      add(rhs) {
        return new Fp(this.value + rhs.value);
      }
      square() {
        return new Fp(this.value * this.value);
      }
      pow(n) {
        return new Fp(powMod(this.value, n, Fp.ORDER));
      }
      sqrt() {
        const root = this.pow((Fp.ORDER + 1n) / 4n);
        if (!root.square().equals(this))
          return;
        return root;
      }
      subtract(rhs) {
        return new Fp(this.value - rhs.value);
      }
      multiply(rhs) {
        if (rhs instanceof Fp)
          rhs = rhs.value;
        return new Fp(this.value * rhs);
      }
      div(rhs) {
        if (typeof rhs === "bigint")
          rhs = new Fp(rhs);
        return this.multiply(rhs.invert());
      }
      toString() {
        const str = this.value.toString(16).padStart(96, "0");
        return str.slice(0, 2) + "." + str.slice(-2);
      }
      static fromBytes(b) {
        if (b.length !== Fp.BYTES_LEN)
          throw new Error(`fromBytes wrong length=${b.length}`);
        return new Fp(bytesToNumberBE(b));
      }
      toBytes() {
        return numberToBytesBE(this.value, Fp.BYTES_LEN);
      }
    };
    exports.Fp = Fp;
    _a = Fp;
    Fp.ORDER = exports.CURVE.P;
    Fp.MAX_BITS = bitLen(exports.CURVE.P);
    Fp.BYTES_LEN = Math.ceil(_a.MAX_BITS / 8);
    Fp.ZERO = new Fp(0n);
    Fp.ONE = new Fp(1n);
    var Fr = class {
      constructor(value) {
        this.value = mod(value, Fr.ORDER);
      }
      static isValid(b) {
        return b <= Fr.ORDER;
      }
      isZero() {
        return this.value === 0n;
      }
      equals(rhs) {
        return this.value === rhs.value;
      }
      negate() {
        return new Fr(-this.value);
      }
      invert() {
        return new Fr(invert(this.value, Fr.ORDER));
      }
      add(rhs) {
        return new Fr(this.value + rhs.value);
      }
      square() {
        return new Fr(this.value * this.value);
      }
      pow(n) {
        return new Fr(powMod(this.value, n, Fr.ORDER));
      }
      subtract(rhs) {
        return new Fr(this.value - rhs.value);
      }
      multiply(rhs) {
        if (rhs instanceof Fr)
          rhs = rhs.value;
        return new Fr(this.value * rhs);
      }
      div(rhs) {
        if (typeof rhs === "bigint")
          rhs = new Fr(rhs);
        return this.multiply(rhs.invert());
      }
      legendre() {
        return this.pow((Fr.ORDER - 1n) / 2n);
      }
      sqrt() {
        if (!this.legendre().equals(Fr.ONE))
          return;
        const P = Fr.ORDER;
        let q, s, z;
        for (q = P - 1n, s = 0; q % 2n === 0n; q /= 2n, s++)
          ;
        if (s === 1)
          return this.pow((P + 1n) / 4n);
        for (z = 2n; z < P && new Fr(z).legendre().value !== P - 1n; z++)
          ;
        let c = powMod(z, q, P);
        let r = powMod(this.value, (q + 1n) / 2n, P);
        let t = powMod(this.value, q, P);
        let t2 = 0n;
        while (mod(t - 1n, P) !== 0n) {
          t2 = mod(t * t, P);
          let i;
          for (i = 1; i < s; i++) {
            if (mod(t2 - 1n, P) === 0n)
              break;
            t2 = mod(t2 * t2, P);
          }
          let b = powMod(c, BigInt(1 << s - i - 1), P);
          r = mod(r * b, P);
          c = mod(b * b, P);
          t = mod(t * c, P);
          s = i;
        }
        return new Fr(r);
      }
      toString() {
        return "0x" + this.value.toString(16).padStart(64, "0");
      }
    };
    exports.Fr = Fr;
    Fr.ORDER = exports.CURVE.r;
    Fr.ZERO = new Fr(0n);
    Fr.ONE = new Fr(1n);
    function powMod_FQP(fqp, fqpOne, n) {
      const elm = fqp;
      if (n === 0n)
        return fqpOne;
      if (n === 1n)
        return elm;
      let p = fqpOne;
      let d = elm;
      while (n > 0n) {
        if (n & 1n)
          p = p.multiply(d);
        n >>= 1n;
        d = d.square();
      }
      return p;
    }
    var Fp2 = class {
      constructor(c0, c1) {
        this.c0 = c0;
        this.c1 = c1;
        if (typeof c0 === "bigint")
          throw new Error("c0: Expected Fp");
        if (typeof c1 === "bigint")
          throw new Error("c1: Expected Fp");
      }
      static fromBigTuple(tuple) {
        const fps = tuple.map((n) => new Fp(n));
        return new Fp2(...fps);
      }
      one() {
        return Fp2.ONE;
      }
      isZero() {
        return this.c0.isZero() && this.c1.isZero();
      }
      toString() {
        return `Fp2(${this.c0} + ${this.c1}\xD7i)`;
      }
      reim() {
        return { re: this.c0.value, im: this.c1.value };
      }
      negate() {
        const { c0, c1 } = this;
        return new Fp2(c0.negate(), c1.negate());
      }
      equals(rhs) {
        const { c0, c1 } = this;
        const { c0: r0, c1: r1 } = rhs;
        return c0.equals(r0) && c1.equals(r1);
      }
      add(rhs) {
        const { c0, c1 } = this;
        const { c0: r0, c1: r1 } = rhs;
        return new Fp2(c0.add(r0), c1.add(r1));
      }
      subtract(rhs) {
        const { c0, c1 } = this;
        const { c0: r0, c1: r1 } = rhs;
        return new Fp2(c0.subtract(r0), c1.subtract(r1));
      }
      multiply(rhs) {
        const { c0, c1 } = this;
        if (typeof rhs === "bigint") {
          return new Fp2(c0.multiply(rhs), c1.multiply(rhs));
        }
        const { c0: r0, c1: r1 } = rhs;
        let t1 = c0.multiply(r0);
        let t2 = c1.multiply(r1);
        return new Fp2(t1.subtract(t2), c0.add(c1).multiply(r0.add(r1)).subtract(t1.add(t2)));
      }
      pow(n) {
        return powMod_FQP(this, Fp2.ONE, n);
      }
      div(rhs) {
        const inv = typeof rhs === "bigint" ? new Fp(rhs).invert().value : rhs.invert();
        return this.multiply(inv);
      }
      mulByNonresidue() {
        const c0 = this.c0;
        const c1 = this.c1;
        return new Fp2(c0.subtract(c1), c0.add(c1));
      }
      square() {
        const c0 = this.c0;
        const c1 = this.c1;
        const a = c0.add(c1);
        const b = c0.subtract(c1);
        const c = c0.add(c0);
        return new Fp2(a.multiply(b), c.multiply(c1));
      }
      sqrt() {
        const candidateSqrt = this.pow((Fp2.ORDER + 8n) / 16n);
        const check = candidateSqrt.square().div(this);
        const R = FP2_ROOTS_OF_UNITY;
        const divisor = [R[0], R[2], R[4], R[6]].find((r) => r.equals(check));
        if (!divisor)
          return;
        const index = R.indexOf(divisor);
        const root = R[index / 2];
        if (!root)
          throw new Error("Invalid root");
        const x1 = candidateSqrt.div(root);
        const x2 = x1.negate();
        const { re: re1, im: im1 } = x1.reim();
        const { re: re2, im: im2 } = x2.reim();
        if (im1 > im2 || im1 === im2 && re1 > re2)
          return x1;
        return x2;
      }
      invert() {
        const { re: a, im: b } = this.reim();
        const factor = new Fp(a * a + b * b).invert();
        return new Fp2(factor.multiply(new Fp(a)), factor.multiply(new Fp(-b)));
      }
      frobeniusMap(power) {
        return new Fp2(this.c0, this.c1.multiply(FP2_FROBENIUS_COEFFICIENTS[power % 2]));
      }
      multiplyByB() {
        let c0 = this.c0;
        let c1 = this.c1;
        let t0 = c0.multiply(4n);
        let t1 = c1.multiply(4n);
        return new Fp2(t0.subtract(t1), t0.add(t1));
      }
      static fromBytes(b) {
        if (b.length !== Fp2.BYTES_LEN)
          throw new Error(`fromBytes wrong length=${b.length}`);
        return new Fp2(Fp.fromBytes(b.subarray(0, Fp.BYTES_LEN)), Fp.fromBytes(b.subarray(Fp.BYTES_LEN)));
      }
      toBytes() {
        return concatBytes(this.c0.toBytes(), this.c1.toBytes());
      }
    };
    exports.Fp2 = Fp2;
    _b = Fp2;
    Fp2.ORDER = exports.CURVE.P2;
    Fp2.MAX_BITS = bitLen(exports.CURVE.P2);
    Fp2.BYTES_LEN = Math.ceil(_b.MAX_BITS / 8);
    Fp2.ZERO = new Fp2(Fp.ZERO, Fp.ZERO);
    Fp2.ONE = new Fp2(Fp.ONE, Fp.ZERO);
    var Fp6 = class {
      constructor(c0, c1, c2) {
        this.c0 = c0;
        this.c1 = c1;
        this.c2 = c2;
      }
      static fromBigSix(t) {
        if (!Array.isArray(t) || t.length !== 6)
          throw new Error("Invalid Fp6 usage");
        const c = [t.slice(0, 2), t.slice(2, 4), t.slice(4, 6)].map((t2) => Fp2.fromBigTuple(t2));
        return new Fp6(...c);
      }
      fromTriple(triple) {
        return new Fp6(...triple);
      }
      one() {
        return Fp6.ONE;
      }
      isZero() {
        return this.c0.isZero() && this.c1.isZero() && this.c2.isZero();
      }
      negate() {
        const { c0, c1, c2 } = this;
        return new Fp6(c0.negate(), c1.negate(), c2.negate());
      }
      toString() {
        return `Fp6(${this.c0} + ${this.c1} * v, ${this.c2} * v^2)`;
      }
      equals(rhs) {
        const { c0, c1, c2 } = this;
        const { c0: r0, c1: r1, c2: r2 } = rhs;
        return c0.equals(r0) && c1.equals(r1) && c2.equals(r2);
      }
      add(rhs) {
        const { c0, c1, c2 } = this;
        const { c0: r0, c1: r1, c2: r2 } = rhs;
        return new Fp6(c0.add(r0), c1.add(r1), c2.add(r2));
      }
      subtract(rhs) {
        const { c0, c1, c2 } = this;
        const { c0: r0, c1: r1, c2: r2 } = rhs;
        return new Fp6(c0.subtract(r0), c1.subtract(r1), c2.subtract(r2));
      }
      multiply(rhs) {
        if (typeof rhs === "bigint") {
          return new Fp6(this.c0.multiply(rhs), this.c1.multiply(rhs), this.c2.multiply(rhs));
        }
        let { c0, c1, c2 } = this;
        let { c0: r0, c1: r1, c2: r2 } = rhs;
        let t0 = c0.multiply(r0);
        let t1 = c1.multiply(r1);
        let t2 = c2.multiply(r2);
        return new Fp6(t0.add(c1.add(c2).multiply(r1.add(r2)).subtract(t1.add(t2)).mulByNonresidue()), c0.add(c1).multiply(r0.add(r1)).subtract(t0.add(t1)).add(t2.mulByNonresidue()), t1.add(c0.add(c2).multiply(r0.add(r2)).subtract(t0.add(t2))));
      }
      pow(n) {
        return powMod_FQP(this, Fp6.ONE, n);
      }
      div(rhs) {
        const inv = typeof rhs === "bigint" ? new Fp(rhs).invert().value : rhs.invert();
        return this.multiply(inv);
      }
      mulByNonresidue() {
        return new Fp6(this.c2.mulByNonresidue(), this.c0, this.c1);
      }
      multiplyBy1(b1) {
        return new Fp6(this.c2.multiply(b1).mulByNonresidue(), this.c0.multiply(b1), this.c1.multiply(b1));
      }
      multiplyBy01(b0, b1) {
        let { c0, c1, c2 } = this;
        let t0 = c0.multiply(b0);
        let t1 = c1.multiply(b1);
        return new Fp6(c1.add(c2).multiply(b1).subtract(t1).mulByNonresidue().add(t0), b0.add(b1).multiply(c0.add(c1)).subtract(t0).subtract(t1), c0.add(c2).multiply(b0).subtract(t0).add(t1));
      }
      multiplyByFp2(rhs) {
        let { c0, c1, c2 } = this;
        return new Fp6(c0.multiply(rhs), c1.multiply(rhs), c2.multiply(rhs));
      }
      square() {
        let { c0, c1, c2 } = this;
        let t0 = c0.square();
        let t1 = c0.multiply(c1).multiply(2n);
        let t3 = c1.multiply(c2).multiply(2n);
        let t4 = c2.square();
        return new Fp6(t3.mulByNonresidue().add(t0), t4.mulByNonresidue().add(t1), t1.add(c0.subtract(c1).add(c2).square()).add(t3).subtract(t0).subtract(t4));
      }
      invert() {
        let { c0, c1, c2 } = this;
        let t0 = c0.square().subtract(c2.multiply(c1).mulByNonresidue());
        let t1 = c2.square().mulByNonresidue().subtract(c0.multiply(c1));
        let t2 = c1.square().subtract(c0.multiply(c2));
        let t4 = c2.multiply(t1).add(c1.multiply(t2)).mulByNonresidue().add(c0.multiply(t0)).invert();
        return new Fp6(t4.multiply(t0), t4.multiply(t1), t4.multiply(t2));
      }
      frobeniusMap(power) {
        return new Fp6(this.c0.frobeniusMap(power), this.c1.frobeniusMap(power).multiply(FP6_FROBENIUS_COEFFICIENTS_1[power % 6]), this.c2.frobeniusMap(power).multiply(FP6_FROBENIUS_COEFFICIENTS_2[power % 6]));
      }
      static fromBytes(b) {
        if (b.length !== Fp6.BYTES_LEN)
          throw new Error(`fromBytes wrong length=${b.length}`);
        return new Fp6(Fp2.fromBytes(b.subarray(0, Fp2.BYTES_LEN)), Fp2.fromBytes(b.subarray(Fp2.BYTES_LEN, 2 * Fp2.BYTES_LEN)), Fp2.fromBytes(b.subarray(2 * Fp2.BYTES_LEN)));
      }
      toBytes() {
        return concatBytes(this.c0.toBytes(), this.c1.toBytes(), this.c2.toBytes());
      }
    };
    exports.Fp6 = Fp6;
    Fp6.ZERO = new Fp6(Fp2.ZERO, Fp2.ZERO, Fp2.ZERO);
    Fp6.ONE = new Fp6(Fp2.ONE, Fp2.ZERO, Fp2.ZERO);
    Fp6.BYTES_LEN = 3 * Fp2.BYTES_LEN;
    var Fp12 = class {
      constructor(c0, c1) {
        this.c0 = c0;
        this.c1 = c1;
      }
      static fromBigTwelve(t) {
        return new Fp12(Fp6.fromBigSix(t.slice(0, 6)), Fp6.fromBigSix(t.slice(6, 12)));
      }
      fromTuple(c) {
        return new Fp12(...c);
      }
      one() {
        return Fp12.ONE;
      }
      isZero() {
        return this.c0.isZero() && this.c1.isZero();
      }
      toString() {
        return `Fp12(${this.c0} + ${this.c1} * w)`;
      }
      negate() {
        const { c0, c1 } = this;
        return new Fp12(c0.negate(), c1.negate());
      }
      equals(rhs) {
        const { c0, c1 } = this;
        const { c0: r0, c1: r1 } = rhs;
        return c0.equals(r0) && c1.equals(r1);
      }
      add(rhs) {
        const { c0, c1 } = this;
        const { c0: r0, c1: r1 } = rhs;
        return new Fp12(c0.add(r0), c1.add(r1));
      }
      subtract(rhs) {
        const { c0, c1 } = this;
        const { c0: r0, c1: r1 } = rhs;
        return new Fp12(c0.subtract(r0), c1.subtract(r1));
      }
      multiply(rhs) {
        if (typeof rhs === "bigint")
          return new Fp12(this.c0.multiply(rhs), this.c1.multiply(rhs));
        let { c0, c1 } = this;
        let { c0: r0, c1: r1 } = rhs;
        let t1 = c0.multiply(r0);
        let t2 = c1.multiply(r1);
        return new Fp12(t1.add(t2.mulByNonresidue()), c0.add(c1).multiply(r0.add(r1)).subtract(t1.add(t2)));
      }
      pow(n) {
        return powMod_FQP(this, Fp12.ONE, n);
      }
      div(rhs) {
        const inv = typeof rhs === "bigint" ? new Fp(rhs).invert().value : rhs.invert();
        return this.multiply(inv);
      }
      multiplyBy014(o0, o1, o4) {
        let { c0, c1 } = this;
        let t0 = c0.multiplyBy01(o0, o1);
        let t1 = c1.multiplyBy1(o4);
        return new Fp12(t1.mulByNonresidue().add(t0), c1.add(c0).multiplyBy01(o0, o1.add(o4)).subtract(t0).subtract(t1));
      }
      multiplyByFp2(rhs) {
        return new Fp12(this.c0.multiplyByFp2(rhs), this.c1.multiplyByFp2(rhs));
      }
      square() {
        let { c0, c1 } = this;
        let ab = c0.multiply(c1);
        return new Fp12(c1.mulByNonresidue().add(c0).multiply(c0.add(c1)).subtract(ab).subtract(ab.mulByNonresidue()), ab.add(ab));
      }
      invert() {
        let { c0, c1 } = this;
        let t = c0.square().subtract(c1.square().mulByNonresidue()).invert();
        return new Fp12(c0.multiply(t), c1.multiply(t).negate());
      }
      conjugate() {
        return new Fp12(this.c0, this.c1.negate());
      }
      frobeniusMap(power) {
        const r0 = this.c0.frobeniusMap(power);
        const { c0, c1, c2 } = this.c1.frobeniusMap(power);
        const coeff = FP12_FROBENIUS_COEFFICIENTS[power % 12];
        return new Fp12(r0, new Fp6(c0.multiply(coeff), c1.multiply(coeff), c2.multiply(coeff)));
      }
      Fp4Square(a, b) {
        const a2 = a.square();
        const b2 = b.square();
        return {
          first: b2.mulByNonresidue().add(a2),
          second: a.add(b).square().subtract(a2).subtract(b2)
        };
      }
      cyclotomicSquare() {
        const { c0: c0c0, c1: c0c1, c2: c0c2 } = this.c0;
        const { c0: c1c0, c1: c1c1, c2: c1c2 } = this.c1;
        const { first: t3, second: t4 } = this.Fp4Square(c0c0, c1c1);
        const { first: t5, second: t6 } = this.Fp4Square(c1c0, c0c2);
        const { first: t7, second: t8 } = this.Fp4Square(c0c1, c1c2);
        let t9 = t8.mulByNonresidue();
        return new Fp12(new Fp6(t3.subtract(c0c0).multiply(2n).add(t3), t5.subtract(c0c1).multiply(2n).add(t5), t7.subtract(c0c2).multiply(2n).add(t7)), new Fp6(t9.add(c1c0).multiply(2n).add(t9), t4.add(c1c1).multiply(2n).add(t4), t6.add(c1c2).multiply(2n).add(t6)));
      }
      cyclotomicExp(n) {
        let z = Fp12.ONE;
        for (let i = BLS_X_LEN - 1; i >= 0; i--) {
          z = z.cyclotomicSquare();
          if (bitGet(n, i))
            z = z.multiply(this);
        }
        return z;
      }
      finalExponentiate() {
        const { x } = exports.CURVE;
        const t0 = this.frobeniusMap(6).div(this);
        const t1 = t0.frobeniusMap(2).multiply(t0);
        const t2 = t1.cyclotomicExp(x).conjugate();
        const t3 = t1.cyclotomicSquare().conjugate().multiply(t2);
        const t4 = t3.cyclotomicExp(x).conjugate();
        const t5 = t4.cyclotomicExp(x).conjugate();
        const t6 = t5.cyclotomicExp(x).conjugate().multiply(t2.cyclotomicSquare());
        const t7 = t6.cyclotomicExp(x).conjugate();
        const t2_t5_pow_q2 = t2.multiply(t5).frobeniusMap(2);
        const t4_t1_pow_q3 = t4.multiply(t1).frobeniusMap(3);
        const t6_t1c_pow_q1 = t6.multiply(t1.conjugate()).frobeniusMap(1);
        const t7_t3c_t1 = t7.multiply(t3.conjugate()).multiply(t1);
        return t2_t5_pow_q2.multiply(t4_t1_pow_q3).multiply(t6_t1c_pow_q1).multiply(t7_t3c_t1);
      }
      static fromBytes(b) {
        if (b.length !== Fp12.BYTES_LEN)
          throw new Error(`fromBytes wrong length=${b.length}`);
        return new Fp12(Fp6.fromBytes(b.subarray(0, Fp6.BYTES_LEN)), Fp6.fromBytes(b.subarray(Fp6.BYTES_LEN)));
      }
      toBytes() {
        return concatBytes(this.c0.toBytes(), this.c1.toBytes());
      }
    };
    exports.Fp12 = Fp12;
    Fp12.ZERO = new Fp12(Fp6.ZERO, Fp6.ZERO);
    Fp12.ONE = new Fp12(Fp6.ONE, Fp6.ZERO);
    Fp12.BYTES_LEN = 2 * Fp6.BYTES_LEN;
    var ProjectivePoint = class {
      constructor(x, y, z, C) {
        this.x = x;
        this.y = y;
        this.z = z;
        this.C = C;
      }
      isZero() {
        return this.z.isZero();
      }
      createPoint(x, y, z) {
        return new this.constructor(x, y, z);
      }
      getZero() {
        return this.createPoint(this.C.ONE, this.C.ONE, this.C.ZERO);
      }
      equals(rhs) {
        if (this.constructor !== rhs.constructor)
          throw new Error(`ProjectivePoint#equals: this is ${this.constructor}, but rhs is ${rhs.constructor}`);
        const a = this;
        const b = rhs;
        const xe = a.x.multiply(b.z).equals(b.x.multiply(a.z));
        const ye = a.y.multiply(b.z).equals(b.y.multiply(a.z));
        return xe && ye;
      }
      negate() {
        return this.createPoint(this.x, this.y.negate(), this.z);
      }
      toString(isAffine = true) {
        if (this.isZero()) {
          return `Point<Zero>`;
        }
        if (!isAffine) {
          return `Point<x=${this.x}, y=${this.y}, z=${this.z}>`;
        }
        const [x, y] = this.toAffine();
        return `Point<x=${x}, y=${y}>`;
      }
      fromAffineTuple(xy) {
        return this.createPoint(xy[0], xy[1], this.C.ONE);
      }
      toAffine(invZ = this.z.invert()) {
        if (invZ.isZero())
          throw new Error("Invalid inverted z");
        return [this.x.multiply(invZ), this.y.multiply(invZ)];
      }
      toAffineBatch(points) {
        const toInv = genInvertBatch(this.C, points.map((p) => p.z));
        return points.map((p, i) => p.toAffine(toInv[i]));
      }
      normalizeZ(points) {
        return this.toAffineBatch(points).map((t) => this.fromAffineTuple(t));
      }
      double() {
        const { x, y, z } = this;
        const W = x.multiply(x).multiply(3n);
        const S = y.multiply(z);
        const SS = S.multiply(S);
        const SSS = SS.multiply(S);
        const B = x.multiply(y).multiply(S);
        const H = W.multiply(W).subtract(B.multiply(8n));
        const X3 = H.multiply(S).multiply(2n);
        const Y3 = W.multiply(B.multiply(4n).subtract(H)).subtract(y.multiply(y).multiply(8n).multiply(SS));
        const Z3 = SSS.multiply(8n);
        return this.createPoint(X3, Y3, Z3);
      }
      add(rhs) {
        if (this.constructor !== rhs.constructor)
          throw new Error(`ProjectivePoint#add: this is ${this.constructor}, but rhs is ${rhs.constructor}`);
        const p1 = this;
        const p2 = rhs;
        if (p1.isZero())
          return p2;
        if (p2.isZero())
          return p1;
        const X1 = p1.x;
        const Y1 = p1.y;
        const Z1 = p1.z;
        const X2 = p2.x;
        const Y2 = p2.y;
        const Z2 = p2.z;
        const U1 = Y2.multiply(Z1);
        const U2 = Y1.multiply(Z2);
        const V1 = X2.multiply(Z1);
        const V2 = X1.multiply(Z2);
        if (V1.equals(V2) && U1.equals(U2))
          return this.double();
        if (V1.equals(V2))
          return this.getZero();
        const U = U1.subtract(U2);
        const V = V1.subtract(V2);
        const VV = V.multiply(V);
        const VVV = VV.multiply(V);
        const V2VV = V2.multiply(VV);
        const W = Z1.multiply(Z2);
        const A = U.multiply(U).multiply(W).subtract(VVV).subtract(V2VV.multiply(2n));
        const X3 = V.multiply(A);
        const Y3 = U.multiply(V2VV.subtract(A)).subtract(VVV.multiply(U2));
        const Z3 = VVV.multiply(W);
        return this.createPoint(X3, Y3, Z3);
      }
      subtract(rhs) {
        if (this.constructor !== rhs.constructor)
          throw new Error(`ProjectivePoint#subtract: this is ${this.constructor}, but rhs is ${rhs.constructor}`);
        return this.add(rhs.negate());
      }
      validateScalar(n) {
        if (typeof n === "number")
          n = BigInt(n);
        if (typeof n !== "bigint" || n <= 0 || n > exports.CURVE.r) {
          throw new Error(`Point#multiply: invalid scalar, expected positive integer < CURVE.r. Got: ${n}`);
        }
        return n;
      }
      multiplyUnsafe(scalar) {
        let n = this.validateScalar(scalar);
        let point = this.getZero();
        let d = this;
        while (n > 0n) {
          if (n & 1n)
            point = point.add(d);
          d = d.double();
          n >>= 1n;
        }
        return point;
      }
      multiply(scalar) {
        let n = this.validateScalar(scalar);
        let point = this.getZero();
        let fake = this.getZero();
        let d = this;
        let bits = Fp.ORDER;
        while (bits > 0n) {
          if (n & 1n) {
            point = point.add(d);
          } else {
            fake = fake.add(d);
          }
          d = d.double();
          n >>= 1n;
          bits >>= 1n;
        }
        return point;
      }
      maxBits() {
        return this.C.MAX_BITS;
      }
      precomputeWindow(W) {
        const windows = Math.ceil(this.maxBits() / W);
        const windowSize = 2 ** (W - 1);
        let points = [];
        let p = this;
        let base = p;
        for (let window = 0; window < windows; window++) {
          base = p;
          points.push(base);
          for (let i = 1; i < windowSize; i++) {
            base = base.add(p);
            points.push(base);
          }
          p = base.double();
        }
        return points;
      }
      calcMultiplyPrecomputes(W) {
        if (this._MPRECOMPUTES)
          throw new Error("This point already has precomputes");
        this._MPRECOMPUTES = [W, this.normalizeZ(this.precomputeWindow(W))];
      }
      clearMultiplyPrecomputes() {
        this._MPRECOMPUTES = void 0;
      }
      wNAF(n) {
        let W, precomputes;
        if (this._MPRECOMPUTES) {
          [W, precomputes] = this._MPRECOMPUTES;
        } else {
          W = 1;
          precomputes = this.precomputeWindow(W);
        }
        let p = this.getZero();
        let f = this.getZero();
        const windows = Math.ceil(this.maxBits() / W);
        const windowSize = 2 ** (W - 1);
        const mask = BigInt(2 ** W - 1);
        const maxNumber = 2 ** W;
        const shiftBy = BigInt(W);
        for (let window = 0; window < windows; window++) {
          const offset = window * windowSize;
          let wbits = Number(n & mask);
          n >>= shiftBy;
          if (wbits > windowSize) {
            wbits -= maxNumber;
            n += 1n;
          }
          if (wbits === 0) {
            f = f.add(window % 2 ? precomputes[offset].negate() : precomputes[offset]);
          } else {
            const cached = precomputes[offset + Math.abs(wbits) - 1];
            p = p.add(wbits < 0 ? cached.negate() : cached);
          }
        }
        return [p, f];
      }
      multiplyPrecomputed(scalar) {
        return this.wNAF(this.validateScalar(scalar))[0];
      }
    };
    exports.ProjectivePoint = ProjectivePoint;
    function sgn0_fp2(x) {
      const { re: x0, im: x1 } = x.reim();
      const sign_0 = x0 % 2n;
      const zero_0 = x0 === 0n;
      const sign_1 = x1 % 2n;
      return BigInt(sign_0 || zero_0 && sign_1);
    }
    function sgn0_m_eq_1(x) {
      return Boolean(x.value % 2n);
    }
    var P_MINUS_9_DIV_16 = (exports.CURVE.P ** 2n - 9n) / 16n;
    function sqrt_div_fp2(u, v) {
      const v7 = v.pow(7n);
      const uv7 = u.multiply(v7);
      const uv15 = uv7.multiply(v7.multiply(v));
      const gamma = uv15.pow(P_MINUS_9_DIV_16).multiply(uv7);
      let success = false;
      let result = gamma;
      const positiveRootsOfUnity = FP2_ROOTS_OF_UNITY.slice(0, 4);
      positiveRootsOfUnity.forEach((root) => {
        const candidate = root.multiply(gamma);
        if (candidate.pow(2n).multiply(v).subtract(u).isZero() && !success) {
          success = true;
          result = candidate;
        }
      });
      return { success, sqrtCandidateOrGamma: result };
    }
    function map_to_curve_simple_swu_9mod16(t) {
      const iso_3_a = new Fp2(new Fp(0n), new Fp(240n));
      const iso_3_b = new Fp2(new Fp(1012n), new Fp(1012n));
      const iso_3_z = new Fp2(new Fp(-2n), new Fp(-1n));
      if (Array.isArray(t))
        t = Fp2.fromBigTuple(t);
      const t2 = t.pow(2n);
      const iso_3_z_t2 = iso_3_z.multiply(t2);
      const ztzt = iso_3_z_t2.add(iso_3_z_t2.pow(2n));
      let denominator = iso_3_a.multiply(ztzt).negate();
      let numerator = iso_3_b.multiply(ztzt.add(Fp2.ONE));
      if (denominator.isZero())
        denominator = iso_3_z.multiply(iso_3_a);
      let v = denominator.pow(3n);
      let u = numerator.pow(3n).add(iso_3_a.multiply(numerator).multiply(denominator.pow(2n))).add(iso_3_b.multiply(v));
      const { success, sqrtCandidateOrGamma } = sqrt_div_fp2(u, v);
      let y;
      if (success)
        y = sqrtCandidateOrGamma;
      const sqrtCandidateX1 = sqrtCandidateOrGamma.multiply(t.pow(3n));
      u = iso_3_z_t2.pow(3n).multiply(u);
      let success2 = false;
      FP2_ETAs.forEach((eta) => {
        const etaSqrtCandidate = eta.multiply(sqrtCandidateX1);
        const temp = etaSqrtCandidate.pow(2n).multiply(v).subtract(u);
        if (temp.isZero() && !success && !success2) {
          y = etaSqrtCandidate;
          success2 = true;
        }
      });
      if (!success && !success2)
        throw new Error("Hash to Curve - Optimized SWU failure");
      if (success2)
        numerator = numerator.multiply(iso_3_z_t2);
      y = y;
      if (sgn0_fp2(t) !== sgn0_fp2(y))
        y = y.negate();
      return [numerator.div(denominator), y];
    }
    exports.map_to_curve_simple_swu_9mod16 = map_to_curve_simple_swu_9mod16;
    function map_to_curve_simple_swu_3mod4(u) {
      const A = new Fp(0x144698a3b8e9433d693a02c96d4982b0ea985383ee66a8d8e8981aefd881ac98936f8da0e0f97f5cf428082d584c1dn);
      const B = new Fp(0x12e2908d11688030018b12e8753eee3b2016c1f0f24f4070a0b9c14fcef35ef55a23215a316ceaa5d1cc48e98e172be0n);
      const Z = new Fp(11n);
      const c1 = (Fp.ORDER - 3n) / 4n;
      const c2 = Z.negate().pow(3n).sqrt();
      const tv1 = u.square();
      const tv3 = Z.multiply(tv1);
      let xDen = tv3.square().add(tv3);
      const xNum1 = xDen.add(Fp.ONE).multiply(B);
      const xNum2 = tv3.multiply(xNum1);
      xDen = A.negate().multiply(xDen);
      if (xDen.isZero())
        xDen = A.multiply(Z);
      let tv2 = xDen.square();
      const gxd = tv2.multiply(xDen);
      tv2 = A.multiply(tv2);
      let gx1 = xNum1.square().add(tv2).multiply(xNum1);
      tv2 = B.multiply(gxd);
      gx1 = gx1.add(tv2);
      tv2 = gx1.multiply(gxd);
      const tv4 = gxd.square().multiply(tv2);
      const y1 = tv4.pow(c1).multiply(tv2);
      const y2 = y1.multiply(c2).multiply(tv1).multiply(u);
      let xNum, yPos;
      if (y1.square().multiply(gxd).equals(gx1)) {
        xNum = xNum1;
        yPos = y1;
      } else {
        xNum = xNum2;
        yPos = y2;
      }
      const yNeg = yPos.negate();
      const y = sgn0_m_eq_1(u) == sgn0_m_eq_1(yPos) ? yPos : yNeg;
      return [xNum.div(xDen), y];
    }
    exports.map_to_curve_simple_swu_3mod4 = map_to_curve_simple_swu_3mod4;
    function isogenyMap(COEFF, x, y) {
      const [xNum, xDen, yNum, yDen] = COEFF.map((val) => val.reduce((acc, i) => acc.multiply(x).add(i)));
      x = xNum.div(xDen);
      y = y.multiply(yNum.div(yDen));
      return [x, y];
    }
    var isogenyMapG2 = (x, y) => isogenyMap(ISOGENY_COEFFICIENTS_G2, x, y);
    exports.isogenyMapG2 = isogenyMapG2;
    var isogenyMapG1 = (x, y) => isogenyMap(ISOGENY_COEFFICIENTS_G1, x, y);
    exports.isogenyMapG1 = isogenyMapG1;
    function calcPairingPrecomputes(x, y) {
      const Qx = x, Qy = y, Qz = Fp2.ONE;
      let Rx = Qx, Ry = Qy, Rz = Qz;
      let ell_coeff = [];
      for (let i = BLS_X_LEN - 2; i >= 0; i--) {
        let t0 = Ry.square();
        let t1 = Rz.square();
        let t2 = t1.multiply(3n).multiplyByB();
        let t3 = t2.multiply(3n);
        let t4 = Ry.add(Rz).square().subtract(t1).subtract(t0);
        ell_coeff.push([
          t2.subtract(t0),
          Rx.square().multiply(3n),
          t4.negate()
        ]);
        Rx = t0.subtract(t3).multiply(Rx).multiply(Ry).div(2n);
        Ry = t0.add(t3).div(2n).square().subtract(t2.square().multiply(3n));
        Rz = t0.multiply(t4);
        if (bitGet(exports.CURVE.x, i)) {
          let t02 = Ry.subtract(Qy.multiply(Rz));
          let t12 = Rx.subtract(Qx.multiply(Rz));
          ell_coeff.push([
            t02.multiply(Qx).subtract(t12.multiply(Qy)),
            t02.negate(),
            t12
          ]);
          let t22 = t12.square();
          let t32 = t22.multiply(t12);
          let t42 = t22.multiply(Rx);
          let t5 = t32.subtract(t42.multiply(2n)).add(t02.square().multiply(Rz));
          Rx = t12.multiply(t5);
          Ry = t42.subtract(t5).multiply(t02).subtract(t32.multiply(Ry));
          Rz = Rz.multiply(t32);
        }
      }
      return ell_coeff;
    }
    exports.calcPairingPrecomputes = calcPairingPrecomputes;
    function millerLoop(ell, g1) {
      const Px = g1[0].value;
      const Py = g1[1].value;
      let f12 = Fp12.ONE;
      for (let j = 0, i = BLS_X_LEN - 2; i >= 0; i--, j++) {
        const E = ell[j];
        f12 = f12.multiplyBy014(E[0], E[1].multiply(Px), E[2].multiply(Py));
        if (bitGet(exports.CURVE.x, i)) {
          j += 1;
          const F = ell[j];
          f12 = f12.multiplyBy014(F[0], F[1].multiply(Px), F[2].multiply(Py));
        }
        if (i !== 0)
          f12 = f12.square();
      }
      return f12.conjugate();
    }
    exports.millerLoop = millerLoop;
    var ut_root = new Fp6(Fp2.ZERO, Fp2.ONE, Fp2.ZERO);
    var wsq = new Fp12(ut_root, Fp6.ZERO);
    var wcu = new Fp12(Fp6.ZERO, ut_root);
    var [wsq_inv, wcu_inv] = genInvertBatch(Fp12, [wsq, wcu]);
    function psi(x, y) {
      const x2 = wsq_inv.multiplyByFp2(x).frobeniusMap(1).multiply(wsq).c0.c0;
      const y2 = wcu_inv.multiplyByFp2(y).frobeniusMap(1).multiply(wcu).c0.c0;
      return [x2, y2];
    }
    exports.psi = psi;
    function psi2(x, y) {
      return [x.multiply(PSI2_C1), y.negate()];
    }
    exports.psi2 = psi2;
    var PSI2_C1 = 0x1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaacn;
    var rv1 = 0x6af0e0437ff400b6831e36d6bd17ffe48395dabc2d3435e77f76e17009241c5ee67992f72ec05f4c81084fbede3cc09n;
    var ev1 = 0x699be3b8c6870965e5bf892ad5d2cc7b0e85a117402dfd83b7f4a947e02d978498255a2aaec0ac627b5afbdf1bf1c90n;
    var ev2 = 0x8157cd83046453f5dd0972b6e3949e4288020b5b8a9cc99ca07e27089a2ce2436d965026adad3ef7baba37f2183e9b5n;
    var ev3 = 0xab1c2ffdd6c253ca155231eb3e71ba044fd562f6f72bc5bad5ec46a0b7a3b0247cf08ce6c6317f40edbc653a72dee17n;
    var ev4 = 0xaa404866706722864480885d68ad0ccac1967c7544b447873cc37e0181271e006df72162a3d3e0287bf597fbf7f8fc1n;
    var FP2_FROBENIUS_COEFFICIENTS = [
      0x1n,
      0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaan
    ].map((item) => new Fp(item));
    var FP2_ROOTS_OF_UNITY = [
      [1n, 0n],
      [rv1, -rv1],
      [0n, 1n],
      [rv1, rv1],
      [-1n, 0n],
      [-rv1, rv1],
      [0n, -1n],
      [-rv1, -rv1]
    ].map((pair) => Fp2.fromBigTuple(pair));
    var FP2_ETAs = [
      [ev1, ev2],
      [-ev2, ev1],
      [ev3, ev4],
      [-ev4, ev3]
    ].map((pair) => Fp2.fromBigTuple(pair));
    var FP6_FROBENIUS_COEFFICIENTS_1 = [
      [0x1n, 0x0n],
      [
        0x0n,
        0x1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaacn
      ],
      [
        0x00000000000000005f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffefffen,
        0x0n
      ],
      [0x0n, 0x1n],
      [
        0x1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaacn,
        0x0n
      ],
      [
        0x0n,
        0x00000000000000005f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffefffen
      ]
    ].map((pair) => Fp2.fromBigTuple(pair));
    var FP6_FROBENIUS_COEFFICIENTS_2 = [
      [0x1n, 0x0n],
      [
        0x1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaadn,
        0x0n
      ],
      [
        0x1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaacn,
        0x0n
      ],
      [
        0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaan,
        0x0n
      ],
      [
        0x00000000000000005f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffefffen,
        0x0n
      ],
      [
        0x00000000000000005f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffeffffn,
        0x0n
      ]
    ].map((pair) => Fp2.fromBigTuple(pair));
    var FP12_FROBENIUS_COEFFICIENTS = [
      [0x1n, 0x0n],
      [
        0x1904d3bf02bb0667c231beb4202c0d1f0fd603fd3cbd5f4f7b2443d784bab9c4f67ea53d63e7813d8d0775ed92235fb8n,
        0x00fc3e2b36c4e03288e9e902231f9fb854a14787b6c7b36fec0c8ec971f63c5f282d5ac14d6c7ec22cf78a126ddc4af3n
      ],
      [
        0x00000000000000005f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffeffffn,
        0x0n
      ],
      [
        0x135203e60180a68ee2e9c448d77a2cd91c3dedd930b1cf60ef396489f61eb45e304466cf3e67fa0af1ee7b04121bdea2n,
        0x06af0e0437ff400b6831e36d6bd17ffe48395dabc2d3435e77f76e17009241c5ee67992f72ec05f4c81084fbede3cc09n
      ],
      [
        0x00000000000000005f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffefffen,
        0x0n
      ],
      [
        0x144e4211384586c16bd3ad4afa99cc9170df3560e77982d0db45f3536814f0bd5871c1908bd478cd1ee605167ff82995n,
        0x05b2cfd9013a5fd8df47fa6b48b1e045f39816240c0b8fee8beadf4d8e9c0566c63a3e6e257f87329b18fae980078116n
      ],
      [
        0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaan,
        0x0n
      ],
      [
        0x00fc3e2b36c4e03288e9e902231f9fb854a14787b6c7b36fec0c8ec971f63c5f282d5ac14d6c7ec22cf78a126ddc4af3n,
        0x1904d3bf02bb0667c231beb4202c0d1f0fd603fd3cbd5f4f7b2443d784bab9c4f67ea53d63e7813d8d0775ed92235fb8n
      ],
      [
        0x1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaacn,
        0x0n
      ],
      [
        0x06af0e0437ff400b6831e36d6bd17ffe48395dabc2d3435e77f76e17009241c5ee67992f72ec05f4c81084fbede3cc09n,
        0x135203e60180a68ee2e9c448d77a2cd91c3dedd930b1cf60ef396489f61eb45e304466cf3e67fa0af1ee7b04121bdea2n
      ],
      [
        0x1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaadn,
        0x0n
      ],
      [
        0x05b2cfd9013a5fd8df47fa6b48b1e045f39816240c0b8fee8beadf4d8e9c0566c63a3e6e257f87329b18fae980078116n,
        0x144e4211384586c16bd3ad4afa99cc9170df3560e77982d0db45f3536814f0bd5871c1908bd478cd1ee605167ff82995n
      ]
    ].map((n) => Fp2.fromBigTuple(n));
    var xnum = [
      [
        0x171d6541fa38ccfaed6dea691f5fb614cb14b4e7f4e810aa22d6108f142b85757098e38d0f671c7188e2aaaaaaaa5ed1n,
        0x0n
      ],
      [
        0x11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71en,
        0x8ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38dn
      ],
      [
        0x0n,
        0x11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71an
      ],
      [
        0x5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6n,
        0x5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6n
      ]
    ].map((pair) => Fp2.fromBigTuple(pair));
    var xden = [
      [0x0n, 0x0n],
      [0x1n, 0x0n],
      [
        0xcn,
        0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa9fn
      ],
      [
        0x0n,
        0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa63n
      ]
    ].map((pair) => Fp2.fromBigTuple(pair));
    var ynum = [
      [
        0x124c9ad43b6cf79bfbf7043de3811ad0761b0f37a1e26286b0e977c69aa274524e79097a56dc4bd9e1b371c71c718b10n,
        0x0n
      ],
      [
        0x11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71cn,
        0x8ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38fn
      ],
      [
        0x0n,
        0x5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97ben
      ],
      [
        0x1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706n,
        0x1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706n
      ]
    ].map((pair) => Fp2.fromBigTuple(pair));
    var yden = [
      [0x1n, 0x0n],
      [
        0x12n,
        0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa99n
      ],
      [
        0x0n,
        0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa9d3n
      ],
      [
        0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fbn,
        0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fbn
      ]
    ].map((pair) => Fp2.fromBigTuple(pair));
    var ISOGENY_COEFFICIENTS_G2 = [xnum, xden, ynum, yden];
    var ISOGENY_COEFFICIENTS_G1 = [
      [
        new Fp(0x06e08c248e260e70bd1e962381edee3d31d79d7e22c837bc23c0bf1bc24c6b68c24b1b80b64d391fa9c8ba2e8ba2d229n),
        new Fp(0x10321da079ce07e272d8ec09d2565b0dfa7dccdde6787f96d50af36003b14866f69b771f8c285decca67df3f1605fb7bn),
        new Fp(0x169b1f8e1bcfa7c42e0c37515d138f22dd2ecb803a0c5c99676314baf4bb1b7fa3190b2edc0327797f241067be390c9en),
        new Fp(0x080d3cf1f9a78fc47b90b33563be990dc43b756ce79f5574a2c596c928c5d1de4fa295f296b74e956d71986a8497e317n),
        new Fp(0x17b81e7701abdbe2e8743884d1117e53356de5ab275b4db1a682c62ef0f2753339b7c8f8c8f475af9ccb5618e3f0c88en),
        new Fp(0x0d6ed6553fe44d296a3726c38ae652bfb11586264f0f8ce19008e218f9c86b2a8da25128c1052ecaddd7f225a139ed84n),
        new Fp(0x1630c3250d7313ff01d1201bf7a74ab5db3cb17dd952799b9ed3ab9097e68f90a0870d2dcae73d19cd13c1c66f652983n),
        new Fp(0x0e99726a3199f4436642b4b3e4118e5499db995a1257fb3f086eeb65982fac18985a286f301e77c451154ce9ac8895d9n),
        new Fp(0x1778e7166fcc6db74e0609d307e55412d7f5e4656a8dbf25f1b33289f1b330835336e25ce3107193c5b388641d9b6861n),
        new Fp(0x0d54005db97678ec1d1048c5d10a9a1bce032473295983e56878e501ec68e25c958c3e3d2a09729fe0179f9dac9edcb0n),
        new Fp(0x17294ed3e943ab2f0588bab22147a81c7c17e75b2f6a8417f565e33c70d1e86b4838f2a6f318c356e834eef1b3cb83bbn),
        new Fp(0x11a05f2b1e833340b809101dd99815856b303e88a2d7005ff2627b56cdb4e2c85610c2d5f2e62d6eaeac1662734649b7n)
      ],
      [
        new Fp(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001n),
        new Fp(0x095fc13ab9e92ad4476d6e3eb3a56680f682b4ee96f7d03776df533978f31c1593174e4b4b7865002d6384d168ecdd0an),
        new Fp(0x0a10ecf6ada54f825e920b3dafc7a3cce07f8d1d7161366b74100da67f39883503826692abba43704776ec3a79a1d641n),
        new Fp(0x14a7ac2a9d64a8b230b3f5b074cf01996e7f63c21bca68a81996e1cdf9822c580fa5b9489d11e2d311f7d99bbdcc5a5en),
        new Fp(0x0772caacf16936190f3e0c63e0596721570f5799af53a1894e2e073062aede9cea73b3538f0de06cec2574496ee84a3an),
        new Fp(0x0e7355f8e4e667b955390f7f0506c6e9395735e9ce9cad4d0a43bcef24b8982f7400d24bc4228f11c02df9a29f6304a5n),
        new Fp(0x13a8e162022914a80a6f1d5f43e7a07dffdfc759a12062bb8d6b44e833b306da9bd29ba81f35781d539d395b3532a21en),
        new Fp(0x03425581a58ae2fec83aafef7c40eb545b08243f16b1655154cca8abc28d6fd04976d5243eecf5c4130de8938dc62cd8n),
        new Fp(0x0b2962fe57a3225e8137e629bff2991f6f89416f5a718cd1fca64e00b11aceacd6a3d0967c94fedcfcc239ba5cb83e19n),
        new Fp(0x12561a5deb559c4348b4711298e536367041e8ca0cf0800c0126c2588c48bf5713daa8846cb026e9e5c8276ec82b3bffn),
        new Fp(0x08ca8d548cff19ae18b2e62f4bd3fa6f01d5ef4ba35b48ba9c9588617fc8ac62b558d681be343df8993cf9fa40d21b1cn)
      ],
      [
        new Fp(0x15e6be4e990f03ce4ea50b3b42df2eb5cb181d8f84965a3957add4fa95af01b2b665027efec01c7704b456be69c8b604n),
        new Fp(0x05c129645e44cf1102a159f748c4a3fc5e673d81d7e86568d9ab0f5d396a7ce46ba1049b6579afb7866b1e715475224bn),
        new Fp(0x0245a394ad1eca9b72fc00ae7be315dc757b3b080d4c158013e6632d3c40659cc6cf90ad1c232a6442d9d3f5db980133n),
        new Fp(0x0b182cac101b9399d155096004f53f447aa7b12a3426b08ec02710e807b4633f06c851c1919211f20d4c04f00b971ef8n),
        new Fp(0x18b46a908f36f6deb918c143fed2edcc523559b8aaf0c2462e6bfe7f911f643249d9cdf41b44d606ce07c8a4d0074d8en),
        new Fp(0x19713e47937cd1be0dfd0b8f1d43fb93cd2fcbcb6caf493fd1183e416389e61031bf3a5cce3fbafce813711ad011c132n),
        new Fp(0x0e1bba7a1186bdb5223abde7ada14a23c42a0ca7915af6fe06985e7ed1e4d43b9b3f7055dd4eba6f2bafaaebca731c30n),
        new Fp(0x09fc4018bd96684be88c9e221e4da1bb8f3abd16679dc26c1e8b6e6a1f20cabe69d65201c78607a360370e577bdba587n),
        new Fp(0x0987c8d5333ab86fde9926bd2ca6c674170a05bfe3bdd81ffd038da6c26c842642f64550fedfe935a15e4ca31870fb29n),
        new Fp(0x04ab0b9bcfac1bbcb2c977d027796b3ce75bb8ca2be184cb5231413c4d634f3747a87ac2460f415ec961f8855fe9d6f2n),
        new Fp(0x16603fca40634b6a2211e11db8f0a6a074a7d0d4afadb7bd76505c3d3ad5544e203f6326c95a807299b23ab13633a5f0n),
        new Fp(0x08cc03fdefe0ff135caf4fe2a21529c4195536fbe3ce50b879833fd221351adc2ee7f8dc099040a841b6daecf2e8fedbn),
        new Fp(0x01f86376e8981c217898751ad8746757d42aa7b90eeb791c09e4a3ec03251cf9de405aba9ec61deca6355c77b0e5f4cbn),
        new Fp(0x00cc786baa966e66f4a384c86a3b49942552e2d658a31ce2c344be4b91400da7d26d521628b00523b8dfe240c72de1f6n),
        new Fp(0x134996a104ee5811d51036d776fb46831223e96c254f383d0f906343eb67ad34d6c56711962fa8bfe097e75a2e41c696n),
        new Fp(0x090d97c81ba24ee0259d1f094980dcfa11ad138e48a869522b52af6c956543d3cd0c7aee9b3ba3c2be9845719707bb33n)
      ],
      [
        new Fp(0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001n),
        new Fp(0x0e0fa1d816ddc03e6b24255e0d7819c171c40f65e273b853324efcd6356caa205ca2f570f13497804415473a1d634b8fn),
        new Fp(0x02660400eb2e4f3b628bdd0d53cd76f2bf565b94e72927c1cb748df27942480e420517bd8714cc80d1fadc1326ed06f7n),
        new Fp(0x0ad6b9514c767fe3c3613144b45f1496543346d98adf02267d5ceef9a00d9b8693000763e3b90ac11e99b138573345ccn),
        new Fp(0x0accbb67481d033ff5852c1e48c50c477f94ff8aefce42d28c0f9a88cea7913516f968986f7ebbea9684b529e2561092n),
        new Fp(0x04d2f259eea405bd48f010a01ad2911d9c6dd039bb61a6290e591b36e636a5c871a5c29f4f83060400f8b49cba8f6aa8n),
        new Fp(0x167a55cda70a6e1cea820597d94a84903216f763e13d87bb5308592e7ea7d4fbc7385ea3d529b35e346ef48bb8913f55n),
        new Fp(0x1866c8ed336c61231a1be54fd1d74cc4f9fb0ce4c6af5920abc5750c4bf39b4852cfe2f7bb9248836b233d9d55535d4an),
        new Fp(0x16a3ef08be3ea7ea03bcddfabba6ff6ee5a4375efa1f4fd7feb34fd206357132b920f5b00801dee460ee415a15812ed9n),
        new Fp(0x166007c08a99db2fc3ba8734ace9824b5eecfdfa8d0cf8ef5dd365bc400a0051d5fa9c01a58b1fb93d1a1399126a775cn),
        new Fp(0x08d9e5297186db2d9fb266eaac783182b70152c65550d881c5ecd87b6f0f5a6449f38db9dfa9cce202c6477faaf9b7acn),
        new Fp(0x0be0e079545f43e4b00cc912f8228ddcc6d19c9f0f69bbb0542eda0fc9dec916a20b15dc0fd2ededda39142311a5001dn),
        new Fp(0x16b7d288798e5395f20d23bf89edb4d1d115c5dbddbcd30e123da489e726af41727364f2c28297ada8d26d98445f5416n),
        new Fp(0x058df3306640da276faaae7d6e8eb15778c4855551ae7f310c35a5dd279cd2eca6757cd636f96f891e2538b53dbf67f2n),
        new Fp(0x1962d75c2381201e1a0cbd6c43c348b885c84ff731c4d59ca4a10356f453e01f78a4260763529e3532f6102c2e49a03dn),
        new Fp(0x16112c4c3a9c98b252181140fad0eae9601a6de578980be6eec3232b5be72e7a07f3688ef60c206d01479253b03663c1n)
      ]
    ];
  }
});

// node_modules/@noble/bls12-381/lib/index.js
var require_lib2 = __commonJS({
  "node_modules/@noble/bls12-381/lib/index.js"(exports) {
    "use strict";
    var __importDefault = exports && exports.__importDefault || function(mod) {
      return mod && mod.__esModule ? mod : { "default": mod };
    };
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.verifyBatch = exports.aggregateSignatures = exports.aggregatePublicKeys = exports.verify = exports.sign = exports.getPublicKey = exports.pairing = exports.PointG2 = exports.PointG1 = exports.utils = exports.CURVE = exports.Fp12 = exports.Fp2 = exports.Fr = exports.Fp = void 0;
    var crypto_1 = __importDefault(require("crypto"));
    var math_js_1 = require_math();
    Object.defineProperty(exports, "Fp", { enumerable: true, get: function() {
      return math_js_1.Fp;
    } });
    Object.defineProperty(exports, "Fr", { enumerable: true, get: function() {
      return math_js_1.Fr;
    } });
    Object.defineProperty(exports, "Fp2", { enumerable: true, get: function() {
      return math_js_1.Fp2;
    } });
    Object.defineProperty(exports, "Fp12", { enumerable: true, get: function() {
      return math_js_1.Fp12;
    } });
    Object.defineProperty(exports, "CURVE", { enumerable: true, get: function() {
      return math_js_1.CURVE;
    } });
    var POW_2_381 = 2n ** 381n;
    var POW_2_382 = POW_2_381 * 2n;
    var POW_2_383 = POW_2_382 * 2n;
    var PUBLIC_KEY_LENGTH = 48;
    function wrapHash(outputLen, h) {
      let tmp = h;
      tmp.outputLen = outputLen;
      return tmp;
    }
    var sha2562 = wrapHash(32, async (message) => {
      if (crypto5.web) {
        const buffer = await crypto5.web.subtle.digest("SHA-256", message.buffer);
        return new Uint8Array(buffer);
      } else if (crypto5.node) {
        return Uint8Array.from(crypto5.node.createHash("sha256").update(message).digest());
      } else {
        throw new Error("The environment doesn't have sha256 function");
      }
    });
    var htfDefaults = {
      DST: "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_",
      p: math_js_1.CURVE.P,
      m: 2,
      k: 128,
      expand: true,
      hash: sha2562
    };
    function isWithinCurveOrder(num) {
      return 0 < num && num < math_js_1.CURVE.r;
    }
    var crypto5 = {
      node: crypto_1.default,
      web: typeof self === "object" && "crypto" in self ? self.crypto : void 0
    };
    exports.utils = {
      hashToField: hash_to_field,
      expandMessageXMD: expand_message_xmd,
      hashToPrivateKey: (hash2) => {
        hash2 = ensureBytes(hash2);
        if (hash2.length < 40 || hash2.length > 1024)
          throw new Error("Expected 40-1024 bytes of private key as per FIPS 186");
        const num = (0, math_js_1.mod)((0, math_js_1.bytesToNumberBE)(hash2), math_js_1.CURVE.r);
        if (num === 0n || num === 1n)
          throw new Error("Invalid private key");
        return numberTo32BytesBE(num);
      },
      stringToBytes: stringToBytes2,
      bytesToHex: math_js_1.bytesToHex,
      hexToBytes: math_js_1.hexToBytes,
      randomBytes: (bytesLength = 32) => {
        if (crypto5.web) {
          return crypto5.web.getRandomValues(new Uint8Array(bytesLength));
        } else if (crypto5.node) {
          const { randomBytes } = crypto5.node;
          return new Uint8Array(randomBytes(bytesLength).buffer);
        } else {
          throw new Error("The environment doesn't have randomBytes function");
        }
      },
      randomPrivateKey: () => {
        return exports.utils.hashToPrivateKey(exports.utils.randomBytes(40));
      },
      sha256: sha2562,
      mod: math_js_1.mod,
      getDSTLabel() {
        return htfDefaults.DST;
      },
      setDSTLabel(newLabel) {
        if (typeof newLabel !== "string" || newLabel.length > 2048 || newLabel.length === 0) {
          throw new TypeError("Invalid DST");
        }
        htfDefaults.DST = newLabel;
      }
    };
    function numberTo32BytesBE(num) {
      const length = 32;
      const hex = num.toString(16).padStart(length * 2, "0");
      return (0, math_js_1.hexToBytes)(hex);
    }
    function toPaddedHex(num, padding) {
      if (typeof num !== "bigint" || num < 0n)
        throw new Error("Expected valid bigint");
      if (typeof padding !== "number")
        throw new TypeError("Expected valid padding");
      return num.toString(16).padStart(padding * 2, "0");
    }
    function ensureBytes(hex) {
      return hex instanceof Uint8Array ? Uint8Array.from(hex) : (0, math_js_1.hexToBytes)(hex);
    }
    function stringToBytes2(str) {
      const bytes2 = new Uint8Array(str.length);
      for (let i = 0; i < str.length; i++) {
        bytes2[i] = str.charCodeAt(i);
      }
      return bytes2;
    }
    function os2ip(bytes2) {
      let result = 0n;
      for (let i = 0; i < bytes2.length; i++) {
        result <<= 8n;
        result += BigInt(bytes2[i]);
      }
      return result;
    }
    function i2osp(value, length) {
      if (value < 0 || value >= 1 << 8 * length) {
        throw new Error(`bad I2OSP call: value=${value} length=${length}`);
      }
      const res = Array.from({ length }).fill(0);
      for (let i = length - 1; i >= 0; i--) {
        res[i] = value & 255;
        value >>>= 8;
      }
      return new Uint8Array(res);
    }
    function strxor(a, b) {
      const arr = new Uint8Array(a.length);
      for (let i = 0; i < a.length; i++) {
        arr[i] = a[i] ^ b[i];
      }
      return arr;
    }
    async function expand_message_xmd(msg, DST, lenInBytes, H = exports.utils.sha256) {
      if (DST.length > 255)
        DST = await H((0, math_js_1.concatBytes)(stringToBytes2("H2C-OVERSIZE-DST-"), DST));
      const b_in_bytes = H.outputLen;
      const r_in_bytes = b_in_bytes * 2;
      const ell = Math.ceil(lenInBytes / b_in_bytes);
      if (ell > 255)
        throw new Error("Invalid xmd length");
      const DST_prime = (0, math_js_1.concatBytes)(DST, i2osp(DST.length, 1));
      const Z_pad = i2osp(0, r_in_bytes);
      const l_i_b_str = i2osp(lenInBytes, 2);
      const b = new Array(ell);
      const b_0 = await H((0, math_js_1.concatBytes)(Z_pad, msg, l_i_b_str, i2osp(0, 1), DST_prime));
      b[0] = await H((0, math_js_1.concatBytes)(b_0, i2osp(1, 1), DST_prime));
      for (let i = 1; i <= ell; i++) {
        const args = [strxor(b_0, b[i - 1]), i2osp(i + 1, 1), DST_prime];
        b[i] = await H((0, math_js_1.concatBytes)(...args));
      }
      const pseudo_random_bytes = (0, math_js_1.concatBytes)(...b);
      return pseudo_random_bytes.slice(0, lenInBytes);
    }
    async function hash_to_field(msg, count, options = {}) {
      const htfOptions = { ...htfDefaults, ...options };
      const log2p = htfOptions.p.toString(2).length;
      const L = Math.ceil((log2p + htfOptions.k) / 8);
      const len_in_bytes = count * htfOptions.m * L;
      const DST = stringToBytes2(htfOptions.DST);
      let pseudo_random_bytes = msg;
      if (htfOptions.expand) {
        pseudo_random_bytes = await expand_message_xmd(msg, DST, len_in_bytes, htfOptions.hash);
      }
      const u = new Array(count);
      for (let i = 0; i < count; i++) {
        const e = new Array(htfOptions.m);
        for (let j = 0; j < htfOptions.m; j++) {
          const elm_offset = L * (j + i * htfOptions.m);
          const tv = pseudo_random_bytes.subarray(elm_offset, elm_offset + L);
          e[j] = (0, math_js_1.mod)(os2ip(tv), htfOptions.p);
        }
        u[i] = e;
      }
      return u;
    }
    function normalizePrivKey(key) {
      let int;
      if (key instanceof Uint8Array && key.length === 32)
        int = (0, math_js_1.bytesToNumberBE)(key);
      else if (typeof key === "string" && key.length === 64)
        int = BigInt(`0x${key}`);
      else if (typeof key === "number" && key > 0 && Number.isSafeInteger(key))
        int = BigInt(key);
      else if (typeof key === "bigint" && key > 0n)
        int = key;
      else
        throw new TypeError("Expected valid private key");
      int = (0, math_js_1.mod)(int, math_js_1.CURVE.r);
      if (!isWithinCurveOrder(int))
        throw new Error("Private key must be 0 < key < CURVE.r");
      return int;
    }
    function assertType(item, type) {
      if (!(item instanceof type))
        throw new Error("Expected Fp* argument, not number/bigint");
    }
    var PointG1 = class extends math_js_1.ProjectivePoint {
      constructor(x, y, z = math_js_1.Fp.ONE) {
        super(x, y, z, math_js_1.Fp);
        assertType(x, math_js_1.Fp);
        assertType(y, math_js_1.Fp);
        assertType(z, math_js_1.Fp);
      }
      static fromHex(bytes2) {
        bytes2 = ensureBytes(bytes2);
        let point;
        if (bytes2.length === 48) {
          const { P } = math_js_1.CURVE;
          const compressedValue = (0, math_js_1.bytesToNumberBE)(bytes2);
          const bflag = (0, math_js_1.mod)(compressedValue, POW_2_383) / POW_2_382;
          if (bflag === 1n) {
            return this.ZERO;
          }
          const x = new math_js_1.Fp((0, math_js_1.mod)(compressedValue, POW_2_381));
          const right = x.pow(3n).add(new math_js_1.Fp(math_js_1.CURVE.b));
          let y = right.sqrt();
          if (!y)
            throw new Error("Invalid compressed G1 point");
          const aflag = (0, math_js_1.mod)(compressedValue, POW_2_382) / POW_2_381;
          if (y.value * 2n / P !== aflag)
            y = y.negate();
          point = new PointG1(x, y);
        } else if (bytes2.length === 96) {
          if ((bytes2[0] & 1 << 6) !== 0)
            return PointG1.ZERO;
          const x = (0, math_js_1.bytesToNumberBE)(bytes2.slice(0, PUBLIC_KEY_LENGTH));
          const y = (0, math_js_1.bytesToNumberBE)(bytes2.slice(PUBLIC_KEY_LENGTH));
          point = new PointG1(new math_js_1.Fp(x), new math_js_1.Fp(y));
        } else {
          throw new Error("Invalid point G1, expected 48/96 bytes");
        }
        point.assertValidity();
        return point;
      }
      static async hashToCurve(msg, options) {
        msg = ensureBytes(msg);
        const [[u0], [u1]] = await hash_to_field(msg, 2, { m: 1, ...options });
        const [x0, y0] = (0, math_js_1.map_to_curve_simple_swu_3mod4)(new math_js_1.Fp(u0));
        const [x1, y1] = (0, math_js_1.map_to_curve_simple_swu_3mod4)(new math_js_1.Fp(u1));
        const [x2, y2] = new PointG1(x0, y0).add(new PointG1(x1, y1)).toAffine();
        const [x3, y3] = (0, math_js_1.isogenyMapG1)(x2, y2);
        return new PointG1(x3, y3).clearCofactor();
      }
      static async encodeToCurve(msg, options) {
        msg = ensureBytes(msg);
        const u = await hash_to_field(msg, 1, {
          m: 1,
          ...options
        });
        const [x0, y0] = (0, math_js_1.map_to_curve_simple_swu_3mod4)(new math_js_1.Fp(u[0][0]));
        const [x1, y1] = (0, math_js_1.isogenyMapG1)(x0, y0);
        return new PointG1(x1, y1).clearCofactor();
      }
      static fromPrivateKey(privateKey) {
        return this.BASE.multiplyPrecomputed(normalizePrivKey(privateKey));
      }
      toRawBytes(isCompressed = false) {
        return (0, math_js_1.hexToBytes)(this.toHex(isCompressed));
      }
      toHex(isCompressed = false) {
        this.assertValidity();
        if (isCompressed) {
          const { P } = math_js_1.CURVE;
          let hex;
          if (this.isZero()) {
            hex = POW_2_383 + POW_2_382;
          } else {
            const [x, y] = this.toAffine();
            const flag = y.value * 2n / P;
            hex = x.value + flag * POW_2_381 + POW_2_383;
          }
          return toPaddedHex(hex, PUBLIC_KEY_LENGTH);
        } else {
          if (this.isZero()) {
            return "4".padEnd(2 * 2 * PUBLIC_KEY_LENGTH, "0");
          } else {
            const [x, y] = this.toAffine();
            return toPaddedHex(x.value, PUBLIC_KEY_LENGTH) + toPaddedHex(y.value, PUBLIC_KEY_LENGTH);
          }
        }
      }
      assertValidity() {
        if (this.isZero())
          return this;
        if (!this.isOnCurve())
          throw new Error("Invalid G1 point: not on curve Fp");
        if (!this.isTorsionFree())
          throw new Error("Invalid G1 point: must be of prime-order subgroup");
        return this;
      }
      [Symbol.for("nodejs.util.inspect.custom")]() {
        return this.toString();
      }
      millerLoop(P) {
        return (0, math_js_1.millerLoop)(P.pairingPrecomputes(), this.toAffine());
      }
      clearCofactor() {
        const t = this.mulCurveMinusX();
        return t.add(this);
      }
      isOnCurve() {
        const b = new math_js_1.Fp(math_js_1.CURVE.b);
        const { x, y, z } = this;
        const left = y.pow(2n).multiply(z).subtract(x.pow(3n));
        const right = b.multiply(z.pow(3n));
        return left.subtract(right).isZero();
      }
      sigma() {
        const BETA = 0x1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaacn;
        const [x, y] = this.toAffine();
        return new PointG1(x.multiply(BETA), y);
      }
      phi() {
        const cubicRootOfUnityModP = 0x5f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffefffen;
        return new PointG1(this.x.multiply(cubicRootOfUnityModP), this.y, this.z);
      }
      mulCurveX() {
        return this.multiplyUnsafe(math_js_1.CURVE.x).negate();
      }
      mulCurveMinusX() {
        return this.multiplyUnsafe(math_js_1.CURVE.x);
      }
      isTorsionFree() {
        const xP = this.mulCurveX();
        const u2P = xP.mulCurveMinusX();
        return u2P.equals(this.phi());
      }
    };
    exports.PointG1 = PointG1;
    PointG1.BASE = new PointG1(new math_js_1.Fp(math_js_1.CURVE.Gx), new math_js_1.Fp(math_js_1.CURVE.Gy), math_js_1.Fp.ONE);
    PointG1.ZERO = new PointG1(math_js_1.Fp.ONE, math_js_1.Fp.ONE, math_js_1.Fp.ZERO);
    var PointG2 = class extends math_js_1.ProjectivePoint {
      constructor(x, y, z = math_js_1.Fp2.ONE) {
        super(x, y, z, math_js_1.Fp2);
        assertType(x, math_js_1.Fp2);
        assertType(y, math_js_1.Fp2);
        assertType(z, math_js_1.Fp2);
      }
      static async hashToCurve(msg, options) {
        msg = ensureBytes(msg);
        const u = await hash_to_field(msg, 2, options);
        const [x0, y0] = (0, math_js_1.map_to_curve_simple_swu_9mod16)(math_js_1.Fp2.fromBigTuple(u[0]));
        const [x1, y1] = (0, math_js_1.map_to_curve_simple_swu_9mod16)(math_js_1.Fp2.fromBigTuple(u[1]));
        const [x2, y2] = new PointG2(x0, y0).add(new PointG2(x1, y1)).toAffine();
        const [x3, y3] = (0, math_js_1.isogenyMapG2)(x2, y2);
        return new PointG2(x3, y3).clearCofactor();
      }
      static async encodeToCurve(msg, options) {
        msg = ensureBytes(msg);
        const u = await hash_to_field(msg, 1, options);
        const [x0, y0] = (0, math_js_1.map_to_curve_simple_swu_9mod16)(math_js_1.Fp2.fromBigTuple(u[0]));
        const [x1, y1] = (0, math_js_1.isogenyMapG2)(x0, y0);
        return new PointG2(x1, y1).clearCofactor();
      }
      static fromSignature(hex) {
        hex = ensureBytes(hex);
        const { P } = math_js_1.CURVE;
        const half = hex.length / 2;
        if (half !== 48 && half !== 96)
          throw new Error("Invalid compressed signature length, must be 96 or 192");
        const z1 = (0, math_js_1.bytesToNumberBE)(hex.slice(0, half));
        const z2 = (0, math_js_1.bytesToNumberBE)(hex.slice(half));
        const bflag1 = (0, math_js_1.mod)(z1, POW_2_383) / POW_2_382;
        if (bflag1 === 1n)
          return this.ZERO;
        const x1 = new math_js_1.Fp(z1 % POW_2_381);
        const x2 = new math_js_1.Fp(z2);
        const x = new math_js_1.Fp2(x2, x1);
        const y2 = x.pow(3n).add(math_js_1.Fp2.fromBigTuple(math_js_1.CURVE.b2));
        let y = y2.sqrt();
        if (!y)
          throw new Error("Failed to find a square root");
        const { re: y0, im: y1 } = y.reim();
        const aflag1 = z1 % POW_2_382 / POW_2_381;
        const isGreater = y1 > 0n && y1 * 2n / P !== aflag1;
        const isZero = y1 === 0n && y0 * 2n / P !== aflag1;
        if (isGreater || isZero)
          y = y.multiply(-1n);
        const point = new PointG2(x, y, math_js_1.Fp2.ONE);
        point.assertValidity();
        return point;
      }
      static fromHex(bytes2) {
        bytes2 = ensureBytes(bytes2);
        const m_byte = bytes2[0] & 224;
        if (m_byte === 32 || m_byte === 96 || m_byte === 224) {
          throw new Error("Invalid encoding flag: " + m_byte);
        }
        const bitC = m_byte & 128;
        const bitI = m_byte & 64;
        const bitS = m_byte & 32;
        let point;
        if (bytes2.length === 96 && bitC) {
          const { P, b2 } = math_js_1.CURVE;
          const b = math_js_1.Fp2.fromBigTuple(b2);
          bytes2[0] = bytes2[0] & 31;
          if (bitI) {
            if (bytes2.reduce((p, c) => p !== 0 ? c + 1 : c, 0) > 0) {
              throw new Error("Invalid compressed G2 point");
            }
            return PointG2.ZERO;
          }
          const x_1 = (0, math_js_1.bytesToNumberBE)(bytes2.slice(0, PUBLIC_KEY_LENGTH));
          const x_0 = (0, math_js_1.bytesToNumberBE)(bytes2.slice(PUBLIC_KEY_LENGTH));
          const x = new math_js_1.Fp2(new math_js_1.Fp(x_0), new math_js_1.Fp(x_1));
          const right = x.pow(3n).add(b);
          let y = right.sqrt();
          if (!y)
            throw new Error("Invalid compressed G2 point");
          const Y_bit = y.c1.value === 0n ? y.c0.value * 2n / P : y.c1.value * 2n / P ? 1n : 0n;
          y = bitS > 0 && Y_bit > 0 ? y : y.negate();
          return new PointG2(x, y);
        } else if (bytes2.length === 192 && !bitC) {
          if ((bytes2[0] & 1 << 6) !== 0) {
            return PointG2.ZERO;
          }
          const x1 = (0, math_js_1.bytesToNumberBE)(bytes2.slice(0, PUBLIC_KEY_LENGTH));
          const x0 = (0, math_js_1.bytesToNumberBE)(bytes2.slice(PUBLIC_KEY_LENGTH, 2 * PUBLIC_KEY_LENGTH));
          const y1 = (0, math_js_1.bytesToNumberBE)(bytes2.slice(2 * PUBLIC_KEY_LENGTH, 3 * PUBLIC_KEY_LENGTH));
          const y0 = (0, math_js_1.bytesToNumberBE)(bytes2.slice(3 * PUBLIC_KEY_LENGTH));
          point = new PointG2(math_js_1.Fp2.fromBigTuple([x0, x1]), math_js_1.Fp2.fromBigTuple([y0, y1]));
        } else {
          throw new Error("Invalid point G2, expected 96/192 bytes");
        }
        point.assertValidity();
        return point;
      }
      static fromPrivateKey(privateKey) {
        return this.BASE.multiplyPrecomputed(normalizePrivKey(privateKey));
      }
      toSignature() {
        if (this.equals(PointG2.ZERO)) {
          const sum = POW_2_383 + POW_2_382;
          const h = toPaddedHex(sum, PUBLIC_KEY_LENGTH) + toPaddedHex(0n, PUBLIC_KEY_LENGTH);
          return (0, math_js_1.hexToBytes)(h);
        }
        const [{ re: x0, im: x1 }, { re: y0, im: y1 }] = this.toAffine().map((a) => a.reim());
        const tmp = y1 > 0n ? y1 * 2n : y0 * 2n;
        const aflag1 = tmp / math_js_1.CURVE.P;
        const z1 = x1 + aflag1 * POW_2_381 + POW_2_383;
        const z2 = x0;
        return (0, math_js_1.hexToBytes)(toPaddedHex(z1, PUBLIC_KEY_LENGTH) + toPaddedHex(z2, PUBLIC_KEY_LENGTH));
      }
      toRawBytes(isCompressed = false) {
        return (0, math_js_1.hexToBytes)(this.toHex(isCompressed));
      }
      toHex(isCompressed = false) {
        this.assertValidity();
        if (isCompressed) {
          const { P } = math_js_1.CURVE;
          let x_1 = 0n;
          let x_0 = 0n;
          if (this.isZero()) {
            x_1 = POW_2_383 + POW_2_382;
          } else {
            const [x, y] = this.toAffine();
            const flag = y.c1.value === 0n ? y.c0.value * 2n / P : y.c1.value * 2n / P ? 1n : 0n;
            x_1 = x.c1.value + flag * POW_2_381 + POW_2_383;
            x_0 = x.c0.value;
          }
          return toPaddedHex(x_1, PUBLIC_KEY_LENGTH) + toPaddedHex(x_0, PUBLIC_KEY_LENGTH);
        } else {
          if (this.equals(PointG2.ZERO)) {
            return "4".padEnd(2 * 4 * PUBLIC_KEY_LENGTH, "0");
          }
          const [{ re: x0, im: x1 }, { re: y0, im: y1 }] = this.toAffine().map((a) => a.reim());
          return toPaddedHex(x1, PUBLIC_KEY_LENGTH) + toPaddedHex(x0, PUBLIC_KEY_LENGTH) + toPaddedHex(y1, PUBLIC_KEY_LENGTH) + toPaddedHex(y0, PUBLIC_KEY_LENGTH);
        }
      }
      assertValidity() {
        if (this.isZero())
          return this;
        if (!this.isOnCurve())
          throw new Error("Invalid G2 point: not on curve Fp2");
        if (!this.isTorsionFree())
          throw new Error("Invalid G2 point: must be of prime-order subgroup");
        return this;
      }
      psi() {
        return this.fromAffineTuple((0, math_js_1.psi)(...this.toAffine()));
      }
      psi2() {
        return this.fromAffineTuple((0, math_js_1.psi2)(...this.toAffine()));
      }
      mulCurveX() {
        return this.multiplyUnsafe(math_js_1.CURVE.x).negate();
      }
      clearCofactor() {
        const P = this;
        let t1 = P.mulCurveX();
        let t2 = P.psi();
        let t3 = P.double();
        t3 = t3.psi2();
        t3 = t3.subtract(t2);
        t2 = t1.add(t2);
        t2 = t2.mulCurveX();
        t3 = t3.add(t2);
        t3 = t3.subtract(t1);
        const Q = t3.subtract(P);
        return Q;
      }
      isOnCurve() {
        const b = math_js_1.Fp2.fromBigTuple(math_js_1.CURVE.b2);
        const { x, y, z } = this;
        const left = y.pow(2n).multiply(z).subtract(x.pow(3n));
        const right = b.multiply(z.pow(3n));
        return left.subtract(right).isZero();
      }
      isTorsionFree() {
        const P = this;
        return P.mulCurveX().equals(P.psi());
      }
      [Symbol.for("nodejs.util.inspect.custom")]() {
        return this.toString();
      }
      clearPairingPrecomputes() {
        this._PPRECOMPUTES = void 0;
      }
      pairingPrecomputes() {
        if (this._PPRECOMPUTES)
          return this._PPRECOMPUTES;
        this._PPRECOMPUTES = (0, math_js_1.calcPairingPrecomputes)(...this.toAffine());
        return this._PPRECOMPUTES;
      }
    };
    exports.PointG2 = PointG2;
    PointG2.BASE = new PointG2(math_js_1.Fp2.fromBigTuple(math_js_1.CURVE.G2x), math_js_1.Fp2.fromBigTuple(math_js_1.CURVE.G2y), math_js_1.Fp2.ONE);
    PointG2.ZERO = new PointG2(math_js_1.Fp2.ONE, math_js_1.Fp2.ONE, math_js_1.Fp2.ZERO);
    function pairing(P, Q, withFinalExponent = true) {
      if (P.isZero() || Q.isZero())
        throw new Error("No pairings at point of Infinity");
      P.assertValidity();
      Q.assertValidity();
      const looped = P.millerLoop(Q);
      return withFinalExponent ? looped.finalExponentiate() : looped;
    }
    exports.pairing = pairing;
    function normP1(point) {
      return point instanceof PointG1 ? point : PointG1.fromHex(point);
    }
    function normP2(point) {
      return point instanceof PointG2 ? point : PointG2.fromSignature(point);
    }
    async function normP2Hash(point) {
      return point instanceof PointG2 ? point : PointG2.hashToCurve(point);
    }
    function getPublicKey(privateKey) {
      return PointG1.fromPrivateKey(privateKey).toRawBytes(true);
    }
    exports.getPublicKey = getPublicKey;
    async function sign(message, privateKey) {
      const msgPoint = await normP2Hash(message);
      msgPoint.assertValidity();
      const sigPoint = msgPoint.multiply(normalizePrivKey(privateKey));
      if (message instanceof PointG2)
        return sigPoint;
      return sigPoint.toSignature();
    }
    exports.sign = sign;
    async function verify(signature, message, publicKey) {
      const P = normP1(publicKey);
      const Hm = await normP2Hash(message);
      const G = PointG1.BASE;
      const S = normP2(signature);
      const ePHm = pairing(P.negate(), Hm, false);
      const eGS = pairing(G, S, false);
      const exp = eGS.multiply(ePHm).finalExponentiate();
      return exp.equals(math_js_1.Fp12.ONE);
    }
    exports.verify = verify;
    function aggregatePublicKeys(publicKeys) {
      if (!publicKeys.length)
        throw new Error("Expected non-empty array");
      const agg = publicKeys.map(normP1).reduce((sum, p) => sum.add(p), PointG1.ZERO);
      if (publicKeys[0] instanceof PointG1)
        return agg.assertValidity();
      return agg.toRawBytes(true);
    }
    exports.aggregatePublicKeys = aggregatePublicKeys;
    function aggregateSignatures(signatures) {
      if (!signatures.length)
        throw new Error("Expected non-empty array");
      const agg = signatures.map(normP2).reduce((sum, s) => sum.add(s), PointG2.ZERO);
      if (signatures[0] instanceof PointG2)
        return agg.assertValidity();
      return agg.toSignature();
    }
    exports.aggregateSignatures = aggregateSignatures;
    async function verifyBatch(signature, messages, publicKeys) {
      if (!messages.length)
        throw new Error("Expected non-empty messages array");
      if (publicKeys.length !== messages.length)
        throw new Error("Pubkey count should equal msg count");
      const sig = normP2(signature);
      const nMessages = await Promise.all(messages.map(normP2Hash));
      const nPublicKeys = publicKeys.map(normP1);
      try {
        const paired = [];
        for (const message of new Set(nMessages)) {
          const groupPublicKey = nMessages.reduce((groupPublicKey2, subMessage, i) => subMessage === message ? groupPublicKey2.add(nPublicKeys[i]) : groupPublicKey2, PointG1.ZERO);
          paired.push(pairing(groupPublicKey, message, false));
        }
        paired.push(pairing(PointG1.BASE.negate(), sig, false));
        const product = paired.reduce((a, b) => a.multiply(b), math_js_1.Fp12.ONE);
        const exp = product.finalExponentiate();
        return exp.equals(math_js_1.Fp12.ONE);
      } catch {
        return false;
      }
    }
    exports.verifyBatch = verifyBatch;
    PointG1.BASE.calcMultiplyPrecomputes(4);
  }
});

// node_modules/drand-client/beacon-verification.js
var require_beacon_verification = __commonJS({
  "node_modules/drand-client/beacon-verification.js"(exports) {
    "use strict";
    var __createBinding = exports && exports.__createBinding || (Object.create ? function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      var desc = Object.getOwnPropertyDescriptor(m, k);
      if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
        desc = { enumerable: true, get: function() {
          return m[k];
        } };
      }
      Object.defineProperty(o, k2, desc);
    } : function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      o[k2] = m[k];
    });
    var __setModuleDefault = exports && exports.__setModuleDefault || (Object.create ? function(o, v) {
      Object.defineProperty(o, "default", { enumerable: true, value: v });
    } : function(o, v) {
      o["default"] = v;
    });
    var __importStar = exports && exports.__importStar || function(mod) {
      if (mod && mod.__esModule)
        return mod;
      var result = {};
      if (mod != null) {
        for (var k in mod)
          if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k))
            __createBinding(result, mod, k);
      }
      __setModuleDefault(result, mod);
      return result;
    };
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.roundBuffer = exports.verifyBeacon = exports.verifySigOnG1 = void 0;
    var bls = __importStar(require_lib2());
    var bls12_381_1 = require_lib2();
    var index_1 = require_drand_client();
    async function verifyBeacon(chainInfo, beacon) {
      const publicKey = chainInfo.public_key;
      if (!await randomnessIsValid(beacon)) {
        return false;
      }
      if ((0, index_1.isChainedBeacon)(beacon, chainInfo)) {
        return bls.verify(beacon.signature, await chainedBeaconMessage(beacon), publicKey);
      }
      if ((0, index_1.isUnchainedBeacon)(beacon, chainInfo)) {
        return bls.verify(beacon.signature, await unchainedBeaconMessage(beacon), publicKey);
      }
      if ((0, index_1.isG1G2SwappedBeacon)(beacon, chainInfo)) {
        return verifySigOnG1(beacon.signature, await unchainedBeaconMessage(beacon), publicKey);
      }
      console.error(`Beacon type ${chainInfo.schemeID} was not supported`);
      return false;
    }
    exports.verifyBeacon = verifyBeacon;
    function normP1(point) {
      return point instanceof bls12_381_1.PointG1 ? point : bls12_381_1.PointG1.fromHex(point);
    }
    function normP2(point) {
      return point instanceof bls12_381_1.PointG2 ? point : bls12_381_1.PointG2.fromHex(point);
    }
    async function normP1Hash(point) {
      return point instanceof bls12_381_1.PointG1 ? point : bls12_381_1.PointG1.hashToCurve(point);
    }
    async function verifySigOnG1(signature, message, publicKey) {
      const P = normP2(publicKey);
      const Hm = await normP1Hash(message);
      const G = bls12_381_1.PointG2.BASE;
      const S = normP1(signature);
      const ePHm = (0, bls12_381_1.pairing)(Hm, P.negate(), false);
      const eGS = (0, bls12_381_1.pairing)(S, G, false);
      const exp = eGS.multiply(ePHm).finalExponentiate();
      return exp.equals(bls12_381_1.Fp12.ONE);
    }
    exports.verifySigOnG1 = verifySigOnG1;
    async function chainedBeaconMessage(beacon) {
      const message = Buffer.concat([
        signatureBuffer(beacon.previous_signature),
        roundBuffer(beacon.round)
      ]);
      return bls.utils.sha256(message);
    }
    async function unchainedBeaconMessage(beacon) {
      return bls.utils.sha256(roundBuffer(beacon.round));
    }
    function signatureBuffer(sig) {
      return Buffer.from(sig, "hex");
    }
    function roundBuffer(round) {
      const buffer = Buffer.alloc(8);
      buffer.writeBigUInt64BE(BigInt(round));
      return buffer;
    }
    exports.roundBuffer = roundBuffer;
    async function randomnessIsValid(beacon) {
      const expectedRandomness = await bls.utils.sha256(Buffer.from(beacon.signature, "hex"));
      return Buffer.from(beacon.randomness, "hex").compare(expectedRandomness) == 0;
    }
  }
});

// node_modules/drand-client/index.js
var require_drand_client = __commonJS({
  "node_modules/drand-client/index.js"(exports) {
    "use strict";
    var __importDefault = exports && exports.__importDefault || function(mod) {
      return mod && mod.__esModule ? mod : { "default": mod };
    };
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.roundTime = exports.roundAt = exports.FastestNodeClient = exports.MultiBeaconNode = exports.HttpCachingChain = exports.HttpChainClient = exports.HttpChain = exports.isG1G2SwappedBeacon = exports.isUnchainedBeacon = exports.isChainedBeacon = exports.watch = exports.fetchBeaconByTime = exports.fetchBeacon = exports.defaultChainOptions = void 0;
    var http_caching_chain_1 = __importDefault(require_http_caching_chain());
    exports.HttpCachingChain = http_caching_chain_1.default;
    var http_caching_chain_2 = require_http_caching_chain();
    Object.defineProperty(exports, "HttpChain", { enumerable: true, get: function() {
      return http_caching_chain_2.HttpChain;
    } });
    var http_chain_client_1 = __importDefault(require_http_chain_client());
    exports.HttpChainClient = http_chain_client_1.default;
    var fastest_node_client_1 = __importDefault(require_fastest_node_client());
    exports.FastestNodeClient = fastest_node_client_1.default;
    var multi_beacon_node_1 = __importDefault(require_multi_beacon_node());
    exports.MultiBeaconNode = multi_beacon_node_1.default;
    var util_1 = require_util();
    Object.defineProperty(exports, "roundAt", { enumerable: true, get: function() {
      return util_1.roundAt;
    } });
    Object.defineProperty(exports, "roundTime", { enumerable: true, get: function() {
      return util_1.roundTime;
    } });
    var beacon_verification_1 = require_beacon_verification();
    exports.defaultChainOptions = {
      disableBeaconVerification: false,
      noCache: false
    };
    async function fetchBeacon(client, roundNumber) {
      let beacon = null;
      if (!roundNumber) {
        beacon = await client.latest();
      } else if (roundNumber < 1) {
        throw Error("Cannot request lower than round number 1");
      } else {
        beacon = await client.get(roundNumber);
      }
      return validatedBeacon(client, beacon);
    }
    exports.fetchBeacon = fetchBeacon;
    async function fetchBeaconByTime2(client, time) {
      const info = await client.chain().info();
      const roundNumber = (0, util_1.roundAt)(time, info);
      return fetchBeacon(client, roundNumber);
    }
    exports.fetchBeaconByTime = fetchBeaconByTime2;
    async function* watch(client, abortController, options = defaultWatchOptions) {
      const info = await client.chain().info();
      let currentRound = (0, util_1.roundAt)(Date.now(), info);
      while (!abortController.signal.aborted) {
        const now = Date.now();
        await (0, util_1.sleep)((0, util_1.roundTime)(info, currentRound) - now);
        const beacon = await (0, util_1.retryOnError)(async () => client.get(currentRound), options.retriesOnFailure);
        yield validatedBeacon(client, beacon);
        currentRound = currentRound + 1;
      }
    }
    exports.watch = watch;
    var defaultWatchOptions = {
      retriesOnFailure: 3
    };
    async function validatedBeacon(client, beacon) {
      if (client.options.disableBeaconVerification) {
        return beacon;
      }
      const info = await client.chain().info();
      if (!await (0, beacon_verification_1.verifyBeacon)(info, beacon)) {
        throw Error("The beacon retrieved was not valid!");
      }
      return beacon;
    }
    function isChainedBeacon(value, info) {
      return info.schemeID === "pedersen-bls-chained" && !!value.previous_signature && !!value.randomness && !!value.signature && value.round > 0;
    }
    exports.isChainedBeacon = isChainedBeacon;
    function isUnchainedBeacon(value, info) {
      return info.schemeID === "pedersen-bls-unchained" && !!value.randomness && !!value.signature && value.previous_signature === void 0 && value.round > 0;
    }
    exports.isUnchainedBeacon = isUnchainedBeacon;
    function isG1G2SwappedBeacon(value, info) {
      return info.schemeID === "bls-unchained-on-g1" && !!value.randomness && !!value.signature && value.previous_signature === void 0 && value.round > 0;
    }
    exports.isG1G2SwappedBeacon = isG1G2SwappedBeacon;
  }
});

// src/index.ts
var fs = __toESM(require("fs/promises"));
var path = __toESM(require("path"));
var core = __toESM(require_core());
var import_promises = require("fs/promises");
var import_drand_client2 = __toESM(require_drand_client());

// src/select.ts
var import_drand_client = __toESM(require_drand_client());

// node_modules/@noble/hashes/esm/_assert.js
function number(n) {
  if (!Number.isSafeInteger(n) || n < 0)
    throw new Error(`Wrong positive integer: ${n}`);
}
function bool(b) {
  if (typeof b !== "boolean")
    throw new Error(`Expected boolean, not ${b}`);
}
function bytes(b, ...lengths) {
  if (!(b instanceof Uint8Array))
    throw new Error("Expected Uint8Array");
  if (lengths.length > 0 && !lengths.includes(b.length))
    throw new Error(`Expected Uint8Array of length ${lengths}, not of length=${b.length}`);
}
function hash(hash2) {
  if (typeof hash2 !== "function" || typeof hash2.create !== "function")
    throw new Error("Hash should be wrapped by utils.wrapConstructor");
  number(hash2.outputLen);
  number(hash2.blockLen);
}
function exists(instance, checkFinished = true) {
  if (instance.destroyed)
    throw new Error("Hash instance has been destroyed");
  if (checkFinished && instance.finished)
    throw new Error("Hash#digest() has already been called");
}
function output(out, instance) {
  bytes(out);
  const min = instance.outputLen;
  if (out.length < min) {
    throw new Error(`digestInto() expects output buffer of length at least ${min}`);
  }
}
var assert = {
  number,
  bool,
  bytes,
  hash,
  exists,
  output
};
var assert_default = assert;

// node_modules/@noble/hashes/esm/cryptoNode.js
var nc = __toESM(require("node:crypto"), 1);
var crypto4 = nc && typeof nc === "object" && "webcrypto" in nc ? nc.webcrypto : void 0;

// node_modules/@noble/hashes/esm/utils.js
var u8a = (a) => a instanceof Uint8Array;
var createView = (arr) => new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
var rotr = (word, shift) => word << 32 - shift | word >>> shift;
var isLE = new Uint8Array(new Uint32Array([287454020]).buffer)[0] === 68;
if (!isLE)
  throw new Error("Non little-endian hardware is not supported");
var hexes = Array.from({ length: 256 }, (v, i) => i.toString(16).padStart(2, "0"));
function utf8ToBytes(str) {
  if (typeof str !== "string")
    throw new Error(`utf8ToBytes expected string, got ${typeof str}`);
  return new Uint8Array(new TextEncoder().encode(str));
}
function toBytes(data) {
  if (typeof data === "string")
    data = utf8ToBytes(data);
  if (!u8a(data))
    throw new Error(`expected Uint8Array, got ${typeof data}`);
  return data;
}
var Hash = class {
  // Safe version that clones internal state
  clone() {
    return this._cloneInto();
  }
};
function wrapConstructor(hashCons) {
  const hashC = (msg) => hashCons().update(toBytes(msg)).digest();
  const tmp = hashCons();
  hashC.outputLen = tmp.outputLen;
  hashC.blockLen = tmp.blockLen;
  hashC.create = () => hashCons();
  return hashC;
}

// node_modules/@noble/hashes/esm/_sha2.js
function setBigUint64(view, byteOffset, value, isLE2) {
  if (typeof view.setBigUint64 === "function")
    return view.setBigUint64(byteOffset, value, isLE2);
  const _32n = BigInt(32);
  const _u32_max = BigInt(4294967295);
  const wh = Number(value >> _32n & _u32_max);
  const wl = Number(value & _u32_max);
  const h = isLE2 ? 4 : 0;
  const l = isLE2 ? 0 : 4;
  view.setUint32(byteOffset + h, wh, isLE2);
  view.setUint32(byteOffset + l, wl, isLE2);
}
var SHA2 = class extends Hash {
  constructor(blockLen, outputLen, padOffset, isLE2) {
    super();
    this.blockLen = blockLen;
    this.outputLen = outputLen;
    this.padOffset = padOffset;
    this.isLE = isLE2;
    this.finished = false;
    this.length = 0;
    this.pos = 0;
    this.destroyed = false;
    this.buffer = new Uint8Array(blockLen);
    this.view = createView(this.buffer);
  }
  update(data) {
    assert_default.exists(this);
    const { view, buffer, blockLen } = this;
    data = toBytes(data);
    const len = data.length;
    for (let pos = 0; pos < len; ) {
      const take = Math.min(blockLen - this.pos, len - pos);
      if (take === blockLen) {
        const dataView = createView(data);
        for (; blockLen <= len - pos; pos += blockLen)
          this.process(dataView, pos);
        continue;
      }
      buffer.set(data.subarray(pos, pos + take), this.pos);
      this.pos += take;
      pos += take;
      if (this.pos === blockLen) {
        this.process(view, 0);
        this.pos = 0;
      }
    }
    this.length += data.length;
    this.roundClean();
    return this;
  }
  digestInto(out) {
    assert_default.exists(this);
    assert_default.output(out, this);
    this.finished = true;
    const { buffer, view, blockLen, isLE: isLE2 } = this;
    let { pos } = this;
    buffer[pos++] = 128;
    this.buffer.subarray(pos).fill(0);
    if (this.padOffset > blockLen - pos) {
      this.process(view, 0);
      pos = 0;
    }
    for (let i = pos; i < blockLen; i++)
      buffer[i] = 0;
    setBigUint64(view, blockLen - 8, BigInt(this.length * 8), isLE2);
    this.process(view, 0);
    const oview = createView(out);
    const len = this.outputLen;
    if (len % 4)
      throw new Error("_sha2: outputLen should be aligned to 32bit");
    const outLen = len / 4;
    const state = this.get();
    if (outLen > state.length)
      throw new Error("_sha2: outputLen bigger than state");
    for (let i = 0; i < outLen; i++)
      oview.setUint32(4 * i, state[i], isLE2);
  }
  digest() {
    const { buffer, outputLen } = this;
    this.digestInto(buffer);
    const res = buffer.slice(0, outputLen);
    this.destroy();
    return res;
  }
  _cloneInto(to) {
    to || (to = new this.constructor());
    to.set(...this.get());
    const { blockLen, buffer, length, finished, destroyed, pos } = this;
    to.length = length;
    to.pos = pos;
    to.finished = finished;
    to.destroyed = destroyed;
    if (length % blockLen)
      to.buffer.set(buffer);
    return to;
  }
};

// node_modules/@noble/hashes/esm/sha256.js
var Chi = (a, b, c) => a & b ^ ~a & c;
var Maj = (a, b, c) => a & b ^ a & c ^ b & c;
var SHA256_K = new Uint32Array([
  1116352408,
  1899447441,
  3049323471,
  3921009573,
  961987163,
  1508970993,
  2453635748,
  2870763221,
  3624381080,
  310598401,
  607225278,
  1426881987,
  1925078388,
  2162078206,
  2614888103,
  3248222580,
  3835390401,
  4022224774,
  264347078,
  604807628,
  770255983,
  1249150122,
  1555081692,
  1996064986,
  2554220882,
  2821834349,
  2952996808,
  3210313671,
  3336571891,
  3584528711,
  113926993,
  338241895,
  666307205,
  773529912,
  1294757372,
  1396182291,
  1695183700,
  1986661051,
  2177026350,
  2456956037,
  2730485921,
  2820302411,
  3259730800,
  3345764771,
  3516065817,
  3600352804,
  4094571909,
  275423344,
  430227734,
  506948616,
  659060556,
  883997877,
  958139571,
  1322822218,
  1537002063,
  1747873779,
  1955562222,
  2024104815,
  2227730452,
  2361852424,
  2428436474,
  2756734187,
  3204031479,
  3329325298
]);
var IV = new Uint32Array([
  1779033703,
  3144134277,
  1013904242,
  2773480762,
  1359893119,
  2600822924,
  528734635,
  1541459225
]);
var SHA256_W = new Uint32Array(64);
var SHA256 = class extends SHA2 {
  constructor() {
    super(64, 32, 8, false);
    this.A = IV[0] | 0;
    this.B = IV[1] | 0;
    this.C = IV[2] | 0;
    this.D = IV[3] | 0;
    this.E = IV[4] | 0;
    this.F = IV[5] | 0;
    this.G = IV[6] | 0;
    this.H = IV[7] | 0;
  }
  get() {
    const { A, B, C, D, E, F, G, H } = this;
    return [A, B, C, D, E, F, G, H];
  }
  // prettier-ignore
  set(A, B, C, D, E, F, G, H) {
    this.A = A | 0;
    this.B = B | 0;
    this.C = C | 0;
    this.D = D | 0;
    this.E = E | 0;
    this.F = F | 0;
    this.G = G | 0;
    this.H = H | 0;
  }
  process(view, offset) {
    for (let i = 0; i < 16; i++, offset += 4)
      SHA256_W[i] = view.getUint32(offset, false);
    for (let i = 16; i < 64; i++) {
      const W15 = SHA256_W[i - 15];
      const W2 = SHA256_W[i - 2];
      const s0 = rotr(W15, 7) ^ rotr(W15, 18) ^ W15 >>> 3;
      const s1 = rotr(W2, 17) ^ rotr(W2, 19) ^ W2 >>> 10;
      SHA256_W[i] = s1 + SHA256_W[i - 7] + s0 + SHA256_W[i - 16] | 0;
    }
    let { A, B, C, D, E, F, G, H } = this;
    for (let i = 0; i < 64; i++) {
      const sigma1 = rotr(E, 6) ^ rotr(E, 11) ^ rotr(E, 25);
      const T1 = H + sigma1 + Chi(E, F, G) + SHA256_K[i] + SHA256_W[i] | 0;
      const sigma0 = rotr(A, 2) ^ rotr(A, 13) ^ rotr(A, 22);
      const T2 = sigma0 + Maj(A, B, C) | 0;
      H = G;
      G = F;
      F = E;
      E = D + T1 | 0;
      D = C;
      C = B;
      B = A;
      A = T1 + T2 | 0;
    }
    A = A + this.A | 0;
    B = B + this.B | 0;
    C = C + this.C | 0;
    D = D + this.D | 0;
    E = E + this.E | 0;
    F = F + this.F | 0;
    G = G + this.G | 0;
    H = H + this.H | 0;
    this.set(A, B, C, D, E, F, G, H);
  }
  roundClean() {
    SHA256_W.fill(0);
  }
  destroy() {
    this.set(0, 0, 0, 0, 0, 0, 0, 0);
    this.buffer.fill(0);
  }
};
var SHA224 = class extends SHA256 {
  constructor() {
    super();
    this.A = 3238371032 | 0;
    this.B = 914150663 | 0;
    this.C = 812702999 | 0;
    this.D = 4144912697 | 0;
    this.E = 4290775857 | 0;
    this.F = 1750603025 | 0;
    this.G = 1694076839 | 0;
    this.H = 3204075428 | 0;
    this.outputLen = 28;
  }
};
var sha256 = wrapConstructor(() => new SHA256());
var sha224 = wrapConstructor(() => new SHA224());

// src/select.ts
async function select(options) {
  const sortedValues = options.values.slice().sort();
  const hashedInput = hashInput(sortedValues);
  if (options.count === 0) {
    return {
      round: 0,
      hashedInput,
      winners: [],
      randomness: ""
    };
  }
  if (options.count >= options.values.length) {
    return {
      round: 0,
      hashedInput,
      winners: options.values,
      randomness: ""
    };
  }
  const beacon = await (0, import_drand_client.fetchBeaconByTime)(options.drandClient, Date.now());
  let remainingValues = sortedValues;
  let remainingDraws = options.count;
  let currentRandomness = sha256.create().update(hashedInput).update(Buffer.from(beacon.randomness, "hex")).digest();
  let chosenValues = [];
  while (remainingDraws > 0) {
    currentRandomness = sha256.create().update(currentRandomness).digest();
    const chosenIndex = indexFromRandomness(currentRandomness, remainingValues.length);
    chosenValues = [...chosenValues, remainingValues[chosenIndex]];
    remainingValues = [
      ...remainingValues.slice(0, chosenIndex),
      ...remainingValues.slice(chosenIndex + 1, remainingValues.length)
    ];
    remainingDraws--;
  }
  return {
    round: beacon.round,
    hashedInput,
    winners: chosenValues,
    randomness: beacon.randomness
  };
}
function indexFromRandomness(randomBytes, totalEntryCount) {
  const someBigNumber = bufferToBigInt(randomBytes);
  return Number(someBigNumber % BigInt(totalEntryCount));
}
function bufferToBigInt(buffer) {
  let output2 = BigInt(0);
  for (let i = buffer.length - 1; i >= 0; i--) {
    output2 = output2 * BigInt(256) + BigInt(buffer[i]);
  }
  return output2;
}
function hashInput(input) {
  const digest = sha256.create().update(input.join("\n")).digest();
  return Buffer.from(digest).toString("hex");
}

// src/index.ts
main().catch((err) => {
  console.error(err);
  console.error(err.stack);
  process.exit(err.code || -1);
});
async function main() {
  const inputDir = core.getInput("inputDir") ?? ".";
  const outputDir = core.getInput("ouputDir") ?? ".";
  const drawPrefix = core.getInput("drawPrefix") ?? "draw-";
  const drandURL = core.getInput("drandURL") ?? "https://api.drand.sh";
  const gitRepo = process.env.GITHUB_WORKSPACE;
  const drandClient = new import_drand_client2.HttpChainClient(new import_drand_client2.HttpCachingChain(drandURL));
  const inputFiles = await fs.readdir(path.join(gitRepo, inputDir));
  const outputFiles = await fs.readdir(path.join(gitRepo, outputDir));
  for (let inputFile of inputFiles) {
    const outputFilename = `${drawPrefix}${inputFile}`;
    if (outputFiles.includes(outputFilename)) {
      console.log(`skipping ${outputFilename}`);
      continue;
    }
    console.log(`processing ${inputFile}`);
    const contents = await (0, import_promises.readFile)(path.join(gitRepo, inputDir, inputFile));
    const lines = contents.toString().split("\n");
    const selectionOutput = await select({
      count: 1,
      values: lines,
      drandClient
    });
    await fs.writeFile(path.join(gitRepo, outputDir, outputFilename), JSON.stringify(selectionOutput));
    console.log(`created ${outputFilename}`);
  }
}
/*! Bundled license information:

@noble/bls12-381/lib/index.js:
  (*! noble-bls12-381 - MIT License (c) 2019 Paul Miller (paulmillr.com) *)

@noble/hashes/esm/utils.js:
  (*! noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com) *)
*/
