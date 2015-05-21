
// SC4 - Secure Communications (or Strong Crypto) for Mere Mortals

"use strict";

var sc4 = sc4 || {};

(function() {

  // Global state
  var my_keys = {};
  var rx_keys = [];     // Each entry is [email, encryption_key, signing_key]
  var enc_key_map = {}; // Encryption public key -> recipient ID
  var sig_key_map = {}; // Signing public key -> recipient ID

  // Indices for storing things in LocalStorage
  var sk_key = 'sc4-secret-keys';
  var pk_key = 'sc4-public-keys';
  var email_key = 'sc4-email';

  // Misc. data conversion utilities
  var string2bytes = nacl.util.decodeUTF8;
  var bytes2string = nacl.util.encodeUTF8;
  var json = JSON.stringify;
  var unjson = JSON.parse;
  var b64 = nacl.util.encodeBase64;
  function unb64(s) {
    try { return nacl.util.decodeBase64(s); }
    catch(e) {
      console.log("Error decoding base64 data");
      console.log(e);
      msg('Data corruption error.');
      throw('base64 data corruption error');
    }
  }

  // Misc. utilities
  function type_of(thing) {
    return Object.prototype.toString.call(thing).slice(8, -1).toLowerCase();
  }

  function u8a_cmp(a1, a2) {
    // NOTE! Not constant time!
    for(var i=0; i<a1.length; i++) {
      if (a1[i]>a2[i]) return 1;
      if (a1[i]<a2[i]) return -1;
    }
    return 0;
  }

  function hash(thing) {
    if (type_of(thing)=='string') thing = nacl.util.decodeUTF8(thing);
    return nacl.hash(thing);
  }

  function to_bytes(thing) {
    return (typeof thing == 'string') ? string2bytes(thing) : thing;
  }

  function split_into_lines(s, line_length) {
    var len = line_length || 72;
    var lines = [];
    for (var i=0; i<s.length; i+=len) lines.push(s.slice(i, i+len));
    lines.push('');
    return lines.join('\n');
  }

  // Can you believe this is still not a built-in?
  function html_escape(s) { return $('<div/>').text(s).html(); }

  // Concatenate a list of Uint8Arrays into a single UInt8Array
  function bufconcat(buflist) {
    var len = 0;
    for (var i=0; i<buflist.length; i++) len += buflist[i].length;
    var buf = new Uint8Array(len);
    len = 0;
    for (var i=0; i<buflist.length; i++) {
      buf.set(buflist[i], len);
      len += buflist[i].length;
    }
    return buf;
  }

  function concat(l) {
    return (typeof l[0] == 'string') ? l.join('') : bufconcat(l);
  }

  function int2bytes(n, n_bytes) {
    var buf = new Uint8Array(n_bytes);
    for (var i=0; i<n_bytes; i++) {
      buf[n_bytes - 1 - i] = n & 0xFF;
      n = n>>8;
    }
    return buf;
  }

  function bytes2int(bytes) {
    var n = 0;
    for (var i=0; i<bytes.length; i++) n = (n<<8) + bytes[i];
    return n;
  }

  // Base-N encoding/decoding
  // Adapted from http://cryptocoinjs.com/modules/misc/bs58/
  function baseN(buffer, alphabet, base) {
    var i, j, digits = [0];
    for (i = 0; i < buffer.length; ++i) {
      for (j = 0; j < digits.length; ++j) digits[j] <<= 8;
      digits[0] += buffer[i];
      var carry = 0;
      for (j = 0; j < digits.length; ++j) {
	digits[j] += carry;
	carry = (digits[j] / base) | 0;
	digits[j] %= base;
      }
      while (carry) {
	digits.push(carry % base);
	carry = (carry / base) | 0;
      }
    }
    // deal with leading zeros
    for (i = 0; buffer[i] === 0 && i < buffer.length - 1; ++i) digits.push(0);
    return digits.map(function(c){return alphabet[c];}).reverse().join('');
  }

  function unbaseN(string, alphabet, base) {
    if (alphabet == undefined) alphabet = B58_ALPHABET;
    if (base==undefined) base = alphabet.length;
    var i, j, bytes = [0];
    for (i = 0; i < string.length; ++i) {
      var c = string[i];
      for (j = 0; j < bytes.length; ++j) bytes[j] *= base;
      var k = alphabet.indexOf(c);
      if (k<0) throw new Error('Illegal character decoding base-N string');
      bytes[0] += k;
      var carry = 0;
      for (j = 0; j < bytes.length; ++j) {
	bytes[j] += carry;
	carry = bytes[j] >> 8;
	bytes[j] &= 0xff;
      }
      while (carry) {
	bytes.push(carry & 0xff);
	carry >>= 8;
      }
    }
    // deal with leading zeros
    for (i = 0; string[i] === '1' && i < string.length - 1; ++i) bytes.push(0);
    return new Uint8Array(bytes.reverse());
  }

  var B58_CHARS = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  function b58(b) { return baseN(b, B58_CHARS, 58); }
  function unb58(s) { return unbaseN(s, B58_CHARS, 58); }
  function b32(b) { return baseN(b, B58_CHARS, 32); }
  function unb32(s) { return unbaseN(s, B58_CHARS, 32); }

  var HEX_CHARS = '0123456789ABCDEF';
  function hex(b) { return baseN(b, HEX_CHARS, 16); }
  function unhex(s) { return unbaseN(s.toUpperCase(), HEX_CHARS, 16); }

  // Show a .toplevel div, hiding all the others
  function show(divname) {
    $('div.toplevel').hide();
    $('#' + divname).fadeIn();
  }

  function msg(s) {
    $('#msgcontent').html(s);
    show('msg');
  }

  function hard_reset() {
    delete localStorage[sk_key];
    delete localStorage[pk_key];
  }

  function genkeys(seed) {
    var seed = hash(seed).subarray(0,32);
    var skpr = nacl.sign.keyPair.fromSeed(seed);
    var h = nacl.hash(seed).subarray(0,32);
    h[0] &= 248;
    h[31] &= 127;
    h[31] |= 64;
    var ekpr = nacl.box.keyPair.fromSecretKey(h);
    return { epk: ekpr.publicKey, esk: ekpr.secretKey,
	     spk: skpr.publicKey, ssk: skpr.secretKey };
  }

  function setup_keys() {
    retrieve_my_keys();
    retrieve_rx_keys();
  }

  function get_rx_key(recipient) {
    var k = rx_keys[recipient];
    if (!k) throw("Invalid recipient: " + recipient);
    return k[1];
  }

  function get_rx_email(recipient)  { return rx_keys[recipient][0]; }

  var local_keys = null;

  function running_from_local_file() {
    return document.location.protocol.toLowerCase()=='file:';
  }
  
  // Get secret keys from LocalStorage and put them in global my_keys
  function retrieve_my_keys() {
    var keys = running_from_local_file() ? local_keys : localStorage[sk_key];
    if (keys == undefined) return false;
    keys = unjson(keys);
    if (keys.length==3) {
      // Old (deprecated) format with separate encryption and signing keys
      // Stored as a JSONified list of three base64 encoded values:
      // [Encryption secret key, encryption public key, signing key seed]
      my_keys['epk'] = unb64(keys[0]); // Encryption Public Key
      my_keys['esk'] = unb64(keys[1]); // Encryption Secret Key
      var seed = unb64(keys[2]);       // Seed for signing key
      var skp = nacl.sign.keyPair.fromSeed(seed);
      my_keys['spk'] = skp['publicKey'];
      my_keys['ssk'] = skp['secretKey'];
      return true;
    }
    my_keys = genkeys(unb58(keys[0]));
    return true;
  }

  // Get receiver public keys from localStorage and set up global state
  function retrieve_rx_keys() {
    rx_keys = unjson(localStorage[pk_key]).map(function(entry) {
      return [entry[0], unb58(entry[1]), unb58(entry[2])]
    });
    // Maybe clear enc_key_map and sig_key_map first?
    for (var k in rx_keys) {
      var entry = rx_keys[k];
      var email = entry[0];
      var epk = entry[1];
      var spk = entry[2];
      enc_key_map[b64(epk)] = email;
      sig_key_map[b64(spk)] = email;
    }
  }

  // Store rx_keys in localStorage.  We can't just JSONify it directly
  // because JSON doesn't handle UInt8Arrays properly.
  function store_rx_keys() {
    var keys = rx_keys.map(function(entry) {
      return [entry[0], b58(entry[1]), b58(entry[2])];
    });
    localStorage[pk_key] = json(keys);
  }

  // Reset the recipient list.  Assumes that my_keys has been initialized.
  function reset_rx_keys() {
    var email = localStorage[email_key];
    rx_keys = [['Myself <' + email + '>', my_keys.epk, my_keys.spk]];
    store_rx_keys();
  }

  // Setup the recipient menu
  function setup_rx_menu() {
    var menu = $('.rx_menu');
    menu.empty();
    for (var k in rx_keys) {
      var email = rx_keys[k][0];
      var esc_email = html_escape(email);
      menu.append('<option value="' + k + '">' + esc_email + "</option>");
    }
  }

  // Install a new public key
  function install_public_key(from, ekey, skey) {
    var entry = [from, ekey, skey];
    if (entry[1].length != 32 || entry[2].length != 32) {
      msg('Invalid keys (this should never happen)');
    } else {
      rx_keys.unshift(entry);
      store_rx_keys();
      retrieve_rx_keys();
      setup_rx_menu();
    }
    $('#text').val('');
  }

  function this_should_never_happen(msg) {
    alert("An unexpected error occurred: " + msg);
    throw(msg);
  }

  // Initial setup - solicit user's email address and provision secret keys
  var email_regex = /[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?/;

  function initial_setup() {
    var email = $('#email').val();
    if (!email_regex.test(email)) {
      alert("Invalid email address");
      return;
    }
    localStorage[email_key] = email;

    // Provision secret keys
    if (!retrieve_my_keys()) {
      var ekp = nacl.box.keyPair();
      var seed = nacl.randomBytes(32);
      localStorage[sk_key] = '["' + b58(seed) + '"]';
      if (!retrieve_my_keys()) {
	this_should_never_happen("Key provisioning failed");
      }
    }

    // Initialize global state
    reset_rx_keys();
    setup_keys();
    setup_rx_menu();
    show('main');
  }

  // Determine if secret keys exist.  If not, start the initial setup
  // process, otherwise get stored keys and show main div.
  function generate_or_setup_keys() {
    if (running_from_local_file()) {
      if (sc4.genlocal_flag != true) {
	return document.location='sc4z.html';
      } else {
	if (local_keys==null) {
	  return show('generate_local_sc4');
	}
      }
    } else { // Running from a server
      if (local_keys != null) {
	return this_should_never_happen(
	  'Local keys found, but not running from a FILE: URL');
      }
      if (sc4.genlocal_flag == true) {
	show('generating_local_sc4');
	return generate_local_sc4();
      }
    }
    try {
      localStorage['sc4-test']='test';
      delete localStorage['sc4-test'];
    } catch (e) {
      return show('no-localstorage');
    }
    if (!retrieve_my_keys() || localStorage[email_key]==undefined) {
      $("#email").val(localStorage[email_key] || '');
      show('initial-setup');
    } else {
      setup_keys();
      setup_rx_menu();
      show('main');
    }
  }

  function generate_local_sc4_aux(s) {
    var ekp = nacl.box.keyPair();
    var seed = nacl.randomBytes(32);
    var skp = nacl.sign.keyPair.fromSeed(seed);
    var keys = [b64(ekp.publicKey), b64(ekp.secretKey), b64(seed)];
    keys = 'local_keys = json(' + json(keys) + ');';
    s = s.replace('local_keys = null;', keys);
    var filename = 'sc4_' + b58(nacl.randomBytes(10)) + '.html';
    export_as_download(filename, 'text/plain', s)
  }

  function generate_local_sc4(url) {
    if (url==undefined) url = document.location.href;
    $.ajaxSetup({dataType: 'html'}); // FF bug workaround
    $.get(url, generate_local_sc4_aux);
  }

  // Main entry point.  Setup keys and drag-and-drop event handling.
  function init() {
    $("#nojs").hide();
    show('initializing');
    $('#main').on('dragenter', dragEnter);
    $('.dropzone').on('dragover', stopEvents);
    $('.dropzone').on('dragleave', dragLeave);
    $('.dropzone').on('drop', drop);
    generate_or_setup_keys();
  }

  // Drag-and-drop event handling
  function stopEvents(e) {
    e.preventDefault();
    e.stopPropagation();
  }

  function dragEnter(e) {
    stopEvents(e);
    var tl = $(e.target).closest('.toplevel');
    tl.children('.dropzone').addClass('active');
    tl.children('.dropmsg').addClass('active');
  }

  function dragLeave(e) {
    stopEvents(e);
    var tl = $(e.target).closest('.toplevel');
    tl.children('.dropzone').removeClass('active');
    tl.children('.dropmsg').removeClass('active');
  }
  
  function drop(e) {
    stopEvents(e);
    var tl = $(e.target).closest('.toplevel');
    tl.children('.dropzone').removeClass('active');
    tl.children('.dropmsg').removeClass('active');
    handle_file_drop(e);
  }

  function handle_file_drop(e) {
    var files = e.originalEvent.dataTransfer.files;
    if (files.length) {
      process_dropped_files(files);
    } else {                     // Something other than a file was dropped
      alert("Drag and drop files from your desktop to upload them");
    }
  }

  function process_dropped_files(files) {
    for (var i=0; i<files.length; i++) {
      var fr = new FileReader();
      fr.onload = process_file;
      fr.file = files[i];
      fr.readAsArrayBuffer(files[i]);
    }
  }

  // Core SC4 code

  var encrypted_header = new Uint8Array([0x48, 0x2e, 0x1e]);
  var signature_header = new Uint8Array([0x48, 0x2e, 0x2c]);
  var    bundle_header = new Uint8Array([0x48, 0x2e, 0x1b]);
  var version_header = [0, 0, 0];

  function encrypt(bytes, recipient) {
    var len = int2bytes(bytes.length, 6);
    var rx_pk = get_rx_key(recipient);
    var my_sk = my_keys.esk;
    var my_pk = my_keys.epk;
    var nonce = nacl.randomBytes(nacl.box.nonceLength);
    // Encode the key order in the nonce
    nonce[0] = (nonce[0] & 0xFC) | u8a_cmp(my_pk, rx_pk) & 3;
    var cipherbytes = nacl.box(bytes, nonce, rx_pk, my_sk);
    return bufconcat([encrypted_header, version_header,
		      len,  nonce, my_pk, cipherbytes]);
  }

  function decrypt(bytes) {
    var len = bytes2int(bytes.subarray(6,12));
    if (len + 84 != bytes.length) return null;
    var nonce = bytes.subarray(12, 36);
    var sender_key = bytes.subarray(36, 68);
    if ((nonce[0] & 3) != (u8a_cmp(sender_key, my_keys.epk) & 3) return null;
    var cipherbytes = bytes.subarray(68);
    var content = nacl.box.open(cipherbytes, nonce, sender_key, my_keys.esk);
    if (!content) return null;
    if (content.length != len) return null;
    sender_key = b64(sender_key);
    return [content, sender_key, enc_key_map[sender_key]];
  }

  function encrypt_pt(bytes, recipient) {
    return split_into_lines(b64(encrypt(bytes, recipient)));
  }

  function decrypt_pt(s) {
    try {
      return decrypt(unb64(s.split('\n').join('')));
    } catch (e) {
      return null;
    }
  }

  function signature(thing) {
    var bytes = to_bytes(thing);
    var hash = nacl.hash(bytes);
    return nacl.sign.detached(hash, my_keys.ssk);
  }

  function sign(thing) {
    var bytes = to_bytes(thing);
    var len = int2bytes(bytes.length, 6);
    var hash = nacl.hash(bytes);
    var spk = my_keys.spk;
    var ssk = my_keys.ssk;
    var signature = nacl.sign.detached(hash, ssk);
    return bufconcat([signature_header, version_header,
		      len, spk, hash, signature]);
  }

  function verify_signature(sig) {
    var content_length = bytes2int(sig.subarray(6,12));
    var signer_key = sig.subarray(12, 44);
    var hash = sig.subarray(44, 108);
    var signature = sig.subarray(108, 172);
    return [nacl.sign.detached.verify(hash, signature, signer_key),
	    b64(signer_key), hash];
  }

  function sign_pt(thing) {
    var bytes = to_bytes(thing);
    var hash = nacl.hash(bytes);
    var spk = my_keys.spk;
    var ssk = my_keys.ssk;
    var signature = nacl.sign.detached(hash, ssk);
    var segments = ['X-SC4-signed: v0.1 ', b58(spk), '\n'];
    segments.push(split_into_lines(b32(hash), 52));
    segments.push(split_into_lines(b32(signature), 52));
    return segments.join('');
  }

  var signature_regex =
    /X-SC4-signed: ([v.0-9]+) (.{32,52})\n(.{32,52})\n(.{32,52})\n(.{32,52})\n(.{32,52})\n/;

  function verify_signature_pt(s) {
    var l = signature_regex.exec(s);
    if (!l) return false;
    var signer_key = unb58(l[2]);
    var hash = unb32(l[3] + l[4]);
    var signature = unb32(l[5] + l[6]);
    return [nacl.sign.detached.verify(hash, signature, signer_key),
	    b64(signer_key), hash]
  }

  function bundle(filename, mimetype, content, sigflag) {
    if (filename == null) filename = '';
    if (filename.length>255) filename = filename.slice(0,255);
    // This should never happen, but better safe than sorry
    if (mimetype.length>255) mimetype = mimetype.slice(0,255);
    if (typeof content == 'string') content = string2bytes(content);
    var len = int2bytes(content.length, 6);
    var sig = sigflag ? sign(content) : [];
    return bufconcat([bundle_header, version_header, len,
		      [filename.length], string2bytes(filename),
		      [mimetype.length], string2bytes(mimetype),
		      [sigflag ? sig.length : 0] , sig,
		      content]);
  }

  function unbundle(bytes) {
    var content_len = bytes2int(bytes.subarray(6,12));
    var idx=12;
    var filename_len = bytes[idx];
    idx += 1;
    var filename = bytes2string(bytes.subarray(idx, idx + filename_len));
    idx += filename_len;
    var mimetype_len = bytes[idx];
    idx += 1;
    var mimetype = bytes2string(bytes.subarray(idx, idx + mimetype_len));
    idx += mimetype_len;
    var siglen = bytes[idx];
    idx += 1;
    var sig = siglen ? bytes.subarray(idx, idx + siglen) : null;
    if (sig) sig = verify_signature(sig);
    idx += siglen;
    var content = bytes.subarray(idx);
    if (content_len != content.length) console.log("Content length mismatch");
    if (mimetype.slice(0,4)=='text') content = bytes2string(content);
    return [filename, mimetype, content, sigcheck(content, sig)];
  }

  function bundle_pt(filename, mimetype, content, sigflag) {
    var is_string = (typeof content == 'string');
    var encoding = is_string ? 'raw' : 'base64';
    var sig = sigflag ? sign_pt(content) : '';
    if (!is_string) content = split_into_lines(b64(content));
    var segments = ['X-SC4-bundle: 0 ', content.length, ' ', mimetype, ' ',
      encoding, ' ', filename, '\n', sig, '\n', content]
    return segments.join('');
  }

  var bundle_regex =
    /X-SC4-bundle: ([0-9]+) ([0-9]+) (\S+) (\S+) (.*)\n([^]*?\n)\n([^]*)/;

  function unbundle_pt(s) {
    var l = bundle_regex.exec(s);
    var version = l[1];
    var content_length = l[2];
    var mimetype = l[3];
    var encoding = l[4];
    var filename = l[5];
    var sig = l[6] ? verify_signature_pt(l[6]) : null;
    var content = l[7];
    if (encoding == 'base64') {
      content = unb64(content.split('\n').join(''));
    }
    return [filename, mimetype, content, sigcheck(content,sig)];
  }

  function sigcheck(content, sig) {
    if (!sig) return "No signature";
    if (!sig[0]) return "Invalid signature";
    var content_hash = nacl.hash(to_bytes(content));
    if (!nacl.verify(sig[2], content_hash)) return "Hash mismatch";    
    var sigkey = sig[1];
    var signer = sig_key_map[sigkey];
    if (!signer) return "Uknown signer: " + sigkey;
    return "Valid signature from " + signer;
  }

  var preamble = 'This is a secure message produced by SC4.  ' +
    'See https://sc4.us/ for more information.\n\n';

  var enc_pt_regex =
    new RegExp('^(' + preamble + ')?(\n){0,2}(SC4eAAAA[^]*)$');

  var key_regex =
    /X-sc4-content-type: public-key (.*)\nFrom: (.*)\nTimestamp: (.*)\n(.{32,44})\n(.{32,44})\n(.{32,44})/;

  function sc4_typeof(thing) {
    if (typeof thing == 'string') {
      if (enc_pt_regex.test(thing)) return 'encrypted_pt';
      if (bundle_regex.test(thing)) return 'bundle_pt';
      if (signature_regex.test(thing)) return 'signature_pt';
      if (key_regex.test(thing)) return "public_key";
      return null;
    } else if (thing.__proto__ == Uint8Array.prototype) {
      var hdr = thing.subarray(0,3);
      if (nacl.verify(hdr, encrypted_header)) return 'encrypted';
      if (nacl.verify(hdr, bundle_header)) return 'bundle';
      if (nacl.verify(hdr, signature_header)) return 'signature';
    }
    return null;
  }
  
  // Export routines
  
  function virtual_click(link) {
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  }
  
  function export_as_email(recipient, subject, body) {
    var href = 'mailto:' + encodeURIComponent(recipient);
    href += '?subject=' + encodeURIComponent(subject);
    href += '&body=' + encodeURIComponent(body);
    var a = document.createElement('a');
    a.href = href;
    virtual_click(a);
  }

  function make_download_link(filename, mimetype, content) {
    if (!mimetype) mimetype='text/plain';
    if (!filename) filename='unknown';
    if (typeof(content) == 'string') content = string2bytes(content);
    content = new Blob([content], {type: mimetype});
    var href = window.URL.createObjectURL(content);
    var a = document.createElement('a');
    a.href = href;
    a.target = filename;
    a.download = filename;
    return a;
  }

  function export_as_download(filename, mimetype, content) {
    virtual_click(make_download_link(filename, mimetype, content));
  }

  // SC4 content handling

  function export_my_key() {
    var s = 'X-sc4-content-type: public-key v0.2\nFrom: ' +
      localStorage[email_key] + '\n' + "Timestamp: " +
      new Date().toUTCString() + '\n' +
      b58(my_keys.spk) + '\n';
    var sig = b58(signature(s));
    s = $('#invitation').text() + '---START KEY---\n' + s
      + split_into_lines(sig, 44) + '---END KEY---\n';
    export_as_email('', 'I would like to send you a secure message', s);
  }

  function wordify(age) {
    if (age<5000) return 'a few seconds ago';
    age = Math.round(age/1000);
    if (age<120) return age + ' seconds ago';
    age = Math.round(age/60);
    if (age<120) return age + ' minutes ago';
    age = Math.round(age/60);
    if (age<48) return age + ' hours ago';
    age = Math.round(age/24);
    if (age<60) return age + ' days ago';
    age = Math.round(age/30);
    return 'about ' + age + ' months ago';
  }

  var two_years = 1000 * 60 * 60 * 24 * 365 * 2;

  function import_key(s) {
    var l = key_regex.exec(s);
    if (!l) return msg("Invalid key (bad format)");
    var version = l[1];
    if (version != 'v0.2') return msg('Incompatible version');
    var email = l[2];
    var timestamp = Date.parse(l[3]);
    var age = Date.now() - timestamp;  // In milliseconds
    if (age<0) return msg('Invalid key (timestamp is in the future)');
    if (age>two_years) return msg('Invalid key (too old)');
    var spk = unb58(l[4]);
    var epk = nacl.spk2epk(spk);
    var sig = unb58(l[5]+l[6]);
    var s = l[0].split('\n').slice(0,4).join('\n')+'\n';
    var hash = nacl.hash(string2bytes(s));
    var flag = nacl.sign.detached.verify(hash, sig, spk);
    if (!flag) return msg('Invalid key (bad signature)');
    if (confirm('This is a valid public key from ' + email + ' signed ' +
		wordify(age) + '  Would you like to install it?')){
      install_public_key(email, epk, spk);
    }
  }

  function process_file(e) {
    var filename = this.file.name;
    var mimetype = this.file.type;
    var content = new Uint8Array(this.result);
    if (!mimetype || (mimetype.slice(0,4)=='text')) {
      try {
	content = bytes2string(content);
	mimetype = mimetype || 'text/unknown';
      } catch(err) {
	mimetype = 'unknown';
      }
    }
    process_content(filename, mimetype, content);
  }

  function process_text_box_data() {
    var content = $('#text').val();
    process_content(null, "text/plain", content);
  }

  function process_content(filename, mimetype, content) {
    var sc4_type = sc4_typeof(content);
    if (sc4_type) return process_sc4_file(filename, sc4_type, content);
    var sign_flag = $("#sign").is(':checked');
    var encrypt_flag = $("#encrypt").is(':checked');
    var recipient = $('.rx_menu').val();
    var bundle_op = encrypt_flag ? bundle : bundle_pt;
    var result = bundle_op(filename, mimetype, content, sign_flag);
    if (encrypt_flag) result = encrypt_pt(result, recipient);
    result = preamble + result;
    if ($('input[name=op1]:checked').val()=='email') {      
      export_as_email(get_rx_email(recipient), 'Secure message', result);
    } else {
      if (filename == null) filename = 'unknown.txt';
      export_as_download(filename + '.sc4', 'text/sc4', result);
    }
  }

  var decrypt_op_table = { encrypted : decrypt, encrypted_pt : decrypt_pt };
  var unbundle_op_table = { bundle : unbundle, bundle_pt : unbundle_pt };

  function process_sc4_file(filename, sc4_type, content) {
    if (sc4_type == 'public_key') return import_key(content);

    if (sc4_type=='encrypted_pt' && content.length>preamble.length &&
	content.slice(0, preamble.length)==preamble) {
      content = content.slice(preamble.length);
    }

    var decrypt_op = decrypt_op_table[sc4_type];
    if (decrypt_op) {
      var l = decrypt_op(content);
      if (!l) return msg("Decryption failed");
      content = l[0];
      sc4_type = sc4_typeof(content);
      var sender_key = l[1];
      var sender_email = l[2];
    }
    var bundle_op = unbundle_op_table[sc4_type];
    if (bundle_op) {
      var l = bundle_op(content);
      var filename = l[0];
      var mimetype = l[1];
      content = l[2];
      var sigstatus = l[3];
    } else {
      return msg('Unknown file format: ' + sc4_type);
    }

    // Present results

    var msgs = ["Success."];
    if (decrypt_op) {
      msgs.push('This message was encrypted by ' +
		html_escape(sender_email) + '(' + sender_key + ')')
    } else {
      msgs.push("This message was <span style='color:red'>NOT ENCRYPTED</span>.");
    }
    var sigcolor = sigstatus.slice(0,5)=='Valid' ? 'green' : 'red';
    var sss = 'Signature status: <span style="color:' + sigcolor + '">' +
      html_escape(sigstatus) + '</span>';
    msgs.push(sss);
    msgs.push(filename ? 'File name: ' + html_escape(filename) : '(No file name)');
    msgs.push('File type: ' + html_escape(mimetype));
    msgs.push('Size: ' + content.length);
    msgs.push('Preview:<br><br>');
    var link = make_download_link(filename, mimetype, content);
    // Purify the preview link if the content it HTML
    var plink = (mimetype != 'text/html') ? link :
      make_download_link(filename, mimetype,  DOMPurify.sanitize(content));
    if (mimetype.slice(0,4) == 'text' && mimetype != 'text/html') {
      msgs.push('<div style="border: 1px solid black; padding: 10px"><pre>' +
		html_escape(content.slice(0,1000)) + '</pre></div>');
    } else {
      msgs.push('<iframe height=400px width=800px src=' + plink.href +
		'></iframe>');
    }
    msgs.push('<br><br>');
    link.innerHTML='Download this file';
    msgs.push(link.outerHTML);
    msg(msgs.join('<br>'));
    $('#text').val('');
  }

  function write_check() {
    var payto = $("#pay_to").val();
    var amount = $("#check_amount").val();
    var memo = $("#check_memo").val();
    var payto_key = get_rx_key(payto);
    var s = 'X-sc4-content-type: echeck\n' +
      'X-sc4-pay-to-the-order-of: ' + payto + '\n' +
      'X-sc4-pto-public-key: ' + b64(payto_key) + '\n' +
      'X-sc4-amount: ' + amount + '\n' +
      'X-sc4-timestamp: ' + new Date().toUTCString() + '\n\n' +
      memo;
    export_as_email(payto, "Electronic check", sign_pt(to_bytes(s))+s);
    show('main');
  }

  function _export(l) {
    for (var i=0; i<l.length; i++) sc4[l[i].name] = l[i];
  }

  sc4.init = init;
  sc4.show = show;
  sc4.reset = hard_reset;
  sc4.initial_setup = initial_setup;
  sc4.export_my_key = export_my_key;
  sc4.encsign = process_text_box_data;
  sc4.write_check = write_check;
  sc4.genlocal = generate_local_sc4;

})();
