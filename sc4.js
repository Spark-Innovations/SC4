
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
    if (localStorage[pk_key]==undefined) reset_rx_keys();
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
      var keyfp = b58(rx_keys[k][2]).slice(0,8);
      menu.append('<option value="' + k + '">' +
		  esc_email + ' (' + keyfp +')' +
		  "</option>");
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
    clear_text_box_data();
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
    var filename = 'SC4_' + b58(nacl.randomBytes(10)) + '.html';
    s = '<!-- Save this file as "' + filename + '" -->\n' + s;
    export_as_download(filename, 'text/plain', s)
  }

  function generate_local_sc4(url) {
    if (url==undefined) url = document.location.href;
    $.ajaxSetup({dataType: 'html'}); // FF bug workaround
    $.get(url, generate_local_sc4_aux);
  }

  // Main entry point.  Setup keys and drag-and-drop event handling.
  function init() {
    if (window.top !== window) {
      return(document.write("Sorry, can't run SC4 inside a frame."));
    }
    if ((window.navigator.userAgent.indexOf("MSIE")>0) ||
	(window.navigator.userAgent.indexOf("Trident")>0)) {
      document.getElementById("nojs").style.display='none';
      document.getElementById("msie").style.display='block';
      return;
    }
    $('#nojs').hide();
    show('initializing');
    install_event_handlers();
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
  var multi_enc_header = new Uint8Array([0x48, 0x2e, 0x26]);
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
    nonce[0] = (nonce[0] & 0xFC) | (u8a_cmp(my_pk, rx_pk) & 3);
    var cipherbytes = nacl.box(bytes, nonce, rx_pk, my_sk);
    return bufconcat([encrypted_header, version_header,
		      len,  nonce, my_pk, cipherbytes]);
  }

  function decrypt(bytes) {
    var len = bytes2int(bytes.subarray(6,12));
    if (len + 84 != bytes.length) return null;
    var nonce = bytes.subarray(12, 36);
    var sender_key = bytes.subarray(36, 68);
    var cipherbytes = bytes.subarray(68);
    if ((nonce[0] & 3) != (u8a_cmp(sender_key, my_keys.epk) & 3)) {
      // This message was not encrypted for us, maybe was encrypted by us
      for (var i=0; i<rx_keys.length; i++) {
	var content = nacl.box.open(cipherbytes, nonce, rx_keys[i][1],
	  my_keys.esk);
	if (content) {
	  return [content, b64(my_keys.epk), "Me for " + rx_keys[i][0]];
	}
      }
    }
    var content = nacl.box.open(cipherbytes, nonce, sender_key, my_keys.esk);
    if (!content) return null;
    if (content.length != len) return null;
    sender_key = b64(sender_key);
    var sender_email = enc_key_map[sender_key];
    return [content, sender_key, sender_email];
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
    segments.push(split_into_lines(hex(hash), 64));
    segments.push(split_into_lines(b58(signature), 44));
    return segments.join('');
  }

  var zeroNonce = new Uint8Array(nacl.secretbox.nonceLength);

  function encrypt_multi(bytes, rx_pk_list) {
    var key = nacl.randomBytes(nacl.secretbox.keyLength);
    var len = int2bytes(bytes.length, 6);
    var cipherbytes = nacl.secretbox(bytes, zeroNonce, key);
    var keys = [nacl.box(key, zeroNonce, my_keys.epk, my_keys.esk)];
    for (var i=0; i<rx_pk_list.length; i++) {
      keys.push(nacl.box(key, zeroNonce, rx_pk_list[i], my_keys.esk));
    }
    return bufconcat([multi_enc_header, version_header,
		      len, cipherbytes, my_keys.epk,
		      bufconcat(keys)]);
  }

  function decrypt_multi(bytes) {
    var len = bytes2int(bytes.subarray(6,12));
    if (len+108 > bytes.length) return null;
    var offset = 12 + len + nacl.box.overheadLength;
    var cipherbytes = bytes.subarray(12, offset);
    var sender_key = bytes.subarray(offset, offset+=32);
    while(offset<bytes.length) {
      var b = bytes.subarray(offset, offset+=48);
      if (b.length != 48) return null;
      var key = nacl.box.open(b, zeroNonce, sender_key, my_keys.esk);
      if (key) {
	var msg = nacl.secretbox.open(cipherbytes, zeroNonce, key);
	return (msg ? [bytes2string(msg), sender_key] : null);
      }
    }
    return null;
  }

  // For Windows, might need:
  // re=/\r\n|\n\r|\n|\r/g;
  // s.replace(re,"\n")

  var signature_regex =
    /X-SC4-signed: ([v.0-9]+) (.{32,52})\n(.{64})\n(.{64})\n(.{44})\n(.{20,44})\n/;

  function verify_signature_pt(s) {
    var l = signature_regex.exec(s);
    if (!l) return false;
    var signer_key = unb58(l[2]);
    var hash = unhex(l[3] + l[4]);
    var signature = unb58(l[5] + l[6]);
    return [nacl.sign.detached.verify(hash, signature, signer_key),
	    b64(signer_key), hash]
  }
  
  function combine4sig(filename, mimetype, content) {
    filename = (filename==null) ? '-' : filename.replace(/\n/g, '');
    mimetype = mimetype.replace(/\n/g, '');
    var h = hex(hash(content)).toLowerCase();
    return h + '  ' + filename + '\n' + mimetype + '\n';
  }

  function bundle(filename, mimetype, content, sigflag) {
    if (filename == null) filename = '';
    if (filename.length>255) filename = filename.slice(0,255);
    // This should never happen, but better safe than sorry
    if (mimetype.length>255) mimetype = mimetype.slice(0,255);
    if (typeof content == 'string') content = string2bytes(content);
    var len = int2bytes(content.length, 6);
    var sig = sigflag ? sign(combine4sig(filename, mimetype, content)) : [];
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
    return [filename, mimetype, content, sig];
  }

  function bundle_pt(filename, mimetype, content, sigflag) {
    if (filename==null) filename='';
    var is_string = (typeof content == 'string');
    var encoding = is_string ? 'raw' : 'base64';
    var sig = sigflag ? sign_pt(combine4sig(filename, mimetype, content)) : '';
    if (!is_string) content = split_into_lines(b64(content));
    var segments = ['X-SC4-bundle: 0 ', content.length, ' ', encoding,
      '\nX-SC4-filename: ', filename, '\nX-SC4-mimetype: ', mimetype,
      '\n', sig, '\n', content]
    return segments.join('');
  }

  var bundle_regex = new RegExp([
    'X-SC4-bundle: ([0-9]+) ([0-9]+) (raw|base64)',
    'X-SC4-filename: ([^]*?)',
    'X-SC4-mimetype: ([^]*?)',
    '(X-SC4-signed: (?:.*\\n){5})?',
    '([^]*)$'].join('\n'));

  function unbundle_pt(s) {
    var l = bundle_regex.exec(s);
    var version = l[1];
    var content_length = l[2];
    var encoding = l[3];
    var filename = l[4];
    var mimetype = l[5];
    var sig = l[6] ? verify_signature_pt(l[6]) : null;
    var content = l[7];
    if (encoding == 'base64') {
      content = unb64(content.split('\n').join(''));
    }
    return [filename, mimetype, content, sig];
  }

  function sigcheck(content, sig) {
    if (!sig) return "No signature";
    if (!sig[0]) return "Invalid signature";
    var content_hash = nacl.hash(to_bytes(content));
    if (!nacl.verify(sig[2], content_hash)) return "Hash mismatch";    
    var sigkey = sig[1];
    var signer_email = sig_key_map[sigkey];
    var keyfp = b58(unb64(sigkey)).slice(0,8);
    if (!signer_email) return 'Signed by an unknown party (' + keyfp + ')';
    return 'Valid signature from ' + signer_email + ' (' + keyfp + ')';
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
    $(a).addClass('button');
    return a;
  }

  function export_as_download(filename, mimetype, content) {
    virtual_click(make_download_link(filename, mimetype, content));
  }

  // SC4 content handling

  function export_my_key_string() {
    var s = 'X-sc4-content-type: public-key v0.2\nFrom: ' +
      localStorage[email_key] + '\n' + "Timestamp: " +
      new Date().toUTCString() + '\n' +
      b58(my_keys.spk) + '\n';
    var sig = b58(signature(s));
    return s + split_into_lines(sig, 44);
  }

  function export_my_key() {
    var s = $('#invitation').text() + '---START KEY---\n' +
      export_my_key_string() + '---END KEY---\n';
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

  function find_rx_key_for_pk(pk) {
    for (var i=0; i<rx_keys.length; i++) {
      if (nacl.verify(pk, rx_keys[i][2])) return rx_keys[i];
    }
    return null;
  }

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
    if (find_rx_key_for_pk(spk)) {
      return alert("You have already installed this key.");
    }
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
    var delivery_mode = $('input[name=op1]:checked').val();
    if (delivery_mode=='email') {
       export_as_email(get_rx_email(recipient), 'Secure message', result);
    } else if (delivery_mode == 'download') {
       if (filename == null) filename = 'unknown.txt';
       export_as_download(filename + '.sc4', 'text/sc4', result);
    } else if (delivery_mode == 'upload') {
      sc4.upload(result, get_rx_email(recipient));
    } else {
      this_should_never_happen("Unknown delivery mode: " + delivery_mode);
     }
   }
  
  sc4.upload = function() {
    msg("Upload delivery is not implemented in this version of SC4.");
  }

  var decrypt_op_table = { encrypted : decrypt, encrypted_pt : decrypt_pt };
  var unbundle_op_table = { bundle : unbundle, bundle_pt : unbundle_pt };

  var text_mime_types = ['text', 'text/plain', 'text/unknown'];
  var sanitize_mime_types = ['text/html', 'application/xhtml+xml'];
  var safe_mime_types = ['image/jpeg', 'image/gif', 'image/png'];
  var pdf_mime_types = ['application/pdf'];
  
  function member(s, l) {
    for (var i=0; i<l.length; i++) {
      if (l[i]==s) return true;
    }
    return false;
  }

  function mimetype_category(s) {
    s = s.toLowerCase();
    if (member(s, text_mime_types)) return 'text';
    if (member(s, safe_mime_types)) return 'safe';
    if (member(s, sanitize_mime_types)) return 'sanitize';
    if (member(s, pdf_mime_types)) return 'pdf';
    return 'unknown';
  }

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
      var encrypter_pk = unb64(l[1]);
      var sender_email = l[2];
    }
    var unbundle_op = unbundle_op_table[sc4_type];
    if (unbundle_op) {
      var l = unbundle_op(content);
      var filename = l[0];
      var mimetype = l[1];
      content = l[2];
      var sig = l[3];
      var signer_pk = sig ? unb64(sig[1]) : null;
      var sigcontent = combine4sig(filename, mimetype, content);
      var sigstatus = sigcheck(sigcontent, sig);
    } else {
      return msg('Unknown file format: ' + sc4_type);
    }

    // Present results

    var msgs = ["Message was processed successfully."];
    if (decrypt_op && sender_email) {
      msgs.push('This message was encrypted by ' + html_escape(sender_email));
    } else if (decrypt_op) {
      msgs.push('<span class=red>This message was encrypted by an ' +
		'unknown party (' + b58(encrypter_pk).slice(0,8) + ')</span>');
    } else {
      msgs.push("This message was <span class=red>NOT ENCRYPTED</span>.");
    }
    var sigcolor = sigstatus.slice(0,5)=='Valid' ? 'green' : 'red';
    var sss = 'Signature status: <span class=' + sigcolor + '>' +
      html_escape(sigstatus) + '</span>';
    msgs.push(sss);

    // Make sure encryption and signing keys match if both exist
    var key_mismatch = signer_pk && encrypter_pk &&
      !nacl.verify(encrypter_pk, nacl.spk2epk(signer_pk));
    if (key_mismatch) {
      msgs.push(
	'<span class=red>NOTE: This message was signed using ' +
	  'a different key than the one used to encrypted it.</span>'
      );
    }
    msgs.push(filename ? 'File name: ' + html_escape(filename) :
	      '<span class=red>No file name</span>');
    msgs.push('File type: ' + html_escape(mimetype));
    msgs.push('Size: ' + content.length);

    // Make sure the preview data is safe to display
    var pv_content = content;
    var pv_mimetype = mimetype;
    var mtcat = mimetype_category(mimetype);
    if (mtcat=='sanitize') {
      pv_content = DOMPurify.sanitize(
	content, {FORBID_ATTR: ['href', 'xlink:href', 'src', 'action']});
    } else if (mtcat=='text') {
      if (pv_content.length>2500) {
	pv_content = content.slice(0,2000) + "\n\n[MORE...]";
      }
      pv_mimetype = 'text/plain; charset=utf-8';
    }
    var pv_link = make_download_link(filename, pv_mimetype, pv_content);

    if (member(mtcat, ['pdf'])) {
      msgs.push(
	'Inline preview not available, content may be unsafe.' +
	  '  (<a href=https://sc4.us/unsafe_content_info.html target=help>' +
	      'More info</a>)<br>');

      msgs.push('<input type=button click=show_unsafe_preview value="I\'ll take my chances, show me a preview anyway">');
      msgs.push("<div id=preview></div>");
      sc4.pv_link = pv_link;
    } else if (member(mtcat, ['unknown'])) {
      msgs.push('<span class=red>Inline preview not available because this file is not of a known type.</span><br><br>');
    } else {
      var pv_link = make_download_link(filename, pv_mimetype, pv_content);
      msgs.push('Preview:<br><br>');
      msgs.push('<iframe height=400px width=800px src=' + pv_link.href +
		'></iframe><br><br>');
    }

    var dl_link = make_download_link(filename, mimetype, content);
    dl_link.innerHTML='Download this file';
    msgs.push(dl_link.outerHTML);
    msg(msgs.join('<br>'));
    clear_text_box_data();
    install_button_event_handlers();
  }

  function show_unsafe_preview() {
    $('#preview').html('<iframe height=400px width=800px src=' +
		       sc4.pv_link.href + '></iframe>');
  }

  function show_main() { show('main'); }
  function clear_text_box_data() { $('#text').val(''); }
  function my_spk() { return my_keys.spk; }
  function recipient_keys() { return rx_keys; }
  function valid_email(s) { return email_regex.test(s); }

  sc4.key_regex = key_regex;

  function install_event_handlers() {
    $('#main').on('dragenter', dragEnter);
    $('.dropzone').on('dragover', stopEvents);
    $('.dropzone').on('dragleave', dragLeave);
    $('.dropzone').on('drop', drop);
    install_button_event_handlers();
  }

  function install_button_event_handlers() {
    $('input[type=button], a.button').unbind();
    $('input[type=button], a.button').each(function(idx, button) {
      var handler = $(button).attr('click');
      if (handler) {
	var f = sc4[handler];
	if (f) $(button).on('click', f);
	else console.log("Unknown handler: " + handler);
      }
    });
  }

  sc4.exports = [
    unb64, type_of, u8a_cmp, hash, to_bytes, split_into_lines,
    html_escape, bufconcat, concat, int2bytes, bytes2int, baseN, unbaseN,
    b58, unb58, b32, unb32, hex, unhex, show, msg, hard_reset, genkeys,
    setup_keys, get_rx_key, get_rx_email, running_from_local_file,
    retrieve_my_keys, retrieve_rx_keys, store_rx_keys, reset_rx_keys,
    setup_rx_menu, install_public_key, this_should_never_happen,
    initial_setup, generate_or_setup_keys, generate_local_sc4_aux,
    generate_local_sc4, init, stopEvents, dragEnter, dragLeave, drop,
    handle_file_drop, process_dropped_files, encrypt, decrypt,
    encrypt_pt, decrypt_pt, signature, sign, verify_signature, sign_pt,
    verify_signature_pt, combine4sig, bundle, unbundle, bundle_pt,
    unbundle_pt, sigcheck, sc4_typeof, virtual_click, export_as_email,
    make_download_link, export_as_download, export_my_key_string,
    export_my_key, wordify, find_rx_key_for_pk, import_key, process_file,
    process_text_box_data, process_content, member, mimetype_category,
    process_sc4_file, install_event_handlers, my_spk,
    recipient_keys, valid_email, show_main, clear_text_box_data,
    show_unsafe_preview, exportify];

  function exportify(exports, target) {
    for (var i=0; i<exports.length; i++) target[exports[i].name]=exports[i];
  }

  exportify(sc4.exports, sc4);

  sc4.init = init; // Because IE doesn't support function.name

})();

$(sc4.init);
