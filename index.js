// holepunch.js
const dgram = require('dgram');
const crypto = require('crypto');
const readline = require('readline');

/**
 * Send a STUN Binding Request to obtain your public IP and port.
 */
function stunRequest(socket, server, port, callback) {
  const buf = Buffer.alloc(20);
  // STUN header:
  // Bytes 0-1: Message Type (Binding Request: 0x0001)
  // Bytes 2-3: Message Length (0 for no attributes)
  // Bytes 4-7: Magic Cookie (0x2112A442)
  // Bytes 8-19: Transaction ID (12 random bytes)
  buf.writeUInt16BE(0x0001, 0);    // Binding Request
  buf.writeUInt16BE(0, 2);         // Message Length
  buf.writeUInt32BE(0x2112A442, 4); // Magic Cookie
  crypto.randomBytes(12).copy(buf, 8);

  // Send the STUN request
  socket.send(buf, port, server, (err) => {
    if (err) return callback(err);
  });

  // Timeout if no response is received in 3 seconds
  const timeout = setTimeout(() => {
    callback(new Error("STUN request timed out"));
  }, 3000);

  // Wait for the STUN response (only once)
  socket.once('message', (msg, rinfo) => {
    clearTimeout(timeout);
    try {
      const res = parseStunResponse(msg);
      callback(null, res);
    } catch (err) {
      callback(err);
    }
  });
}

/**
 * Parse the STUN response to extract the XOR-MAPPED-ADDRESS.
 */
function parseStunResponse(msg) {
  if (msg.length < 20) throw new Error("STUN response too short");

  // STUN header is 20 bytes; attributes follow.
  let offset = 20;
  while (offset + 4 <= msg.length) {
    // Each attribute has a 4-byte header: Type (2 bytes) and Length (2 bytes)
    const attrType = msg.readUInt16BE(offset);
    const attrLen = msg.readUInt16BE(offset + 2);
    if (attrType === 0x0020) { // XOR-MAPPED-ADDRESS attribute
      if (attrLen < 8) {
        throw new Error("Invalid XOR-MAPPED-ADDRESS length");
      }
      // The attribute value starts at offset + 4
      // Structure:
      //  Byte 0: Reserved
      //  Byte 1: Family (0x01 for IPv4, 0x02 for IPv6)
      //  Bytes 2-3: X-Port (XOR'ed with most-significant 16 bits of magic cookie)
      //  Bytes 4-7: X-Address (IPv4 address XOR'ed with magic cookie bytes)
      const family = msg.readUInt8(offset + 5);
      let xport = msg.readUInt16BE(offset + 6);
      xport = xport ^ 0x2112; // XOR with most significant 16 bits of magic cookie

      let ip;
      if (family === 0x01) { // IPv4
        const xaddr = msg.slice(offset + 8, offset + 12);
        const magicCookie = Buffer.from([0x21, 0x12, 0xA4, 0x42]);
        const ipBytes = Buffer.alloc(4);
        for (let i = 0; i < 4; i++) {
          ipBytes[i] = xaddr[i] ^ magicCookie[i];
        }
        ip = Array.from(ipBytes).join('.');
      } else if (family === 0x02) { // IPv6 not implemented in this example
        throw new Error("IPv6 not supported in this example");
      } else {
        throw new Error("Unknown address family");
      }
      return { ip, port: xport };
    }
    // Move to the next attribute: header (4 bytes) + attribute value
    offset += 4 + attrLen;
  }
  throw new Error("XOR-MAPPED-ADDRESS attribute not found");
}

// Create a UDP socket
const socket = dgram.createSocket('udp4');

// Bind the socket (letting the OS pick an available port)
socket.bind(() => {
  const localAddr = socket.address();
  console.log('Local socket bound on', localAddr);

  // Use a STUN server to get the public IP and port
  stunRequest(socket, 'stun.l.google.com', 19302, (err, res) => {
    if (err) {
      console.error('STUN request failed:', err);
      process.exit(1);
    }
    console.log(`Your public IP: ${res.ip} and public port: ${res.port}`);

    // Set up readline to ask for your friend's public details
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout
    });

    rl.question("Enter friend's public IP: ", (friendIP) => {
      rl.question("Enter friend's public port: ", (friendPortStr) => {
        const friendPort = parseInt(friendPortStr, 10);
        console.log(`Starting UDP hole punching to ${friendIP}:${friendPort} ...`);

        let connected = false;

        // Listen for incoming UDP messages on this socket
        socket.on('message', (msg, rinfo) => {
          if (rinfo.address === friendIP && rinfo.port === friendPort) {
            console.log(`Received message from friend ${rinfo.address}:${rinfo.port}: ${msg.toString()}`);
            if (!connected) {
              connected = true;
              console.log('Hole punching successful. You can now chat!');
              // In chat mode, every new line typed is sent to your friend.
              rl.on('line', (line) => {
                socket.send(line, friendPort, friendIP, (err) => {
                  if (err) console.error('Send error:', err);
                });
              });
            }
          }
        });

        // Send 100 UDP "punch" packets at intervals of 100ms
        let count = 0;
        const interval = setInterval(() => {
          if (count < 100) {
            const message = `Punch ${count}`;
            socket.send(message, friendPort, friendIP, (err) => {
              if (err) console.error('Error sending punch:', err);
            });
            count++;
          } else {
            clearInterval(interval);
          }
        }, 100);
      });
    });
  });
});
