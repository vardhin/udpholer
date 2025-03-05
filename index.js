// holepunch.js
const dgram = require('dgram');
const crypto = require('crypto');
const readline = require('readline');
const https = require('https');

// Add colors for beautiful logging
const colors = {
  reset: "\x1b[0m",
  bright: "\x1b[1m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  magenta: "\x1b[35m",
  cyan: "\x1b[36m"
};

// Enhanced logging function
function log(type, message) {
  const timestamp = new Date().toISOString();
  switch(type) {
    case 'info':
      console.log(`${colors.cyan}[${timestamp}] ℹ️  ${message}${colors.reset}`);
      break;
    case 'success':
      console.log(`${colors.green}[${timestamp}] ✅ ${message}${colors.reset}`);
      break;
    case 'error':
      console.log(`${colors.red}[${timestamp}] ❌ ${message}${colors.reset}`);
      break;
    case 'warning':
      console.log(`${colors.yellow}[${timestamp}] ⚠️  ${message}${colors.reset}`);
      break;
    case 'attack':
      console.log(`${colors.magenta}[${timestamp}] 🎯 ${message}${colors.reset}`);
      break;
    default:
      console.log(`[${timestamp}] ${message}`);
  }
}

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

// Simplified time handling - use local time
function getCurrentTime() {
  const now = new Date();
  const currentHour = now.getHours();
  const currentMinute = now.getMinutes();
  const currentSecond = now.getSeconds();
  const ampm = currentHour >= 12 ? 'PM' : 'AM';
  const hour12 = currentHour % 12 || 12;
  
  return {
    now,
    currentHour,
    currentMinute,
    currentSecond,
    hour12,
    ampm
  };
}

// Create a UDP socket
const socket = dgram.createSocket('udp4');

// Bind the socket (letting the OS pick an available port)
socket.bind(() => {
  const localAddr = socket.address();
  log('info', `Local socket bound on ${JSON.stringify(localAddr)}`);

  // Use a STUN server to get the public IP and port
  stunRequest(socket, 'stun.l.google.com', 19302, (err, res) => {
    if (err) {
      log('error', `STUN request failed: ${err.message}`);
      process.exit(1);
    }
    log('success', `Your public IP: ${res.ip} and public port: ${res.port}`);

    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout
    });

    rl.question(`${colors.cyan}Enter friend's public IP: ${colors.reset}`, (friendIP) => {
      rl.question(`${colors.cyan}Enter friend's public port: ${colors.reset}`, async (friendPortStr) => {
        const friendPort = parseInt(friendPortStr, 10);
        
        // Validate port number
        if (isNaN(friendPort) || friendPort <= 0 || friendPort >= 65536) {
          log('error', 'Invalid port number. Port must be between 1 and 65535');
          process.exit(1);
        }
        
        // Get and display current time
        const time = getCurrentTime();
        log('info', `Current time: ${time.currentHour}:${time.currentMinute.toString().padStart(2, '0')}:${time.currentSecond.toString().padStart(2, '0')} (24hr)`);
        log('info', `           : ${time.hour12}:${time.currentMinute.toString().padStart(2, '0')}:${time.currentSecond.toString().padStart(2, '0')} ${time.ampm}`);
        
        rl.question(`${colors.cyan}Enter target minute (0-59) for attack: ${colors.reset}`, (targetMinute) => {
          const minute = parseInt(targetMinute);
          
          if (isNaN(minute) || minute < 0 || minute > 59) {
            log('error', 'Invalid minute. Please enter a number between 0 and 59');
            process.exit(1);
          }

          const targetTime = new Date(time.now);
          targetTime.setMinutes(minute);
          targetTime.setSeconds(0);
          targetTime.setMilliseconds(0);

          // If target minute is earlier than current minute, move to next hour
          if (minute <= time.currentMinute) {
            targetTime.setHours(targetTime.getHours() + 1);
          }

          const delayToTarget = targetTime.getTime() - time.now.getTime();
          const countdown = Math.round(delayToTarget / 1000);

          log('attack', `Attack scheduled for: ${targetTime.toLocaleTimeString()}`);
          log('info', `Time until attack: ${Math.floor(countdown/60)}m ${countdown%60}s`);
          
          let packetCount = 0;
          let connected = false;
          let lastMessageTime = Date.now();
          let keepAliveInterval;
          let punchInterval;

          // Start countdown display
          let remainingSeconds = countdown;
          const countdownInterval = setInterval(() => {
            remainingSeconds--;
            if (remainingSeconds > 0) {
              if (remainingSeconds <= 10) {
                  log('warning', `Attack starting in ${remainingSeconds} seconds...`);
              } else if (remainingSeconds % 30 === 0) {
                  // Update every 30 seconds
                  log('info', `${Math.floor(remainingSeconds/60)}m ${remainingSeconds%60}s remaining`);
              }
            }
          }, 1000);

          // Schedule the precise attack
          setTimeout(() => {
            clearInterval(countdownInterval);
            log('attack', '🚀 ATTACK INITIATED! 🚀');
            
            // Enhanced hole punching with packet logging
            let packetCount = 0;
            let connected = false;
            let attempt = 0;
            const maxAttempts = 10;
            const baseDelay = 100; // Start with 100ms

            const punch = () => {
              if (attempt >= maxAttempts || connected) {
                if (punchInterval) {
                  clearInterval(punchInterval);
                  punchInterval = null;
                }
                if (!connected) {
                  log('error', 'Failed to establish connection after maximum attempts');
                }
                return;
              }

              packetCount++;
              const message = JSON.stringify({
                type: 'punch',
                attempt: attempt + 1,
                timestamp: Date.now()
              });

              socket.send(message, friendPort, friendIP, (err) => {
                if (err) {
                  log('error', `Packet #${packetCount} failed: ${err.message}`);
                } else {
                  log('info', `Packet #${packetCount} sent (attempt ${attempt + 1}/${maxAttempts})`);
                }
              });

              attempt++;
            };

            punchInterval = setInterval(punch, baseDelay);
            punch(); // Send first punch immediately
          }, delayToTarget);

          // Message handler
          socket.on('message', (msg, rinfo) => {
            if (rinfo.address === friendIP && rinfo.port === friendPort) {
              lastMessageTime = Date.now();
              
              if (punchInterval) {
                clearInterval(punchInterval);
                punchInterval = null;
              }
              
              try {
                const message = msg.toString();
                if (message === 'keep-alive') {
                  log('info', 'Keep-alive received');
                  return;
                }
                
                if (!connected) {
                  connected = true;
                  log('success', 'Connection established! You can now chat.');
                  startKeepAlive();
                  
                  rl.on('line', (line) => {
                    if (line.trim()) {
                      socket.send(line, friendPort, friendIP, (err) => {
                        if (err) log('error', `Send error: ${err.message}`);
                      });
                    }
                  });
                }
                
                try {
                  const parsed = JSON.parse(message);
                  if (parsed.type !== 'punch') {
                    log('info', `Friend: ${message}`);
                  }
                } catch {
                  log('info', `Friend: ${message}`);
                }
              } catch (e) {
                log('error', `Error processing message: ${e.message}`);
              }
            }
          });

          // Keep-alive mechanism
          function startKeepAlive() {
            if (keepAliveInterval) clearInterval(keepAliveInterval);
            keepAliveInterval = setInterval(() => {
              socket.send('keep-alive', friendPort, friendIP, (err) => {
                if (err) log('error', `Keep-alive error: ${err.message}`);
              });
            }, 5000); // Send keep-alive every 5 seconds
          }

          // Cleanup on exit
          process.on('SIGINT', () => {
            log('info', '\nClosing connection...');
            if (keepAliveInterval) clearInterval(keepAliveInterval);
            if (punchInterval) clearInterval(punchInterval);
            socket.close();
            rl.close();
            process.exit(0);
          });
        });
      });
    });
  });
});
