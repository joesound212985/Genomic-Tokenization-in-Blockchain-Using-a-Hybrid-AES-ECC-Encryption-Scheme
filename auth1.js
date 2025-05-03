const fs = require('fs');
const IPFS = require('ipfs-http-client');
const ethers = require('ethers');
const crypto = require('crypto');
const nacl = require('tweetnacl');
const { ArgumentParser } = require('argparse');

nacl.util = require('tweetnacl-util');

//
// 1. IPFS + Ethereum setup
//
const ipfs = IPFS.create();  // Connects to a local daemon at 127.0.0.1:5001 by default.
const provider = new ethers.providers.JsonRpcProvider('https://sepolia.infura.io/v3/ce62d114de644ff29ac5fb8f196a6e1d');
provider.resolveName = async (name) => name; // Disable ENS resolution


const privateKey = '0eb6d02ad152e0403e9ea49ef56aa2396e02147a771dad0e461247b240ff7e31';

const base64Key = Buffer.from(privateKey.replace(/^0x/, ''), 'hex').toString('base64');
console.log("Private Key (Base64):", base64Key);


const wallet = new ethers.Wallet(privateKey, provider);

const contractAddress = '0xBa059E10d3B25CC0616873972C7635DbaCf205E6';

const contractArtifact = require('./artifacts/contracts/FileStorage.sol/FileStorage.json');
const contractABI = contractArtifact.abi;

const contract = new ethers.Contract(contractAddress, contractABI, wallet);

//
// 2. Optional helper: Watermark generator (for provenance)
//
function generateWatermark(userAddress) {
  return crypto.createHash('sha256').update(userAddress).digest('hex');
}

//
// 3. Encrypt and upload file
//
async function encryptFile(filePath, recipientPublicKeyBase64) {
  try {
    // 3a. Read plaintext file from disk
    const fileBuffer = fs.readFileSync(filePath);
    console.log("File read successfully.");

    // 3b. Generate AES key & IV
    const aesKey = crypto.randomBytes(32); // 256-bit key
    console.log("AES key generated.");
    const iv = crypto.randomBytes(16);

    // 3c. Encrypt file with AES-256 in CBC mode
    const cipher = crypto.createCipheriv('aes-256-cbc', aesKey, iv);
    const encryptedFileBuffer = Buffer.concat([
      iv,
      cipher.update(fileBuffer),
      cipher.final()
    ]);
    console.log("File encrypted, uploading to IPFS...");

    // 3d. Upload encrypted file to IPFS
    const ipfsResult = await ipfs.add(encryptedFileBuffer);
    console.log("IPFS upload result:", ipfsResult);
    const ipfsHash = ipfsResult.path;

    // 3e. Encrypt the AES key using ephemeral key pair + the recipient's public key
    const recipientPublicKey = nacl.util.decodeBase64(recipientPublicKeyBase64);
    if (recipientPublicKey.length !== 32) {
      throw new Error('Recipient public key must be 32 bytes long after Base64 decoding.');
    }
    
    const ephemeralKeyPair = nacl.box.keyPair();
    const ephemeralPublicKey = ephemeralKeyPair.publicKey;
    const ephemeralSecretKey = ephemeralKeyPair.secretKey;
    const nonce = nacl.randomBytes(nacl.box.nonceLength);
    const naclBox = nacl.box(aesKey, nonce, recipientPublicKey, ephemeralSecretKey);

    const encryptedAesKeyBuffer = Buffer.concat([
      Buffer.from(ephemeralPublicKey),
      Buffer.from(nonce),
      Buffer.from(naclBox)
    ]);
    const encryptedAesKeyBase64 = nacl.util.encodeBase64(encryptedAesKeyBuffer);

    // 3f. Store encrypted AES key & file hash on the blockchain
    const tx = await contract.addFile(ipfsHash, encryptedAesKeyBase64);
    console.log("Transaction sent, hash:", tx.hash);
    await tx.wait();

    console.log(`Encrypted file uploaded to IPFS: ${ipfsHash}`);
    console.log('Encrypted AES key (with ephemeral public key) stored on the blockchain.');
  } catch (error) {
    console.error("Encryption failed:", error);
  }
}


//
// 4. Decrypt file with access control verification
//
async function decryptFile(fileIndex, userPrivateKeyBase64, userPublicKeyBase64) {
  try {
    // 4a. Check if this user has on-chain permission
    const hasAccess = await contract.hasAccess(wallet.address, fileIndex);
    if (!hasAccess) {
      throw new Error("Access Denied: You do not have permission to decrypt this file.");
    }

    // 4b. Retrieve file metadata (IPFS hash + encrypted AES key)
    const fileDetails = await contract.getFile(fileIndex);
    const ipfsHash = fileDetails[0];
    const encryptedAesKeyBase64 = fileDetails[1];

    // 4c. Download the encrypted file from IPFS
    const encryptedFileChunks = [];
    for await (const chunk of ipfs.cat(ipfsHash)) {
      encryptedFileChunks.push(chunk);
    }
    const encryptedFile = Buffer.concat(encryptedFileChunks);

    // The file format is [IV (16 bytes)] + [AES-encrypted data]
    const iv = encryptedFile.slice(0, 16);
    const encryptedFileData = encryptedFile.slice(16);

    // 4d. Decrypt the AES key using the ephemeral public key and the user's secret key
    const userPublicKey = nacl.util.decodeBase64(userPublicKeyBase64);
    const userPrivateKey = nacl.util.decodeBase64(userPrivateKeyBase64);

    // Decode the encrypted AES key buffer from Base64
    const encryptedAesKeyBuffer = nacl.util.decodeBase64(encryptedAesKeyBase64);

    // Extract ephemeral public key, nonce, and the box
    const ephemeralPublicKey = encryptedAesKeyBuffer.slice(0, 32);
    const nonce = encryptedAesKeyBuffer.slice(32, 32 + nacl.box.nonceLength);
    const naclBox = encryptedAesKeyBuffer.slice(32 + nacl.box.nonceLength);

    // Recover the AES key
    const aesKey = nacl.box.open(naclBox, nonce, ephemeralPublicKey, userPrivateKey);
    if (!aesKey) {
      throw new Error('Decryption failed! Could not open the box with the provided key.');
    }

    // 4e. Decrypt the file with AES-256
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(aesKey), iv);
    const decryptedFile = Buffer.concat([decipher.update(encryptedFileData), decipher.final()]);

    console.log('Decrypted file content:', decryptedFile.toString());
  } catch (error) {
    console.error('Decryption failed:', error);
  }
}

//
// 5. Access control functions
//
async function grantAccess(fileIndex, addressToGrant) {
  const tx = await contract.grantAccess(addressToGrant, fileIndex);
  await tx.wait();
  console.log(`Access granted to ${addressToGrant} for file index ${fileIndex}`);
}

async function revokeAccess(fileIndex, addressToRevoke) {
  const tx = await contract.revokeAccess(addressToRevoke, fileIndex);
  await tx.wait();
  console.log(`Access revoked from ${addressToRevoke} for file index ${fileIndex}`);
}

//
// 6. Auditing logs
//
async function getAccessLogs(fileIndex) {
  const filter = contract.filters.AccessAttempt(null, fileIndex);
  const events = await contract.queryFilter(filter);
  console.log(`Access logs for file index ${fileIndex}:`);
  events.forEach(event => {
    console.log(`User: ${event.args.user}, Success: ${event.args.success}, Time: ${event.blockNumber}`);
  });
}

//
// 7. Get access list for a file
//
async function getAccessList(fileIndex) {
  const accessList = await contract.getAccessList(fileIndex);
  console.log(`Users with access to file index ${fileIndex}:`);
  accessList.forEach(address => console.log(address));
}

//
// 8. Get total count of files
//
async function getFilesCount() {
  const filesCount = await contract.getFilesCount();
  console.log(`Total files count: ${filesCount}`);
}

//
// 9. Command-line interface
//
async function main() {
  const parser = new ArgumentParser({ description: 'File encryption and decryption system' });
  
  // Update the encryption flag to accept 2 arguments
  parser.add_argument('-e', '--encrypt', {
    help: 'Encrypt a file',
    nargs: 2,
    metavar: ['FILE_PATH', 'RECIPIENT_PUBLIC_KEY']
  });
  parser.add_argument('-d', '--decrypt', {
    help: 'Decrypt a file',
    nargs: 3,
    metavar: ['FILE_INDEX', 'USER_PRIVATE_KEY', 'USER_PUBLIC_KEY']
  });
  parser.add_argument('-g', '--grant', {
    help: 'Grant access to a file',
    nargs: 2,
    metavar: ['FILE_INDEX', 'ADDRESS']
  });
  parser.add_argument('-r', '--revoke', {
    help: 'Revoke access from a file',
    nargs: 2,
    metavar: ['FILE_INDEX', 'ADDRESS']
  });
  parser.add_argument('-l', '--list', {
    help: 'Get the access list for a file',
    nargs: 1,
    metavar: 'FILE_INDEX'
  });
  parser.add_argument('-i', '--indexes', {
    help: 'Get the total count of files',
    action: 'store_true'
  });

  const args = parser.parse_args();

  if (args.encrypt) {
    const [filePath, recipientPublicKey] = args.encrypt;
    await encryptFile(filePath, recipientPublicKey);
  } else if (args.decrypt) {
    const [fileIndex, userPrivateKey, userPublicKey] = args.decrypt;
    await decryptFile(fileIndex, userPrivateKey, userPublicKey);
  } else if (args.grant) {
    await grantAccess(...args.grant);
  } else if (args.revoke) {
    await revokeAccess(...args.revoke);
  } else if (args.list) {
    await getAccessList(args.list[0]);
  } else if (args.indexes) {
    await getFilesCount();
  }
}

console.log("File read successfully.");
console.log("AES key generated.");



main().catch(console.error);
