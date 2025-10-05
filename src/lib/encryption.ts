import CryptoJS from "crypto-js";

// IMPORTANT: This SALT is retrieved from the .env.local file on the server.
// For client-side use, we will pass this value to the client during app initialization,
// or we can hardcode a non-sensitive but unique salt if the app were purely client-side.
// Since we have a Next.js backend, we'll retrieve it there.
const ENCRYPTION_SALT =
  process.env.NEXT_PUBLIC_ENCRYPTION_SALT ||
  "default-secure-salt-for-client-ops";

// --- Key Derivation ---
/**
 * Derives a strong, symmetric key from the user's master password using PBKDF2.
 * This function should run on the CLIENT.
 * @param masterPassword The user's master password (MUST NOT be stored).
 * @returns A symmetric key as a CryptoJS WordArray.
 */
export const deriveKey = (masterPassword: string): CryptoJS.lib.WordArray => {
  // We use a high number of iterations for security
  const iterations = 100000;
  const keySize = 256 / 32; // 256-bit key

  // The salt is technically public but needs to be consistent for key derivation
  return CryptoJS.PBKDF2(masterPassword, ENCRYPTION_SALT, {
    keySize: keySize,
    iterations: iterations,
  });
};

// --- Encryption (Client-side) ---
/**
 * Encrypts plaintext data using the derived symmetric key.
 * @param plaintext The data to encrypt (e.g., a JSON string of the vault item).
 * @param key The derived symmetric key.
 * @returns A JSON string containing the ciphertext and initialization vector (IV).
 */
export const encrypt = (
  plaintext: string,
  key: CryptoJS.lib.WordArray
): string => {
  // Generate a random 128-bit IV
  const iv = CryptoJS.lib.WordArray.random(128 / 8);

  const ciphertext = CryptoJS.AES.encrypt(plaintext, key, {
    iv: iv,
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.Pkcs7,
  });

  // We return the IV and ciphertext so we can decrypt later.
  return JSON.stringify({
    ciphertext: ciphertext.toString(),
    iv: iv.toString(),
  });
};

// --- Decryption (Client-side) ---
/**
 * Decrypts ciphertext data using the derived symmetric key.
 * @param encryptedJson A JSON string from the database containing ciphertext and IV.
 * @param key The derived symmetric key.
 * @returns The original plaintext string.
 */
export const decrypt = (
  encryptedJson: string,
  key: CryptoJS.lib.WordArray
): string | null => {
  try {
    const encrypted = JSON.parse(encryptedJson);
    const iv = CryptoJS.enc.Hex.parse(encrypted.iv);
    const cipherParams = CryptoJS.lib.CipherParams.create({
      ciphertext: CryptoJS.enc.Base64.parse(encrypted.ciphertext),
    });

    const decrypted = CryptoJS.AES.decrypt(cipherParams, key, {
      iv: iv,
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7,
    });

    return decrypted.toString(CryptoJS.enc.Utf8);
  } catch (error) {
    console.error("Decryption failed:", error);
    // Return null or throw an error if decryption fails (e.g., wrong master password)
    return null;
  }
};

/**
 * Type for the encrypted object stored in the database.
 */
export type EncryptedData = {
  ciphertext: string;
  iv: string;
};
