/**
 * Generates a strong, random password based on configurable options.
 * This logic should run on the CLIENT.
 */
export interface PasswordOptions {
  length: number;
  includeUppercase: boolean;
  includeLowercase: boolean;
  includeNumbers: boolean;
  includeSymbols: boolean;
  excludeLookAlikes: boolean;
}

const CHAR_SETS = {
  LOWERCASE: "abcdefghijklmnopqrstuvwxyz",
  UPPERCASE: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  NUMBERS: "0123456789",
  SYMBOLS: "!@#$%^&*()-_+=[]{}|;:,.<>/?",
};

const LOOK_ALIKES = "lIO01"; // Characters often confused with others

/**
 * Generates a password string.
 * @param options Configuration for the password.
 * @returns The generated password string.
 */
export function generatePassword(options: PasswordOptions): string {
  let allChars = "";
  if (options.includeLowercase) allChars += CHAR_SETS.LOWERCASE;
  if (options.includeUppercase) allChars += CHAR_SETS.UPPERCASE;
  if (options.includeNumbers) allChars += CHAR_SETS.NUMBERS;
  if (options.includeSymbols) allChars += CHAR_SETS.SYMBOLS;

  if (options.excludeLookAlikes) {
    // Filter out look-alike characters from the allowed set
    allChars = allChars
      .split("")
      .filter((char) => !LOOK_ALIKES.includes(char))
      .join("");
  }

  // Ensure at least one character set is selected
  if (allChars.length === 0) {
    return "Please select at least one character type.";
  }

  let password = "";
  // Ensure at least one character from each required set is included
  const requiredChars: string[] = [];
  if (options.includeLowercase)
    requiredChars.push(getRandomChar(CHAR_SETS.LOWERCASE));
  if (options.includeUppercase)
    requiredChars.push(getRandomChar(CHAR_SETS.UPPERCASE));
  if (options.includeNumbers)
    requiredChars.push(getRandomChar(CHAR_SETS.NUMBERS));
  if (options.includeSymbols)
    requiredChars.push(getRandomChar(CHAR_SETS.SYMBOLS));

  // Pad the rest of the password length with random characters from the combined set
  for (let i = requiredChars.length; i < options.length; i++) {
    password += getRandomChar(allChars);
  }

  // Combine required characters and random characters, then shuffle
  password = (requiredChars.join("") + password).slice(0, options.length);
  return shuffleString(password);
}

/** Helper function to get a random character from a string. */
function getRandomChar(charSet: string): string {
  if (!charSet) return "";
  const randomIndex = Math.floor(Math.random() * charSet.length);
  return charSet[randomIndex];
}

/** Helper function to shuffle a string (Fisher-Yates algorithm for strings). */
function shuffleString(str: string): string {
  const arr = str.split("");
  for (let i = arr.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr.join("");
}
