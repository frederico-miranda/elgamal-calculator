import {
  PRIME_MODULUS,
  encryptionIngredientFrom,
  decryptionIngredientFrom,
  encrypt,
  decrypt,
} from './lib/cryptography';

import {
  SUBGROUP_MODULUS,
  verificationKeyFrom,
  sign,
  verify,
} from './lib/authentication';

const texExpressions = document.querySelectorAll('.tex-expression');

texExpressions.forEach((element) => {
  element.setAttribute('role', 'presentation');
  element.setAttribute('aria-hidden', 'true');

  const expression = element.innerText;
  katex.render(expression, element, {
    throwOnError: false
  });
});

const generateRandom = () => bigInt.randBetween(2, PRIME_MODULUS);

const cryptographySanityTest = () => {
  const generator = generateRandom();
  const privateKey = generateRandom();
  const encryptionIngredient = encryptionIngredientFrom(generator, privateKey);

  const randomSecret = generateRandom();
  const decryptionIngredient = decryptionIngredientFrom(generator, randomSecret);

  const privateKeyInverse = PRIME_MODULUS.minus(privateKey).minus(1);
  const encryptionKey = encryptionIngredient.modPow(randomSecret, PRIME_MODULUS);
  const decryptionKey = decryptionIngredient.modPow(privateKeyInverse, PRIME_MODULUS);
  const productOfInverses = encryptionKey.times(decryptionKey).mod(PRIME_MODULUS);

  if (productOfInverses.notEquals(1)) {
    return 'FAIL #1';
  }

  const originalPlainText = generateRandom();
  const [cipherText, ingredientDecryption] = encrypt(
    generator,
    encryptionIngredient,
    originalPlainText,
    randomSecret,
  );

  const resultPlainText = decrypt(
    privateKey,
    ingredientDecryption,
    cipherText,
  );

  if (originalPlainText.notEquals(resultPlainText)) {
    return 'FAIL #2';
  }

  return 'PASS';
};

const authenticationSanityTest = () => {
  let generator = generateRandom();
  let signingKey = generateRandom();
  let verificationKey = verificationKeyFrom(generator, signingKey);

  let message = generateRandom();
  let nonce = generateRandom().or(1); /* forces odd number, because even numbers are not co-prime */
  let [witnessR, witnessS] = sign(generator, message, signingKey, nonce);

  /* m = xr + ks (mod SUBGROUP_MODULUS) */
  const leftAddend = signingKey.times(witnessR);
  const rightAddend = nonce.times(witnessS);
  const messageClone = leftAddend.plus(rightAddend).mod(SUBGROUP_MODULUS);

  if (message.notEquals(messageClone)) {
    return 'FAIL #1';
  }

  if (!verify(generator, message, verificationKey, witnessR, witnessS)) {
    return 'FAIL #2';
  }
  
  return 'PASS';
};

if (cryptographySanityTest() !== 'PASS' || authenticationSanityTest() !== 'PASS') {
  throw "Something is wrong with the library!";
}

const cryptographyGenerator = document.getElementById('cryptography-generator');
const cryptographyPrivateKey = document.getElementById('cryptography-private-key');
const cryptographyButton = document.getElementById('cryptography-button');
const cryptographyStatus = document.getElementById('cryptography-status');
const cryptographyPublicKey = document.getElementById('cryptography-public-key');

let generator1 = "generator";
let privateKey = "privateKey";
let publicKey = "publicKey";

cryptographyButton.onclick = () => {
  generator1 = "generator";
  privateKey = "privateKey";
  publicKey = "publicKey";

  try {
    generator1 = bigInt(cryptographyGenerator.value);
    privateKey = bigInt(cryptographyPrivateKey.value);
    publicKey = decryptionIngredientFrom(generator1, privateKey);
    cryptographyPublicKey.value = publicKey.toString();
    cryptographyStatus.innerText = "";
  } catch(error) {
    cryptographyStatus.innerText = error.toString();
  }
};

const encryptionPlaintextInteger = document.getElementById('encryption-plaintext-integer');
const encryptionSecretNonce = document.getElementById('encryption-secret-nonce');
const encryptButton = document.getElementById('encrypt-button');
const encryptStatus = document.getElementById('encrypt-status');
const encryptionCiphertextInteger = document.getElementById('encryption-ciphertext-integer');
const encryptionDecryptionIngredient = document.getElementById('encryption-decryption-ingredient');

let plainText1 = "plainText";
let secretNonce1 = "secretNonce";
let cipherText1 = "cipherText";
let decryptionIngredient1 = "decryptionIngredient";

encryptButton.onclick = () => {
  plainText1 = "plainText";
  secretNonce1 = "secretNonce";
  cipherText1 = "cipherText";
  decryptionIngredient1 = "decryptionIngredient";
  try {
    plainText1 = bigInt(encryptionPlaintextInteger.value);
    secretNonce1 = bigInt(encryptionSecretNonce.value);
    const [cipherText, decryptionIngredient] = encrypt(generator1, publicKey, plainText1, secretNonce1);
    cipherText1 = cipherText;
    decryptionIngredient1 = decryptionIngredient;
    
    encryptionCiphertextInteger.value = cipherText1.toString();
    encryptionDecryptionIngredient.value = decryptionIngredient1.toString();
    
    encryptStatus.innerText = "";    
  } catch(error) {
    encryptStatus.innerText = error.toString();
    encryptionCiphertextInteger.value = "";
    encryptionDecryptionIngredient.value = "";
  }
};

const decryptionCiphertextInteger = document.getElementById('decryption-ciphertext-integer');
const decryptionDecryptionIngredient = document.getElementById('decryption-decryption-ingredient');
const decryptButton = document.getElementById('decrypt-button');
const decryptStatus = document.getElementById('decrypt-status');
const decryptionPlaintextInteger = document.getElementById('decryption-plaintext-integer');

let plainText2 = "plainText";
let cipherText2 = "cipherText";
let decryptionIngredient2 = "decryptionIngredient";

decryptButton.onclick = () => {
  cipherText2 = "cipherText";
  decryptionIngredient2 = "decryptionIngredient";
  try {
    cipherText2 = bigInt(decryptionCiphertextInteger.value);
    decryptionIngredient2 = bigInt(decryptionDecryptionIngredient.value);
    plainText2 = decrypt(privateKey, decryptionIngredient2, cipherText2);
    
    decryptionPlaintextInteger.value = plainText2.toString();
    decryptStatus.innerText = "";
  } catch(error) {
    decryptStatus.innerText = error.toString();
    decryptionPlaintextInteger.value = "";
  }
};

const authenticationGenerator = document.getElementById('authentication-generator');
const authenticationSigningKey = document.getElementById('authentication-signing-key');
const authenticationButton = document.getElementById('authentication-button');
const authenticationStatus = document.getElementById('authentication-status');
const authenticationVerificationKey = document.getElementById('authentication-verification-key');

let generator2 = "generator";
let signingKey = "signingKey";
let verificationKey = "verificationKey";

authenticationButton.onclick = () => {
  generator2 = "generator";
  signingKey = "signingKey";
  verificationKey = "verificationKey";

  try {
    generator2 = bigInt(authenticationGenerator.value);
    signingKey = bigInt(authenticationSigningKey.value);
    verificationKey = verificationKeyFrom(generator2, signingKey);
    authenticationVerificationKey.value = verificationKey.toString();
    authenticationStatus.innerText = "";
  } catch(error) {
    authenticationStatus.innerText = error.toString();
    authenticationVerificationKey.value = "";
  }
};

const signatureMessageInteger = document.getElementById('signature-message-integer');
const signatureSecretNonce = document.getElementById('signature-secret-nonce');
const signatureButton = document.getElementById('signature-button');
const signatureStatus = document.getElementById('signature-status');
const signatureWitnessR = document.getElementById('signature-witness-r');
const signatureWitnessS = document.getElementById('signature-witness-s');

let messageInteger1 = "messageInteger";
let secretNonce2 = "secretNonce";
let witnessR1 = "witnessR";
let witnessS1 = "witnessS";

signatureButton.onclick = () => {
  messageInteger1 = "messageInteger";
  secretNonce2 = "secretNonce";
  witnessR1 = "witnessR";
  witnessR2 = "witnessS";

  try {
    messageInteger1 = bigInt(signatureMessageInteger.value);
    secretNonce2 = bigInt(signatureSecretNonce.value);
    const [witnessR, witnessS] = sign(generator2, messageInteger1, signingKey, secretNonce2);
    witnessR1 = witnessR;
    witnessS1 = witnessS;

    signatureWitnessR.value = witnessR1.toString();
    signatureWitnessS.value = witnessS1.toString();
    signatureStatus.innerText = "";
  } catch(error) {
    signatureWitnessR.value = "";
    signatureWitnessS.value = "";
    signatureStatus.innerText = error.toString();
  }
};

const verifyMessageInteger = document.getElementById('verify-message-integer');
const verifyWitnessR = document.getElementById('verify-witness-r');
const verifyWitnessS = document.getElementById('verify-witness-s');
const verifyButton = document.getElementById('verify-button');
const verifyStatus = document.getElementById('verify-status');
const verifyAuthenticity = document.getElementById('verify-authenticity');

let messageInteger2 = "messageInteger";
let witnessR2 = "witnessR";
let witnessS2 = "witnessS";

verifyButton.onclick = () => {
  messageInteger2 = "messageInteger";
  witnessR2 = "witnessR";
  witnessS2 = "witnessS2";

  try {
    messageInteger2 = bigInt(verifyMessageInteger.value);
    witnessR2 = bigInt(verifyWitnessR.value);
    witnessS2 = bigInt(verifyWitnessS.value);
    
    if (verify(generator2, messageInteger2, verificationKey, witnessR2, witnessS2)) {
      verifyAuthenticity.value = "Authentic";
    } else {
      verifyAuthenticity.value = "Forgery";
    }

    verifyStatus.innerText = "";
  } catch(error) {
    verifyAuthenticity.value = "";
    verifyStatus.innerText = error.toString();
  }
};
