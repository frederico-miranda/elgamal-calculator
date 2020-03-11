/* 2048-bit safe prime "1942, 28th of September", 2^2048 - 1942289 */
export const PRIME_MODULUS = bigInt(2).pow(2048).minus(1942289);

export const encryptionIngredientFrom = (generator, privateKey) => {
  const encryptionIngredient = generator.modPow(privateKey,  PRIME_MODULUS);
  return encryptionIngredient;
};

export const decryptionIngredientFrom = (generator, randomSecret) => {
  const decryptionIngredient = generator.modPow(randomSecret, PRIME_MODULUS);
  return decryptionIngredient;
};

export const encrypt = (generator, encryptionIngredient, plainText, randomSecret) => {
  const encryptionKey = encryptionIngredient.modPow(randomSecret, PRIME_MODULUS);
  const cipherText = plainText.times(encryptionKey).mod(PRIME_MODULUS);
  const decryptionIngredient = decryptionIngredientFrom(generator, randomSecret);

  return [cipherText, decryptionIngredient];
};

export const decrypt = (privateKey, decryptionIngredient, cipherText) => {
  const minusPrivateKey = PRIME_MODULUS.minus(privateKey).minus(1); /* -x */
  const decryptionKey = decryptionIngredient.modPow(minusPrivateKey, PRIME_MODULUS);
  const plainText = cipherText.times(decryptionKey).mod(PRIME_MODULUS);

  return plainText;
};
