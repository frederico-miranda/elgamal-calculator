/* 2048-bit safe prime "1942, 28th of September", 2^2048 - 1942289 */
import { PRIME_MODULUS } from './cryptography';

export const SUBGROUP_MODULUS = PRIME_MODULUS.minus(1);

export const verificationKeyFrom = (generator, signingKey) => {
  const verificationKey = generator.modPow(signingKey, PRIME_MODULUS);
  return verificationKey;
};

export const sign = (generator, message, signingKey, nonce) => {
  const witnessR = generator.modPow(nonce, PRIME_MODULUS);

  const XR = signingKey.times(witnessR).mod(SUBGROUP_MODULUS);
  const minusXR = SUBGROUP_MODULUS.minus(XR);
  const nonceInverse = nonce.modInv(SUBGROUP_MODULUS);
  const witnessS = message.plus(minusXR).times(nonceInverse).mod(SUBGROUP_MODULUS);

  return [witnessR, witnessS];
};

export const verify = (generator, message, verificationKey, witnessR, witnessS) => {
  const expectedSeal = generator.modPow(message, PRIME_MODULUS);
  const sealPartA = verificationKey.modPow(witnessR, PRIME_MODULUS);
  const sealPartB = witnessR.modPow(witnessS, PRIME_MODULUS);
  const givenSeal = sealPartA.times(sealPartB).mod(PRIME_MODULUS);

  return expectedSeal.equals(givenSeal);
};
