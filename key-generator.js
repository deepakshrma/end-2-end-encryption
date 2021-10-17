import { promisify } from "util";
import { generateKeyPair } from "crypto";
const _keyGenerator = promisify(generateKeyPair);

let vault = {};
export const keyGenerator = async (key) => {
  if (typeof vault[key] === "undefined") {
    vault[key] = await _keyGenerator("rsa", { modulusLength: 512 });
  }
  return vault[key];
};
