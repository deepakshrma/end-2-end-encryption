import assert from "assert";
import {
  privateDecrypt,
  publicEncrypt,
  createSign,
  createVerify,
  generateKeyPairSync,
} from "crypto";
import { readFile } from "fs/promises";
import path from "path";
import { keyGenerator } from "./key-generator.js";
const __dirname = path.resolve(path.dirname(""));

describe("E2E Encryption", () => {
  let user1, user2, user3, message;
  let message1, message2;
  before(async () => {
    user1 = await keyGenerator("user1");
    user2 = await keyGenerator("user2");
    user3 = await keyGenerator("user3");
    message = await readFile(__dirname + "/message.txt");
  });
  it("user1 encrypt message to generate chipher", () => {
    message1 = {
      chipher: publicEncrypt(user2.publicKey, message),
    };
  });
  it("user1 sign message to generate signatute", () => {
    const sign = createSign("SHA256");
    sign.write(message1.chipher);
    sign.end();
    message1.signatute = sign.sign(user1.privateKey, "hex");
  });
  it("user2 validate message signatute", () => {
    const verify = createVerify("SHA256");
    verify.write(message1.chipher);
    verify.end();

    assert.equal(
      verify.verify(user1.publicKey, message1.signatute, "hex"),
      true,
      "Message has been compromised."
    );
  });
  it("user2 decrypt message to generate message", () => {
    message2 = {
      message: privateDecrypt(user2.privateKey, message1.chipher),
    };
    assert.equal(
      message2.message.toString("utf-8"),
      message.toString("utf-8"),
      "message should be equal"
    );
  });

  it("user3 modify the message1, without modifiying signature", () => {
    message1.chipher = publicEncrypt(
      user2.publicKey,
      Buffer.from("Some other message!!!")
    );
  });
  it("user2 validate message signatute, should test for compromised.", () => {
    const verify = createVerify("SHA256");
    verify.write(message1.chipher);
    verify.end();

    assert.notEqual(
      verify.verify(user1.publicKey, message1.signatute, "hex"),
      true,
      "Message has been compromised."
    );
  });
});
