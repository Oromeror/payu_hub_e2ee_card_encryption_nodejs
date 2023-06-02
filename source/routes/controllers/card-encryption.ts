import { Request, Response, NextFunction } from "express";
import axios, { AxiosResponse } from "axios";
import * as jose from "jose";

import { Card } from "../../interfaces/card";
import { Key } from "../../interfaces/key";

class CiphertextService {
  constructor() {
    this.generateEncryptedCard = this.generateEncryptedCard.bind(this);
  }
  /*
   * Retrieve a PaymentsOs session token
   * docs: https://developers.paymentsos.com/docs/apis/management/1.1.0/#tag/Sessions
   */
  private async getSessionToken(): Promise<string> {
    const url = "https://api.paymentsos.com/sessions";
    const body = {
      email: "", // PaymentsOs Admin Email
      password: "", // PaymentsOs Admin Password
    };
    const sessionResult: AxiosResponse = await axios.post(url, body);
    return sessionResult.data.session_token;
  }

  /*
   * Retrieve a PaymentsOs Key by Version
   * docs: https://developers.paymentsos.com/docs/apis/management/1.1.0/#operation/retrieve-a-key-by-version
   */
  private async retrieveKey(req: Request, sessionToken: string): Promise<Key> {
    const url = `https://api.paymentsos.com/accounts/${req.params.account_id}/keys/${req.params.key_name}/versions/${req.params.key_version}`;
    const config = {
      headers: {
        "api-version": req.header("api-version")!.toString(),
        "x-payments-os-env": req.header("x-payments-os-env")!.toString(),
        Authorization: `Bearer ${sessionToken}`,
      },
    };
    try {
      const result: AxiosResponse = await axios.get(url, config);
      return result.data;
    } catch (error) {
      console.error("Request error:", error);
      throw error;
    }
  }

  /*
   * Generates encrypted card using JOSE framework - PaymentsOs E2E Encryption
   * docs: https://developers.paymentsos.com/docs/security/e2ee.html
   */
  private async encryptCardData(key: Key, card: Card): Promise<string> {
    const TOKEN_TTL_MIN = 10; // Used to compute the expiration date that will be added to protected_headers
    const CREDIT_CARD_DATA = JSON.stringify(card); // Card data to encrypt
    const JWK_KEY = key; // Encryption key used to generate card encripted

    // Creating the date object so we can add it to protected_headers
    const createdDate = new Date();
    const expiredDate = new Date(createdDate);
    expiredDate.setMinutes(expiredDate.getMinutes() + TOKEN_TTL_MIN);
    const iat = createdDate.getTime();
    const exp = expiredDate.getTime();

    // Encrypting the card data
    const rsaPublicKey = await jose.importJWK(JWK_KEY.jwk);
    const jwe = await new jose.CompactEncrypt(new TextEncoder().encode(CREDIT_CARD_DATA))
      .setProtectedHeader({
        alg: "RSA-OAEP-256",
        enc: JWK_KEY.protected_headers.enc,
        kid: JWK_KEY.protected_headers.kid,
        iat,
        exp,
      })
      .encrypt(rsaPublicKey);
    return jwe;
  }

  /*
   * Returns the ciphertext generated with the private function encryptCardData()
   * to be used in the Charge or the Authorization creation
   */
  public async generateEncryptedCard(
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> {
    try {
      const sessionToken = await this.getSessionToken();
      const jwkKey: Key = await this.retrieveKey(req, sessionToken);
      const ciphertext = await this.encryptCardData(jwkKey, {
        credit_card_number: req.body.credit_card_number,
        cvv: req.body.cvv,
      });
      res.status(200).json({ ciphertext });
    } catch (err) {
      next(err);
      res.status(400).json({ message: err });
    }
  }
}

export default CiphertextService;
