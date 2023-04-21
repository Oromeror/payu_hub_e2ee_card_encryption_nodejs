import { Request, Response, NextFunction } from "express";
import axios, { AxiosResponse } from "axios";
import { JWE, JSONWebKey } from "jose";

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
    const result: AxiosResponse = await axios.get(url, config);
    return result.data;
  }

  /*
   * Generates encrypted card using JOSE framework - PaymentsOs E2E Encryption
   * docs: https://developers.paymentsos.com/docs/security/e2ee.html
   */
  private encryptCardData(key: Key, card: Card): string {
    // Card data to encrypt
    const CREDIT_CARD_DATA = JSON.stringify(card);

    // Used to compute the expiration date that will be added to protected_headers
    const TOKEN_TTL_MIN = 10;

    // Creating the date object so we can add it to protected_headers
    const createdDate = new Date();
    const expiredDate = new Date(createdDate);

    // Creating the date object so we can add it to protected_headers
    expiredDate.setMinutes(expiredDate.getMinutes() + TOKEN_TTL_MIN);
    const date = {
      iat: createdDate.getTime(),
      exp: expiredDate.getTime(),
    };

    // Adding the iat and exp to the protected headers
    const protected_headers = Object.assign(key.protected_headers, date);

    // Jason web key
    const jwkKey = key.jwk as JSONWebKey;

    return JWE.encrypt(
      CREDIT_CARD_DATA, // clear text
      jwkKey, // key
      protected_headers // protected headers with iat and exp
    );
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
      const ciphertext = this.encryptCardData(jwkKey, {
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