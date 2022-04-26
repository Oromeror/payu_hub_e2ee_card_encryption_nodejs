import { Request, Response, NextFunction } from 'express';
import axios, { AxiosResponse } from 'axios';

import { Card } from '../../interfaces/card';
import { Key } from '../../interfaces/key'

import * as jose from 'jose'

/*
 * Generates ciphertext with card data encrypted
 */

async function generateEncryptedCard(req: Request, res: Response, next: NextFunction) {

    //Body Params
    let card: Card = { credit_card_number: req.body.credit_card_number, cvv: req.body.cvv }

    /*
     * Retrieve a PaymentsOs Key by Version
     * docs: https://developers.paymentsos.com/docs/apis/management/1.1.0/#operation/retrieve-a-key-by-version
    */

    try {

        //Endpoint
        const url = `https://api.paymentsos.com/accounts/${req.params.account_id}/keys/${req.params.key_name}/versions/${req.params.key_version}`;

        //Config
        const config = {
            headers: {
                'api-version': req.header('api-version')!.toString(),
                'x-payments-os-env': req.header('x-payments-os-env')!.toString(),
                'Authorization': req.headers.authorization!.toString()
            }
        };

        //Request
        const result: AxiosResponse = await axios.get(url, config);

        if (result.status === 200) {
            const key: Key = result.data;
            
            const rsaPublicKey = await jose.importJWK({
                e: key.jwk.e,
                n: key.jwk.n,
                kty: key.jwk.kty,
                kid: key.jwk.kid,
                use: key.jwk.use,
                alg: 'RS256'
                })
            
            const TOKEN_TTL_MIN = 10; // Used to compute the expiration date that will be added to protected_headers 
            const CREDIT_CARD_DATA = JSON.stringify(card);
            const createdDate = new Date();  // Creating the date object so we can add it to protected_headers
            const expiredDate = new Date(createdDate);
           
            expiredDate.setMinutes(expiredDate.getMinutes() + TOKEN_TTL_MIN);

            const jwe = await new jose.GeneralEncrypt( new TextEncoder().encode(CREDIT_CARD_DATA))
                .setProtectedHeader({
                    jwk: key.jwk,
                    enc: key.protected_headers.enc,
                    kid: key.protected_headers.kid,
                    iat: createdDate.getTime(),
                    exp: expiredDate.getTime(),
                    alg: 'RSA-OAEP-384'
                })
                .addRecipient(rsaPublicKey)
                .encrypt()

            return res.status(200).json({
                ciphertext: jwe
            });

        } else {
            return res.json({
                message: result.data
            })
        }

    } catch (err) {
        next(err)
        res.status(400).json({
            message: err
        })
    }
}

export default { generateEncryptedCard };