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
            
            console.log(key);
            //const JWK_KEY = key;

            const JWK_KEY = {
                "jwk": {
                    e: key.jwk.e,
                    n: key.jwk.n,
                    kty: key.jwk.kty,
                    kid: key.jwk.kid,
                    use: key.jwk.use,
                },
                "created": key.created,
                "version": key.version,
                "key_type": key.key_type,
                "name": key.name,
                "protected_headers": {
                    "kid": key.protected_headers.kid,
                    "enc": key.protected_headers.enc
                }
            };

            const TOKEN_TTL_MIN = 10; // Used to compute the expiration date that will be added to protected_headers
            const CREDIT_CARD_DATA = JSON.stringify(card);
            const createdDate = new Date();  // Creating the date object so we can add it to protected_headers
            const expiredDate = new Date(createdDate);

            // Creating the date object so we can add it to protected_headers
            expiredDate.setMinutes(expiredDate.getMinutes() + TOKEN_TTL_MIN);
            const date = {
                iat: createdDate.getTime(),
                exp: expiredDate.getTime(),
            };

            // Encrypting the card data. Making sure to add in the date object as well. 
            const ciphertext = jose.JWE.encrypt(CREDIT_CARD_DATA, JWK_KEY.jwk.n, Object.assign(JWK_KEY.protected_headers, date));

            return res.status(200).json({
                ciphertext: ciphertext
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