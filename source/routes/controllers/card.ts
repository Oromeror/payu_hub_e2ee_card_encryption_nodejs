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
    let card: Card = { credit_card_number: req.params.card_number, cvv: req.params.credit_card_cvv }

    /*
     * Retrieve a PaymentsOs Key by Version
     * docs: https://developers.paymentsos.com/docs/apis/management/1.1.0/#operation/retrieve-a-key-by-version
    */

    try {

        //Query Params
        let account_id: string = req.params.account_id;
        let key_name: string = req.params.key_name;
        let key_version: string = req.params.key_version;

        // Config
        const config = {
            headers: {
                'api-version': req.header('api-version')!.toString(),
                'x-payments-os-env': req.header('x-payments-os-env')!.toString(),
                'Authorization': req.headers.authorization!.toString()
            }
        };
        //Endpoint
        const url = `https://api.paymentsos.com/accounts/${account_id}/keys/${key_name}/versions/${key_version}`;

        //Request
        const result: AxiosResponse = await axios.get(url, config);
        
        if (result.status === 200) {
            
            let key: Key = result.data;
            const thumbprint = await jose.calculateJwkThumbprint(key.jwk)

            return res.status(200).json({
                ciphertext: thumbprint
            });
        } else {
            return res.json({
                message: result.data
            })
        }

    } catch (err) {
        console.error(err)
        res.status(400).json({
            message: err
        })
    }
}

export default { generateEncryptedCard };