/** source/routes/posts.ts */
import express from 'express';
import card from './controllers/card';

const router = express.Router();

router.post('/card/ciphertext/:account_id/keys/:key_name/versions/:key_version', card.generateEncryptedCard);

export = router;