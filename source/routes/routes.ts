// source/routes/routes.ts

import express from "express";
import CiphertextService from "./controllers/card-encryption";

const router = express.Router();

// Instance of CiphertextService
const ciphertextService = new CiphertextService();

router.post(
  "/card-encryption/:account_id/keys/:key_name/versions/:key_version",
  ciphertextService.generateEncryptedCard
);

export = router;
