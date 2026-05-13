#!/usr/bin/env node
import { startServer } from './server.js';

const config = {
  host: process.env.TANOD_HOST ?? '127.0.0.1',
  port: Number(process.env.TANOD_PORT ?? '8787'),
  policyFile: process.env.TANOD_POLICY_FILE ?? 'examples/policies/default.json',
  auditFile: process.env.TANOD_AUDIT_FILE ?? '.tanod/audit.jsonl',
  privateKeyFile: process.env.TANOD_PRIVATE_KEY_FILE ?? '.tanod/ed25519-private.pem',
  publicKeyFile: process.env.TANOD_PUBLIC_KEY_FILE ?? '.tanod/ed25519-public.pem',
};

await startServer(config);
