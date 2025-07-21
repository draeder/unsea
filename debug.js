#!/usr/bin/env node

import {
  generateRandomPair,
  signMessage,
  verifyMessage
} from './index.js';

async function debugTest() {
  console.log('🔍 Debug Test for Signing Issue');
  
  try {
    const keys = await generateRandomPair();
    console.log('Keys generated:', {
      pub: keys.pub.slice(0, 20) + '...',
      priv: keys.priv.slice(0, 20) + '...'
    });
    
    const message = 'Hello, test!';
    console.log('Message:', message);
    
    console.log('Calling signMessage...');
    const signature = await signMessage(message, keys.priv);
    console.log('Signature result:', signature);
    console.log('Signature type:', typeof signature);
    console.log('Signature length:', signature ? signature.length : 'null/undefined');
    
    if (signature) {
      console.log('Calling verifyMessage...');
      const isValid = await verifyMessage(message, signature, keys.pub);
      console.log('Verification result:', isValid);
    }
    
  } catch (error) {
    console.error('Error:', error);
  }
}

debugTest();
