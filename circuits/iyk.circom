pragma circom 2.0.2;

include "ecdsa.circom";

/**
    Goals of the entire protocol
    --------------------
    - Verify nonce was not used
    - Don't allow MEV searcher to claim the reward
        - Signature from dummy signer must be in a "hidden envelope"
*/

/**
    ZL Setup
    --------
    - inputs
        - nonce (public)
        - chip signature (private)
        - chip public key (public)
        - recipient public key (public)

    - logic
        1) verify the signature of the nonce is from the chip
           public key
        2) constrain pubkey with a dummy square
*/
template IYKPrivateNFTClaim(n, k) {
    // chip private data
    signal input nonce[k];
    signal input chipPubkey[2][k];
    signal input chipR[k];
    signal input chipS[k];

    // recipient data
    signal input recipientPubkey[2][k];

    // 1) verify the signature of the nonce is from the chip public key
    component ECDSAVerify = ECDSAVerifyNoPubkeyCheck(n, k);
    for (var idx = 0; idx < k; idx++) {
        ECDSAVerify.msghash[idx] = nonce[idx];
        ECDSAVerify.pubkey[0][idx] = chipPubkey[0][idx];
        ECDSAVerify.pubkey[1][idx] = chipPubkey[1][idx];
        ECDSAVerify.r[idx] = chipR[idx];
        ECDSAVerify.s[idx] = chipS[idx];
    }
    ECDSAVerify.result === 1;
    
    // 2) constrain pubkey with a dummy square
    signal pubkeySquared[2][k];
    for (var idx = 0; idx < k; idx++) {
        pubkeySquared[0][idx] = chipPubkey[0][idx] * chipPubkey[0][idx];
        pubkeySquared[1][idx] = chipPubkey[1][idx] * chipPubkey[1][idx];
    }
}

// here is where we actually define which inputs are public
component main {
    public [
        nonce,
        chipPubkey,
        recipientPubkey
    ]
} = IYKPrivateNFTClaim(64, 4);