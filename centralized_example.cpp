#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <bls/bls384_256.h>
#include <bls/bls.h>
#include <iostream>

int main() {
    if (blsInit(MCL_BLS12_381, MCLBN_COMPILED_TIME_VAR) != 0) {
        printf("Failed to initialize BLS\n");
        return -1;
    }

    const int N = 5;
    const int K = 3;

    blsSecretKey msk[K];
    blsSecretKey secVec[N];
    blsPublicKey pubVec[N];
    blsSignature sigVec[N];
    blsId idVec[N];

    for (int i = 0; i < K; i++) {
        blsSecretKeySetByCSPRNG(&msk[i]);
    }

    for (int i = 0; i < N; i++) {
        blsIdSetInt(&idVec[i], i + 1);
    }

    for (int i = 0; i < N; i++) {
        blsSecretKeyShare(&secVec[i], msk, K, &idVec[i]);
    }

    blsPublicKey mpk;

    for (int i = 0; i < N; i++) {
        blsGetPublicKey(&pubVec[i], &secVec[i]);
    }

    blsPublicKeyRecover(&mpk, pubVec, idVec, N);

    unsigned char buf[96];
    mclSize bufSize = sizeof(buf);
    mclSize serializedSize = blsPublicKeySerialize(buf, bufSize, &mpk);

    if (serializedSize == 0) {
        printf("Failed to serialize the master public key.\n");
        return -1;
    } else {
        printf("Serialized master public key size: %zu bytes\n", serializedSize);
        std::cout << "Master Public Key: ";
        for (size_t i = 0; i < serializedSize; i++) {
            printf("%02x", buf[i]);
        }
        printf("\n");
    }

    const char* msg = "Beauty in things exists in the mind which contemplates them";
    const size_t msgSize = strlen(msg);

    for (int i = 0; i < N; i++) {
        blsSign(&sigVec[i], &secVec[i], msg, msgSize);
    }

    blsSignature aggSig;
    blsAggregateSignature(&aggSig, sigVec, N);

    blsSignature recoveredSig;
    if (blsSignatureRecover(&recoveredSig, sigVec, idVec, K) != 0) {
        printf("Failed to recover signature\n");
        return -1;
    }

    
    int isValidGroupAggSig = blsVerify(&aggSig, &mpk, msg, msgSize); 
    int isValidRecoveredSig = blsVerify(&recoveredSig, &mpk, msg, msgSize);

    if (isValidGroupAggSig) {
        printf("The aggregated signature is valid using the master public key!\n");
    } else {
        printf("The aggregated signature is invalid using the master public key.\n");
    }

    if (isValidRecoveredSig) {
        printf("The recovered signature is valid using the master public key!\n");
    } else {
        printf("The recovered signature is invalid using the master public key.\n");
    }

    return 0;
}