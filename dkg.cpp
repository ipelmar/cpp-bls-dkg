#include <iostream>
#include "subnet/dkg.h"
#include <bls/bls384_256.h>
#include <vector>
#include <array>

void generateKeyVectors(int threshold, std::vector<blsPublicKey>& vvec, std::vector<blsSecretKey>& svec, bool zeroContribution = false) {
    if (zeroContribution) {
        std::array<uint8_t, 32> zero_array = {0};
        blsSecretKey zero_sk;
        blsSecretKeyDeserialize(&zero_sk, zero_array.data(), zero_array.size());
        svec.push_back(zero_sk);

        blsPublicKey zero_pk;
        blsGetPublicKey(&zero_pk, &zero_sk);
        vvec.push_back(zero_pk);
    }

    for (int i = (zeroContribution ? 1 : 0); i < threshold; i++) {
        blsSecretKey sk;
        blsSecretKeySetByCSPRNG(&sk);
        svec.push_back(sk);

        blsPublicKey pk;
        blsGetPublicKey(&pk, &sk);
        vvec.push_back(pk);
    }
}

GenerateContribution generateContribution(const std::vector<Member>& ids, int threshold) {
    std::vector<blsPublicKey> vvec;
    std::vector<blsSecretKey> skContribution;
    std::vector<blsSecretKey> svec;

    generateKeyVectors(threshold, vvec, svec);

    for (size_t i = 0; i < ids.size(); ++i) {
        blsSecretKey sk;
        blsSecretKeyShare(&sk, svec.data(), svec.size(), &ids[i].bls_id);
        skContribution.push_back(sk);
    }

    return { vvec, skContribution };
}

GenerateContribution generateZeroContribution(std::vector<Member>& ids, int threshold) {
    std::vector<blsPublicKey> vvec;
    std::vector<blsSecretKey> skContribution;
    std::vector<blsSecretKey> svec;

    generateKeyVectors(threshold, vvec, svec, true);

    for (size_t i = 0; i < ids.size(); i++) {
        blsSecretKey sk;
        blsSecretKeyShare(&sk, svec.data(), svec.size(), &ids[i].bls_id);
        skContribution.push_back(sk);
    }

    return { vvec, skContribution };
}

blsSecretKey addContributionShares(const std::vector<blsSecretKey>& secretKeyShares) {
    blsSecretKey sum = secretKeyShares.back();
    for (size_t i = 0; i < secretKeyShares.size()-1; i++) {
        blsSecretKeyAdd(&sum, &secretKeyShares[i]);
    }
    return sum;
}

bool verifyContributionShare(const blsId& id, const blsSecretKey& contribution, const std::vector<blsPublicKey>& vvec) {
    blsPublicKey pk1, pk2;
    blsPublicKeyShare(&pk1, vvec.data(), vvec.size(), &id);
    blsGetPublicKey(&pk2, &contribution);
    return blsPublicKeyIsEqual(&pk1, &pk2);
}

std::vector<blsPublicKey> addVerificationVectors(std::vector<std::vector<blsPublicKey>>& vvecs) {
    std::vector<blsPublicKey> groupsVvec;

    for (size_t i = 0; i < vvecs.size(); i++) {
        for (size_t j = 0; j < vvecs[i].size(); j++) {
            blsPublicKey pk2 = vvecs[i][j];

            if (j >= groupsVvec.size()) {
                groupsVvec.push_back(pk2);
            } else {
                blsPublicKey& pk1 = groupsVvec[j];
                blsPublicKeyAdd(&pk1, &pk2);
            }
        }
    }
    return groupsVvec;
}

