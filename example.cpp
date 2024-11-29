#include <iostream>
#include <vector>
#include <array>
#include <cstring>
#include "dkg.h"

#define N 5
#define K 3

int main() {
    blsInit(MCL_BLS12_381, MCLBN_COMPILED_TIME_VAR);

    std::vector<uint32_t> members_ids = {1, 2, 3, 4, 5};
    std::vector<Member> members;
    members.reserve(N);

    for (size_t i = 0; i < N; i++) {
        Member new_member;
        blsSecretKey sk;
        blsHashToSecretKey(&sk, &members_ids[i], sizeof(uint32_t));

        blsId bls_id;
        std::memcpy(&bls_id, &sk, 32);
        new_member.bls_id = bls_id;

        members.push_back(std::move(new_member));
    }

    std::vector<std::vector<blsPublicKey>> vvecs;
    std::vector<std::vector<blsSecretKey>> skContributions;
    vvecs.reserve(N);
    skContributions.reserve(N);

    for (const auto& member : members) {
        auto cont = generateContribution(members, K);
        skContributions.push_back(cont.skContribution);
        vvecs.push_back(cont.vvec);
    }

    for (size_t i = 0; i < N; i++) {
        for (size_t j = 0; j < N; j++) {
            if (!verifyContributionShare(members[i].bls_id, skContributions[j][i], vvecs[j])) {
                std::cout << "Something isn't right with the contribution shares\n";
            }
        }
    }

    std::vector<blsSecretKey> groupsSks;
    groupsSks.reserve(N);

    for (size_t i = 0; i < N; i++) {
        std::vector<blsSecretKey> shares;
        shares.reserve(N);

        for (size_t j = 0; j < N; j++) {
            shares.push_back(skContributions[j][i]);
        }

        blsSecretKey group_sk = addContributionShares(shares);
        groupsSks.push_back(group_sk);
    }

    std::array<blsSignature, N> sigArr;
    std::string msg = "This is a test message.";
    const size_t msgSize = msg.length();

    for (int i = 0; i < N; i++) {
        blsSign(&sigArr[i], &groupsSks[i], msg.data(), msgSize);
    }

    std::vector<blsId> idVec;
    idVec.reserve(N);

    for (const auto& member : members) {
        idVec.push_back(member.bls_id);
    }

    blsSignature recoveredSig;
    if (blsSignatureRecover(&recoveredSig, sigArr.data(), idVec.data(), K) != 0) {
        std::cout << "Failed to recover signature\n";
        return -1;
    }

    std::vector<blsPublicKey> groupsVvec = addVerificationVectors(vvecs);

    blsPublicKey mpk;
    std::vector<blsPublicKey> pubVec(N);
    for (int i = 0; i < N; i++) {
        blsGetPublicKey(&pubVec[i], &groupsSks[i]);

        blsPublicKey recoveredPk;
        blsPublicKeyShare(&recoveredPk, groupsVvec.data(), groupsVvec.size(), &idVec[i]);

        if (!blsPublicKeyIsEqual(&recoveredPk, &pubVec[i])) {
            std::cout << "recovered public key not equal to public key derived from secret key\n";
        }
    }

    blsPublicKeyRecover(&mpk, pubVec.data(), idVec.data(), N);

    unsigned char buf[96];
    mclSize bufSize = sizeof(buf);
    mclSize serializedSize = blsSignatureSerialize(buf, bufSize, &recoveredSig);

    std::cout << "Recovered master public key: ";
    for (size_t i = 0; i < serializedSize; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");

    if (blsVerify(&recoveredSig, &mpk, msg.data(), msgSize)) {
        std::cout << "The recovered signature is valid using the recovered public key\n";
    } else {
        std::cout << "The recovered signature is invalid using the recovered public key\n";
    }

    return 0;
}
