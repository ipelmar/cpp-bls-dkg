#ifndef DKG_CPP
#define DKG_CPP

#include <bls/bls384_256.h>
#include <vector>


struct Member {
    blsSecretKey id;
    blsId bls_id;
    std::vector<blsSecretKey> recevied_shares;
};

struct GenerateContribution {
    std::vector<blsPublicKey> vvec;
    std::vector<blsSecretKey> skContribution;
};

GenerateContribution generateContribution(const std::vector<Member>& ids, int threshold);
GenerateContribution generateZeroContribution(std::vector<Member>& ids, int threshold);
blsSecretKey addContributionShares(const std::vector<blsSecretKey>& secret_key_shares);
bool verifyContributionShare(const blsId& id, const blsSecretKey& contribution, const std::vector<blsPublicKey>& vvec);
std::vector<blsPublicKey> addVerificationVectors(std::vector<std::vector<blsPublicKey>>& vvecs);

#endif