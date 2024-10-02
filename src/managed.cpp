

#include "managed.hpp"
#include <filesystem>


void test_unique()
{
    std::filesystem::path path("/workspaces/openssl-ecdsa/scripts/cms-out/signedtext.der");
    OpensslUniquePtr uniquebioptr = OpensslUniquePtr(BIO_new_file(path.c_str(), "r"));
    auto *cms = d2i_CMS_bio(uniquebioptr.get(), NULL);
    auto *si_stack = CMS_get0_SignerInfos(cms);
    auto *si = sk_CMS_SignerInfo_value(si_stack, 0);
    auto *sig = CMS_SignerInfo_get0_signature(si);
    std::cout << std::hex << sig->data;

}

void test_shared()
{
    std::filesystem::path path("/workspaces/openssl-ecdsa/scripts/cms-out/signedtext.der");
    OpensslSharedPtr sharedbioptr = OpensslSharedPtr(BIO_new_file(path.c_str(), "r"));
    auto *cms = d2i_CMS_bio(sharedbioptr.get(), NULL);
    auto *si_stack = CMS_get0_SignerInfos(cms);
    auto *si = sk_CMS_SignerInfo_value(si_stack, 0);
    auto *sig = CMS_SignerInfo_get0_signature(si);
    std::cout << std::hex << sig->data;
}

int main()
{
    test_unique();
    test_shared();
    return 0;
}