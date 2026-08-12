#include <botan/gost_3410.h>
#include <botan/version.h>
#if BOTAN_VERSION_MAJOR >= 3
#include <botan/asn1_obj.h>
#else
#include <botan/oids.h>
#endif
int main()
{
        try {
                const std::string name("gost_256A");
#if BOTAN_VERSION_MAJOR >= 3
                const Botan::OID oid(Botan::OID::from_string(name));
                const Botan::EC_Group ecg(oid);
                const std::vector<uint8_t> der =
                    ecg.DER_encode(Botan::EC_Group_Encoding::NamedCurve);
#else
                const Botan::OID oid(Botan::OIDS::lookup(name));
                const Botan::EC_Group ecg(oid);
                const std::vector<Botan::byte> der =
                    ecg.DER_encode(Botan::EC_DOMPAR_ENC_OID);
#endif
        } catch(...) {
                return 1;
        }

        return 0;
}
