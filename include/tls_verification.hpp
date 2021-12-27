#pragma once
#include <string>

#include <websocketpp/config/asio_client.hpp>

class TlsVerification

{
public:
        bool verify_subject_alternative_name(const char * hostname, X509 * cert)
        {
            STACK_OF(GENERAL_NAME) * san_names = NULL;

            san_names = (STACK_OF(GENERAL_NAME) *) X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
            if (san_names == NULL)
            {
                return false;
            }

            int san_names_count = sk_GENERAL_NAME_num(san_names);

            bool result = false;

            for (int i = 0; i < san_names_count; i++)
            {
                const GENERAL_NAME * current_name = sk_GENERAL_NAME_value(san_names, i);

                if (current_name->type != GEN_DNS)
                {
                    continue;
                }

                char const * dns_name = (char const *) ASN1_STRING_get0_data(current_name->d.dNSName);

                int current_dns_len = ASN1_STRING_length(current_name->d.dNSName);

                if (current_dns_len < 0 || static_cast<size_t>(current_dns_len) != strlen(dns_name))
                {
                    break;
                }
                result = (strcasecmp(hostname, dns_name) == 0);
            }
            sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);

            return result;
        }

        bool verify_common_name(char const * hostname, X509 * cert)
        {
            int common_name_loc = X509_NAME_get_index_by_NID(X509_get_subject_name(cert), NID_commonName, -1);
            if (common_name_loc < 0)
            {
                return false;
            }

            X509_NAME_ENTRY * common_name_entry = X509_NAME_get_entry(X509_get_subject_name(cert), common_name_loc);
            if (common_name_entry == NULL)
            {
                return false;
            }

            ASN1_STRING * common_name_asn1 = X509_NAME_ENTRY_get_data(common_name_entry);
            if (common_name_asn1 == NULL)
            {
                return false;
            }

            char const * common_name_str = (char const *) ASN1_STRING_get0_data(common_name_asn1);

            int current_name_len = ASN1_STRING_length(common_name_asn1);

            if (current_name_len < 0 || static_cast<size_t>(current_name_len) != strlen(common_name_str))
            {
                return false;
            }

            return (strcasecmp(hostname, common_name_str) == 0);
        }

        bool verify_certificate(const char * hostname, bool preverified, boost::asio::ssl::verify_context& ctx)
        {
            int depth = X509_STORE_CTX_get_error_depth(ctx.native_handle());

            if (depth == 0 && preverified)
            {
                X509* cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());

                if (verify_subject_alternative_name(hostname, cert))
                {
                    return true;
                } else if (verify_common_name(hostname, cert))
                {
                    return true;
                } else
                {
                    return false;
                }
            }

            return preverified;
        }
};

