#include "netguard.h"
#include "string.h"
#include "picohttpparser.h"
#include "regex.h"
#include <sys/system_properties.h> // IMEI

#define REGEX_IMEI "[0-9]{15,15}"

void processData(char *search_regex, char *data);
void freeParserData(struct tcp_session *tcp);
char* getIMEI(bool* is_regex);
bool validateIMEI(char* imei);

void processTcpRequest(struct tcp_session *tcp, const struct segment *segment)
{
    if (!(segment && segment->data && segment->len > 0)) return;

    log_android(ANDROID_LOG_DEBUG, "ACN: Request - Segment Length: %d - TCPSession: 0x%04x", segment->len, tcp);

    // parse the request
    if(!tcp->parser_data)
    {
        log_android(ANDROID_LOG_DEBUG, "ACN: New Parser Data");

        tcp->parser_data = malloc(sizeof(struct http_parser_data));
        tcp->parser_data->buf = malloc(segment->len);
        memcpy(tcp->parser_data->buf, segment->data, segment->len);
        tcp->parser_data->buflen = 0;
    }
    else
    {
        log_android(ANDROID_LOG_DEBUG, "ACN: Reuse Parser Data");

        tcp->parser_data->buf = realloc(tcp->parser_data->buf, tcp->parser_data->buflen + segment->len);
        memcpy(tcp->parser_data->buf + tcp->parser_data->buflen, segment->data, segment->len);
    }

    struct http_parser_data *pdata = tcp->parser_data;
    pdata->num_headers = sizeof(pdata->headers) / sizeof(pdata->headers[0]);
    pdata->method = NULL;
    pdata->path = NULL;
    pdata->minor_version = 0;
    pdata->method_len = 0;
    pdata->path_len = 0;

    size_t prevbuflen = pdata->buflen;
    pdata->buflen = pdata->buflen + segment->len;
    int pret = phr_parse_request(pdata->buf, pdata->buflen, &pdata->method, &pdata->method_len, &pdata->path, &pdata->path_len,
                                    &pdata->minor_version, pdata->headers, &pdata->num_headers, prevbuflen);

    if (pret > 0)
    {
        if (pdata->buflen > 0) {
            log_android(ANDROID_LOG_DEBUG, "ACN: Request - SUCCESS");

            if (pdata->num_headers > 0)
                log_android(ANDROID_LOG_DEBUG, "ACN: Request - num_headers = %d", pdata->num_headers);
            if (pdata->method_len > 0)
                log_android(ANDROID_LOG_DEBUG, "ACN: Request - method_len = %d", pdata->method_len);
            if (pdata->path_len > 0)
                log_android(ANDROID_LOG_DEBUG, "ACN: Request - path_len = %d", pdata->path_len);

            // append '\0' at the end
            pdata->buf = realloc(pdata->buf, pdata->buflen + 1);
            pdata->buf[pdata->buflen] = '\0';
            log_android(ANDROID_LOG_DEBUG, "ACN: Request - Data = \n%s", pdata->buf);

            // process data
            processData(NULL, (char *) pdata->buf);
        }
    }
    else if (pret == 0)
    {
        log_android(ANDROID_LOG_DEBUG, "ACN: Request - Request is 0 bytes long");
    }
    else if (pret == -1)
    {
        log_android(ANDROID_LOG_DEBUG, "ACN: Request - Parse Error");
    }
    else if (pret == -2)
    {
        log_android(ANDROID_LOG_DEBUG, "ACN: Request - Not finished");
    }
    else
    {
        log_android(ANDROID_LOG_DEBUG, "ACN: Request - UNKNOWN");
    }

    // free data on success and on error
    if (pret != -2)
        freeParserData(tcp); // TODO´: also when tcp session is freed
}

void freeParserData(struct tcp_session *tcp)
{
    log_android(ANDROID_LOG_DEBUG, "ACN: Request - Free Data");

    if(tcp->parser_data->buf) free(tcp->parser_data->buf);
    free(tcp->parser_data);
    tcp->parser_data = NULL;
}

void checkAndProcessTLSHandshake(struct tcp_session *tcp, const uint8_t *buffer, const size_t buf_len)
{
    // https://en.wikipedia.org/wiki/Transport_Layer_Security#Handshake_protocol
    // https://tools.ietf.org/html/rfc5246
    if (!(buffer && buf_len >= sizeof(tls_handshake_record))) return;

    struct tls_handshake_record *tls = (struct tls_handshake_record*) buffer;
    if (tls->content_type != TLS_CONTENTTYPE_HANDSHAKE) return;

    char partner[INET6_ADDRSTRLEN + 1];
    inet_ntop(tcp->version == 4 ? AF_INET : AF_INET6,
              tcp->version == 4 ? (const void *) &tcp->daddr.ip4 : (const void *) &tcp->daddr.ip6,
              partner, sizeof(partner));
    log_android(ANDROID_LOG_DEBUG, "ACN: Response - Found TLS Handshake with %s - Packet Length: %d - TCPSession: 0x%04x", partner, buf_len, tcp);
    log_android(ANDROID_LOG_DEBUG, "ACN: TLS Handshake - MessageType = %d, "
                                   "TLSVersion = 0x%04x (Major = %d, Minor = %d), "
                                   "MessageLength = %d, "
                                   "DataLength = %d",
                                   tls->message_type,
                                   (uint16_t)tls->version_major << 8 | (uint16_t)tls->version_minor, tls->version_major, tls->version_major,
                                   ntohs(tls->length),
                                   ntohl((uint32_t)tls->data_length << 8));

    // for now assume that ServerHello data is not split into multiple TLSPlaintext records
    // also ServerHello should be the first packet the server sends back and is very short so no TCP
    // fragmentation should occur
    // TODO: on error buffer until complete but after multiple runs it is usually more data, not less
    if (tls->message_type != TLS_MESSAGETYPE_SERVERHELLO) return; // we only care about ServerHello

    uint32_t data_length = ntohl((uint32_t)tls->data_length << 8);
    if (buf_len < (sizeof(struct tls_handshake_record) + data_length))
    {
        log_android(ANDROID_LOG_DEBUG, "ACN: TLS Handshake - Only partial ServerHello found");
        return;
    }

    // TODO: save in tcp session and propagate to java log
    // TODO: in java: CipherSuite LookUp + secure or not
    uint8_t *handshake_data = buffer + sizeof(struct tls_handshake_record);
    uint8_t version_major = handshake_data[TLS_SERVERHELLO_VERSION_MAJOR];
    uint8_t version_minor = handshake_data[TLS_SERVERHELLO_VERSION_MINOR];
    uint8_t sessionid_len = handshake_data[TLS_SERVERHELLO_SESSIONID_LEN]; // after major + minor + 32byte random
    uint16_t cipher_suite = ntohs(*(uint16_t*)&handshake_data[TLS_SERVERHELLO_SESSIONID_LEN + 1 + sessionid_len]);

    log_android(ANDROID_LOG_DEBUG, "ACN: TLS Handshake - ServerHello - Major: %d, Minor: %d, CipherSuite: %04x", version_major, version_minor, cipher_suite);
}

void processData(char *search_regex, char *data)
{
    regex_t regex;
    int reti;
    char msgbuf[100];

    bool imei_regex;
    char* imei = getIMEI(&imei_regex);

    /* Compile regular expression */
    reti = regcomp(&regex, "test123", REG_NOSUB);
    if (reti) {
        log_android(ANDROID_LOG_DEBUG, "ACN: Could not compile regex");
        return;
    }

    /* Execute regular expression */
    reti = regexec(&regex, data, 0, NULL, 0);
    if (!reti) {
        log_android(ANDROID_LOG_DEBUG, "ACN: Match");
    }
    else if (reti == REG_NOMATCH) {
        log_android(ANDROID_LOG_DEBUG, "ACN: No match");
    }
    else {
        regerror(reti, &regex, msgbuf, sizeof(msgbuf));
        log_android(ANDROID_LOG_DEBUG, "ACN: Regex match failed: %s", msgbuf);
        return;
    }

    /* Free memory allocated to the pattern buffer by regcomp() */
    regfree(&regex);
}

char* getIMEI(bool* is_regex)
{
    static char* imei = NULL;

    if (imei == NULL) {
        char *imei_start = malloc(PROP_VALUE_MAX);

        //returns the string length of the value.
        int ir = __system_property_get("ro.gsm.imei", imei_start);

        if (ir > 0)
        {
            imei_start[15] = '\0';

            imei = realloc(imei, 16 * sizeof(char));
            strcpy(imei, imei_start);

            if (is_regex) is_regex = false;
        }
        else
        {
            imei = REGEX_IMEI;
            if (is_regex) is_regex = true;
        }

        free(imei_start);

        log_android(ANDROID_LOG_DEBUG, "ACN: IMEI = %s", imei);
    }

    return imei;
}

bool validateIMEI(char* imei)
{
    // https://en.wikipedia.org/wiki/International_Mobile_Equipment_Identity#Check_digit_computation
    int validation_digit = imei[14] - '0';
    log_android(ANDROID_LOG_DEBUG, "ACN: Validation Digit = %d", validation_digit);

    int sum = 0;
    for (int i = 0; i < 14; ++i)
    {
        if (i % 2 == 1)
        {
            int doubled = 2 * (imei[i] - '0');
            sum += (doubled >= 10) ? 1 + (doubled - 10) : doubled;
        }
        else
        {
            sum += (imei[i] - '0');
        }
    }

    if ((sum + validation_digit) % 10 == 0) return true;
    return false;
}