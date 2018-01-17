#include <regex.h>
#include "netguard.h"
#include "string.h"
#include "picohttpparser.h"
#include "regex.h"

#define REGEX_IMEI "[0-9]{15,15}"
// Austria: https://de.wikipedia.org/wiki/International_Mobile_Subscriber_Identity#IMSI_in_%C3%96sterreich
#define REGEX_IMSI "232(0([1-3]|5|[7-9])|1[0-7]|91)[0-9]{9,10}"
// Austria: https://en.wikipedia.org/wiki/List_of_mobile_phone_number_series_by_country
#define REGEX_PHONE_NUMBER "((650|660|664|676|680)[0-9]{7,7})|((677|681|688|699)[0-9]{8,8})"
// https://www.regular-expressions.info/creditcard.html
#define REGEX_CREDIT_CARD "(4[0-9]{12}([0-9]{3})?|(5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}|3[47][0-9]{13}|3(0[0-5]|[68][0-9])[0-9]{11}|6(011|5[0-9]{2})[0-9]{12}|(2131|1800|35\\d{3})\\d{11})"

#define KEYWORD_IMEI "IMEI"
#define KEYWORD_IMSI "IMSI"
#define KEYWORD_PHONE_NUMBER "Phone Number"
#define KEYWORD_CREDIT_CARD "Credit Card"

void processData(const struct arguments *args, struct tcp_session *tcp, char *data);
bool validateIMEI(char* imei);
bool doLuhnAlgorithm(char* data, int len);
bool checkIMEIRegex(char *search, char *data);
bool checkCreditCardRegex(char *search, char *data);
bool checkRegex(char *search, char *data);
bool checkContains(char *search, char *data);

char *g_phone_imei = NULL;
char *g_phone_imsi = NULL;
char *g_phone_number = NULL;
bool security_analysis_enabled = false;

struct app_keywords *check_keywords = NULL;
int num_apps_keywords = 0;

void processTcpRequest(const struct arguments *args, struct tcp_session *tcp, const struct segment *segment)
{
    if (!(security_analysis_enabled && segment && segment->data && segment->len > 0)) return;

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

    // log_android(ANDROID_LOG_DEBUG, "ACN: Request - PRET = %d, SegmentLen = %d", pret, segment->len);
    // => one segment contains at most 1 request

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

            // cannot output data or sometimes stack smashing is detected ...
            // log_android(ANDROID_LOG_DEBUG, "ACN: Request - Data = \n%s", pdata->buf);

            // process data
            processData(args, tcp, (char *) pdata->buf);
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

    if (tcp != NULL && tcp->parser_data != NULL)
    {
        if (tcp->parser_data->buf) free(tcp->parser_data->buf);
        free(tcp->parser_data);
        tcp->parser_data = NULL;
    }
}

void checkAndProcessTLSHandshake(const struct arguments *args, struct tcp_session *tcp, const uint8_t *buffer, const size_t buf_len)
{
    // https://en.wikipedia.org/wiki/Transport_Layer_Security#Handshake_protocol
    // https://tools.ietf.org/html/rfc5246
    if (!(security_analysis_enabled && buffer && buf_len >= sizeof(tls_handshake_record))) return;

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

    uint8_t *handshake_data = buffer + sizeof(struct tls_handshake_record);
    uint8_t version_major = handshake_data[TLS_SERVERHELLO_VERSION_MAJOR];
    uint8_t version_minor = handshake_data[TLS_SERVERHELLO_VERSION_MINOR];
    uint8_t sessionid_len = handshake_data[TLS_SERVERHELLO_SESSIONID_LEN]; // after major + minor + 32byte random
    uint16_t cipher_suite = ntohs(*(uint16_t*)&handshake_data[TLS_SERVERHELLO_SESSIONID_LEN + 1 + sessionid_len]);
    uint8_t compression = handshake_data[TLS_SERVERHELLO_SESSIONID_LEN + 1 + sessionid_len + 2];

    log_android(ANDROID_LOG_DEBUG, "ACN: TLS Handshake - ServerHello - Major: %d, Minor: %d, CipherSuite: %04x, Compression: %d", version_major, version_minor, cipher_suite, compression);

    // create packet and log it
    jobject packet = create_acnpacket(args, tcp->version, partner, ntohs(tcp->dest), tcp->uid, 0, NULL, cipher_suite, (uint16_t)version_major << 8 | (uint16_t)version_minor, compression);
    log_connection(args, packet);
}

void processData(const struct arguments *args, struct tcp_session *tcp, char *data)
{
    char **keywords = NULL;
    int num_predefined = 0;
    int num_keywords = 0;

    // IMEI
    if (g_phone_imei != NULL)
    {
        bool sends_imei = false;
        if (g_phone_imei == REGEX_IMEI) // emulator or when IMEI could not be extracted
        {
            sends_imei = checkIMEIRegex(g_phone_imei, data);
        }
        else
        {
            sends_imei = checkContains(g_phone_imei, data);
        }

        log_android(ANDROID_LOG_DEBUG, "ACN: Contains IMEI (%s) = %d", g_phone_imei, sends_imei);

        // if imei found in packet -> set keyword
        if (sends_imei)
        {
            keywords = realloc(keywords, (num_predefined + 1) * sizeof(char*));
            keywords[num_predefined] = KEYWORD_IMEI;

            num_predefined++;
        }
    }

    // IMSI
    if (g_phone_imsi != NULL)
    {
        bool sends_imsi = false;
        if (g_phone_imsi == REGEX_IMSI) // emulator or when IMSI could not be extracted
        {
            sends_imsi = checkRegex(g_phone_imsi, data);
        }
        else
        {
            sends_imsi = checkContains(g_phone_imsi, data);
        }

        log_android(ANDROID_LOG_DEBUG, "ACN: Contains IMSI (%s) = %d", g_phone_imsi, sends_imsi);

        // if imei found in packet -> set keyword
        if (sends_imsi)
        {
            keywords = realloc(keywords, (num_predefined + 1) * sizeof(char*));
            keywords[num_predefined] = KEYWORD_IMSI;

            num_predefined++;
        }
    }

    // phone number
    if (g_phone_number != NULL)
    {
        bool sends_number = false;
        if (g_phone_number == REGEX_PHONE_NUMBER) // emulator or when number could not be extracted
        {
            sends_number = checkRegex(g_phone_number, data);
        }
        else
        {
            sends_number = checkContains(g_phone_number, data);
        }

        log_android(ANDROID_LOG_DEBUG, "ACN: Contains Phone Number (%s) = %d", g_phone_number, sends_number);

        // if number found in packet -> set keyword
        if (sends_number)
        {
            keywords = realloc(keywords, (num_predefined + 1) * sizeof(char*));
            keywords[num_predefined] = KEYWORD_PHONE_NUMBER;

            num_predefined++;
        }
    }

    // credit card
    bool sends_credit_card = checkCreditCardRegex(REGEX_CREDIT_CARD, data);

    log_android(ANDROID_LOG_DEBUG, "ACN: Contains Credit Card number = %d", sends_credit_card);

    // if number found in packet -> set keyword
    if (sends_credit_card)
    {
        keywords = realloc(keywords, (num_predefined + 1) * sizeof(char*));
        keywords[num_predefined] = KEYWORD_CREDIT_CARD;

        num_predefined++;
    }

    // keywords
    int app_index = -1;
    if (check_keywords != NULL)
    {
        int i = 0;
        for (i = 0; i < num_apps_keywords; ++i)
        {
            if (check_keywords[i].uid == tcp->uid) break;
        }
        if (i < num_apps_keywords) app_index = i;
    }

    if (app_index != -1) {
        struct app_keywords *app = &check_keywords[app_index];

        for (int i = 0; i < app->num_keywords; ++i)
        {
            bool sends_keyword = false;

            if (app->keywords[i].is_regex)
            {
                sends_keyword = checkRegex(app->keywords[i].keyword, data);
            }
            else
            {
                sends_keyword = checkContains(app->keywords[i].keyword, data);
            }

            log_android(ANDROID_LOG_DEBUG, "ACN: Contains keyword \"%s\" = %d", app->keywords[i].keyword, sends_keyword);

            if (sends_keyword)
            {
                int keyword_index = num_predefined + num_keywords;
                keywords = realloc(keywords, (keyword_index + 1) * sizeof(char *));

                keywords[keyword_index] = malloc((strlen(app->keywords[i].keyword) + 1) * sizeof(char));
                strcpy(keywords[keyword_index], app->keywords[i].keyword);

                num_keywords++;
            }
        }
    }


    // create packet and log it
    char dest[INET6_ADDRSTRLEN + 1];
    inet_ntop(tcp->version == 4 ? AF_INET : AF_INET6,
              tcp->version == 4 ? (const void *) &tcp->daddr.ip4 : (const void *) &tcp->daddr.ip6,
              dest, sizeof(dest));

    jobject packet = create_acnpacket(args, tcp->version, dest, ntohs(tcp->dest), tcp->uid, num_predefined + num_keywords, keywords, -1, 0, 0);
    log_connection(args, packet);


    // free everything
    if (num_keywords > 0 && keywords != NULL)
    {
        for (int i = 0; i < num_keywords; ++i) {
            free(keywords[num_predefined + i]);
        }
        free(keywords);
    }
}

bool checkContains(char *search, char *data)
{
    if (strstr(data, search) != NULL)
        return true;

    return false;
}

bool checkRegex(char *search, char *data)
{
    bool ret_val = false;

    regex_t regex;
    int reti;
    char msgbuf[100];

    // Compile regular expression
    reti = regcomp(&regex, search, REG_EXTENDED | REG_NEWLINE | REG_NOSUB);
    if (reti) {
        log_android(ANDROID_LOG_DEBUG, "ACN: Could not compile regex \"%s\"", search);
        return false;
    }

    // Execute regular expression
    reti = regexec(&regex, data, 0, NULL, 0);
    if (!reti) {
        // log_android(ANDROID_LOG_DEBUG, "ACN: Match");

        ret_val = true;
    }
    else if (reti == REG_NOMATCH)
    {
        // log_android(ANDROID_LOG_DEBUG, "ACN: No match");
    }
    else {
        regerror(reti, &regex, msgbuf, sizeof(msgbuf));
        log_android(ANDROID_LOG_DEBUG, "ACN: Regex match failed: %s", msgbuf);
    }

    // Free memory allocated to the pattern buffer by regcomp()
    regfree(&regex);

    return ret_val;
}

bool checkIMEIRegex(char *search, char *data)
{
    bool ret_val = false;

    regex_t regex;
    int reti;
    char msgbuf[100];
    regmatch_t pmatch[1];

    // Compile regular expression
    log_android(ANDROID_LOG_DEBUG, "ACN: IMEI Regex = %s", search);
    reti = regcomp(&regex, search, REG_EXTENDED | REG_NEWLINE);
    if (reti) {
        log_android(ANDROID_LOG_DEBUG, "ACN: Could not compile regex \"%s\"", search);
        return false;
    }

    // check every possible 15 digit number if it is a valid IMEI
    int offset = 0;
    while (!ret_val)
    {
        // get next regex match
        reti = regexec(&regex, data + offset, 1, pmatch, 0);
        if (!reti) // Match found
        {
            //log_android(ANDROID_LOG_DEBUG, "ACN: checkIMEIRegex: Match from %d to %d", offset + pmatch[0].rm_so, offset + pmatch[0].rm_eo);

            // check if found numbers are a valid IMEI
            offset = offset + pmatch[0].rm_so;
            ret_val = doLuhnAlgorithm(data + offset, pmatch[0].rm_eo - pmatch[0].rm_so);
            offset++; // start searching again 1 digit afterwards

            //log_android(ANDROID_LOG_DEBUG, "ACN: checkIMEIRegex: validIMEI = %d", ret_val);
        }
        else if (reti == REG_NOMATCH)
        {
            // log_android(ANDROID_LOG_DEBUG, "ACN: No match");

            break;
        }
        else // error
        {
            regerror(reti, &regex, msgbuf, sizeof(msgbuf));
            log_android(ANDROID_LOG_DEBUG, "ACN: IMEIRegex match failed: %s", msgbuf);
            break;
        }
    }

    // free memory allocated regcomp
    regfree(&regex);

    return ret_val;
}

bool checkCreditCardRegex(char *search, char *data)
{
    bool ret_val = false;

    regex_t regex;
    int reti;
    char msgbuf[100];
    regmatch_t pmatch[1];

    // Compile regular expression
    reti = regcomp(&regex, search, REG_EXTENDED | REG_NEWLINE);
    if (reti) {
        log_android(ANDROID_LOG_DEBUG, "ACN: Could not compile regex \"%s\"", search);
        return false;
    }

    // check every possible credit card number if it is valid (Luhn algorithm)
    int offset = 0;
    while (!ret_val)
    {
        // get next regex match
        reti = regexec(&regex, data + offset, 1, pmatch, 0);
        if (!reti) // Match found
        {
            // check if found numbers are a valid
            offset = offset + pmatch[0].rm_so;
            ret_val = doLuhnAlgorithm(data + offset, pmatch[0].rm_eo - pmatch[0].rm_so);
            offset++; // start searching again 1 digit afterwards
        }
        else if (reti == REG_NOMATCH)
        {
            // log_android(ANDROID_LOG_DEBUG, "ACN: No match");

            break;
        }
        else // error
        {
            regerror(reti, &regex, msgbuf, sizeof(msgbuf));
            log_android(ANDROID_LOG_DEBUG, "ACN: CreditCardRegex match failed: %s", msgbuf);
            break;
        }
    }

    // free memory allocated regcomp
    regfree(&regex);

    return ret_val;
}

bool doLuhnAlgorithm(char* data, int len)
{
    int validation_digit = data[len - 1] - '0';

    // log_android(ANDROID_LOG_DEBUG, "ACN: doLuhnAlgorithm - Validation digit = %d", validation_digit);

    int sum = 0;
    bool double_val = true;
    for (int i = len - 2; i >= 0; --i)
    {
        // log_android(ANDROID_LOG_DEBUG, "ACN: doLuhnAlgorithm - Digit = %d", data[i] - '0');
        if (double_val)
        {
            int doubled = 2 * (data[i] - '0');
            sum += (doubled >= 10) ? 1 + (doubled - 10) : doubled;
        }
        else
        {
            sum += (data[i] - '0');
        }

        double_val = !double_val;

        // log_android(ANDROID_LOG_DEBUG, "ACN: doLuhnAlgorithm - Sum = %d", sum);
    }

    if ((sum + validation_digit) % 10 == 0) return true;
    return false;
}

void JNI_enableSecurityAnalysis(JNIEnv *env, jobject instance, jboolean val)
{
    log_android(ANDROID_LOG_DEBUG, "ACN: JNI_enableSecurityAnalysis: %d", val);

    security_analysis_enabled = val;
}

void JNI_setIMEI(JNIEnv *env, jobject instance, jstring imei)
{
    const char *native_imei = (*env)->GetStringUTFChars(env, imei, 0);

    if (strlen(native_imei) > 0)
    {
        g_phone_imei = realloc(g_phone_imei, strlen(native_imei) + 1);
        strcpy(g_phone_imei, native_imei);
    }
    else
    {
        g_phone_imei = REGEX_IMEI;
    }

    log_android(ANDROID_LOG_DEBUG, "ACN: Set IMEI to %s", g_phone_imei);

    (*env)->ReleaseStringUTFChars(env, imei, native_imei);
}

void JNI_setIMSI(JNIEnv *env, jobject instance, jstring imsi)
{
    const char *native_imsi = (*env)->GetStringUTFChars(env, imsi, 0);

    if (strlen(native_imsi) > 0)
    {
        g_phone_imsi = realloc(g_phone_imsi, strlen(native_imsi) + 1);
        strcpy(g_phone_imsi, native_imsi);
    }
    else
    {
        g_phone_imsi = REGEX_IMSI;
    }

    log_android(ANDROID_LOG_DEBUG, "ACN: Set IMSI to %s", g_phone_imsi);

    (*env)->ReleaseStringUTFChars(env, imsi, native_imsi);
}

void JNI_setPhoneNumber(JNIEnv *env, jobject instance, jstring phone_number)
{
    const char *native_number = (*env)->GetStringUTFChars(env, phone_number, 0);

    if (strlen(native_number) > 0)
    {
        g_phone_number = realloc(g_phone_number, strlen(native_number) + 1);
        strcpy(g_phone_number, native_number);
    }
    else
    {
        g_phone_number = REGEX_PHONE_NUMBER;
    }

    log_android(ANDROID_LOG_DEBUG, "ACN: Set Phone Number to %s", g_phone_number);

    (*env)->ReleaseStringUTFChars(env, phone_number, native_number);
}

void JNI_updateKeywords(JNIEnv *env, jobject instance, jint uid, jobjectArray keywords, jintArray is_regex)
{
    int app_index = -1;

    // check if keywords for uid already exist
    if (check_keywords != NULL)
    {
        int i = 0;
        for (i = 0; i < num_apps_keywords; ++i)
        {
            if (check_keywords[i].uid == uid) break;
        }
        if (i < num_apps_keywords) app_index = i;
    }

    // if not -> resize and add
    if (app_index == -1)
    {
        num_apps_keywords++;
        check_keywords = realloc(check_keywords, num_apps_keywords * sizeof(struct app_keywords));

        app_index = num_apps_keywords - 1;
        check_keywords[app_index] = (struct app_keywords) {.uid = uid, .keywords = NULL, .num_keywords = 0};
    }

    struct app_keywords *app = &check_keywords[app_index];

    // free all previous keywords
    if (app->keywords != NULL)
    {
        for (int i = 0; i < app->num_keywords; ++i)
            free(app->keywords[i].keyword);

        free(app->keywords);
        app->keywords = NULL;
    }

    // add new keywords
    app->num_keywords = (*env)->GetArrayLength(env, keywords);
    log_android(ANDROID_LOG_DEBUG, "ACN: Adding %d keywords to app uid %d", app->num_keywords, uid);

    app->keywords = malloc(app->num_keywords * sizeof(struct app_keyword));
    jint *is_regex_array = (*env)->GetIntArrayElements(env, is_regex, NULL);
    for (int i = 0; i < app->num_keywords; ++i)
    {
        jstring keyword = (jstring) ((*env)->GetObjectArrayElement(env, keywords, i));
        const char *native_keyword = (*env)->GetStringUTFChars(env, keyword, 0);

        app->keywords[i].is_regex = (bool) is_regex_array[i];
        app->keywords[i].keyword = malloc((strlen(native_keyword) + 1) * sizeof(char));
        strcpy(app->keywords[i].keyword, native_keyword);

        (*env)->ReleaseStringUTFChars(env, keyword, native_keyword);

        log_android(ANDROID_LOG_DEBUG, "ACN: Added keyword \"%s\"%s to app uid %d", app->keywords[i].keyword, (app->keywords[i].is_regex ? " (REGEX)" : ""), uid);
    }
    (*env)->ReleaseIntArrayElements(env, is_regex, is_regex_array, NULL);
}
