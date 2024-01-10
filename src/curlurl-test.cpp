#include <vector>
#include <string>
#include <iostream>

#include "curl/curl.h"

int main(int argc, char *argv[])
{
    std::vector<std::string> urls{
        "http://www.yahoo.com",
        "http://www.yahoo.com/",
        "https://www.yahoo.com",
        "https://www.yahoo.com/",
        "www.yahoo.com",
        "www.yahoo.com/",
        "127.0.0.1:8080",
        "http://127.0.0.1:8080",
        "https://127.0.0.1:8080",
        "htp://malformed",
        "//malformed",
        "malformed"
    };

    for (std::string url : urls)
    {
        CURLU *curlh = curl_url();

        if (CURLUcode retval = curl_url_set(curlh, CURLUPART_URL, url.c_str(), CURLU_GUESS_SCHEME); CURLUE_OK != retval)
        {
            std::cout << "rejected: " << url << std::endl;
            continue;
        }

        char *scheme,
            *hostname,
            *port,
            *path;

        if (CURLUcode retval = curl_url_get(curlh, CURLUPART_SCHEME, &scheme, 0); CURLUE_OK == retval)
        {
            std::cout << "scheme: " << scheme << std::endl;
            curl_free(scheme);
        }
        if (CURLUcode retval = curl_url_get(curlh, CURLUPART_HOST, &hostname, 0); CURLUE_OK == retval)
        {
            std::cout << "hostname: " << hostname << std::endl;
            curl_free(hostname);
        }
        if (CURLUcode retval = curl_url_get(curlh, CURLUPART_PORT, &port, CURLU_DEFAULT_PORT); CURLUE_OK == retval)
        {
            std::cout << "port: " << port << std::endl;
            curl_free(port);
        }
        if (CURLUcode retval = curl_url_get(curlh, CURLUPART_PATH, &path, 0); CURLUE_OK == retval)
        {
            std::cout << "path: " << path << std::endl;
            curl_free(path);
        }
    }

    return 0;
}
