// Handle an incoming HTTP request. (Return a response).
void http_handle(char *raw)
{
    struct req request;
    char *data;

    request = get_request(raw);

    data = http_get_data(request);
    http_send_response(data);
{

// Send data to the client, as an HTTP 200 response.
void http_respond(data)
{
    // XXX data contains body + headers
    // XXX just need to do ksocket_send()
}

// Send a HTTP request to a remote server. Behaves like ruby equiv
http_response http_get(request, mod_date)
{
}

// Get the (possibly cached) data corresponding to the given tag.
data http_get_data(request)
{
    if (cache_contains(request)) { // the request has been cached previously
        if (mod_date = cache_get_mod_date(request)) { // the request is cached w/ a last modified date stored
            response = http_get(request, mod_date);
            if (response) {
                data = cache_write(request, response);
            } else {
                data = cache_read(request);
            }

        } else if (cache_is_expired(request)) {
            response = http_get(request);
            data = cache_write(request, response);
        } else {
            data = cache_read(request);
        }
    } else { // the request has never been cached
        response = http_get(request);
        data = cache_write(request, response);
    }

    return data;
}

// Update the cache with the given request/response combo (file-based?)
data cache_write(request, response)
{
    // XXX
    // XXX cache entries need: 1)data, 2)expiry date, 3) last modified datecache_update(request, response);
}

// Read from the cache. (File-based)
data cache_read(request)
{
    // XXX munge the request into index and read from cache
}

// Is the expiry past time.now?
boolean cache_is_expired(request)
{
    // XXX
}
