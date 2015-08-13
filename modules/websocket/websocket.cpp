
#include <stdlib.h>
#include <time.h>
#include <string>

#include "core/typedefs.h"
#include "core/io/base64.h"
#include "io/stream_peer_ssl.h"

#include "websocket.h"
#include "websocket_sha1.h"

#define WS_VERSION 13



void Websocket::_bind_methods()
{
    ObjectTypeDB::bind_method(_MD("create_connection:Error","url","use_mask","sub_protocol","origin"),&Websocket::create_connection,DEFVAL(true),DEFVAL(String()),DEFVAL(String()));
    ObjectTypeDB::bind_method(_MD("poll:Error"),&Websocket::poll);
    ObjectTypeDB::bind_method(_MD("send_text:Error","message"),&Websocket::send_text);
    ObjectTypeDB::bind_method(_MD("send_binary:Error","message"),&Websocket::send_binary);
    ObjectTypeDB::bind_method(_MD("send_ping:Error"),&Websocket::send_ping);
    ObjectTypeDB::bind_method(_MD("is_connected:bool"),&Websocket::is_connected);
    ObjectTypeDB::bind_method(_MD("is_secure:bool"),&Websocket::is_secure);
    ObjectTypeDB::bind_method(_MD("set_blocking","block"),&Websocket::set_blocking);
    ObjectTypeDB::bind_method(_MD("is_blocking:bool"),&Websocket::is_blocking);
    ObjectTypeDB::bind_method(_MD("set_verify_host","verify"),&Websocket::set_verif_host);
    ObjectTypeDB::bind_method(_MD("get_verify_host:bool"),&Websocket::get_verify_host);
    ObjectTypeDB::bind_method(_MD("set_validate_cert","validate"),&Websocket::set_validate_cert);
    ObjectTypeDB::bind_method(_MD("get_validate_cert:bool"),&Websocket::get_validate_cert);
    ObjectTypeDB::bind_method(_MD("get_status"),&Websocket::get_status);
    ObjectTypeDB::bind_method(_MD("close"),&Websocket::close);


    BIND_CONSTANT( STATUS_DISCONNECTED );
    BIND_CONSTANT( STATUS_RESOLVING );  //resolving hostname (if passed a hostname)
    BIND_CONSTANT( STATUS_CANT_RESOLVE );
    BIND_CONSTANT( STATUS_CONNECTING );  //connecting to ip
    BIND_CONSTANT( STATUS_CANT_CONNECT );
    BIND_CONSTANT( STATUS_UPDATE_PROTOCOL_SEND );
    BIND_CONSTANT( STATUS_UPDATE_PROTOCOL_RECV );
    BIND_CONSTANT( STATUS_BODY );  // request resulted in body );  which must be read
    BIND_CONSTANT( STATUS_SSL_HANDSHAKE_ERROR );
    BIND_CONSTANT( STATUS_CONNECTED );  //connected );  requests only accepted here
    BIND_CONSTANT( STATUS_CANT_UPGRADE );
    BIND_CONSTANT( STATUS_CLOSING );
    BIND_CONSTANT( STATUS_CONNECTION_ERROR );

    ADD_SIGNAL(MethodInfo("body_received", PropertyInfo(Variant::RAW_ARRAY, "body")));
    ADD_SIGNAL(MethodInfo("message_received", PropertyInfo(Variant::STRING, "message")));
    ADD_SIGNAL(MethodInfo("binary_received", PropertyInfo(Variant::RAW_ARRAY, "message")));
}

Websocket::Websocket()
{
    m_use_mask = false;
    m_verify_host = false;
    m_validate_cert = false;
    m_port = 80;
    m_secure = false;
    m_blocking = false;
    m_status = STATUS_DISCONNECTED;
    m_resp_code = 0;
    m_chunked = false;
    m_chunk_size = 4096;
    m_chunk_left = 0;
    m_body_size = 0;
    m_body_left = 0;
    m_tcp_conn = StreamPeerTCP::create_ref();
    m_resolving = IP::RESOLVER_INVALID_ID;
}

Websocket::~Websocket()
{

}


Error Websocket::create_connection(const String& url, bool use_mask, const String& subprotcol, const String& origin)
{
    close();
    if(_parse_url(url) != OK) {
        return ERR_INVALID_PARAMETER;
    }

    m_use_mask = use_mask;
    m_subprotocol = subprotcol;
    m_origin = origin;
    m_conn = m_tcp_conn;

    if(m_host.is_valid_ip_address()) {
        Error err = m_tcp_conn->connect(IP_Address(m_host),m_port);
        if(err) {
            m_status = STATUS_CANT_CONNECT;
            return err;
        }

        m_status = STATUS_CONNECTING;
    } else {
        m_resolving = IP::get_singleton()->resolve_hostname_queue_item(m_host);
        m_status = STATUS_RESOLVING;
    }

    return OK;
}

Error Websocket::poll()
{
    switch(m_status) {
        case STATUS_RESOLVING: {
            ERR_FAIL_COND_V(m_resolving == IP::RESOLVER_INVALID_ID, ERR_BUG);

            IP::ResolverStatus rstatus = IP::get_singleton()->get_resolve_item_status(m_resolving);
            switch(rstatus) {
                case IP::RESOLVER_STATUS_WAITING: {
                    return OK;
                }
                case IP::RESOLVER_STATUS_DONE: {
                    IP_Address host = IP::get_singleton()->get_resolve_item_address(m_resolving);
                    Error err = m_tcp_conn->connect(host,m_port);
                    IP::get_singleton()->erase_resolve_item(m_resolving);
                    m_resolving = IP::RESOLVER_INVALID_ID;
                    if(err) {
                        m_status = STATUS_CANT_CONNECT;
                        return err;
                    }
                    m_status = STATUS_CONNECTING;
                    return OK;
                }
                case IP::RESOLVER_STATUS_NONE:
                case IP::RESOLVER_STATUS_ERROR: {
                    IP::get_singleton()->erase_resolve_item(m_resolving);
                    m_resolving=IP::RESOLVER_INVALID_ID;
                    close();
                    m_status=STATUS_CANT_RESOLVE;
                    return ERR_CANT_RESOLVE;
                }
            }

            return OK;
        }

        case STATUS_CONNECTING: {
            StreamPeerTCP::Status conn_status = m_tcp_conn->get_status();

            switch(conn_status) {
                case StreamPeerTCP::STATUS_CONNECTING:
                    return OK;
                case StreamPeerTCP::STATUS_CONNECTED: {
                    if (m_secure) {
                        Ref<StreamPeerSSL> ssl = StreamPeerSSL::create();
                        Error err = ssl->connect(m_tcp_conn, m_validate_cert, m_verify_host ? m_host : String());
                        if(err != OK) {
                            close();
                            m_status = STATUS_SSL_HANDSHAKE_ERROR;
                            return ERR_CANT_CONNECT;
                        }
                        print_line("SSL! TURNED ON!");
                        m_conn=ssl;
                    }
                    m_status=STATUS_UPDATE_PROTOCOL_SEND;
                    return OK;
                }
                case StreamPeerTCP::STATUS_ERROR:
                case StreamPeerTCP::STATUS_NONE: {
                    close();
                    m_status=STATUS_CANT_CONNECT;
                    return ERR_CANT_CONNECT;
                }
            }

            return OK;
        }

        case STATUS_UPDATE_PROTOCOL_SEND: {
            String request = String("GET " + m_path + " HTTP/1.1\r\n");
            request += "Host: " + m_host;
            if ((!m_secure && m_port != 80) || (m_secure && m_port != 443)) {
                request += ":" + itos(m_port) + "\r\n";
            } else {
                request += "\r\n";
            }
            request += "Upgrade: websocket\r\n";
            request += "Connection: Upgrade\r\n";
            request += "Sec-WebSocket-Key: " + _websocket_key() + "\r\n";
            request += "Sec-WebSocket-Version: " + itos(WS_VERSION) + "\r\n";
            if(!m_subprotocol.empty()) {
                request += "Sec-WebSocket-Protocol: " + m_subprotocol + "\r\n";
            }
            if(!m_origin.empty()) {
                request += "Origin: " + m_origin.strip_edges() + "\r\n";
            }
            request += "\r\n";

            CharString cs = request.utf8();
            Error err = m_conn->put_data((const uint8_t*)cs.ptr(),cs.length());
            if (err != OK) {
                close();
                m_status = STATUS_CONNECTION_ERROR;
                return err;
            }

            m_status = STATUS_UPDATE_PROTOCOL_RECV;

            return OK;
        }


        case STATUS_UPDATE_PROTOCOL_RECV: {
            while(true) {
                uint8_t byte;
                int rec = 0;
                Error err = _get_data(&byte,1,rec);
                if (err != OK) {
                    close();
                    m_status = STATUS_CONNECTION_ERROR;
                    return ERR_CONNECTION_ERROR;
                }

                if (rec == 0) {
                    return OK;
                }

                m_resp_str.push_back(byte);
                int rs = m_resp_str.size();
                if ((rs>=2 && m_resp_str[rs-2]=='\n' && m_resp_str[rs-1]=='\n') ||
                        (rs>=4 && m_resp_str[rs-4]=='\r' && m_resp_str[rs-3]=='\n' &&
                         rs>=4 && m_resp_str[rs-2]=='\r' && m_resp_str[rs-1]=='\n')) {

                    //end of response, parse.
                    m_resp_str.push_back(0);
                    String response((const char*)m_resp_str.ptr());
                    Vector<String> responses = response.split("\n");
                    m_body_size = 0;
                    m_chunked = false;
                    m_body_left = 0;
                    m_chunk_left = 0;
                    m_resp_headers.clear();
                    m_resp_code = 400;

                    for(int i = 0; i < responses.size(); i++) {
                        String s = responses[i].strip_edges();

                        if (s.length() == 0)
                            continue;
                        if (s.begins_with("Content-Length:")) {
                            m_body_size = s.substr(s.find(":") + 1, s.length()).strip_edges().to_int();
                            m_body_left = m_body_size;
                        } else if (s.begins_with("Transfer-Encoding:")) {
                            String encoding = s.substr(s.find(":") + 1, s.length()).strip_edges();
                            if (encoding=="chunked") {
                                m_chunked=true;
                            }
                        }

                        if (i == 0 && responses[i].begins_with("HTTP")) {
                            String num = responses[i].get_slice(" ",1);
                            m_resp_code = num.to_int();
                        } else {
                            m_resp_headers.push_back(s);
                        }

                    }

                    Error err = _validate_response_headers();
                    if(err != OK) {
                        close();
                        m_status = STATUS_CANT_UPGRADE;
                        return err;
                    }

                    if (m_body_size == 0 && !m_chunked) {
                        m_status = STATUS_CONNECTED;
                    } else {
                        m_status = STATUS_BODY;
                    }

                    return OK;
                }
            }
            //wait for response
            return OK;
        }

        case STATUS_BODY: {
            return _handle_body();
        }

        case STATUS_CONNECTED: {
            return _pool_ws();
        }

        case STATUS_CLOSING:
        case STATUS_DISCONNECTED: {
            return ERR_UNCONFIGURED;
        }

        case STATUS_CANT_CONNECT: {
            return ERR_CANT_CONNECT;
        }

        case STATUS_CANT_RESOLVE: {
            return ERR_CANT_RESOLVE;
        }

        case STATUS_CANT_UPGRADE:
        case STATUS_SSL_HANDSHAKE_ERROR:
        case STATUS_CONNECTION_ERROR: {
            return ERR_CONNECTION_ERROR;
        }
    }

    return OK;
}

Error Websocket::send_text(const String& message)
{
    return _data_to_send(WSHeaderType::TEXT_FRAME, message);
}

Error Websocket::send_binary(const ByteArray& message)
{
    return _data_to_send(WSHeaderType::BINARY_FRAME, message);
}

Error Websocket::send_ping()
{
    String empty;
    return _data_to_send(WSHeaderType::PING, empty);
}

bool Websocket::is_connected() const
{
    return m_tcp_conn->get_status() == StreamPeerTCP::STATUS_CONNECTED;
}

bool Websocket::is_secure() const
{
    return m_secure;
}

void Websocket::set_blocking(bool block)
{
    m_blocking = block;
}

bool Websocket::is_blocking() const
{
    return m_blocking;
}

void Websocket::set_verif_host(bool verify)
{
    m_verify_host = verify;
}

bool Websocket::get_verify_host() const
{
    return m_verify_host;
}

void Websocket::set_validate_cert(bool validate)
{
    m_validate_cert = validate;
}

bool Websocket::get_validate_cert() const
{
    return m_validate_cert;
}

Websocket::Status Websocket::get_status() const
{
    return m_status;
}

void Websocket::close()
{
    if(is_connected()) {
        m_status = STATUS_CLOSING;
        uint8_t closeFrame[6] = {0x88, 0x80, 0x00, 0x00, 0x00, 0x00};
        m_conn->put_data(closeFrame, 6);
    }

    if (m_tcp_conn->get_status()!=StreamPeerTCP::STATUS_NONE) {
        m_tcp_conn->disconnect();
    }

    m_conn.unref();
    m_status = STATUS_DISCONNECTED;
    if (m_resolving != IP::RESOLVER_INVALID_ID) {
        IP::get_singleton()->erase_resolve_item(m_resolving);
        m_resolving=IP::RESOLVER_INVALID_ID;
    }

    m_txbuff.resize(0);
    m_rxbuff.resize(0);
    m_read_buf.resize(0);

    m_resp_headers.clear();
    m_resp_str.clear();
    m_body_size = 0;
    m_body_left = 0;
    m_chunk_left = 0;
    m_resp_code = 0;

    m_wait_for = WS_ANY;
}


Error Websocket::_parse_url(const String &url)
{
    int port;
    char host[256];
    char path[256];

    if(url.begins_with("wss://")) {
        m_secure = true;
    } else if (url.begins_with("ws://")) {
        m_secure = false;
    } else {
        ERR_PRINT("Invalid url!");
        return ERR_INVALID_PARAMETER;
    }

    if(sscanf(url.ascii(), "%*3[^:]://%[^:/]:%d/%s", host, &port, path) == 3) {
        m_host = String(host);
        m_port = port;
        m_path = String(path);
    } else if(sscanf(url.ascii(), "%*3[^:]://%[^:/]/%s", host, path) == 2) {
        m_host = String(host);
        m_path = String(path);
        if(is_secure()) {
            m_port = 443;
        } else {
            m_port = 80;
        }
    } else if(sscanf(url.ascii(), "%*3[^:]://%[^:/]:%d", host, &port) == 2) {
        m_host = String(host);
        m_port = port;
        m_path = String("/");
    } else if(sscanf(url.ascii(), "%*3[^:]://%[^:/]", host) == 1) {
        m_host = String(host);
        m_path = String("/");
        if(is_secure()) {
            m_port = 443;
        } else {
            m_port = 80;
        }
    } else {
        ERR_PRINT("Invalid url!");
        return ERR_INVALID_PARAMETER;
    }

    if (!m_path.begins_with("/")) {
        m_path = "/" + m_path;
    }

    return OK;
}

String Websocket::_websocket_key()
{
    char rnd[16];
    char buff[16 / 3 * 4 + 4 + 1];

    srand(time(0));
    for (int i = 0; i < 16; i++) {
        rnd[i] = rand() % 0xFF;
    }

    uint32_t size = base64_encode(buff, rnd, 16);
    buff[size] = 0;

    m_websocket_key = buff;
    return m_websocket_key;
}

Error Websocket::_validate_response_headers()
{
    if (m_resp_code != 101) {
        ERR_PRINT(String("Invalid response code: " + itos(m_resp_code)).ascii());
        return ERR_CONNECTION_ERROR;
    }


    HashMap<String, String> headers;
    for (int i =0; i < m_resp_headers.size(); i++) {
        String header = m_resp_headers[i];
        int sp = header.find(":");
        if(sp == -1) {
            continue;
        }

        String key = header.substr(0, sp).strip_edges().to_lower();
        String value = header.substr(sp + 1, header.length()).strip_edges().to_lower();
        headers[key]=value;
    }

    if ((headers.get("upgrade") != String("websocket")) || (headers.get("connection") != String("upgrade"))) {
        ERR_PRINT("Invalid WebSocket headers!");
        return ERR_CONNECTION_ERROR;
    }

    if (!m_subprotocol.empty()) {
        if(!headers.has("sec-websocket-protocol") || m_subprotocol.split(",").find(headers["sec-websocket-protocol"]) == -1) {
            ERR_PRINT("Subprotocol not suported!");
            return ERR_CONNECTION_ERROR;
        }
    }


    String accept = headers["sec-websocket-accept"].ptr();
    std::string key(m_websocket_key.strip_edges().ascii().ptr());
    key += "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

    sha1::sha1nfo si;
    sha1::sha1_init(&si);
    sha1::sha1_write(&si, key.c_str(), key.length());
    uint8_t* sha_result = sha1::sha1_result(&si);

    char base64[29] = {0};
    int bytes = base64_encode(base64, (char*)sha_result, 20);
    base64[bytes] = 0;

    if (String(base64).to_lower() != accept) {
        ERR_PRINT("Invalid key on header Sec-Websocket-Accept!");
        return ERR_CONNECTION_ERROR;
    }

    return OK;
}

Error Websocket::_handle_body()
{
    ERR_FAIL_COND_V(m_status != STATUS_BODY, ERR_SKIP);

    Error err = OK;

    if (m_chunked) {
        while(true) {
            if (m_chunk_left == 0) {
                uint8_t b;
                int rec = 0;
                err = _get_data(&b, 1, rec);

                if (rec == 0) {
                    break;
                }

                m_chunk.push_back(b);

                if (m_chunk.size() > 32) {
                    ERR_PRINT("HTTP Invalid chunk hex len");
                    m_status=STATUS_CONNECTION_ERROR;
                    return ERR_CONNECTION_ERROR;
                }

                if (m_chunk.size()>2 && m_chunk[m_chunk.size()-2]=='\r' && m_chunk[m_chunk.size()-1]=='\n') {
                    int len=0;
                    for(int i = 0; i < m_chunk.size()-2; i++) {
                        char c = m_chunk[i];
                        int v = 0;
                        if (c >= '0' && c <= '9')
                            v = c-'0';
                        else if (c >= 'a' && c <= 'f')
                            v = c-'a'+10;
                        else if (c >= 'A' && c <= 'F')
                            v = c-'A'+10;
                        else {
                            ERR_PRINT("HTTP Chunk len not in hex!!");
                            m_status=STATUS_CONNECTION_ERROR;
                            return ERR_CONNECTION_ERROR;
                        }
                        len <<= 4;
                        len |= v;
                        if (len > (1<<24)) {
                            ERR_PRINT("HTTP Chunk too big!! >16mb");
                            m_status=STATUS_CONNECTION_ERROR;
                            return ERR_CONNECTION_ERROR;
                        }
                    }

                    if (len == 0) {
                        //end!
                        m_status = STATUS_CONNECTED;
                        m_chunk.clear();
                        return OK;
                    }

                    m_chunk_left = len + 2;
                    m_chunk.resize(m_chunk_left);
                }
            } else {
                int rec = 0;
                err = _get_data(&m_chunk[m_chunk.size() - m_chunk_left], m_chunk_left, rec);
                if (rec == 0) {
                    break;
                }

                m_chunk_left -= rec;

                if (m_chunk_left == 0) {
                    if (m_chunk[m_chunk.size()-2]!='\r' || m_chunk[m_chunk.size()-1]!='\n') {
                        ERR_PRINT("HTTP Invalid chunk terminator (not \\r\\n)");
                        m_status=STATUS_CONNECTION_ERROR;
                        return ERR_CONNECTION_ERROR;
                    }

                    ByteArray ret;
                    ret.resize(m_chunk.size() - 2);
                    {
                        ByteArray::Write w = ret.write();
                        copymem(w.ptr(),m_chunk.ptr(),m_chunk.size()-2);
                    }
                    m_chunk.clear();

                    emit_signal("body_received", ret);
                }

                break;
            }
        }
    } else {
        int to_read = MIN(m_body_left, m_chunk_size);
        ByteArray ret;
        ret.resize(to_read);
        ByteArray::Write w = ret.write();
        int _offset = 0;
        while (to_read > 0) {
            int rec=0;
            err = _get_data(w.ptr() + _offset, to_read, rec);
            if (rec>0) {
                m_body_left-=rec;
                to_read-=rec;
                _offset += rec;
            } else {
                if (to_read > 0) //ended up reading less
                    ret.resize(_offset);
                break;
            }
        }

        if (m_body_left == 0) {
            m_status = STATUS_CONNECTED;
        }

        emit_signal("body_received", ret);
    }

    if (err != OK) {
        close();
        if (err==ERR_FILE_EOF) {
            m_status=STATUS_DISCONNECTED; //server disconnected
        } else {
            m_status=STATUS_CONNECTION_ERROR;
        }
    } else if (m_body_left == 0 && !m_chunked) {
        m_status=STATUS_CONNECTED;
    }

    return err;
}

Error Websocket::_pool_ws()
{
    Error err = OK;

    int rec = 0;
    ByteArray buff;
    buff.resize(4096);
    ByteArray::Write w = buff.write();

    err = _get_data(w.ptr(), 4096, rec);
    w = ByteArray::Write();

    if (err != OK) {
        close();
        m_status = STATUS_CONNECTION_ERROR;
    } else if (rec > 0) {
        buff.resize(rec);
        m_read_buf.append_array(buff);
    }

    err = _dispatch_data();
    if (err != OK) {
        close();
        m_status = STATUS_CONNECTION_ERROR;
    }

    int bytes = m_txbuff.size();
    while(err == OK && bytes > 0) {
        ByteArray::Read r = m_txbuff.read();
        int sent = 0;
        err = _put_data(r.ptr(), bytes, sent);
        r = ByteArray::Read();

        if(err != OK) {
            close();
            m_status = STATUS_CONNECTION_ERROR;
            break;
        }

        if (sent == 0) {
            break;
        }

        if (sent == bytes) {
            m_txbuff.resize(0);
            break;
        } else if(sent < bytes) {
            ByteArray::Write w = m_txbuff.write();
            for (int i = 0; i < bytes-sent; i++) {
                w[i]=w[i+sent];
            };
            w = ByteArray::Write();
            m_txbuff.resize(bytes-sent);
        }
    }

    return err;
}

Error Websocket::_get_data(uint8_t* p_buffer, int p_bytes, int& r_received)
{
    if (m_status == STATUS_DISCONNECTED) {
        return ERR_UNCONFIGURED;
    }

    if(m_blocking) {
        Error err = m_conn->get_data(p_buffer, p_bytes);
        if (err == OK) {
            r_received = p_bytes;
        } else {
            r_received = 0;
        }
        return err;
    } else {
        return m_conn->get_partial_data(p_buffer, p_bytes, r_received);
    }
}

Error Websocket::_put_data(const uint8_t* p_buffer, int p_bytes, int& r_sent)
{
    if (m_status == STATUS_DISCONNECTED) {
        return ERR_UNCONFIGURED;
    }

    if(m_blocking) {
        Error err = m_conn->put_data(p_buffer, p_bytes);
        if (err == OK) {
            r_sent = p_bytes;
        } else {
            r_sent = 0;
        }
        return err;
    } else {
        return m_conn->put_partial_data(p_buffer, p_bytes, r_sent);
    }
}

Error Websocket::_data_to_send(WSHeaderType::opcode_type type, const Variant& var_message)
{
    if (m_status == STATUS_CLOSING || m_status == STATUS_DISCONNECTED) {
        return ERR_UNAVAILABLE;
    }

    if (m_txbuff.size() > (24 * 1024 * 1024)) {
        ERR_PRINT("Message buffer is full!");
        return ERR_OUT_OF_MEMORY;
    }

    srand(time(0));
    uint8_t masking_key[4];
    for (int i = 0; i < 4; i++) {
        masking_key[i] = rand() % 0xFF;
    }

    ByteArray header;
    ByteArray message;
    if (var_message.is_array()) {
        message = var_message.operator DVector<uint8_t>();
    } else if (var_message.get_type() == Variant::STRING) {
        String m = var_message.operator String();
        message.resize(m.length());
        for(int i = 0; i < m.length(); i++) {
            message.set(i, m[i]);
        }
    } else {
        return ERR_INVALID_PARAMETER;
    }

    uint64_t message_size = message.size();
    int header_size = 2 + (message_size >= 126 ? 2 : 0) + (message_size >= 65536 ? 6 : 0) + (m_use_mask ? 4 : 0);

    header.resize(header_size);
    header.set(0, 0x80|type);

    if (message_size < 126) {
        header.set(1, (message_size & 0xff) | (m_use_mask ? 0x80 : 0));
        if (m_use_mask) {
            header.set(2, masking_key[0]);
            header.set(3, masking_key[1]);
            header.set(4, masking_key[2]);
            header.set(5, masking_key[3]);
        }
    } else if (message_size < 65536) {
        header.set(1, 126 | (m_use_mask ? 0x80 : 0));
        header.set(2, (message_size >> 8) & 0xff);
        header.set(3, (message_size >> 0) & 0xff);
        if (m_use_mask) {
            header.set(4, masking_key[0]);
            header.set(5, masking_key[1]);
            header.set(6, masking_key[2]);
            header.set(7, masking_key[3]);
        }
    } else { // TODO: run coverage testing here
        header.set(1, 127 | (m_use_mask ? 0x80 : 0));
        header.set(2, (message_size >> 56) & 0xff);
        header.set(3, (message_size >> 48) & 0xff);
        header.set(4, (message_size >> 40) & 0xff);
        header.set(5, (message_size >> 32) & 0xff);
        header.set(6, (message_size >> 24) & 0xff);
        header.set(7, (message_size >> 16) & 0xff);
        header.set(8, (message_size >>  8) & 0xff);
        header.set(9, (message_size >>  0) & 0xff);
        if (m_use_mask) {
            header.set(10, masking_key[0]);
            header.set(11, masking_key[1]);
            header.set(12, masking_key[2]);
            header.set(13, masking_key[3]);
        }
    }

    if (m_use_mask) {
        for (uint64_t i = 0; i < message_size; i++) {
            message.set(i, message[i] ^ masking_key[i&0x3]);
        }
    }

    // N.B. - txbuf will keep growing until it can be transmitted over the socket:
    m_txbuff.append_array(header);
    m_txbuff.append_array(message);

    return OK;
}


Error Websocket::_dispatch_data()
{
    while (true) {
        WSHeaderType ws;
        ByteArray::Read read = m_read_buf.read();
        const uint8_t *data = read.ptr();

        if (m_read_buf.size() < 2) {
            break; /* Need at least 2 */
        }

        ws.fin = (data[0] & 0x80) == 0x80;
        ws.opcode = (WSHeaderType::opcode_type)(data[0] & 0x0f);
        ws.mask = (data[1] & 0x80) == 0x80;
        ws.N0 = (data[1] & 0x7f);
        ws.header_size = 2 + (ws.N0 == 126 ? 2 : 0) + (ws.N0 == 127 ? 8 : 0) + (ws.mask ? 4 : 0);

        if (m_read_buf.size() < (int)ws.header_size) {
            break; /* Need: ws.header_size - rxbuf.size() */
        }

        int i;
        if (ws.N0 < 126) {
            ws.N = ws.N0;
            i = 2;
        } else if (ws.N0 == 126) {
            ws.N = 0;
            ws.N |= ((uint64_t) data[2]) << 8;
            ws.N |= ((uint64_t) data[3]) << 0;
            i = 4;
        } else if (ws.N0 == 127) {
            ws.N = 0;
            ws.N |= ((uint64_t) data[2]) << 56;
            ws.N |= ((uint64_t) data[3]) << 48;
            ws.N |= ((uint64_t) data[4]) << 40;
            ws.N |= ((uint64_t) data[5]) << 32;
            ws.N |= ((uint64_t) data[6]) << 24;
            ws.N |= ((uint64_t) data[7]) << 16;
            ws.N |= ((uint64_t) data[8]) << 8;
            ws.N |= ((uint64_t) data[9]) << 0;
            i = 10;
        }

        if (ws.mask) {
            ws.masking_key[0] = ((uint8_t) data[i+0]) << 0;
            ws.masking_key[1] = ((uint8_t) data[i+1]) << 0;
            ws.masking_key[2] = ((uint8_t) data[i+2]) << 0;
            ws.masking_key[3] = ((uint8_t) data[i+3]) << 0;
        } else {
            ws.masking_key[0] = 0;
            ws.masking_key[1] = 0;
            ws.masking_key[2] = 0;
            ws.masking_key[3] = 0;
        }

        int frame_size = ws.header_size + ws.N;
        if (m_read_buf.size() < frame_size) {
            break; /* Need: ws.header_size+ws.N - rxbuf.size() */
        }

        ByteArray message;
        message.resize(ws.N);
        for(int i = 0; i < (int)ws.N; i++) {
            message.set(i, data[i+ws.header_size]);
        }

        read = ByteArray::Read();

        if (m_read_buf.size() == frame_size) {
            m_read_buf.resize(0);
        } else {
            int size = m_read_buf.size();
            for (int i = 0; i < size-frame_size; i++) {
                m_read_buf.set(i, m_read_buf[i+frame_size]);
            };
            m_read_buf.resize(size-frame_size);
        }

        if (ws.mask) {
            for (size_t i = 0; i != ws.N; ++i) {
                message.set(i, message[i] ^ ws.masking_key[i&0x3]);
            }
        }

        if ((m_wait_for == WS_TEXT && ws.opcode == WSHeaderType::BINARY_FRAME) ||
                (m_wait_for == WS_BINARY && ws.opcode == WSHeaderType::TEXT_FRAME) ||
                (m_wait_for == WS_ANY && ws.opcode == WSHeaderType::CONTINUATION)) {
            ERR_PRINT("Invalid message received!");
            break;
        }

        // We got a whole message, now do something with it:
        if (ws.opcode == WSHeaderType::TEXT_FRAME ||
                ws.opcode == WSHeaderType::BINARY_FRAME ||
                ws.opcode == WSHeaderType::CONTINUATION) {

            if(ws.fin) {
                ByteArray msg_fin;
                msg_fin.append_array(m_rxbuff);
                m_rxbuff.resize(0);
                msg_fin.append_array(message);

                if (ws.opcode == WSHeaderType::TEXT_FRAME || (ws.opcode == WSHeaderType::CONTINUATION && m_wait_for == WS_TEXT)) {
                    String m;
                    m.resize(message.size() + 1);
                    for(int i = 0; i < message.size(); i++) {
                        m.set(i, message[i]);
                    }

                    emit_signal("message_received", m);
                } else {
                    emit_signal("binary_received", msg_fin);
                }

                m_wait_for = WS_ANY;
            } else {
                m_rxbuff.append_array(message);

                if(ws.opcode == WSHeaderType::TEXT_FRAME) {
                    m_wait_for = WS_TEXT;
                } else if(ws.opcode == WSHeaderType::BINARY_FRAME) {
                    m_wait_for = WS_BINARY;
                }
            }
        } else if (ws.opcode == WSHeaderType::PING) {
            _data_to_send(WSHeaderType::PONG, message);
        } else if (ws.opcode == WSHeaderType::PONG) {
            // Ignore
        } else if (ws.opcode == WSHeaderType::CLOSE) {
            close();
        } else {
            ERR_PRINT("Got unexpected WebSocket message.");
            close();
        }
    }

    return OK;
}
