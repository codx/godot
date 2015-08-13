#ifndef WEBSOCKET_H
#define WEBSOCKET_H

#include "reference.h"
#include "io/stream_peer.h"
#include "io/stream_peer_tcp.h"
#include "io/ip.h"



class Websocket: public Reference {
    OBJ_TYPE(Websocket, Reference)

protected:
    static void _bind_methods();


    // http://tools.ietf.org/html/rfc6455#section-5.2  Base Framing Protocol
    //
    //  0                   1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-------+-+-------------+-------------------------------+
    // |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
    // |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
    // |N|V|V|V|       |S|             |   (if payload len==126/127)   |
    // | |1|2|3|       |K|             |                               |
    // +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
    // |     Extended payload length continued, if payload len == 127  |
    // + - - - - - - - - - - - - - - - +-------------------------------+
    // |                               |Masking-key, if MASK set to 1  |
    // +-------------------------------+-------------------------------+
    // | Masking-key (continued)       |          Payload Data         |
    // +-------------------------------- - - - - - - - - - - - - - - - +
    // :                     Payload Data continued ...                :
    // + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
    // |                     Payload Data continued ...                |
    // +---------------------------------------------------------------+

    struct WSHeaderType {
        uint32_t header_size;
        bool fin;
        bool mask;
        enum opcode_type {
            CONTINUATION = 0x0,
            TEXT_FRAME = 0x1,
            BINARY_FRAME = 0x2,
            CLOSE = 8,
            PING = 9,
            PONG = 0xa,
        } opcode;
        int N0;
        uint64_t N;
        uint8_t masking_key[4];
    };

    enum WaitingFor {
        WS_ANY,
        WS_TEXT,
        WS_BINARY
    };

public:

    enum Status {
        STATUS_DISCONNECTED,
        STATUS_RESOLVING, //resolving hostname (if passed a hostname)
        STATUS_CANT_RESOLVE,
        STATUS_CONNECTING,
        STATUS_CANT_CONNECT,
        STATUS_CONNECTED,
        STATUS_UPDATE_PROTOCOL_SEND,
        STATUS_UPDATE_PROTOCOL_RECV,
        STATUS_BODY, // request resulted in body, which must be read
        STATUS_SSL_HANDSHAKE_ERROR,
        STATUS_CANT_UPGRADE,
        STATUS_CONNECTION_ERROR,
        STATUS_CLOSING
    };

    Websocket();
    ~Websocket();

    Error create_connection(const String& url, bool use_mask = true, const String& subprotcol = String(), const String& origin = String());

    Error poll();
    Error send_text(const String& message);
    Error send_binary(const ByteArray& message);
    Error send_ping();

    bool is_connected() const;
    bool is_secure() const;

    void set_blocking(bool block);
    bool is_blocking() const;

    void set_verif_host(bool verify);
    bool get_verify_host() const;

    void set_validate_cert(bool validate);
    bool get_validate_cert() const;

    Status get_status() const;
    void close();

private:
    Error _parse_url(const String& url);
    String _websocket_key();
    Error _validate_response_headers();
    Error _handle_body();
    Error _pool_ws();

    Error _get_data(uint8_t* p_buffer, int p_bytes,int &r_received);
    Error _put_data(const uint8_t* p_buffer, int p_bytes, int &r_sent);
    Error _data_to_send(WSHeaderType::opcode_type type, const Variant& message);
    Error _dispatch_data();
    Error _dispatch_text(WSHeaderType &header, ByteArray &msg);

    bool m_use_mask;
    String m_origin;
    bool m_verify_host;
    bool m_validate_cert;
    String m_websocket_key;
    String m_subprotocol;
    ByteArray m_txbuff;
    ByteArray m_rxbuff;
    ByteArray m_read_buf;
    WaitingFor m_wait_for;

    int m_port;
    String m_host;
    String m_path;
    bool m_secure;
    bool m_blocking;
    Status m_status;
    IP::ResolverID m_resolving;

    int m_resp_code;
    Vector<String> m_resp_headers;
    Vector<uint8_t> m_resp_str;
    bool m_chunked;
    Vector<uint8_t> m_chunk;
    int m_chunk_size;
    int m_chunk_left;
    int m_body_size;
    int m_body_left;

    Ref<StreamPeer> m_conn;
    Ref<StreamPeerTCP> m_tcp_conn;
};


#endif
