use libc::{sockaddr, socklen_t, iovec};

pub const XQC_OK: u32 = 0;
pub const XQC_ERROR: i32 = -1;
pub const XQC_TRUE: u32 = 1;
pub const XQC_FALSE: u32 = 0;
pub const XQC_MAX_CID_LEN: u32 = 20;
pub const XQC_MIN_CID_LEN: u32 = 4;
pub const XQC_LB_CID_KEY_LEN: u32 = 16;
pub const XQC_STATELESS_RESET_TOKENLEN: u32 = 16;
pub const XQC_BBR_RTTVAR_COMPENSATION_ENABLED: u32 = 0;
pub const XQC_BBR2_PLUS_ENABLED: u32 = 1;
pub const XQC_DEFAULT_HTTP_PRIORITY_URGENCY: u32 = 3;
pub const XQC_HIGHEST_HTTP_PRIORITY_URGENCY: u32 = 0;
pub const XQC_LOWEST_HTTP_PRIORITY_URGENCY: u32 = 7;
pub const XQC_DEFINED_ALPN_H3: &[u8; 3] = b"h3\0";
pub const XQC_DEFINED_ALPN_H3_29: &[u8; 6] = b"h3-29\0";
pub const XQC_DEFINED_ALPN_H3_EXT: &[u8; 7] = b"h3-ext\0";
pub const XQC_MAX_ALPN_BUF_LEN: u32 = 256;
pub const XQC_MAX_FEC_BUF_LEN: u32 = 64;
pub const XQC_MAX_COMMON_BUF_LEN: u32 = 64;
pub const XQC_SUPPORT_VERSION_MAX: u32 = 64;
pub const XQC_TLS_CIPHERS: &[u8; 75] =
    b"TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256\0";
pub const XQC_TLS_GROUPS: &[u8; 25] = b"P-256:X25519:P-384:P-521\0";
pub const XQC_RESET_TOKEN_MAX_KEY_LEN: u32 = 256;
pub const XQC_TOKEN_MAX_KEY_VERSION: u32 = 4;
pub const XQC_TOKEN_VERSION_MASK: u32 = 3;
pub const XQC_TOKEN_MAX_KEY_LEN: u32 = 256;
pub const XQC_MAX_SEND_MSG_ONCE: u32 = 32;
pub const XQC_INITIAL_PATH_ID: u32 = 0;
pub const XQC_DGRAM_RETX_ASKED_BY_APP: u32 = 1;
pub const XQC_CO_MAX_NUM: u32 = 16;
pub const XQC_CO_STR_MAX_LEN: u32 = 80;
pub const XQC_FEC_MAX_SCHEME_NUM: u32 = 5;
pub const XQC_SOCKET_ERROR: i32 = -1;
pub const XQC_SOCKET_EAGAIN: i32 = -2;
pub const XQC_PATH_HARD_CAP: u32 = 256;
pub const XQC_CONN_INFO_LEN: u32 = 400;
pub const XQC_EXTERN_CONN_INFO_LEN: u32 = 128;
pub const XQC_STREAM_INFO_LEN: u32 = 128;
pub const XQC_H3_CAPSULE_DATAGRAM: u32 = 0;
pub const XQC_H3_CAPSULE_ADDRESS_ASSIGN: u32 = 1;
pub const XQC_H3_CAPSULE_ADDRESS_REQUEST: u32 = 2;
pub const XQC_H3_CAPSULE_ROUTE_ADVERTISEMENT: u32 = 3;
pub type __socklen_t = ::core::ffi::c_uint;
#[doc = " no peer CONNECTION_CLOSE frame has been received"]
pub const XQC_CONN_ERR_TYPE_UNKNOWN: xqc_conn_err_type_t = 0;
#[doc = " error code from CONNECTION_CLOSE type 0x1c"]
pub const XQC_CONN_ERR_TYPE_TRANSPORT: xqc_conn_err_type_t = 1;
#[doc = " error code from CONNECTION_CLOSE type 0x1d"]
pub const XQC_CONN_ERR_TYPE_APPLICATION: xqc_conn_err_type_t = 2;
#[doc = " @brief namespace of an error code received in CONNECTION_CLOSE"]
pub type xqc_conn_err_type_t = ::core::ffi::c_uint;
pub const TRA_NO_ERROR: xqc_trans_err_code_t = 0;
pub const TRA_INTERNAL_ERROR: xqc_trans_err_code_t = 1;
pub const TRA_CONNECTION_REFUSED_ERROR: xqc_trans_err_code_t = 2;
pub const TRA_FLOW_CONTROL_ERROR: xqc_trans_err_code_t = 3;
pub const TRA_STREAM_LIMIT_ERROR: xqc_trans_err_code_t = 4;
pub const TRA_STREAM_STATE_ERROR: xqc_trans_err_code_t = 5;
pub const TRA_FINAL_SIZE_ERROR: xqc_trans_err_code_t = 6;
pub const TRA_FRAME_ENCODING_ERROR: xqc_trans_err_code_t = 7;
pub const TRA_TRANSPORT_PARAMETER_ERROR: xqc_trans_err_code_t = 8;
pub const TRA_CONNECTION_ID_LIMIT_ERROR: xqc_trans_err_code_t = 9;
pub const TRA_PROTOCOL_VIOLATION: xqc_trans_err_code_t = 10;
pub const TRA_INVALID_TOKEN: xqc_trans_err_code_t = 11;
pub const TRA_APPLICATION_ERROR: xqc_trans_err_code_t = 12;
pub const TRA_CRYPTO_BUFFER_EXCEEDED: xqc_trans_err_code_t = 13;
#[doc = "< MUST delete the current saved 0RTT transport parameters"]
pub const TRA_0RTT_TRANS_PARAMS_ERROR: xqc_trans_err_code_t = 14;
#[doc = "< RFC 9001 §6.6: AEAD integrity limit reached"]
pub const TRA_AEAD_LIMIT_REACHED: xqc_trans_err_code_t = 30;
pub const TRA_VERSION_NEGOTIATION_ERROR: xqc_trans_err_code_t = 83;
pub const TRA_NO_APPLICATION_PROTOCOL: xqc_trans_err_code_t = 376;
#[doc = " @brief QUIC Transport Protocol error codes"]
pub type xqc_trans_err_code_t = ::core::ffi::c_uint;
pub const H3_NO_ERROR: xqc_h3_err_code_t = 256;
pub const H3_GENERAL_PROTOCOL_ERROR: xqc_h3_err_code_t = 257;
pub const H3_INTERNAL_ERROR: xqc_h3_err_code_t = 258;
pub const H3_STREAM_CREATION_ERROR: xqc_h3_err_code_t = 259;
pub const H3_CLOSED_CRITICAL_STREAM: xqc_h3_err_code_t = 260;
pub const H3_FRAME_UNEXPECTED: xqc_h3_err_code_t = 261;
pub const H3_FRAME_ERROR: xqc_h3_err_code_t = 262;
pub const H3_EXCESSIVE_LOAD: xqc_h3_err_code_t = 263;
pub const H3_ID_ERROR: xqc_h3_err_code_t = 264;
pub const H3_SETTINGS_ERROR: xqc_h3_err_code_t = 265;
pub const H3_MISSING_SETTINGS: xqc_h3_err_code_t = 266;
pub const H3_REQUEST_REJECTED: xqc_h3_err_code_t = 267;
pub const H3_REQUEST_CANCELLED: xqc_h3_err_code_t = 268;
pub const H3_REQUEST_INCOMPLETE: xqc_h3_err_code_t = 269;
pub const H3_MESSAGE_ERROR: xqc_h3_err_code_t = 270;
pub const H3_CONNECT_ERROR: xqc_h3_err_code_t = 271;
pub const H3_VERSION_FALLBACK: xqc_h3_err_code_t = 272;
pub const H3_DATAGRAM_ERROR: xqc_h3_err_code_t = 51;
#[doc = " @brief QUIC Http/3 Protocol error codes"]
pub type xqc_h3_err_code_t = ::core::ffi::c_uint;
pub const QPACK_DECOMPRESSION_FAILED: xqc_qpack_err_code_t = 512;
pub const QPACK_ENCODER_STREAM_ERROR: xqc_qpack_err_code_t = 513;
pub const QPACK_DECODER_STREAM_ERROR: xqc_qpack_err_code_t = 514;
#[doc = " @brief QPACK protocol error codes"]
pub type xqc_qpack_err_code_t = ::core::ffi::c_uint;
#[doc = "< not enough buf space"]
pub const XQC_ENOBUF: xqc_transport_error_t = 600;
#[doc = "< parse frame error"]
pub const XQC_EVINTREAD: xqc_transport_error_t = 601;
#[doc = "< empty pointer, usually a malloc failure"]
pub const XQC_ENULLPTR: xqc_transport_error_t = 602;
#[doc = "< malloc failure"]
pub const XQC_EMALLOC: xqc_transport_error_t = 603;
#[doc = "< illegal packet, don't close connection, just drop it"]
pub const XQC_EILLPKT: xqc_transport_error_t = 604;
#[doc = "< incorrect encryption level"]
pub const XQC_ELEVEL: xqc_transport_error_t = 605;
#[doc = "< fail to create a connection"]
pub const XQC_ECREATE_CONN: xqc_transport_error_t = 606;
#[doc = "< connection is closing, operation denied"]
pub const XQC_CLOSING: xqc_transport_error_t = 607;
#[doc = "< fail to find the corresponding connection"]
pub const XQC_ECONN_NFOUND: xqc_transport_error_t = 608;
#[doc = "< system error, usually a public library interface failure"]
pub const XQC_ESYS: xqc_transport_error_t = 609;
#[doc = "< write blocking, similar to EAGAIN"]
pub const XQC_EAGAIN: xqc_transport_error_t = 610;
#[doc = "< wrong parameters"]
pub const XQC_EPARAM: xqc_transport_error_t = 611;
#[doc = "< abnormal connection status"]
pub const XQC_ESTATE: xqc_transport_error_t = 612;
#[doc = "< exceed cache limit"]
pub const XQC_ELIMIT: xqc_transport_error_t = 613;
#[doc = "< violation of protocol"]
pub const XQC_EPROTO: xqc_transport_error_t = 614;
#[doc = "< socket interface error"]
pub const XQC_ESOCKET: xqc_transport_error_t = 615;
#[doc = "< fatal error, engine will immediately destroy the connection"]
pub const XQC_EFATAL: xqc_transport_error_t = 616;
#[doc = "< abnormal flow status"]
pub const XQC_ESTREAM_ST: xqc_transport_error_t = 617;
#[doc = "< send retry failure"]
pub const XQC_ESEND_RETRY: xqc_transport_error_t = 618;
#[doc = "< connection-level flow control"]
pub const XQC_ECONN_BLOCKED: xqc_transport_error_t = 619;
#[doc = "< stream-level flow control"]
pub const XQC_ESTREAM_BLOCKED: xqc_transport_error_t = 620;
#[doc = "< encryption error"]
pub const XQC_EENCRYPT: xqc_transport_error_t = 621;
#[doc = "< decryption error"]
pub const XQC_EDECRYPT: xqc_transport_error_t = 622;
#[doc = "< AEAD integrity limit reached per RFC 9001 §6.6"]
pub const XQC_EAEAD_LIMIT: xqc_transport_error_t = 623;
#[doc = "< fail to find the corresponding stream"]
pub const XQC_ESTREAM_NFOUND: xqc_transport_error_t = 623;
#[doc = "< fail to create a package or write a package header"]
pub const XQC_EWRITE_PKT: xqc_transport_error_t = 624;
#[doc = "< fail to create stream"]
pub const XQC_ECREATE_STREAM: xqc_transport_error_t = 625;
#[doc = "< stream has been reset"]
pub const XQC_ESTREAM_RESET: xqc_transport_error_t = 626;
#[doc = "< duplicate frames"]
pub const XQC_EDUP_FRAME: xqc_transport_error_t = 627;
#[doc = "< STREAM frame final size error"]
pub const XQC_EFINAL_SIZE: xqc_transport_error_t = 628;
#[doc = "< this version is not supported and requires negotiation"]
pub const XQC_EVERSION: xqc_transport_error_t = 629;
#[doc = "< need to wait"]
pub const XQC_EWAITING: xqc_transport_error_t = 630;
#[doc = "< ignore unknown packet/frame, don't close connection"]
pub const XQC_EIGNORE_PKT: xqc_transport_error_t = 631;
#[doc = "< connection ID generation error"]
pub const XQC_EGENERATE_CID: xqc_transport_error_t = 632;
#[doc = "< server reached the anti-amplification limit"]
pub const XQC_EANTI_AMPLIFICATION_LIMIT: xqc_transport_error_t = 633;
#[doc = "< no available connection ID"]
pub const XQC_ECONN_NO_AVAIL_CID: xqc_transport_error_t = 634;
#[doc = "< can't find cid in connection"]
pub const XQC_ECONN_CID_NOT_FOUND: xqc_transport_error_t = 635;
#[doc = "< illegal stream & frame, close connection"]
pub const XQC_EILLEGAL_FRAME: xqc_transport_error_t = 636;
#[doc = "< abnormal connection ID status"]
pub const XQC_ECID_STATE: xqc_transport_error_t = 637;
#[doc = "< active cid exceed active_connection_id_limit"]
pub const XQC_EACTIVE_CID_LIMIT: xqc_transport_error_t = 638;
#[doc = "< alpn is not supported by server"]
pub const XQC_EALPN_NOT_SUPPORTED: xqc_transport_error_t = 639;
#[doc = "< alpn is not registered"]
pub const XQC_EALPN_NOT_REGISTERED: xqc_transport_error_t = 640;
#[doc = "< connection is reset by peer"]
pub const XQC_ESTATELESS_RESET: xqc_transport_error_t = 641;
#[doc = "< error with packet filter callback function"]
pub const XQC_EPACKET_FILETER_CALLBACK: xqc_transport_error_t = 642;
#[doc = "< client received a Version Negotiation packet, RFC 9000 §6.2 mandates abandoning the connection attempt"]
pub const XQC_EVERSION_NEGOTIATION: xqc_transport_error_t = 643;
#[doc = "< Multipath - don't support multipath"]
pub const XQC_EMP_NOT_SUPPORT_MP: xqc_transport_error_t = 650;
#[doc = "< Multipath - no available path id"]
pub const XQC_EMP_NO_AVAIL_PATH_ID: xqc_transport_error_t = 651;
#[doc = "< Multipath - create path error"]
pub const XQC_EMP_CREATE_PATH: xqc_transport_error_t = 652;
#[doc = "< Multipath - can't find path in paths_list"]
pub const XQC_EMP_PATH_NOT_FOUND: xqc_transport_error_t = 653;
#[doc = "< Multipath - abnormal path status"]
pub const XQC_EMP_PATH_STATE_ERROR: xqc_transport_error_t = 654;
#[doc = "< Multipath - fail to schedule path for sending"]
pub const XQC_EMP_SCHEDULE_PATH: xqc_transport_error_t = 655;
#[doc = "< Multipath - no another active path"]
pub const XQC_EMP_NO_ACTIVE_PATH: xqc_transport_error_t = 656;
pub const XQC_EMP_INVALID_MP_VERTION: xqc_transport_error_t = 657;
pub const XQC_EMP_NO_AVAILABLE_CID_FOR_PATH: xqc_transport_error_t = 658;
#[doc = "< FEC - fec not supported"]
pub const XQC_EFEC_NOT_SUPPORT_FEC: xqc_transport_error_t = 660;
#[doc = "< FEC - no available scheme"]
pub const XQC_EFEC_SCHEME_ERROR: xqc_transport_error_t = 661;
#[doc = "< FEC - symbol value error"]
pub const XQC_EFEC_SYMBOL_ERROR: xqc_transport_error_t = 662;
#[doc = "< FEC - tolerable error"]
pub const XQC_EFEC_TOLERABLE_ERROR: xqc_transport_error_t = 663;
#[doc = "< load balance connection ID encryption error"]
pub const XQC_EENCRYPT_LB_CID: xqc_transport_error_t = 670;
#[doc = "< aes_128_ecb algorithm error"]
pub const XQC_EENCRYPT_AES_128_ECB: xqc_transport_error_t = 671;
#[doc = "< Datagram - not supported"]
pub const XQC_EDGRAM_NOT_SUPPORTED: xqc_transport_error_t = 680;
#[doc = "< Datagram - payload size too large"]
pub const XQC_EDGRAM_TOO_LARGE: xqc_transport_error_t = 681;
#[doc = "< PMTUD - probing size error"]
pub const XQC_EPMTUD_PROBING_SIZE: xqc_transport_error_t = 682;
#[doc = "< ACK Extension - abnormal value"]
pub const XQC_EACK_EXT_ABN_VAL: xqc_transport_error_t = 690;
pub const XQC_E_MAX: xqc_transport_error_t = 691;
#[doc = " @brief xquic transport internal error codes: 6xx"]
pub type xqc_transport_error_t = ::core::ffi::c_uint;
pub const XQC_TLS_INVALID_ARGUMENT: xqc_tls_error_t = 700;
pub const XQC_TLS_UNKNOWN_PKT_TYPE: xqc_tls_error_t = 701;
pub const XQC_TLS_NOBUF: xqc_tls_error_t = 702;
pub const XQC_TLS_PROTO: xqc_tls_error_t = 703;
pub const XQC_TLS_INVALID_STATE: xqc_tls_error_t = 704;
pub const XQC_TLS_ACK_FRAME: xqc_tls_error_t = 705;
pub const XQC_TLS_STREAM_ID_BLOCKED: xqc_tls_error_t = 706;
pub const XQC_TLS_STREAM_IN_USE: xqc_tls_error_t = 707;
pub const XQC_TLS_STREAM_DATA_BLOCKED: xqc_tls_error_t = 708;
pub const XQC_TLS_FLOW_CONTROL: xqc_tls_error_t = 709;
pub const XQC_TLS_STREAM_LIMIT: xqc_tls_error_t = 710;
pub const XQC_TLS_FINAL_OFFSET: xqc_tls_error_t = 711;
pub const XQC_TLS_CRYPTO: xqc_tls_error_t = 712;
pub const XQC_TLS_PKT_NUM_EXHAUSTED: xqc_tls_error_t = 713;
pub const XQC_TLS_REQUIRED_TRANSPORT_PARAM: xqc_tls_error_t = 714;
pub const XQC_TLS_MALFORMED_TRANSPORT_PARAM: xqc_tls_error_t = 715;
pub const XQC_TLS_FRAME_ENCODING: xqc_tls_error_t = 716;
pub const XQC_TLS_DECRYPT: xqc_tls_error_t = 717;
pub const XQC_TLS_STREAM_SHUT_WR: xqc_tls_error_t = 718;
pub const XQC_TLS_STREAM_NOT_FOUND: xqc_tls_error_t = 719;
pub const XQC_TLS_VERSION_NEGOTIATION: xqc_tls_error_t = 720;
pub const XQC_TLS_STREAM_STATE: xqc_tls_error_t = 721;
pub const XQC_TLS_NOKEY: xqc_tls_error_t = 722;
pub const XQC_TLS_EARLY_DATA_REJECTED: xqc_tls_error_t = 723;
pub const XQC_TLS_RECV_VERSION_NEGOTIATION: xqc_tls_error_t = 724;
pub const XQC_TLS_CLOSING: xqc_tls_error_t = 725;
pub const XQC_TLS_DRAINING: xqc_tls_error_t = 726;
pub const XQC_TLS_TRANSPORT_PARAM: xqc_tls_error_t = 727;
pub const XQC_TLS_DISCARD_PKT: xqc_tls_error_t = 728;
pub const XQC_TLS_FATAL: xqc_tls_error_t = 729;
pub const XQC_TLS_NOMEM: xqc_tls_error_t = 730;
pub const XQC_TLS_CALLBACK_FAILURE: xqc_tls_error_t = 731;
pub const XQC_TLS_INTERNAL: xqc_tls_error_t = 732;
pub const XQC_TLS_DATA_REJECT: xqc_tls_error_t = 733;
pub const XQC_TLS_CLIENT_INITIAL_ERROR: xqc_tls_error_t = 734;
pub const XQC_TLS_CLIENT_REINTIAL_ERROR: xqc_tls_error_t = 735;
pub const XQC_TLS_ENCRYPT_DATA_ERROR: xqc_tls_error_t = 736;
pub const XQC_TLS_DECRYPT_DATA_ERROR: xqc_tls_error_t = 737;
pub const XQC_TLS_CRYPTO_CTX_NEGOTIATED_ERROR: xqc_tls_error_t = 738;
pub const XQC_TLS_SET_TRANSPORT_PARAM_ERROR: xqc_tls_error_t = 739;
pub const XQC_TLS_SET_CIPHER_SUITES_ERROR: xqc_tls_error_t = 740;
pub const XQC_TLS_DERIVE_KEY_ERROR: xqc_tls_error_t = 741;
pub const XQC_TLS_DO_HANDSHAKE_ERROR: xqc_tls_error_t = 742;
pub const XQC_TLS_POST_HANDSHAKE_ERROR: xqc_tls_error_t = 743;
pub const XQC_TLS_UPDATE_KEY_ERROR: xqc_tls_error_t = 744;
pub const XQC_TLS_DECRYPT_WHEN_KU_ERROR: xqc_tls_error_t = 745;
pub const XQC_TLS_ERR_MAX: xqc_tls_error_t = 746;
#[doc = " @brief xquic TLS internal error codes: 7xx"]
pub type xqc_tls_error_t = ::core::ffi::c_uint;
#[doc = "< malloc failure"]
pub const XQC_H3_EMALLOC: xqc_h3_error_t = 800;
#[doc = "< fail to create a stream"]
pub const XQC_H3_ECREATE_STREAM: xqc_h3_error_t = 801;
#[doc = "< fail to create a request"]
pub const XQC_H3_ECREATE_REQUEST: xqc_h3_error_t = 802;
#[doc = "< GOAWAY received, operation denied"]
pub const XQC_H3_EGOAWAY_RECVD: xqc_h3_error_t = 803;
#[doc = "< fail to create a connection"]
pub const XQC_H3_ECREATE_CONN: xqc_h3_error_t = 804;
#[doc = "< QPACK - encode error"]
pub const XQC_H3_EQPACK_ENCODE: xqc_h3_error_t = 805;
#[doc = "< QPACK - decode error"]
pub const XQC_H3_EQPACK_DECODE: xqc_h3_error_t = 806;
#[doc = "< priority tree error"]
pub const XQC_H3_EPRI_TREE: xqc_h3_error_t = 807;
#[doc = "< fail to process control stream"]
pub const XQC_H3_EPROC_CONTROL: xqc_h3_error_t = 808;
#[doc = "< fail to process request stream"]
pub const XQC_H3_EPROC_REQUEST: xqc_h3_error_t = 809;
#[doc = "< fail to process push stream"]
pub const XQC_H3_EPROC_PUSH: xqc_h3_error_t = 810;
#[doc = "< wrong parameters"]
pub const XQC_H3_EPARAM: xqc_h3_error_t = 811;
#[doc = "< http send buffer exceeds the maximum"]
pub const XQC_H3_BUFFER_EXCEED: xqc_h3_error_t = 812;
#[doc = "< decode error"]
pub const XQC_H3_DECODE_ERROR: xqc_h3_error_t = 813;
#[doc = "< invalid stream, such as multiple control streams, etc."]
pub const XQC_H3_INVALID_STREAM: xqc_h3_error_t = 814;
#[doc = "< illegal closure of control stream and qpack encoder/decoder stream"]
pub const XQC_H3_CLOSE_CRITICAL_STREAM: xqc_h3_error_t = 815;
#[doc = "< http3 decoding status error"]
pub const XQC_H3_STATE_ERROR: xqc_h3_error_t = 816;
#[doc = "< control stream error, such as setting not send first or send twice"]
pub const XQC_H3_CONTROL_ERROR: xqc_h3_error_t = 817;
#[doc = "< control stream decode error, such as encountering an unrecognized frame type"]
pub const XQC_H3_CONTROL_DECODE_ERROR: xqc_h3_error_t = 818;
#[doc = "< control stream decode invalid, eg. illegal remaining length"]
pub const XQC_H3_CONTROL_DECODE_INVALID: xqc_h3_error_t = 819;
#[doc = "< priority error"]
pub const XQC_H3_PRIORITY_ERROR: xqc_h3_error_t = 820;
#[doc = "< invalid frame type"]
pub const XQC_H3_INVALID_FRAME_TYPE: xqc_h3_error_t = 821;
#[doc = "< unsupported frame type"]
pub const XQC_H3_UNSUPPORT_FRAME_TYPE: xqc_h3_error_t = 822;
#[doc = "< invalid header field, such as the length exceeds the limit, etc."]
pub const XQC_H3_INVALID_HEADER: xqc_h3_error_t = 823;
#[doc = "< SETTING error"]
pub const XQC_H3_SETTING_ERROR: xqc_h3_error_t = 824;
#[doc = "< blocked_stream exceed limit"]
pub const XQC_H3_BLOCKED_STREAM_EXCEED: xqc_h3_error_t = 825;
#[doc = "< call xqc_stream_recv error"]
pub const XQC_H3_STREAM_RECV_ERROR: xqc_h3_error_t = 826;
#[doc = "< invalid http priority params or values"]
pub const XQC_H3_INVALID_PRIORITY: xqc_h3_error_t = 827;
#[doc = "< invalid bidi stream type"]
pub const XQC_H3_INVALID_BIDI_STREAM_TYPE: xqc_h3_error_t = 828;
#[doc = "< fail to create a bytestream"]
pub const XQC_H3_ECREATE_BYTESTREAM: xqc_h3_error_t = 829;
#[doc = "< fail to process bytestream"]
pub const XQC_H3_EPROC_BYTESTREAM: xqc_h3_error_t = 830;
#[doc = "< try to send data on a bytestream that already sent FIN"]
pub const XQC_H3_BYTESTREAM_FIN_SENT: xqc_h3_error_t = 831;
#[doc = "< try to create a msg buf while it already exists"]
pub const XQC_H3_BYTESTREAM_MSG_BUF_EXIST: xqc_h3_error_t = 832;
#[doc = "< request-only frame received on control stream (RFC 9114 §7.2.1/§7.2.5)"]
pub const XQC_H3_CONTROL_FRAME_UNEXPECTED: xqc_h3_error_t = 833;
#[doc = "< first frame on control stream is not SETTINGS, RFC 9114 §6.2.1"]
pub const XQC_H3_MISSING_SETTINGS: xqc_h3_error_t = 834;
#[doc = "< control-only frame received on request stream (RFC 9114 §7.2)"]
pub const XQC_H3_REQUEST_FRAME_UNEXPECTED: xqc_h3_error_t = 835;
#[doc = "< RFC 9114 §7.2.7"]
pub const XQC_H3_INVALID_MAX_PUSH_ID: xqc_h3_error_t = 836;
pub const XQC_H3_ERR_MAX: xqc_h3_error_t = 837;
#[doc = " @brief xquic HTTP3/QPACK application error codes: 8xx"]
pub type xqc_h3_error_t = ::core::ffi::c_uint;
pub const XQC_QPACK_DECODER_VARINT_ERROR: xqc_qpack_error_t = 900;
#[doc = "< qpack encode error"]
pub const XQC_QPACK_ENCODER_ERROR: xqc_qpack_error_t = 901;
#[doc = "< qpack decode error"]
pub const XQC_QPACK_DECODER_ERROR: xqc_qpack_error_t = 902;
#[doc = "< qpack dynamic table error"]
pub const XQC_QPACK_DYNAMIC_TABLE_ERROR: xqc_qpack_error_t = 903;
#[doc = "< qpack static table error"]
pub const XQC_QPACK_STATIC_TABLE_ERROR: xqc_qpack_error_t = 904;
#[doc = "< set dynamic table capacity error"]
pub const XQC_QPACK_SET_DTABLE_CAP_ERROR: xqc_qpack_error_t = 905;
#[doc = "< send data error or control message error"]
pub const XQC_QPACK_SEND_ERROR: xqc_qpack_error_t = 906;
pub const XQC_QPACK_SAVE_HEADERS_ERROR: xqc_qpack_error_t = 907;
#[doc = "< unknown encoder/decoder instruction"]
pub const XQC_QPACK_UNKNOWN_INSTRUCTION: xqc_qpack_error_t = 908;
#[doc = "< error instruction"]
pub const XQC_QPACK_INSTRUCTION_ERROR: xqc_qpack_error_t = 909;
#[doc = "< dynamic table entry is still referred"]
pub const XQC_QPACK_DYNAMIC_TABLE_REFERRED: xqc_qpack_error_t = 910;
#[doc = "< entry inexists in dynamic table"]
pub const XQC_QPACK_DYNAMIC_TABLE_VOID_ENTRY: xqc_qpack_error_t = 911;
#[doc = "< state is error"]
pub const XQC_QPACK_STATE_ERROR: xqc_qpack_error_t = 912;
#[doc = "< dynamic table not enough"]
pub const XQC_QPACK_DYNAMIC_TABLE_NOT_ENOUGH: xqc_qpack_error_t = 913;
#[doc = "< huffman decode error"]
pub const XQC_QPACK_HUFFMAN_DEC_ERROR: xqc_qpack_error_t = 914;
#[doc = "< huffman decode state error"]
pub const XQC_QPACK_HUFFMAN_DEC_STATE_ERROR: xqc_qpack_error_t = 915;
pub const XQC_QPACK_ERR_MAX: xqc_qpack_error_t = 916;
#[doc = " @brief xquic QPACK application error codes: 9xx"]
pub type xqc_qpack_error_t = ::core::ffi::c_uint;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xqc_stream_s {
    _unused: [u8; 0],
}
pub type xqc_stream_t = xqc_stream_s;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xqc_connection_s {
    _unused: [u8; 0],
}
pub type xqc_connection_t = xqc_connection_s;
#[doc = " @brief structures of connection settings"]
pub type xqc_conn_settings_t = xqc_conn_settings_s;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xqc_engine_s {
    _unused: [u8; 0],
}
pub type xqc_engine_t = xqc_engine_s;
#[doc = " @brief log callback functions"]
pub type xqc_log_callbacks_t = xqc_log_callbacks_s;
#[doc = " @brief tranport callback functions are more related to attributes of QUIC [Transport]\n but not ALPN.\n\n These callback functions are events of QUIC Transport layer, and need to\n interact with application-layer, which have less thing to do with ALPN layer.\n\n These callback functions shall directly call back to application layer, with user_data\n from struct xqc_connection_t. unless Application-Layer-Protocol take over them.\n\n Generally, xquic defines callbacks as below:\n 1. Callbacks between Transport and Application:\n QUIC events that are common between different Application Protocols,\n and is much more convenient to interact with Application and Application Protocol.\n\n 2. Callbacks between Application Protocol and Application:\n Application-Protocol events will interact with Application Layer. these callback\n functions are defined by Application Protocol Layers.\n\n 3. Callbacks between Transport and Application Protocol:\n QUIC events that might be more essential to Application-Layer-Protocols, especially\n stream data\n\n +------------------------------------------------------------------------------+\n |                             Application                                      |\n |                                 +-- Application Protocol defined callbacks --+\n |                                 |             Application Protocol           |\n +-------- transport callbacks ----+--------- app protocol callbacks -----------+\n |                              Transport                                       |\n +------------------------------------------------------------------------------+"]
pub type xqc_transport_callbacks_t = xqc_transport_callbacks_s;
#[doc = " @brief http3 connection callbacks for application layer"]
pub type xqc_h3_conn_callbacks_t = xqc_h3_conn_callbacks_s;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xqc_random_generator_s {
    _unused: [u8; 0],
}
pub type xqc_random_generator_t = xqc_random_generator_s;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xqc_client_connection_s {
    _unused: [u8; 0],
}
pub type xqc_client_connection_t = xqc_client_connection_s;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xqc_id_hash_table_s {
    _unused: [u8; 0],
}
pub type xqc_id_hash_table_t = xqc_id_hash_table_s;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xqc_str_hash_table_s {
    _unused: [u8; 0],
}
pub type xqc_str_hash_table_t = xqc_str_hash_table_s;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xqc_priority_queue_s {
    _unused: [u8; 0],
}
pub type xqc_pq_t = xqc_priority_queue_s;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xqc_wakeup_pq_s {
    _unused: [u8; 0],
}
pub type xqc_wakeup_pq_t = xqc_wakeup_pq_s;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xqc_log_s {
    _unused: [u8; 0],
}
pub type xqc_log_t = xqc_log_s;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xqc_send_ctl_s {
    _unused: [u8; 0],
}
pub type xqc_send_ctl_t = xqc_send_ctl_s;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xqc_send_queue_s {
    _unused: [u8; 0],
}
pub type xqc_send_queue_t = xqc_send_queue_s;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xqc_pn_ctl_s {
    _unused: [u8; 0],
}
pub type xqc_pn_ctl_t = xqc_pn_ctl_s;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xqc_packet_s {
    _unused: [u8; 0],
}
pub type xqc_packet_t = xqc_packet_s;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xqc_packet_in_s {
    _unused: [u8; 0],
}
pub type xqc_packet_in_t = xqc_packet_in_s;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xqc_packet_out_s {
    _unused: [u8; 0],
}
pub type xqc_packet_out_t = xqc_packet_out_s;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xqc_stream_frame_s {
    _unused: [u8; 0],
}
pub type xqc_stream_frame_t = xqc_stream_frame_s;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xqc_h3_request_s {
    _unused: [u8; 0],
}
pub type xqc_h3_request_t = xqc_h3_request_s;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xqc_h3_conn_s {
    _unused: [u8; 0],
}
pub type xqc_h3_conn_t = xqc_h3_conn_s;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xqc_h3_stream_s {
    _unused: [u8; 0],
}
pub type xqc_h3_stream_t = xqc_h3_stream_s;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xqc_h3_frame_s {
    _unused: [u8; 0],
}
pub type xqc_h3_frame_t = xqc_h3_frame_s;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xqc_qpack_s {
    _unused: [u8; 0],
}
pub type xqc_qpack_t = xqc_qpack_s;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xqc_dtable_s {
    _unused: [u8; 0],
}
pub type xqc_dtable_t = xqc_dtable_s;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xqc_sample_s {
    _unused: [u8; 0],
}
pub type xqc_sample_t = xqc_sample_s;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xqc_memory_pool_s {
    _unused: [u8; 0],
}
pub type xqc_memory_pool_t = xqc_memory_pool_s;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xqc_bbr_info_interface_s {
    _unused: [u8; 0],
}
pub type xqc_bbr_info_interface_t = xqc_bbr_info_interface_s;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xqc_path_ctx_s {
    _unused: [u8; 0],
}
pub type xqc_path_ctx_t = xqc_path_ctx_s;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xqc_timer_manager_s {
    _unused: [u8; 0],
}
pub type xqc_timer_manager_t = xqc_timer_manager_s;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xqc_h3_ext_bytestream_s {
    _unused: [u8; 0],
}
pub type xqc_h3_ext_bytestream_t = xqc_h3_ext_bytestream_s;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xqc_ping_record_s {
    _unused: [u8; 0],
}
pub type xqc_ping_record_t = xqc_ping_record_s;
pub type xqc_conn_qos_stats_t = xqc_conn_qos_stats_s;
pub type xqc_msec_t = u64;
pub type xqc_usec_t = u64;
pub type xqc_packet_number_t = u64;
pub type xqc_stream_id_t = u64;
pub type xqc_int_t = i32;
pub type xqc_uint_t = u32;
pub type xqc_flag_t = isize;
pub type xqc_bool_t = u8;
#[doc = " @brief cid structure for xquic connection identification"]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xqc_cid_s {
    pub cid_len: u8,
    pub cid_buf: [u8; 20usize],
    pub cid_seq_num: u64,
    pub sr_token: [u8; 16usize],
    #[doc = "< preallocate for multi-path"]
    pub path_id: u64,
}
#[allow(clippy::unnecessary_operation, clippy::identity_op)]
const _: () = {
    ["Size of xqc_cid_s"][::core::mem::size_of::<xqc_cid_s>() - 56usize];
    ["Alignment of xqc_cid_s"][::core::mem::align_of::<xqc_cid_s>() - 8usize];
    ["Offset of field: xqc_cid_s::cid_len"][::core::mem::offset_of!(xqc_cid_s, cid_len) - 0usize];
    ["Offset of field: xqc_cid_s::cid_buf"][::core::mem::offset_of!(xqc_cid_s, cid_buf) - 1usize];
    ["Offset of field: xqc_cid_s::cid_seq_num"]
        [::core::mem::offset_of!(xqc_cid_s, cid_seq_num) - 24usize];
    ["Offset of field: xqc_cid_s::sr_token"]
        [::core::mem::offset_of!(xqc_cid_s, sr_token) - 32usize];
    ["Offset of field: xqc_cid_s::path_id"][::core::mem::offset_of!(xqc_cid_s, path_id) - 48usize];
};
#[doc = " @brief cid structure for xquic connection identification"]
pub type xqc_cid_t = xqc_cid_s;
pub const XQC_LOG_REPORT: xqc_log_level_s = 0;
pub const XQC_LOG_FATAL: xqc_log_level_s = 1;
pub const XQC_LOG_ERROR: xqc_log_level_s = 2;
pub const XQC_LOG_WARN: xqc_log_level_s = 3;
pub const XQC_LOG_STATS: xqc_log_level_s = 4;
pub const XQC_LOG_INFO: xqc_log_level_s = 5;
pub const XQC_LOG_DEBUG: xqc_log_level_s = 6;
pub type xqc_log_level_s = ::core::ffi::c_uint;
pub use self::xqc_log_level_s as xqc_log_level_t;
#[doc = "< qlog will be emitted selectly"]
pub const EVENT_IMPORTANCE_SELECTED: qlog_event_importance_s = 0;
pub const EVENT_IMPORTANCE_CORE: qlog_event_importance_s = 1;
pub const EVENT_IMPORTANCE_BASE: qlog_event_importance_s = 2;
pub const EVENT_IMPORTANCE_EXTRA: qlog_event_importance_s = 3;
#[doc = "< Currently, some events have been removed in the latest qlog draft. But old qvis need them!"]
pub const EVENT_IMPORTANCE_REMOVED: qlog_event_importance_s = 4;
#[doc = " @brief qlog Importance level definition"]
pub type qlog_event_importance_s = ::core::ffi::c_uint;
#[doc = " @brief qlog Importance level definition"]
pub use self::qlog_event_importance_s as qlog_event_importance_t;
pub const XQC_BBR_FLAG_NONE: xqc_bbr_optimization_flag_t = 0;
pub type xqc_bbr_optimization_flag_t = ::core::ffi::c_uint;
pub const XQC_BBR2_FLAG_NONE: xqc_bbr2_optimization_flag_t = 0;
pub const XQC_BBR2_FLAG_RTTVAR_COMPENSATION: xqc_bbr2_optimization_flag_t = 1;
pub const XQC_BBR2_FLAG_FAST_CONVERGENCE: xqc_bbr2_optimization_flag_t = 2;
pub type xqc_bbr2_optimization_flag_t = ::core::ffi::c_uint;
pub const XQC_CONN_TYPE_CLIENT: xqc_conn_type_t = 0;
pub const XQC_CONN_TYPE_SERVER: xqc_conn_type_t = 1;
pub type xqc_conn_type_t = ::core::ffi::c_uint;
pub const XQC_STREAM_BIDI: xqc_stream_direction_t = 0;
pub const XQC_STREAM_UNI: xqc_stream_direction_t = 1;
pub type xqc_stream_direction_t = ::core::ffi::c_uint;
pub const XQC_FEC_DEFAULT: xqc_fec_priority_t = 0;
pub const XQC_FEC_CLOSE: xqc_fec_priority_t = 2048;
pub const XQC_FEC_NORMAL: xqc_fec_priority_t = 4096;
pub const XQC_FEC_MIDDLE: xqc_fec_priority_t = 20480;
#[doc = " @brief FEC priority settings decided by h3 requests size"]
pub type xqc_fec_priority_t = ::core::ffi::c_uint;
pub const XQC_DEFAULT_SIZE_REQ: xqc_stream_size_type_t = 0;
pub const XQC_SLIM_SIZE_REQ: xqc_stream_size_type_t = 1;
pub const XQC_NORMAL_SIZE_REQ: xqc_stream_size_type_t = 2;
pub const XQC_MIDDLE_SIZE_REQ: xqc_stream_size_type_t = 3;
pub const XQC_LARGE_SIZE_REQ: xqc_stream_size_type_t = 4;
#[doc = " @brief FEC inner priority types decided by xqc_fec_priority_t"]
pub type xqc_stream_size_type_t = ::core::ffi::c_uint;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xqc_http_priority_s {
    pub urgency: u8,
    pub incremental: u8,
    pub schedule: u8,
    pub reinject: u8,
    pub fec: u32,
    pub fastpath: u8,
}
#[allow(clippy::unnecessary_operation, clippy::identity_op)]
const _: () = {
    ["Size of xqc_http_priority_s"][::core::mem::size_of::<xqc_http_priority_s>() - 12usize];
    ["Alignment of xqc_http_priority_s"][::core::mem::align_of::<xqc_http_priority_s>() - 4usize];
    ["Offset of field: xqc_http_priority_s::urgency"]
        [::core::mem::offset_of!(xqc_http_priority_s, urgency) - 0usize];
    ["Offset of field: xqc_http_priority_s::incremental"]
        [::core::mem::offset_of!(xqc_http_priority_s, incremental) - 1usize];
    ["Offset of field: xqc_http_priority_s::schedule"]
        [::core::mem::offset_of!(xqc_http_priority_s, schedule) - 2usize];
    ["Offset of field: xqc_http_priority_s::reinject"]
        [::core::mem::offset_of!(xqc_http_priority_s, reinject) - 3usize];
    ["Offset of field: xqc_http_priority_s::fec"]
        [::core::mem::offset_of!(xqc_http_priority_s, fec) - 4usize];
    ["Offset of field: xqc_http_priority_s::fastpath"]
        [::core::mem::offset_of!(xqc_http_priority_s, fastpath) - 8usize];
};
pub type xqc_h3_priority_t = xqc_http_priority_s;
pub const XQC_CONN_SETTINGS_DEFAULT: xqc_conn_settings_type_e = 0;
pub const XQC_CONN_SETTINGS_LOW_DELAY: xqc_conn_settings_type_e = 1;
pub type xqc_conn_settings_type_e = ::core::ffi::c_uint;
pub use self::xqc_conn_settings_type_e as xqc_conn_settings_type_t;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xqc_conn_public_local_trans_settings_s {
    pub max_datagram_frame_size: u16,
    pub datagram_redundancy: u8,
}
#[allow(clippy::unnecessary_operation, clippy::identity_op)]
const _: () = {
    ["Size of xqc_conn_public_local_trans_settings_s"]
        [::core::mem::size_of::<xqc_conn_public_local_trans_settings_s>() - 4usize];
    ["Alignment of xqc_conn_public_local_trans_settings_s"]
        [::core::mem::align_of::<xqc_conn_public_local_trans_settings_s>() - 2usize];
    ["Offset of field: xqc_conn_public_local_trans_settings_s::max_datagram_frame_size"][::core::mem::offset_of!(
        xqc_conn_public_local_trans_settings_s,
        max_datagram_frame_size
    )
        - 0usize];
    ["Offset of field: xqc_conn_public_local_trans_settings_s::datagram_redundancy"][::core::mem::offset_of!(
        xqc_conn_public_local_trans_settings_s,
        datagram_redundancy
    ) - 2usize];
};
pub type xqc_conn_public_local_trans_settings_t = xqc_conn_public_local_trans_settings_s;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xqc_conn_public_remote_trans_settings_s {
    pub max_datagram_frame_size: u16,
}
#[allow(clippy::unnecessary_operation, clippy::identity_op)]
const _: () = {
    ["Size of xqc_conn_public_remote_trans_settings_s"]
        [::core::mem::size_of::<xqc_conn_public_remote_trans_settings_s>() - 2usize];
    ["Alignment of xqc_conn_public_remote_trans_settings_s"]
        [::core::mem::align_of::<xqc_conn_public_remote_trans_settings_s>() - 2usize];
    ["Offset of field: xqc_conn_public_remote_trans_settings_s::max_datagram_frame_size"][::core::mem::offset_of!(
        xqc_conn_public_remote_trans_settings_s,
        max_datagram_frame_size
    )
        - 0usize];
};
pub type xqc_conn_public_remote_trans_settings_t = xqc_conn_public_remote_trans_settings_s;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xqc_stream_settings_s {
    pub recv_rate_bytes_per_sec: u64,
}
#[allow(clippy::unnecessary_operation, clippy::identity_op)]
const _: () = {
    ["Size of xqc_stream_settings_s"][::core::mem::size_of::<xqc_stream_settings_s>() - 8usize];
    ["Alignment of xqc_stream_settings_s"]
        [::core::mem::align_of::<xqc_stream_settings_s>() - 8usize];
    ["Offset of field: xqc_stream_settings_s::recv_rate_bytes_per_sec"]
        [::core::mem::offset_of!(xqc_stream_settings_s, recv_rate_bytes_per_sec) - 0usize];
};
pub type xqc_stream_settings_t = xqc_stream_settings_s;
pub const XQC_CO_TBBR: xqc_conn_option_e = 1413628498;
pub const XQC_CO_1RTT: xqc_conn_option_e = 827479124;
pub const XQC_CO_2RTT: xqc_conn_option_e = 844256340;
pub const XQC_CO_BBR4: xqc_conn_option_e = 1111642676;
pub const XQC_CO_BBR5: xqc_conn_option_e = 1111642677;
pub const XQC_CO_IW03: xqc_conn_option_e = 1230450739;
pub const XQC_CO_IW10: xqc_conn_option_e = 1230450992;
pub const XQC_CO_IW20: xqc_conn_option_e = 1230451248;
pub const XQC_CO_IW50: xqc_conn_option_e = 1230452016;
pub const XQC_CO_B2ON: xqc_conn_option_e = 1110593358;
pub const XQC_CO_COPA: xqc_conn_option_e = 1129271361;
pub const XQC_CO_C2ON: xqc_conn_option_e = 1127370574;
pub const XQC_CO_QBIC: xqc_conn_option_e = 1363298627;
pub const XQC_CO_RENO: xqc_conn_option_e = 1380273743;
pub const XQC_CO_SPRI: xqc_conn_option_e = 1397772873;
pub const XQC_CO_9218: xqc_conn_option_e = 959590712;
pub const XQC_CO_D218: xqc_conn_option_e = 1144140088;
pub const XQC_CO_DRST: xqc_conn_option_e = 1146245972;
pub const XQC_CO_CBBR: xqc_conn_option_e = 1128415826;
pub const XQC_CO_BNLS: xqc_conn_option_e = 1112427603;
pub const XQC_CO_BACG: xqc_conn_option_e = 1111573319;
pub const XQC_CO_CG03: xqc_conn_option_e = 1128738867;
pub const XQC_CO_CG05: xqc_conn_option_e = 1128738869;
pub const XQC_CO_CG10: xqc_conn_option_e = 1128739120;
pub const XQC_CO_CG20: xqc_conn_option_e = 1128739376;
pub const XQC_CO_PG11: xqc_conn_option_e = 1346842929;
pub const XQC_CO_PG15: xqc_conn_option_e = 1346842933;
pub const XQC_CO_BNLR: xqc_conn_option_e = 1112427602;
pub const XQC_CO_MW10: xqc_conn_option_e = 1297559856;
pub const XQC_CO_MW20: xqc_conn_option_e = 1297560112;
pub const XQC_CO_MW32: xqc_conn_option_e = 1297560370;
pub const XQC_CO_MW50: xqc_conn_option_e = 1297560880;
pub const XQC_CO_WL20: xqc_conn_option_e = 1464611376;
pub const XQC_CO_WL30: xqc_conn_option_e = 1464611632;
pub const XQC_CO_WL40: xqc_conn_option_e = 1464611888;
pub const XQC_CO_WL50: xqc_conn_option_e = 1464612144;
pub const XQC_CO_PR02: xqc_conn_option_e = 1347563570;
pub const XQC_CO_PR03: xqc_conn_option_e = 1347563571;
pub const XQC_CO_PR04: xqc_conn_option_e = 1347563572;
pub const XQC_CO_PR05: xqc_conn_option_e = 1347563573;
pub const XQC_CO_PR06: xqc_conn_option_e = 1347563574;
pub const XQC_CO_PR07: xqc_conn_option_e = 1347563575;
pub const XQC_CO_ENWC: xqc_conn_option_e = 1162762051;
pub const XQC_CO_JW10: xqc_conn_option_e = 1247228208;
pub const XQC_CO_JW20: xqc_conn_option_e = 1247228464;
pub const XQC_CO_JW30: xqc_conn_option_e = 1247228720;
pub const XQC_CO_JW40: xqc_conn_option_e = 1247228976;
pub const XQC_CO_JW50: xqc_conn_option_e = 1247229232;
pub const XQC_CO_SL03: xqc_conn_option_e = 1397502003;
pub const XQC_CO_SL04: xqc_conn_option_e = 1397502004;
pub const XQC_CO_SL05: xqc_conn_option_e = 1397502005;
pub const XQC_CO_SL10: xqc_conn_option_e = 1397502256;
pub type xqc_conn_option_e = ::core::ffi::c_uint;
pub use self::xqc_conn_option_e as xqc_conn_option_t;
pub const XQC_APP_PATH_STATUS_NONE: xqc_app_path_status_t = 0;
pub const XQC_APP_PATH_STATUS_STANDBY: xqc_app_path_status_t = 1;
pub const XQC_APP_PATH_STATUS_AVAILABLE: xqc_app_path_status_t = 2;
pub const XQC_APP_PATH_STATUS_FROZEN: xqc_app_path_status_t = 3;
pub const XQC_APP_PATH_STATUS_MAX: xqc_app_path_status_t = 4;
pub type xqc_app_path_status_t = ::core::ffi::c_uint;
pub const XQC_TLS_1_3_CLIENT_HELLO: xqc_tls_msg_type_e = 0;
pub const XQC_TLS_1_3_SERVER_HELLO: xqc_tls_msg_type_e = 1;
pub type xqc_tls_msg_type_e = ::core::ffi::c_uint;
pub use self::xqc_tls_msg_type_e as xqc_tls_msg_type_t;
pub const XQC_TLS_GROUP_DEFAULT: xqc_tls_group_type_e = 0;
pub const XQC_TLS_GROUP_P256_FIRST: xqc_tls_group_type_e = 1;
pub const XQC_TLS_GROUP_X25519_FIRST: xqc_tls_group_type_e = 2;
pub const XQC_TLS_GROUP_P384_FIRST: xqc_tls_group_type_e = 3;
pub const XQC_TLS_GROUP_P521_FIRST: xqc_tls_group_type_e = 4;
pub type xqc_tls_group_type_e = ::core::ffi::c_uint;
pub use self::xqc_tls_group_type_e as xqc_tls_group_type_t;
pub type sa_family_t = ::core::ffi::c_ushort;
pub const XQC_ENGINE_SERVER: xqc_engine_type_t = 0;
pub const XQC_ENGINE_CLIENT: xqc_engine_type_t = 1;
#[doc = " @brief engine type definition"]
pub type xqc_engine_type_t = ::core::ffi::c_uint;
#[doc = " placeholder"]
pub const XQC_IDRAFT_INIT_VER: xqc_proto_version_s = 0;
#[doc = " former version of QUIC RFC 9000"]
pub const XQC_VERSION_V1: xqc_proto_version_s = 1;
#[doc = " IETF Draft-29"]
pub const XQC_IDRAFT_VER_29: xqc_proto_version_s = 2;
#[doc = " Special version for version negotiation."]
pub const XQC_IDRAFT_VER_NEGOTIATION: xqc_proto_version_s = 3;
#[doc = " max value of proto value."]
pub const XQC_VERSION_MAX: xqc_proto_version_s = 4;
#[doc = " @brief supported versions for IETF drafts"]
pub type xqc_proto_version_s = ::core::ffi::c_uint;
#[doc = " @brief supported versions for IETF drafts"]
pub use self::xqc_proto_version_s as xqc_proto_version_t;
#[doc = " @brief get timestamp callback function. this might be useful on different platforms\n @return timestamp in microsecond"]
pub type xqc_timestamp_pt = ::core::option::Option<unsafe extern "C" fn() -> xqc_usec_t>;
#[doc = " @brief event timer callback function. MUST be set for both client and server\n xquic don't have implementation of timer, but will tell the interval of timer by this\n function. applications shall implement the timer, and invoke xqc_engine_main_logic\n after timer expires.\n\n @param wake_after interval of timer, with micro-second.\n @param engine_user_data user_data of engine"]
pub type xqc_set_event_timer_pt = ::core::option::Option<
    unsafe extern "C" fn(wake_after: xqc_usec_t, engine_user_data: *mut ::core::ffi::c_void),
>;
#[doc = " @brief cid generate callback.\n\n @param ori_cid the original dcid sent by client.\n @param cid_buf  buffer for cid generated\n @param cid_buflen len for cid_buf\n @param engine_user_data  user data of engine from `xqc_engine_create`\n @return negative for failed, non-negative (including 0) for the length of bytes\n written. if the count of written bytes is less than cid_buflen, xquic will fill rest of\n cid_buf with random bytes"]
pub type xqc_cid_generate_pt = ::core::option::Option<
    unsafe extern "C" fn(
        ori_cid: *const xqc_cid_t,
        cid_buf: *mut u8,
        cid_buflen: usize,
        engine_user_data: *mut ::core::ffi::c_void,
    ) -> isize,
>;
#[doc = " @brief engine secret log callback. will only be effective when build with\n XQC_PRINT_SECRET\n\n this callback will be invoked everytime when TLS layer generates a secret, and will be\n triggered multiple times during handshake. keylog could be used in wireshark to parse\n QUIC packets"]
pub type xqc_eng_keylog_pt = ::core::option::Option<
    unsafe extern "C" fn(
        scid: *const xqc_cid_t,
        line: *const ::core::ffi::c_char,
        engine_user_data: *mut ::core::ffi::c_void,
    ),
>;
#[doc = " @brief tls secret log callback. will only be effective when build with XQC_PRINT_SECRET\n\n this callback will be invoked everytime when TLS layer generates a secret, and will be\n triggered multiple times during handshake. keylog could be used in wireshark to parse\n QUIC packets"]
pub type xqc_keylog_pt = ::core::option::Option<
    unsafe extern "C" fn(
        line: *const ::core::ffi::c_char,
        engine_user_data: *mut ::core::ffi::c_void,
    ),
>;
#[doc = " @brief log callback functions"]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xqc_log_callbacks_s {
    #[doc = " trace log callback function\n\n trace log including XQC_LOG_FATAL, XQC_LOG_ERROR, XQC_LOG_WARN, XQC_LOG_STATS,\n XQC_LOG_INFO, XQC_LOG_DEBUG, xquic will output logs with the level higher or equal\n to the level configured in xqc_log_init. Besides, when qlog enable and\n EVENT_IMPORTANCE_SELECTED importance is set, some event log will output log by\n xqc_log_write_err callback."]
    pub xqc_log_write_err: ::core::option::Option<
        unsafe extern "C" fn(
            lvl: xqc_log_level_t,
            buf: *const ::core::ffi::c_void,
            size: usize,
            engine_user_data: *mut ::core::ffi::c_void,
        ),
    >,
    #[doc = " statistic log callback function\n\n this function will be triggered when write XQC_LOG_REPORT or XQC_LOG_STATS level\n logs. mainly when connection close, stream close."]
    pub xqc_log_write_stat: ::core::option::Option<
        unsafe extern "C" fn(
            lvl: xqc_log_level_t,
            buf: *const ::core::ffi::c_void,
            size: usize,
            engine_user_data: *mut ::core::ffi::c_void,
        ),
    >,
    #[doc = " qlog event callback function\n\n qlog event importance including EVENT_IMPORTANCE_SELECTED, EVENT_IMPORTANCE_CORE,\n EVENT_IMPORTANCE_BASE, EVENT_IMPORTANCE_EXTRA and EVENT_IMPORTANCE_REMOVED.\n EVENT_IMPORTANCE_CORE, EVENT_IMPORTANCE_BASE and EVENT_IMPORTANCE_EXTRA follow the\n defination of qlog draft. EVENT_IMPORTANCE_SELECTED works by xqc_log_write_err\n EVENT_IMPORTANCE_REMOVED exits, because the last qlog draft remove some qlog event,\n but the current qvis tool still need them."]
    pub xqc_qlog_event_write: ::core::option::Option<
        unsafe extern "C" fn(
            imp: qlog_event_importance_t,
            buf: *const ::core::ffi::c_void,
            size: usize,
            engine_user_data: *mut ::core::ffi::c_void,
        ),
    >,
}
#[allow(clippy::unnecessary_operation, clippy::identity_op)]
const _: () = {
    ["Size of xqc_log_callbacks_s"][::core::mem::size_of::<xqc_log_callbacks_s>() - 24usize];
    ["Alignment of xqc_log_callbacks_s"][::core::mem::align_of::<xqc_log_callbacks_s>() - 8usize];
    ["Offset of field: xqc_log_callbacks_s::xqc_log_write_err"]
        [::core::mem::offset_of!(xqc_log_callbacks_s, xqc_log_write_err) - 0usize];
    ["Offset of field: xqc_log_callbacks_s::xqc_log_write_stat"]
        [::core::mem::offset_of!(xqc_log_callbacks_s, xqc_log_write_stat) - 8usize];
    ["Offset of field: xqc_log_callbacks_s::xqc_qlog_event_write"]
        [::core::mem::offset_of!(xqc_log_callbacks_s, xqc_qlog_event_write) - 16usize];
};
#[doc = " @brief connection accept callback.\n\n this function is invoked when incoming a new QUIC connection. return 0 means accept\n this new connection. return negative values if application layer will not accept the\n new connection due to busy or some reason else\n\n @param user_data the user_data parameter of xqc_engine_packet_process\n @return negative for refuse connection. 0 for accept"]
pub type xqc_server_accept_pt = ::core::option::Option<
    unsafe extern "C" fn(
        engine: *mut xqc_engine_t,
        conn: *mut xqc_connection_t,
        cid: *const xqc_cid_t,
        user_data: *mut ::core::ffi::c_void,
    ) -> ::core::ffi::c_int,
>;
#[doc = " @brief connection refused callback. corresponding to xqc_server_accept_pt callback\n function. this function will be invoked when a QUIC connection is refused by xquic due\n to security considerations, applications SHALL link the connection's lifetime between\n itself and xquic, and free the context if it was created during xqc_server_accept_pt.\n\n @param user_data the user_data parameter of connection"]
pub type xqc_server_refuse_pt = ::core::option::Option<
    unsafe extern "C" fn(
        engine: *mut xqc_engine_t,
        conn: *mut xqc_connection_t,
        cid: *const xqc_cid_t,
        user_data: *mut ::core::ffi::c_void,
    ),
>;
#[doc = " @brief engine can't find connection related to input udp packet, and return a\n STATELESS_RESET packet, implementations shall send this buffer back to peer. this\n callback function is almost the same with xqc_socket_write_pt, but with different\n user_data definition.\n\n @param user_data user_data related to connection, originated from the user_data\n parameter of xqc_engine_packet_process"]
pub type xqc_stateless_reset_pt = ::core::option::Option<
    unsafe extern "C" fn(
        buf: *const ::core::ffi::c_uchar,
        size: usize,
        peer_addr: *const sockaddr,
        peer_addrlen: socklen_t,
        local_addr: *const sockaddr,
        local_addrlen: socklen_t,
        user_data: *mut ::core::ffi::c_void,
    ) -> isize,
>;
#[doc = " @brief connection closing notify callback function.\n\n This function will be triggered when a connection is not available and will not\n send/receive data any more. this callback is helpful to avoid attempts to send data on\n a closing connection. \\n NOTICE: this callback function will be triggered at the\n beginning of connection close, while the conn_close_notify will be triggered at the end\n of connection close.\n\n @param conn pointer of connection\n @param cid connection id\n @param err_code the reason of connection close\n @param conn_user_data the user_data which will be used in callback functions\n between xquic transport connection and application"]
pub type xqc_conn_closing_notify_pt = ::core::option::Option<
    unsafe extern "C" fn(
        conn: *mut xqc_connection_t,
        cid: *const xqc_cid_t,
        err_code: xqc_int_t,
        conn_user_data: *mut ::core::ffi::c_void,
    ) -> xqc_int_t,
>;
#[doc = " @brief general callback function definition for connection create and close\n\n @param conn_user_data the user_data which will be used in callback functions\n between xquic transport connection and application\n @param conn_proto_data the user_data which will be used in callback functions\n between xquic transport connection and application-layer-protocol"]
pub type xqc_conn_notify_pt = ::core::option::Option<
    unsafe extern "C" fn(
        conn: *mut xqc_connection_t,
        cid: *const xqc_cid_t,
        conn_user_data: *mut ::core::ffi::c_void,
        conn_proto_data: *mut ::core::ffi::c_void,
    ) -> ::core::ffi::c_int,
>;
#[doc = " @brief QUIC connection token callback. REQUIRED for client.\n token is used by the server to validate client's address during the handshake period of\n next connection to the same server. client applications shall save token to local\n storage, if need to connect the same server, read the token and take it as the\n parameter of xqc_connect.\n\n NOTICE: as client initiate multiple connections to multiple QUIC servers or server\n clusters, it shall save the tokens separately, e.g. save the token with the domain as\n the key"]
pub type xqc_save_token_pt = ::core::option::Option<
    unsafe extern "C" fn(
        token: *const ::core::ffi::c_uchar,
        token_len: u32,
        conn_user_data: *mut ::core::ffi::c_void,
    ),
>;
#[doc = " @brief general type of session ticket and transport parameter callback function"]
pub type xqc_save_string_pt = ::core::option::Option<
    unsafe extern "C" fn(
        data: *const ::core::ffi::c_char,
        data_len: usize,
        conn_user_data: *mut ::core::ffi::c_void,
    ),
>;
#[doc = " @brief session ticket callback function\n\n session ticket is essential for 0-RTT connections. with the same storage requirements\n and strategy as token. when initiating a new connection, session ticket is part of\n xqc_conn_ssl_config_t parameter"]
pub type xqc_save_session_pt = xqc_save_string_pt;
#[doc = " @brief transport parameters callback\n\n transport parameters are use when initiating 0-RTT connections to avoid violating the\n server's restriction, it shall be remembered with the same storage requirements and\n strategy as token. When initiating a new connection, transport parameters is part of\n xqc_conn_ssl_config_t parameter"]
pub type xqc_save_trans_param_pt = xqc_save_string_pt;
#[doc = " @brief handshake finished callback function\n\n this will be trigger when the QUIC connection handshake is completed, that is, when the\n TLS stack has both sent a Finished message and verified the peer's Finished message"]
pub type xqc_handshake_finished_pt = ::core::option::Option<
    unsafe extern "C" fn(
        conn: *mut xqc_connection_t,
        conn_user_data: *mut ::core::ffi::c_void,
        conn_proto_data: *mut ::core::ffi::c_void,
    ),
>;
#[doc = " @brief PING acked callback function.\n\n if application send a PING frame with xqc_conn_send_ping function, this callback\n function will be triggered when this PING frame is acked by peer. noticing that PING\n frame do not need repair, it might not be triggered if PING frame is lost or ACK frame\n is lost. xquic might send PING frames  will not trigger this callback"]
pub type xqc_conn_ping_ack_notify_pt = ::core::option::Option<
    unsafe extern "C" fn(
        conn: *mut xqc_connection_t,
        cid: *const xqc_cid_t,
        ping_user_data: *mut ::core::ffi::c_void,
        conn_user_data: *mut ::core::ffi::c_void,
        conn_proto_data: *mut ::core::ffi::c_void,
    ),
>;
#[doc = " @brief cid update callback function.\n\n this function will be trigger after receive peer's RETIRE_CONNECTION_ID frame and the\n SCID of endpoint is changed. cid change might be essential if load balance or some\n other mechanism related with cid is introduced, applications shall update the CID after\n the callback is triggered\n\n @param conn connection handler\n @param retire_cid cid that was retired by peer\n @param new_cid cid that would be used\n @param conn_user_data connection level user_data"]
pub type xqc_conn_update_cid_notify_pt = ::core::option::Option<
    unsafe extern "C" fn(
        conn: *mut xqc_connection_t,
        retire_cid: *const xqc_cid_t,
        new_cid: *const xqc_cid_t,
        conn_user_data: *mut ::core::ffi::c_void,
    ),
>;
#[doc = " @brief client certificate verify callback\n\n @param certs[] X509 certificates in DER format\n @param cert_len[] lengths of X509 certificates in DER format\n @return 0 for success, -1 for verify failed and xquic will close the connection"]
pub type xqc_cert_verify_pt = ::core::option::Option<
    unsafe extern "C" fn(
        certs: *mut *const ::core::ffi::c_uchar,
        cert_len: *const usize,
        certs_len: usize,
        conn_user_data: *mut ::core::ffi::c_void,
    ) -> ::core::ffi::c_int,
>;
#[doc = " @brief server peer addr changed notify\n\n this function will be trigger after receive peer's changed addr.\n\n @param conn connection handler\n @param conn_user_data connection level user_data"]
pub type xqc_conn_peer_addr_changed_nofity_pt = ::core::option::Option<
    unsafe extern "C" fn(conn: *mut xqc_connection_t, conn_user_data: *mut ::core::ffi::c_void),
>;
#[doc = " @brief server peer addr changed notify\n\n this function will be trigger after receive peer's changed addr.\n\n @param conn connection handler\n @param path_id id of path\n @param conn_user_data connection level user_data"]
pub type xqc_path_peer_addr_changed_nofity_pt = ::core::option::Option<
    unsafe extern "C" fn(
        conn: *mut xqc_connection_t,
        path_id: u64,
        conn_user_data: *mut ::core::ffi::c_void,
    ),
>;
#[doc = " @brief writing data callback function\n\n @param buf  packet buffer\n @param size  packet size\n @param peer_addr  peer address\n @param peer_addrlen  peer address length\n @param conn_user_data user_data of connection\n @return bytes of data which is successfully sent:\n XQC_SOCKET_ERROR for error, xquic will destroy the connection\n XQC_SOCKET_EAGAIN for EAGAIN, application could continue sending data with\n xqc_conn_continue_send function when socket write event is ready"]
pub type xqc_socket_write_pt = ::core::option::Option<
    unsafe extern "C" fn(
        buf: *const ::core::ffi::c_uchar,
        size: usize,
        peer_addr: *const sockaddr,
        peer_addrlen: socklen_t,
        conn_user_data: *mut ::core::ffi::c_void,
    ) -> isize,
>;
#[doc = " @brief sendmmsg callback function. the implementation of this shall send data with\n sendmmsg\n\n @param msg_iov message vector\n @param vlen vector of messages\n @param peer_addr address of peer\n @param peer_addrlen  length of peer_addr param\n @param conn_user_data user_data of connection\n @return count of messages that are successfully sent:\n XQC_SOCKET_ERROR for error, xquic will destroy the connection\n XQC_SOCKET_EAGAIN for EAGAIN, application could continue sending data with\n xqc_conn_continue_send function when socket write event is ready Warning: server's\n user_data is what passed in xqc_engine_packet_process when send a stateless reset\n packet, as xquic can't find a connection"]
pub type xqc_send_mmsg_pt = ::core::option::Option<
    unsafe extern "C" fn(
        msg_iov: *const iovec,
        vlen: ::core::ffi::c_uint,
        peer_addr: *const sockaddr,
        peer_addrlen: socklen_t,
        conn_user_data: *mut ::core::ffi::c_void,
    ) -> isize,
>;
#[doc = " @brief set data callback mode for a transport connection. this mode differs\n from write_socket, which has a different user_data, once this callback\n function is set, write_socket will be not functional until it is unset.\n\n @param buf packet buffer\n @param size packet size\n @param peer_addr peer address\n @param peer_addrlen peer address length\n @param cb_user_data user_data of xqc_conn_pkt_filter_callback_pt"]
pub type xqc_conn_pkt_filter_callback_pt = ::core::option::Option<
    unsafe extern "C" fn(
        buf: *const ::core::ffi::c_uchar,
        size: usize,
        peer_addr: *const sockaddr,
        peer_addrlen: socklen_t,
        cb_user_data: *mut ::core::ffi::c_void,
    ) -> isize,
>;
#[doc = " @brief multi-path ready callback function\n\n this callback function will be triggered when a new connection id is received and\n endpoint get unused cids. it's a precondition of multi-path\n\n @param scid source connection id of endpoint\n @param conn_user_data user_data of connection"]
pub type xqc_conn_ready_to_create_path_notify_pt = ::core::option::Option<
    unsafe extern "C" fn(scid: *const xqc_cid_t, conn_user_data: *mut ::core::ffi::c_void),
>;
#[doc = " @brief get chain certs and key by sin"]
pub type xqc_conn_cert_cb_pt = ::core::option::Option<
    unsafe extern "C" fn(
        sni: *const ::core::ffi::c_char,
        chain: *mut *mut ::core::ffi::c_void,
        crt: *mut *mut ::core::ffi::c_void,
        key: *mut *mut ::core::ffi::c_void,
        user_data: *mut ::core::ffi::c_void,
    ) -> xqc_int_t,
>;
pub type xqc_conn_ssl_msg_cb_pt = ::core::option::Option<
    unsafe extern "C" fn(
        msg_type: ::core::ffi::c_int,
        msg: *const ::core::ffi::c_void,
        msg_len: usize,
        user_data: *mut ::core::ffi::c_void,
    ),
>;
#[doc = " @brief to determine whether to send a retry packet\n @return XQC_TRUE(1): meet condition to send a retry packet\n         XQC_FALSE(0): don't meet condition to send a retry packet or  an error occurred\n while judging the condition"]
pub type xqc_conn_retry_packet_pt = ::core::option::Option<
    unsafe extern "C" fn(
        engine: *mut xqc_engine_t,
        conn: *mut xqc_connection_t,
        cid: *const xqc_cid_t,
        user_data: *mut ::core::ffi::c_void,
    ) -> ::core::ffi::c_int,
>;
#[doc = " @brief multi-path create callback function\n\n @param conn connection handler\n @param scid source connection id of endpoint\n @param path_id id of path\n @param conn_user_data user_data of connection"]
pub type xqc_path_created_notify_pt = ::core::option::Option<
    unsafe extern "C" fn(
        conn: *mut xqc_connection_t,
        scid: *const xqc_cid_t,
        path_id: u64,
        conn_user_data: *mut ::core::ffi::c_void,
    ) -> ::core::ffi::c_int,
>;
#[doc = " @brief multi-path remove path callback function.\n\n this callback function will be triggered when path is closing\n and then the application-layer can release related resource.\n\n @param scid source connection id of endpoint\n @param path_id id of path\n @param conn_user_data user_data of connection"]
pub type xqc_path_removed_notify_pt = ::core::option::Option<
    unsafe extern "C" fn(
        scid: *const xqc_cid_t,
        path_id: u64,
        conn_user_data: *mut ::core::ffi::c_void,
    ),
>;
pub const XQC_PATH_DEGRADE: xqc_path_status_change_type_t = 0;
pub const XQC_PATH_RECOVERY: xqc_path_status_change_type_t = 1;
pub type xqc_path_status_change_type_t = ::core::ffi::c_uint;
#[doc = " @brief multi-path write socket callback function\n\n @param path_id path identifier\n @param conn_user_data user_data of connection\n @param buf packet buffer\n @param size packet size\n @param peer_addr peer address\n @param peer_addrlen peer address length\n @param conn_user_data user_data of connection\n @return bytes of data which is successfully sent to socket:\n XQC_SOCKET_ERROR for error, xquic will destroy the connection\n XQC_SOCKET_EAGAIN for EAGAIN, we should call xqc_conn_continue_send when socket is\n ready to write Warning: server's user_data is what passed in xqc_engine_packet_process\n when send a reset packet"]
pub type xqc_socket_write_ex_pt = ::core::option::Option<
    unsafe extern "C" fn(
        path_id: u64,
        buf: *const ::core::ffi::c_uchar,
        size: usize,
        peer_addr: *const sockaddr,
        peer_addrlen: socklen_t,
        conn_user_data: *mut ::core::ffi::c_void,
    ) -> isize,
>;
#[doc = " @brief multi-path write socket callback function with sendmmsg\n\n @param path_id path identifier\n @param msg_iov vector of messages\n @param vlen count of messages\n @param peer_addr peer address\n @param peer_addrlen peer address length\n @param conn_user_data user_data of connection, which was the parameter of xqc_connect\n set by client, or the parameter of xqc_conn_set_transport_user_data set by server\n @return bytes of data which is successfully sent to socket:\n XQC_SOCKET_ERROR for error, xquic will destroy the connection\n XQC_SOCKET_EAGAIN for EAGAIN, we should call xqc_conn_continue_send when socket is\n ready to write Warning: server's user_data is what passed in xqc_engine_packet_process\n when send a reset packet"]
pub type xqc_send_mmsg_ex_pt = ::core::option::Option<
    unsafe extern "C" fn(
        path_id: u64,
        msg_iov: *const iovec,
        vlen: ::core::ffi::c_uint,
        peer_addr: *const sockaddr,
        peer_addrlen: socklen_t,
        conn_user_data: *mut ::core::ffi::c_void,
    ) -> isize,
>;
#[doc = " @brief general callback function definition for stream create, close, read and write.\n\n @param stream QUIC stream handler\n @param strm_user_data stream level user_data, which was the parameter of\n xqc_stream_create set by client, or the parameter of xqc_stream_set_user_data set by\n server\n @return 0 for success, -1 for failure"]
pub type xqc_stream_notify_pt = ::core::option::Option<
    unsafe extern "C" fn(
        stream: *mut xqc_stream_t,
        strm_user_data: *mut ::core::ffi::c_void,
    ) -> xqc_int_t,
>;
#[doc = " @brief stream closing callback function, this will be triggered when some\n error on a stream happens.\n\n @param stream QUIC stream handler\n @param err_code error code\n @param strm_user_data stream level user_data, which was the parameter of\n xqc_stream_create set by client, or the parameter of xqc_stream_set_user_data set by\n server\n @return 0 for success, -1 for failure"]
pub type xqc_stream_closing_notify_pt = ::core::option::Option<
    unsafe extern "C" fn(
        stream: *mut xqc_stream_t,
        err_code: xqc_int_t,
        strm_user_data: *mut ::core::ffi::c_void,
    ),
>;
#[doc = " @brief the callback API to notify application that there is a datagram to be read\n\n @param conn the connection handle\n @param user_data the dgram_data set by xqc_datagram_set_user_data\n @param data the data delivered by this callback\n @param data_len the length of the delivered data\n @param dgram_recv_ts the unix timestamp when the datagram is received from socket"]
pub type xqc_datagram_read_notify_pt = ::core::option::Option<
    unsafe extern "C" fn(
        conn: *mut xqc_connection_t,
        user_data: *mut ::core::ffi::c_void,
        data: *const ::core::ffi::c_void,
        data_len: usize,
        unix_ts: u64,
    ),
>;
#[doc = " @brief the callback API to notify application that datagrams can be sent\n\n @param conn the connection handle\n @param user_data the dgram_data set by xqc_datagram_set_user_data"]
pub type xqc_datagram_write_notify_pt = ::core::option::Option<
    unsafe extern "C" fn(conn: *mut xqc_connection_t, user_data: *mut ::core::ffi::c_void),
>;
#[doc = " @brief the callback API to notify application that a datagram is declared lost.\n\n However, the datagram could also be acknowledged later, as the underlying\n loss detection is not fully accurate. Applications should handle this type of\n spurious loss. The return value indicates how this lost datagram is\n handled by the QUIC stack. NOTE, if the QUIC stack replicates the datagram\n (e.g. reinjection or retransmission), this callback can be triggered\n multiple times for a dgram_id.\n\n @param conn the connection handle\n @param user_data the dgram_data set by xqc_datagram_set_user_data\n @param dgram_id the id of the lost datagram\n @return 0: the stack will not retransmit the packet;\n         XQC_DGRAM_RETX_ASKED_BY_APP (1): the stack will retransmit the packet;\n         others are ignored by the QUIC stack."]
pub type xqc_datagram_lost_notify_pt = ::core::option::Option<
    unsafe extern "C" fn(
        conn: *mut xqc_connection_t,
        dgram_id: u64,
        user_data: *mut ::core::ffi::c_void,
    ) -> xqc_int_t,
>;
#[doc = " @brief the callback API to notify application that a datagram is acked. Note,\n for every unique dgram_id, this callback will be only called once.\n\n @param conn the connection handle\n @param user_data the dgram_data set by xqc_datagram_set_user_data\n @param dgram_id the id of the acked datagram"]
pub type xqc_datagram_acked_notify_pt = ::core::option::Option<
    unsafe extern "C" fn(
        conn: *mut xqc_connection_t,
        dgram_id: u64,
        user_data: *mut ::core::ffi::c_void,
    ),
>;
#[doc = " @brief the callback to notify application the MSS of QUIC datagrams. Note,\n the MSS of QUIC datagrams will never shrink. If the MSS is zero, it\n means this connection does not support sending QUIC datagrams.\n\n @param conn the connection handle\n @param user_data the dgram_data set by xqc_datagram_set_user_data\n @param mss the MSS of QUIC datagrams"]
pub type xqc_datagram_mss_updated_notify_pt = ::core::option::Option<
    unsafe extern "C" fn(
        conn: *mut xqc_connection_t,
        mss: usize,
        user_data: *mut ::core::ffi::c_void,
    ),
>;
#[doc = " @brief tranport callback functions are more related to attributes of QUIC [Transport]\n but not ALPN.\n\n These callback functions are events of QUIC Transport layer, and need to\n interact with application-layer, which have less thing to do with ALPN layer.\n\n These callback functions shall directly call back to application layer, with user_data\n from struct xqc_connection_t. unless Application-Layer-Protocol take over them.\n\n Generally, xquic defines callbacks as below:\n 1. Callbacks between Transport and Application:\n QUIC events that are common between different Application Protocols,\n and is much more convenient to interact with Application and Application Protocol.\n\n 2. Callbacks between Application Protocol and Application:\n Application-Protocol events will interact with Application Layer. these callback\n functions are defined by Application Protocol Layers.\n\n 3. Callbacks between Transport and Application Protocol:\n QUIC events that might be more essential to Application-Layer-Protocols, especially\n stream data\n\n +------------------------------------------------------------------------------+\n |                             Application                                      |\n |                                 +-- Application Protocol defined callbacks --+\n |                                 |             Application Protocol           |\n +-------- transport callbacks ----+--------- app protocol callbacks -----------+\n |                              Transport                                       |\n +------------------------------------------------------------------------------+"]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xqc_transport_callbacks_s {
    #[doc = " accept new connection callback. REQUIRED only for server \\n\n NOTICE: this is the headmost callback trigger by xquic, the user_data of\n server_accept is what was passed into xqc_engine_packet_process"]
    pub server_accept: xqc_server_accept_pt,
    #[doc = " connection refused by xquic. REQUIRED only for server"]
    pub server_refuse: xqc_server_refuse_pt,
    #[doc = " stateless reset callback"]
    pub stateless_reset: xqc_stateless_reset_pt,
    #[doc = " write socket callback, ALTERNATIVE with write_mmsg"]
    pub write_socket: xqc_socket_write_pt,
    #[doc = " write socket with send_mmsg callback, ALTERNATIVE with write_socket"]
    pub write_mmsg: xqc_send_mmsg_pt,
    #[doc = " write socket callback, ALTERNATIVE with write_mmsg"]
    pub write_socket_ex: xqc_socket_write_ex_pt,
    #[doc = " write socket with send_mmsg callback, ALTERNATIVE with write_socket"]
    pub write_mmsg_ex: xqc_send_mmsg_ex_pt,
    #[doc = " QUIC connection cid update callback, REQUIRED for both server and client"]
    pub conn_update_cid_notify: xqc_conn_update_cid_notify_pt,
    #[doc = " QUIC token callback. REQUIRED for client"]
    pub save_token: xqc_save_token_pt,
    #[doc = " tls session ticket callback. REQUIRED for client"]
    pub save_session_cb: xqc_save_session_pt,
    #[doc = " QUIC transport parameter callback. REQUIRED for client"]
    pub save_tp_cb: xqc_save_trans_param_pt,
    #[doc = " tls certificate verify callback. REQUIRED for client"]
    pub cert_verify_cb: xqc_cert_verify_pt,
    #[doc = " multi-path available callback. REQUIRED for client if multi-path is needed"]
    pub ready_to_create_path_notify: xqc_conn_ready_to_create_path_notify_pt,
    #[doc = " path create callback function. REQUIRED for server if multi-path is needed"]
    pub path_created_notify: xqc_path_created_notify_pt,
    #[doc = " path remove callback function. REQUIRED both for client and server if multi-path is\n needed"]
    pub path_removed_notify: xqc_path_removed_notify_pt,
    #[doc = " connection closing callback function. OPTIONAL for both client and server"]
    pub conn_closing: xqc_conn_closing_notify_pt,
    #[doc = " QUIC connection peer addr changed callback, REQUIRED for server."]
    pub conn_peer_addr_changed_notify: xqc_conn_peer_addr_changed_nofity_pt,
    #[doc = " QUIC path peer addr changed callback, REQUIRED for server."]
    pub path_peer_addr_changed_notify: xqc_path_peer_addr_changed_nofity_pt,
    #[doc = " @brief cert callback"]
    pub conn_cert_cb: xqc_conn_cert_cb_pt,
    pub conn_ssl_msg_cb: xqc_conn_ssl_msg_cb_pt,
    #[doc = " @brief check the conditions to send retry packet"]
    pub conn_retry_packet_condition_check: xqc_conn_retry_packet_pt,
    #[doc = " @brief server send packet before server accept the connection.\n for example, retry packet is sent when the application layer connection has not\n been established,"]
    pub conn_send_packet_before_accept: xqc_socket_write_pt,
}
#[allow(clippy::unnecessary_operation, clippy::identity_op)]
const _: () = {
    ["Size of xqc_transport_callbacks_s"]
        [::core::mem::size_of::<xqc_transport_callbacks_s>() - 176usize];
    ["Alignment of xqc_transport_callbacks_s"]
        [::core::mem::align_of::<xqc_transport_callbacks_s>() - 8usize];
    ["Offset of field: xqc_transport_callbacks_s::server_accept"]
        [::core::mem::offset_of!(xqc_transport_callbacks_s, server_accept) - 0usize];
    ["Offset of field: xqc_transport_callbacks_s::server_refuse"]
        [::core::mem::offset_of!(xqc_transport_callbacks_s, server_refuse) - 8usize];
    ["Offset of field: xqc_transport_callbacks_s::stateless_reset"]
        [::core::mem::offset_of!(xqc_transport_callbacks_s, stateless_reset) - 16usize];
    ["Offset of field: xqc_transport_callbacks_s::write_socket"]
        [::core::mem::offset_of!(xqc_transport_callbacks_s, write_socket) - 24usize];
    ["Offset of field: xqc_transport_callbacks_s::write_mmsg"]
        [::core::mem::offset_of!(xqc_transport_callbacks_s, write_mmsg) - 32usize];
    ["Offset of field: xqc_transport_callbacks_s::write_socket_ex"]
        [::core::mem::offset_of!(xqc_transport_callbacks_s, write_socket_ex) - 40usize];
    ["Offset of field: xqc_transport_callbacks_s::write_mmsg_ex"]
        [::core::mem::offset_of!(xqc_transport_callbacks_s, write_mmsg_ex) - 48usize];
    ["Offset of field: xqc_transport_callbacks_s::conn_update_cid_notify"]
        [::core::mem::offset_of!(xqc_transport_callbacks_s, conn_update_cid_notify) - 56usize];
    ["Offset of field: xqc_transport_callbacks_s::save_token"]
        [::core::mem::offset_of!(xqc_transport_callbacks_s, save_token) - 64usize];
    ["Offset of field: xqc_transport_callbacks_s::save_session_cb"]
        [::core::mem::offset_of!(xqc_transport_callbacks_s, save_session_cb) - 72usize];
    ["Offset of field: xqc_transport_callbacks_s::save_tp_cb"]
        [::core::mem::offset_of!(xqc_transport_callbacks_s, save_tp_cb) - 80usize];
    ["Offset of field: xqc_transport_callbacks_s::cert_verify_cb"]
        [::core::mem::offset_of!(xqc_transport_callbacks_s, cert_verify_cb) - 88usize];
    ["Offset of field: xqc_transport_callbacks_s::ready_to_create_path_notify"]
        [::core::mem::offset_of!(xqc_transport_callbacks_s, ready_to_create_path_notify) - 96usize];
    ["Offset of field: xqc_transport_callbacks_s::path_created_notify"]
        [::core::mem::offset_of!(xqc_transport_callbacks_s, path_created_notify) - 104usize];
    ["Offset of field: xqc_transport_callbacks_s::path_removed_notify"]
        [::core::mem::offset_of!(xqc_transport_callbacks_s, path_removed_notify) - 112usize];
    ["Offset of field: xqc_transport_callbacks_s::conn_closing"]
        [::core::mem::offset_of!(xqc_transport_callbacks_s, conn_closing) - 120usize];
    ["Offset of field: xqc_transport_callbacks_s::conn_peer_addr_changed_notify"][::core::mem::offset_of!(
        xqc_transport_callbacks_s,
        conn_peer_addr_changed_notify
    ) - 128usize];
    ["Offset of field: xqc_transport_callbacks_s::path_peer_addr_changed_notify"][::core::mem::offset_of!(
        xqc_transport_callbacks_s,
        path_peer_addr_changed_notify
    ) - 136usize];
    ["Offset of field: xqc_transport_callbacks_s::conn_cert_cb"]
        [::core::mem::offset_of!(xqc_transport_callbacks_s, conn_cert_cb) - 144usize];
    ["Offset of field: xqc_transport_callbacks_s::conn_ssl_msg_cb"]
        [::core::mem::offset_of!(xqc_transport_callbacks_s, conn_ssl_msg_cb) - 152usize];
    ["Offset of field: xqc_transport_callbacks_s::conn_retry_packet_condition_check"][::core::mem::offset_of!(
        xqc_transport_callbacks_s,
        conn_retry_packet_condition_check
    ) - 160usize];
    ["Offset of field: xqc_transport_callbacks_s::conn_send_packet_before_accept"][::core::mem::offset_of!(
        xqc_transport_callbacks_s,
        conn_send_packet_before_accept
    ) - 168usize];
};
#[doc = " @brief QUIC connection callback functions for Application-layer-Protocol."]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xqc_conn_callbacks_s {
    #[doc = " connection create notify callback. REQUIRED for server, OPTIONAL for client.\n\n this function will be invoked after connection is created, user can create\n application layer context in this callback function\n\n return 0 for success, -1 for failure, e.g. malloc error, on which xquic will close\n connection"]
    pub conn_create_notify: xqc_conn_notify_pt,
    #[doc = " connection close notify. REQUIRED for both client and server\n\n this function will be invoked after QUIC connection is closed. user can free\n application level context created in conn_create_notify callback function"]
    pub conn_close_notify: xqc_conn_notify_pt,
    #[doc = " handshake complete callback. OPTIONAL for client and server"]
    pub conn_handshake_finished: xqc_handshake_finished_pt,
    #[doc = " active PING acked callback. OPTIONAL for both client and server"]
    pub conn_ping_acked: xqc_conn_ping_ack_notify_pt,
}
#[allow(clippy::unnecessary_operation, clippy::identity_op)]
const _: () = {
    ["Size of xqc_conn_callbacks_s"][::core::mem::size_of::<xqc_conn_callbacks_s>() - 32usize];
    ["Alignment of xqc_conn_callbacks_s"][::core::mem::align_of::<xqc_conn_callbacks_s>() - 8usize];
    ["Offset of field: xqc_conn_callbacks_s::conn_create_notify"]
        [::core::mem::offset_of!(xqc_conn_callbacks_s, conn_create_notify) - 0usize];
    ["Offset of field: xqc_conn_callbacks_s::conn_close_notify"]
        [::core::mem::offset_of!(xqc_conn_callbacks_s, conn_close_notify) - 8usize];
    ["Offset of field: xqc_conn_callbacks_s::conn_handshake_finished"]
        [::core::mem::offset_of!(xqc_conn_callbacks_s, conn_handshake_finished) - 16usize];
    ["Offset of field: xqc_conn_callbacks_s::conn_ping_acked"]
        [::core::mem::offset_of!(xqc_conn_callbacks_s, conn_ping_acked) - 24usize];
};
#[doc = " @brief QUIC connection callback functions for Application-layer-Protocol."]
pub type xqc_conn_callbacks_t = xqc_conn_callbacks_s;
#[doc = " @brief QUIC layer stream callback functions"]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xqc_stream_callbacks_s {
    #[doc = " @brief stream read callback function. REQUIRED for both client and server\n\n this will be triggered when QUIC stream data is ready for read. application layer\n could read data when xqc_stream_recv interface."]
    pub stream_read_notify: xqc_stream_notify_pt,
    #[doc = " @brief stream write callback function. REQUIRED for both client and server\n\n when sending data with xqc_stream_send, xquic might be blocked or send part of the\n data. if this callback function is triggered, applications can continue to send the\n rest data."]
    pub stream_write_notify: xqc_stream_notify_pt,
    #[doc = " @brief stream create callback function. REQUIRED for server, OPTIONAL for client.\n\n this will be triggered when QUIC stream is created. applications can create its own\n stream context in this callback function."]
    pub stream_create_notify: xqc_stream_notify_pt,
    #[doc = " @brief stream close callback function. REQUIRED for both server and client.\n\n this will be triggered when QUIC stream is finally closed. xquic will close stream\n after sending or receiving RESET_STREAM frame after 3 times of PTO, or when\n connection is closed. Applications can free the context which was created in\n stream_create_notify here."]
    pub stream_close_notify: xqc_stream_notify_pt,
    #[doc = " @brief stream reset callback function. OPTIONAL for both server and client\n\n this function will be triggered when a RESET_STREAM frame is received."]
    pub stream_closing_notify: xqc_stream_closing_notify_pt,
}
#[allow(clippy::unnecessary_operation, clippy::identity_op)]
const _: () = {
    ["Size of xqc_stream_callbacks_s"][::core::mem::size_of::<xqc_stream_callbacks_s>() - 40usize];
    ["Alignment of xqc_stream_callbacks_s"]
        [::core::mem::align_of::<xqc_stream_callbacks_s>() - 8usize];
    ["Offset of field: xqc_stream_callbacks_s::stream_read_notify"]
        [::core::mem::offset_of!(xqc_stream_callbacks_s, stream_read_notify) - 0usize];
    ["Offset of field: xqc_stream_callbacks_s::stream_write_notify"]
        [::core::mem::offset_of!(xqc_stream_callbacks_s, stream_write_notify) - 8usize];
    ["Offset of field: xqc_stream_callbacks_s::stream_create_notify"]
        [::core::mem::offset_of!(xqc_stream_callbacks_s, stream_create_notify) - 16usize];
    ["Offset of field: xqc_stream_callbacks_s::stream_close_notify"]
        [::core::mem::offset_of!(xqc_stream_callbacks_s, stream_close_notify) - 24usize];
    ["Offset of field: xqc_stream_callbacks_s::stream_closing_notify"]
        [::core::mem::offset_of!(xqc_stream_callbacks_s, stream_closing_notify) - 32usize];
};
#[doc = " @brief QUIC layer stream callback functions"]
pub type xqc_stream_callbacks_t = xqc_stream_callbacks_s;
#[doc = " @brief QUIC layer datagram callback functions"]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xqc_datagram_callbacks_s {
    #[doc = " @brief datagram read callback function. REQUIRED for both client and server if they\n want to use datagram\n\n this will be triggered when a QUIC datagram is received. application layer could\n read data from the arguments of this callback."]
    pub datagram_read_notify: xqc_datagram_read_notify_pt,
    #[doc = " @brief datagram write callback function. REQUIRED for both client and server if\n they want to use datagram\n\n when sending data with xqc_datagram_send or xqc_datagram_send_multiple, xquic might\n be blocked or send part of the data. if this callback function is triggered,\n applications can continue to send the rest data."]
    pub datagram_write_notify: xqc_datagram_write_notify_pt,
    #[doc = " @brief datagram acked callback function. OPTIONAL for server and client.\n\n this will be triggered when a QUIC packet containing a DATAGRAM frame is acked."]
    pub datagram_acked_notify: xqc_datagram_acked_notify_pt,
    #[doc = " @brief datagram lost callback function. OPTIONAL for server and client.\n\n this will be triggered when a QUIC packet containing a DATAGRAM frame is lost."]
    pub datagram_lost_notify: xqc_datagram_lost_notify_pt,
    pub datagram_mss_updated_notify: xqc_datagram_mss_updated_notify_pt,
}
#[allow(clippy::unnecessary_operation, clippy::identity_op)]
const _: () = {
    ["Size of xqc_datagram_callbacks_s"]
        [::core::mem::size_of::<xqc_datagram_callbacks_s>() - 40usize];
    ["Alignment of xqc_datagram_callbacks_s"]
        [::core::mem::align_of::<xqc_datagram_callbacks_s>() - 8usize];
    ["Offset of field: xqc_datagram_callbacks_s::datagram_read_notify"]
        [::core::mem::offset_of!(xqc_datagram_callbacks_s, datagram_read_notify) - 0usize];
    ["Offset of field: xqc_datagram_callbacks_s::datagram_write_notify"]
        [::core::mem::offset_of!(xqc_datagram_callbacks_s, datagram_write_notify) - 8usize];
    ["Offset of field: xqc_datagram_callbacks_s::datagram_acked_notify"]
        [::core::mem::offset_of!(xqc_datagram_callbacks_s, datagram_acked_notify) - 16usize];
    ["Offset of field: xqc_datagram_callbacks_s::datagram_lost_notify"]
        [::core::mem::offset_of!(xqc_datagram_callbacks_s, datagram_lost_notify) - 24usize];
    ["Offset of field: xqc_datagram_callbacks_s::datagram_mss_updated_notify"]
        [::core::mem::offset_of!(xqc_datagram_callbacks_s, datagram_mss_updated_notify) - 32usize];
};
#[doc = " @brief QUIC layer datagram callback functions"]
pub type xqc_datagram_callbacks_t = xqc_datagram_callbacks_s;
#[doc = " @brief connection and stream callbacks for QUIC level, Application-Layer-Protocol shall\n implement these callback functions and register ALP with xqc_engine_register_alpn"]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xqc_app_proto_callbacks_s {
    #[doc = " @brief QUIC connection callback functions for Application-Layer-Protocol"]
    pub conn_cbs: xqc_conn_callbacks_t,
    #[doc = " @brief QUIC stream callback functions"]
    pub stream_cbs: xqc_stream_callbacks_t,
    #[doc = "  @brief QUIC datagram callback functions"]
    pub dgram_cbs: xqc_datagram_callbacks_t,
}
#[allow(clippy::unnecessary_operation, clippy::identity_op)]
const _: () = {
    ["Size of xqc_app_proto_callbacks_s"]
        [::core::mem::size_of::<xqc_app_proto_callbacks_s>() - 112usize];
    ["Alignment of xqc_app_proto_callbacks_s"]
        [::core::mem::align_of::<xqc_app_proto_callbacks_s>() - 8usize];
    ["Offset of field: xqc_app_proto_callbacks_s::conn_cbs"]
        [::core::mem::offset_of!(xqc_app_proto_callbacks_s, conn_cbs) - 0usize];
    ["Offset of field: xqc_app_proto_callbacks_s::stream_cbs"]
        [::core::mem::offset_of!(xqc_app_proto_callbacks_s, stream_cbs) - 32usize];
    ["Offset of field: xqc_app_proto_callbacks_s::dgram_cbs"]
        [::core::mem::offset_of!(xqc_app_proto_callbacks_s, dgram_cbs) - 72usize];
};
#[doc = " @brief connection and stream callbacks for QUIC level, Application-Layer-Protocol shall\n implement these callback functions and register ALP with xqc_engine_register_alpn"]
pub type xqc_app_proto_callbacks_t = xqc_app_proto_callbacks_s;
pub const XQC_DATA_QOS_HIGHEST: xqc_data_qos_level_t = 1;
pub const XQC_DATA_QOS_HIGH: xqc_data_qos_level_t = 2;
pub const XQC_DATA_QOS_MEDIUM: xqc_data_qos_level_t = 3;
pub const XQC_DATA_QOS_NORMAL: xqc_data_qos_level_t = 4;
pub const XQC_DATA_QOS_LOW: xqc_data_qos_level_t = 5;
pub const XQC_DATA_QOS_LOWEST: xqc_data_qos_level_t = 6;
pub const XQC_DATA_QOS_PROBING: xqc_data_qos_level_t = 7;
pub type xqc_data_qos_level_t = ::core::ffi::c_uint;
#[doc = " @brief congestion control algorithm parameters"]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xqc_cc_params_s {
    pub customize_on: u32,
    pub init_cwnd: u32,
    pub min_cwnd: u32,
    pub expect_bw: u32,
    pub max_expect_bw: u32,
    pub bbr_enable_lt_bw: u8,
    pub bbr_ignore_app_limit: u8,
    pub cc_optimization_flags: u32,
    #[doc = " 0 < delta <= delta_max, default 0.05, ->0 = more throughput-oriented"]
    pub copa_delta_base: f64,
    #[doc = " 0 < delta_max <= 1.0, default 0.5"]
    pub copa_delta_max: f64,
    #[doc = " 1.0 <= delta_ai_unit, default 1.0, greater values mean more aggressive\n when Copa competes with loss-based CCAs."]
    pub copa_delta_ai_unit: f64,
}
#[allow(clippy::unnecessary_operation, clippy::identity_op)]
const _: () = {
    ["Size of xqc_cc_params_s"][::core::mem::size_of::<xqc_cc_params_s>() - 56usize];
    ["Alignment of xqc_cc_params_s"][::core::mem::align_of::<xqc_cc_params_s>() - 8usize];
    ["Offset of field: xqc_cc_params_s::customize_on"]
        [::core::mem::offset_of!(xqc_cc_params_s, customize_on) - 0usize];
    ["Offset of field: xqc_cc_params_s::init_cwnd"]
        [::core::mem::offset_of!(xqc_cc_params_s, init_cwnd) - 4usize];
    ["Offset of field: xqc_cc_params_s::min_cwnd"]
        [::core::mem::offset_of!(xqc_cc_params_s, min_cwnd) - 8usize];
    ["Offset of field: xqc_cc_params_s::expect_bw"]
        [::core::mem::offset_of!(xqc_cc_params_s, expect_bw) - 12usize];
    ["Offset of field: xqc_cc_params_s::max_expect_bw"]
        [::core::mem::offset_of!(xqc_cc_params_s, max_expect_bw) - 16usize];
    ["Offset of field: xqc_cc_params_s::bbr_enable_lt_bw"]
        [::core::mem::offset_of!(xqc_cc_params_s, bbr_enable_lt_bw) - 20usize];
    ["Offset of field: xqc_cc_params_s::bbr_ignore_app_limit"]
        [::core::mem::offset_of!(xqc_cc_params_s, bbr_ignore_app_limit) - 21usize];
    ["Offset of field: xqc_cc_params_s::cc_optimization_flags"]
        [::core::mem::offset_of!(xqc_cc_params_s, cc_optimization_flags) - 24usize];
    ["Offset of field: xqc_cc_params_s::copa_delta_base"]
        [::core::mem::offset_of!(xqc_cc_params_s, copa_delta_base) - 32usize];
    ["Offset of field: xqc_cc_params_s::copa_delta_max"]
        [::core::mem::offset_of!(xqc_cc_params_s, copa_delta_max) - 40usize];
    ["Offset of field: xqc_cc_params_s::copa_delta_ai_unit"]
        [::core::mem::offset_of!(xqc_cc_params_s, copa_delta_ai_unit) - 48usize];
};
#[doc = " @brief congestion control algorithm parameters"]
pub type xqc_cc_params_t = xqc_cc_params_s;
#[doc = " @brief multipath scheduler algorithm parameters"]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xqc_scheduler_params_u {
    pub rtt_us_thr_high: u64,
    pub rtt_us_thr_low: u64,
    pub bw_Bps_thr: u64,
    pub loss_percent_thr_high: f64,
    pub loss_percent_thr_low: f64,
    pub pto_cnt_thr: u32,
}
#[allow(clippy::unnecessary_operation, clippy::identity_op)]
const _: () = {
    ["Size of xqc_scheduler_params_u"][::core::mem::size_of::<xqc_scheduler_params_u>() - 48usize];
    ["Alignment of xqc_scheduler_params_u"]
        [::core::mem::align_of::<xqc_scheduler_params_u>() - 8usize];
    ["Offset of field: xqc_scheduler_params_u::rtt_us_thr_high"]
        [::core::mem::offset_of!(xqc_scheduler_params_u, rtt_us_thr_high) - 0usize];
    ["Offset of field: xqc_scheduler_params_u::rtt_us_thr_low"]
        [::core::mem::offset_of!(xqc_scheduler_params_u, rtt_us_thr_low) - 8usize];
    ["Offset of field: xqc_scheduler_params_u::bw_Bps_thr"]
        [::core::mem::offset_of!(xqc_scheduler_params_u, bw_Bps_thr) - 16usize];
    ["Offset of field: xqc_scheduler_params_u::loss_percent_thr_high"]
        [::core::mem::offset_of!(xqc_scheduler_params_u, loss_percent_thr_high) - 24usize];
    ["Offset of field: xqc_scheduler_params_u::loss_percent_thr_low"]
        [::core::mem::offset_of!(xqc_scheduler_params_u, loss_percent_thr_low) - 32usize];
    ["Offset of field: xqc_scheduler_params_u::pto_cnt_thr"]
        [::core::mem::offset_of!(xqc_scheduler_params_u, pto_cnt_thr) - 40usize];
};
#[doc = " @brief multipath scheduler algorithm parameters"]
pub type xqc_scheduler_params_t = xqc_scheduler_params_u;
pub const XQC_REED_SOLOMON_CODE: xqc_fec_schemes_e = 8;
pub const XQC_XOR_CODE: xqc_fec_schemes_e = 11;
pub const XQC_PACKET_MASK_CODE: xqc_fec_schemes_e = 12;
#[doc = " @brief FEC schemes type enum"]
pub type xqc_fec_schemes_e = ::core::ffi::c_uint;
pub const XQC_FEC_MP_DEFAULT: xqc_fec_mp_mode_e = 0;
pub const XQC_FEC_MP_USE_STB: xqc_fec_mp_mode_e = 1;
pub type xqc_fec_mp_mode_e = ::core::ffi::c_uint;
pub const XQC_FEC_RANDOM_TBL: xqc_fec_tbl_mode_e = 0;
pub const XQC_FEC_BURST_TBL: xqc_fec_tbl_mode_e = 1;
pub type xqc_fec_tbl_mode_e = ::core::ffi::c_uint;
#[doc = " @brief FEC parameters on connection settings"]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xqc_fec_params_s {
    #[doc = " code rate represents the source symbol percents in total symbols"]
    pub fec_code_rate: f32,
    #[doc = " element bit size of current fec finite filed"]
    pub fec_ele_bit_size: xqc_int_t,
    #[doc = " frame type that should be protected by fec"]
    pub fec_protected_frames: u64,
    #[doc = " maximum number of block that current host can store"]
    pub fec_max_window_size: u64,
    #[doc = " (B) maximum symbol number of each block"]
    pub fec_max_symbol_num_per_block: u64,
    #[doc = " fec specific mp mode"]
    pub fec_mp_mode: xqc_fec_mp_mode_e,
    pub fec_log_on: xqc_bool_t,
    pub fec_encoder_schemes_num: xqc_int_t,
    pub fec_decoder_schemes_num: xqc_int_t,
    #[doc = " fec schemes supported by current host as encoder"]
    pub fec_encoder_schemes: [xqc_fec_schemes_e; 5usize],
    #[doc = " fec schemes supported by current host as decoder"]
    pub fec_decoder_schemes: [xqc_fec_schemes_e; 5usize],
    #[doc = " final fec scheme as encoder after negotiation"]
    pub fec_encoder_scheme: xqc_fec_schemes_e,
    #[doc = " final fec scheme as decoder after negotiation"]
    pub fec_decoder_scheme: xqc_fec_schemes_e,
    pub fec_blk_log_mod: xqc_flag_t,
    pub fec_packet_mask_mode: xqc_fec_tbl_mode_e,
}
#[allow(clippy::unnecessary_operation, clippy::identity_op)]
const _: () = {
    ["Size of xqc_fec_params_s"][::core::mem::size_of::<xqc_fec_params_s>() - 112usize];
    ["Alignment of xqc_fec_params_s"][::core::mem::align_of::<xqc_fec_params_s>() - 8usize];
    ["Offset of field: xqc_fec_params_s::fec_code_rate"]
        [::core::mem::offset_of!(xqc_fec_params_s, fec_code_rate) - 0usize];
    ["Offset of field: xqc_fec_params_s::fec_ele_bit_size"]
        [::core::mem::offset_of!(xqc_fec_params_s, fec_ele_bit_size) - 4usize];
    ["Offset of field: xqc_fec_params_s::fec_protected_frames"]
        [::core::mem::offset_of!(xqc_fec_params_s, fec_protected_frames) - 8usize];
    ["Offset of field: xqc_fec_params_s::fec_max_window_size"]
        [::core::mem::offset_of!(xqc_fec_params_s, fec_max_window_size) - 16usize];
    ["Offset of field: xqc_fec_params_s::fec_max_symbol_num_per_block"]
        [::core::mem::offset_of!(xqc_fec_params_s, fec_max_symbol_num_per_block) - 24usize];
    ["Offset of field: xqc_fec_params_s::fec_mp_mode"]
        [::core::mem::offset_of!(xqc_fec_params_s, fec_mp_mode) - 32usize];
    ["Offset of field: xqc_fec_params_s::fec_log_on"]
        [::core::mem::offset_of!(xqc_fec_params_s, fec_log_on) - 36usize];
    ["Offset of field: xqc_fec_params_s::fec_encoder_schemes_num"]
        [::core::mem::offset_of!(xqc_fec_params_s, fec_encoder_schemes_num) - 40usize];
    ["Offset of field: xqc_fec_params_s::fec_decoder_schemes_num"]
        [::core::mem::offset_of!(xqc_fec_params_s, fec_decoder_schemes_num) - 44usize];
    ["Offset of field: xqc_fec_params_s::fec_encoder_schemes"]
        [::core::mem::offset_of!(xqc_fec_params_s, fec_encoder_schemes) - 48usize];
    ["Offset of field: xqc_fec_params_s::fec_decoder_schemes"]
        [::core::mem::offset_of!(xqc_fec_params_s, fec_decoder_schemes) - 68usize];
    ["Offset of field: xqc_fec_params_s::fec_encoder_scheme"]
        [::core::mem::offset_of!(xqc_fec_params_s, fec_encoder_scheme) - 88usize];
    ["Offset of field: xqc_fec_params_s::fec_decoder_scheme"]
        [::core::mem::offset_of!(xqc_fec_params_s, fec_decoder_scheme) - 92usize];
    ["Offset of field: xqc_fec_params_s::fec_blk_log_mod"]
        [::core::mem::offset_of!(xqc_fec_params_s, fec_blk_log_mod) - 96usize];
    ["Offset of field: xqc_fec_params_s::fec_packet_mask_mode"]
        [::core::mem::offset_of!(xqc_fec_params_s, fec_packet_mask_mode) - 104usize];
};
#[doc = " @brief FEC parameters on connection settings"]
pub type xqc_fec_params_t = xqc_fec_params_s;
#[doc = " @brief congestion control callbacks"]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xqc_congestion_control_callback_s {
    #[doc = " Callback on initialization, for memory allocation"]
    pub xqc_cong_ctl_size: ::core::option::Option<unsafe extern "C" fn() -> usize>,
    #[doc = " Callback on connection initialization, support for passing in congestion algorithm\n parameters"]
    pub xqc_cong_ctl_init: ::core::option::Option<
        unsafe extern "C" fn(
            cong_ctl: *mut ::core::ffi::c_void,
            ctl_ctx: *mut xqc_send_ctl_t,
            cc_params: xqc_cc_params_t,
        ),
    >,
    #[doc = " Callback when packet loss is detected, reduce congestion window according to\n algorithm"]
    pub xqc_cong_ctl_on_lost: ::core::option::Option<
        unsafe extern "C" fn(cong_ctl: *mut ::core::ffi::c_void, lost_sent_time: xqc_usec_t),
    >,
    #[doc = " Callback when packet acked, increase congestion window according to algorithm"]
    pub xqc_cong_ctl_on_ack: ::core::option::Option<
        unsafe extern "C" fn(
            cong_ctl: *mut ::core::ffi::c_void,
            po: *mut xqc_packet_out_t,
            now: xqc_usec_t,
        ),
    >,
    #[doc = " Callback when sending a packet, to determine if the packet can be sent"]
    pub xqc_cong_ctl_get_cwnd:
        ::core::option::Option<unsafe extern "C" fn(cong_ctl: *mut ::core::ffi::c_void) -> u64>,
    #[doc = " Callback when all packets are detected as lost within 1-RTT, reset the congestion\n window"]
    pub xqc_cong_ctl_reset_cwnd:
        ::core::option::Option<unsafe extern "C" fn(cong_ctl: *mut ::core::ffi::c_void)>,
    #[doc = " If the connection is in slow start state"]
    pub xqc_cong_ctl_in_slow_start: ::core::option::Option<
        unsafe extern "C" fn(cong_ctl: *mut ::core::ffi::c_void) -> ::core::ffi::c_int,
    >,
    #[doc = " If the connection is in recovery state."]
    pub xqc_cong_ctl_in_recovery: ::core::option::Option<
        unsafe extern "C" fn(cong_ctl: *mut ::core::ffi::c_void) -> ::core::ffi::c_int,
    >,
    #[doc = " This function is used by BBR and Cubic"]
    pub xqc_cong_ctl_restart_from_idle:
        ::core::option::Option<unsafe extern "C" fn(cong_ctl: *mut ::core::ffi::c_void, arg: u64)>,
    #[doc = " For BBR"]
    pub xqc_cong_ctl_on_ack_multiple_pkts: ::core::option::Option<
        unsafe extern "C" fn(cong_ctl: *mut ::core::ffi::c_void, sampler: *mut xqc_sample_t),
    >,
    #[doc = " initialize bbr"]
    pub xqc_cong_ctl_init_bbr: ::core::option::Option<
        unsafe extern "C" fn(
            cong_ctl: *mut ::core::ffi::c_void,
            sampler: *mut xqc_sample_t,
            cc_params: xqc_cc_params_t,
        ),
    >,
    #[doc = " get pacing rate"]
    pub xqc_cong_ctl_get_pacing_rate:
        ::core::option::Option<unsafe extern "C" fn(cong_ctl: *mut ::core::ffi::c_void) -> u32>,
    #[doc = " get estimation of bandwidth"]
    pub xqc_cong_ctl_get_bandwidth_estimate:
        ::core::option::Option<unsafe extern "C" fn(cong_ctl: *mut ::core::ffi::c_void) -> u32>,
    pub xqc_cong_ctl_info_cb: *mut xqc_bbr_info_interface_t,
}
#[allow(clippy::unnecessary_operation, clippy::identity_op)]
const _: () = {
    ["Size of xqc_congestion_control_callback_s"]
        [::core::mem::size_of::<xqc_congestion_control_callback_s>() - 112usize];
    ["Alignment of xqc_congestion_control_callback_s"]
        [::core::mem::align_of::<xqc_congestion_control_callback_s>() - 8usize];
    ["Offset of field: xqc_congestion_control_callback_s::xqc_cong_ctl_size"]
        [::core::mem::offset_of!(xqc_congestion_control_callback_s, xqc_cong_ctl_size) - 0usize];
    ["Offset of field: xqc_congestion_control_callback_s::xqc_cong_ctl_init"]
        [::core::mem::offset_of!(xqc_congestion_control_callback_s, xqc_cong_ctl_init) - 8usize];
    ["Offset of field: xqc_congestion_control_callback_s::xqc_cong_ctl_on_lost"][::core::mem::offset_of!(
        xqc_congestion_control_callback_s,
        xqc_cong_ctl_on_lost
    ) - 16usize];
    ["Offset of field: xqc_congestion_control_callback_s::xqc_cong_ctl_on_ack"]
        [::core::mem::offset_of!(xqc_congestion_control_callback_s, xqc_cong_ctl_on_ack) - 24usize];
    ["Offset of field: xqc_congestion_control_callback_s::xqc_cong_ctl_get_cwnd"][::core::mem::offset_of!(
        xqc_congestion_control_callback_s,
        xqc_cong_ctl_get_cwnd
    ) - 32usize];
    ["Offset of field: xqc_congestion_control_callback_s::xqc_cong_ctl_reset_cwnd"][::core::mem::offset_of!(
        xqc_congestion_control_callback_s,
        xqc_cong_ctl_reset_cwnd
    ) - 40usize];
    ["Offset of field: xqc_congestion_control_callback_s::xqc_cong_ctl_in_slow_start"][::core::mem::offset_of!(
        xqc_congestion_control_callback_s,
        xqc_cong_ctl_in_slow_start
    ) - 48usize];
    ["Offset of field: xqc_congestion_control_callback_s::xqc_cong_ctl_in_recovery"][::core::mem::offset_of!(
        xqc_congestion_control_callback_s,
        xqc_cong_ctl_in_recovery
    ) - 56usize];
    ["Offset of field: xqc_congestion_control_callback_s::xqc_cong_ctl_restart_from_idle"][::core::mem::offset_of!(
        xqc_congestion_control_callback_s,
        xqc_cong_ctl_restart_from_idle
    )
        - 64usize];
    ["Offset of field: xqc_congestion_control_callback_s::xqc_cong_ctl_on_ack_multiple_pkts"][::core::mem::offset_of!(
        xqc_congestion_control_callback_s,
        xqc_cong_ctl_on_ack_multiple_pkts
    )
        - 72usize];
    ["Offset of field: xqc_congestion_control_callback_s::xqc_cong_ctl_init_bbr"][::core::mem::offset_of!(
        xqc_congestion_control_callback_s,
        xqc_cong_ctl_init_bbr
    ) - 80usize];
    ["Offset of field: xqc_congestion_control_callback_s::xqc_cong_ctl_get_pacing_rate"][::core::mem::offset_of!(
        xqc_congestion_control_callback_s,
        xqc_cong_ctl_get_pacing_rate
    )
        - 88usize];
    ["Offset of field: xqc_congestion_control_callback_s::xqc_cong_ctl_get_bandwidth_estimate"][::core::mem::offset_of!(
        xqc_congestion_control_callback_s,
        xqc_cong_ctl_get_bandwidth_estimate
    )
        - 96usize];
    ["Offset of field: xqc_congestion_control_callback_s::xqc_cong_ctl_info_cb"][::core::mem::offset_of!(
        xqc_congestion_control_callback_s,
        xqc_cong_ctl_info_cb
    ) - 104usize];
};
#[doc = " @brief congestion control callbacks"]
pub type xqc_cong_ctrl_callback_t = xqc_congestion_control_callback_s;
unsafe extern "C" {
    pub static xqc_bbr2_cb: xqc_cong_ctrl_callback_t;
}
unsafe extern "C" {
    pub static xqc_bbr_cb: xqc_cong_ctrl_callback_t;
}
unsafe extern "C" {
    pub static xqc_cubic_cb: xqc_cong_ctrl_callback_t;
}
unsafe extern "C" {
    pub static xqc_unlimited_cc_cb: xqc_cong_ctrl_callback_t;
}
pub const XQC_SCHED_EVENT_PATH_NOT_FULL: xqc_scheduler_path_event_e = 0;
pub type xqc_scheduler_path_event_e = ::core::ffi::c_uint;
pub use self::xqc_scheduler_path_event_e as xqc_scheduler_path_event_t;
pub const XQC_SCHED_EVENT_CONN_ROUND_START: xqc_scheduler_conn_event_e = 0;
pub const XQC_SCHED_EVENT_CONN_ROUND_FIN: xqc_scheduler_conn_event_e = 1;
pub type xqc_scheduler_conn_event_e = ::core::ffi::c_uint;
pub use self::xqc_scheduler_conn_event_e as xqc_scheduler_conn_event_t;
#[doc = " @brief multipath scheduler callbacks"]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xqc_scheduler_callback_s {
    pub xqc_scheduler_size: ::core::option::Option<unsafe extern "C" fn() -> usize>,
    pub xqc_scheduler_init: ::core::option::Option<
        unsafe extern "C" fn(
            scheduler: *mut ::core::ffi::c_void,
            log: *mut xqc_log_t,
            params: *mut xqc_scheduler_params_t,
        ),
    >,
    pub xqc_scheduler_get_path: ::core::option::Option<
        unsafe extern "C" fn(
            scheduler: *mut ::core::ffi::c_void,
            conn: *mut xqc_connection_t,
            packet_out: *mut xqc_packet_out_t,
            check_cwnd: ::core::ffi::c_int,
            reinject: ::core::ffi::c_int,
            cc_blocked: *mut xqc_bool_t,
        ) -> *mut xqc_path_ctx_t,
    >,
    pub xqc_scheduler_handle_path_event: ::core::option::Option<
        unsafe extern "C" fn(
            scheduler: *mut ::core::ffi::c_void,
            path: *mut xqc_path_ctx_t,
            event: xqc_scheduler_path_event_t,
            event_arg: *mut ::core::ffi::c_void,
        ),
    >,
    pub xqc_scheduler_handle_conn_event: ::core::option::Option<
        unsafe extern "C" fn(
            scheduler: *mut ::core::ffi::c_void,
            conn: *mut xqc_connection_t,
            event: xqc_scheduler_conn_event_t,
            event_arg: *mut ::core::ffi::c_void,
        ),
    >,
    #[doc = " Optional. Invoked when a packet carrying application payload (STREAM\n or DATAGRAM bytes) is confirmed acknowledged for the first time, with\n the acknowledged payload byte count and the path it was sent on. Never\n invoked with payload_bytes == 0, so a control-only packet does not\n reach it. Schedulers that learn per-path goodput implement this; leave\n NULL otherwise. No ack timestamp is passed: a scheduler that needs one\n reads the clock where it consumes the counter, which is what keeps a\n sample spanning wall clock rather than the span of an ACK burst.\n Appended last so existing designated initialisers keep zero-filling it."]
    pub xqc_scheduler_on_app_packet_acked: ::core::option::Option<
        unsafe extern "C" fn(scheduler: *mut ::core::ffi::c_void, path_id: u64, payload_bytes: u64),
    >,
}
#[allow(clippy::unnecessary_operation, clippy::identity_op)]
const _: () = {
    ["Size of xqc_scheduler_callback_s"]
        [::core::mem::size_of::<xqc_scheduler_callback_s>() - 48usize];
    ["Alignment of xqc_scheduler_callback_s"]
        [::core::mem::align_of::<xqc_scheduler_callback_s>() - 8usize];
    ["Offset of field: xqc_scheduler_callback_s::xqc_scheduler_size"]
        [::core::mem::offset_of!(xqc_scheduler_callback_s, xqc_scheduler_size) - 0usize];
    ["Offset of field: xqc_scheduler_callback_s::xqc_scheduler_init"]
        [::core::mem::offset_of!(xqc_scheduler_callback_s, xqc_scheduler_init) - 8usize];
    ["Offset of field: xqc_scheduler_callback_s::xqc_scheduler_get_path"]
        [::core::mem::offset_of!(xqc_scheduler_callback_s, xqc_scheduler_get_path) - 16usize];
    ["Offset of field: xqc_scheduler_callback_s::xqc_scheduler_handle_path_event"][::core::mem::offset_of!(
        xqc_scheduler_callback_s,
        xqc_scheduler_handle_path_event
    ) - 24usize];
    ["Offset of field: xqc_scheduler_callback_s::xqc_scheduler_handle_conn_event"][::core::mem::offset_of!(
        xqc_scheduler_callback_s,
        xqc_scheduler_handle_conn_event
    ) - 32usize];
    ["Offset of field: xqc_scheduler_callback_s::xqc_scheduler_on_app_packet_acked"][::core::mem::offset_of!(
        xqc_scheduler_callback_s,
        xqc_scheduler_on_app_packet_acked
    ) - 40usize];
};
#[doc = " @brief multipath scheduler callbacks"]
pub type xqc_scheduler_callback_t = xqc_scheduler_callback_s;
unsafe extern "C" {
    pub static xqc_minrtt_scheduler_cb: xqc_scheduler_callback_t;
}
unsafe extern "C" {
    pub static xqc_backup_scheduler_cb: xqc_scheduler_callback_t;
}
unsafe extern "C" {
    pub static xqc_backup_fec_scheduler_cb: xqc_scheduler_callback_t;
}
unsafe extern "C" {
    pub static xqc_rap_scheduler_cb: xqc_scheduler_callback_t;
}
unsafe extern "C" {
    pub static xqc_wlb_scheduler_cb: xqc_scheduler_callback_t;
}
unsafe extern "C" {
    #[doc = " @brief Set flow hash hint for WLB scheduler before calling datagram_send().\n The WLB scheduler uses this hash for flow-affinity path selection.\n Must be called before each xqc_h3_ext_datagram_send() call."]
    pub fn xqc_conn_set_dgram_flow_hash(conn: *mut xqc_connection_t, flow_hash: u32);
}
pub const XQC_REINJ_UNACK_AFTER_SCHED: xqc_reinjection_mode_t = 1;
pub const XQC_REINJ_UNACK_BEFORE_SCHED: xqc_reinjection_mode_t = 2;
pub const XQC_REINJ_UNACK_AFTER_SEND: xqc_reinjection_mode_t = 4;
pub type xqc_reinjection_mode_t = ::core::ffi::c_uint;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xqc_reinj_ctl_callback_s {
    pub xqc_reinj_ctl_size: ::core::option::Option<unsafe extern "C" fn() -> usize>,
    pub xqc_reinj_ctl_init: ::core::option::Option<
        unsafe extern "C" fn(reinj_ctl: *mut ::core::ffi::c_void, conn: *mut xqc_connection_t),
    >,
    pub xqc_reinj_ctl_update: ::core::option::Option<
        unsafe extern "C" fn(
            reinj_ctl: *mut ::core::ffi::c_void,
            qoe_info: *mut ::core::ffi::c_void,
        ),
    >,
    pub xqc_reinj_ctl_reset: ::core::option::Option<
        unsafe extern "C" fn(
            reinj_ctl: *mut ::core::ffi::c_void,
            qoe_info: *mut ::core::ffi::c_void,
        ),
    >,
    pub xqc_reinj_ctl_can_reinject: ::core::option::Option<
        unsafe extern "C" fn(
            reinj_ctl: *mut ::core::ffi::c_void,
            po: *mut xqc_packet_out_t,
            mode: xqc_reinjection_mode_t,
        ) -> xqc_bool_t,
    >,
}
#[allow(clippy::unnecessary_operation, clippy::identity_op)]
const _: () = {
    ["Size of xqc_reinj_ctl_callback_s"]
        [::core::mem::size_of::<xqc_reinj_ctl_callback_s>() - 40usize];
    ["Alignment of xqc_reinj_ctl_callback_s"]
        [::core::mem::align_of::<xqc_reinj_ctl_callback_s>() - 8usize];
    ["Offset of field: xqc_reinj_ctl_callback_s::xqc_reinj_ctl_size"]
        [::core::mem::offset_of!(xqc_reinj_ctl_callback_s, xqc_reinj_ctl_size) - 0usize];
    ["Offset of field: xqc_reinj_ctl_callback_s::xqc_reinj_ctl_init"]
        [::core::mem::offset_of!(xqc_reinj_ctl_callback_s, xqc_reinj_ctl_init) - 8usize];
    ["Offset of field: xqc_reinj_ctl_callback_s::xqc_reinj_ctl_update"]
        [::core::mem::offset_of!(xqc_reinj_ctl_callback_s, xqc_reinj_ctl_update) - 16usize];
    ["Offset of field: xqc_reinj_ctl_callback_s::xqc_reinj_ctl_reset"]
        [::core::mem::offset_of!(xqc_reinj_ctl_callback_s, xqc_reinj_ctl_reset) - 24usize];
    ["Offset of field: xqc_reinj_ctl_callback_s::xqc_reinj_ctl_can_reinject"]
        [::core::mem::offset_of!(xqc_reinj_ctl_callback_s, xqc_reinj_ctl_can_reinject) - 32usize];
};
pub type xqc_reinj_ctl_callback_t = xqc_reinj_ctl_callback_s;
unsafe extern "C" {
    pub static xqc_default_reinj_ctl_cb: xqc_reinj_ctl_callback_t;
}
unsafe extern "C" {
    pub static xqc_deadline_reinj_ctl_cb: xqc_reinj_ctl_callback_t;
}
unsafe extern "C" {
    pub static xqc_dgram_reinj_ctl_cb: xqc_reinj_ctl_callback_t;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xqc_fec_code_callback_s {
    pub xqc_fec_init: ::core::option::Option<unsafe extern "C" fn(conn: *mut xqc_connection_t)>,
    pub xqc_fec_encode: ::core::option::Option<
        unsafe extern "C" fn(
            conn: *mut xqc_connection_t,
            unit_data: *mut ::core::ffi::c_uchar,
            un_size: usize,
            outputs: *mut *mut ::core::ffi::c_uchar,
            fec_bm_mode: u8,
        ) -> xqc_int_t,
    >,
    pub xqc_fec_decode: ::core::option::Option<
        unsafe extern "C" fn(
            conn: *mut xqc_connection_t,
            recovered_symbols_buff: *mut *mut ::core::ffi::c_uchar,
            size: *mut usize,
            block_idx: xqc_int_t,
        ) -> xqc_int_t,
    >,
    pub xqc_fec_decode_one: ::core::option::Option<
        unsafe extern "C" fn(
            conn: *mut xqc_connection_t,
            recovered_symbols_buff: *mut ::core::ffi::c_uchar,
            block_id: xqc_int_t,
            symbol_idx: xqc_int_t,
        ) -> xqc_int_t,
    >,
    pub xqc_fec_init_one:
        ::core::option::Option<unsafe extern "C" fn(conn: *mut xqc_connection_t, bm_idx: u8)>,
}
#[allow(clippy::unnecessary_operation, clippy::identity_op)]
const _: () = {
    ["Size of xqc_fec_code_callback_s"]
        [::core::mem::size_of::<xqc_fec_code_callback_s>() - 40usize];
    ["Alignment of xqc_fec_code_callback_s"]
        [::core::mem::align_of::<xqc_fec_code_callback_s>() - 8usize];
    ["Offset of field: xqc_fec_code_callback_s::xqc_fec_init"]
        [::core::mem::offset_of!(xqc_fec_code_callback_s, xqc_fec_init) - 0usize];
    ["Offset of field: xqc_fec_code_callback_s::xqc_fec_encode"]
        [::core::mem::offset_of!(xqc_fec_code_callback_s, xqc_fec_encode) - 8usize];
    ["Offset of field: xqc_fec_code_callback_s::xqc_fec_decode"]
        [::core::mem::offset_of!(xqc_fec_code_callback_s, xqc_fec_decode) - 16usize];
    ["Offset of field: xqc_fec_code_callback_s::xqc_fec_decode_one"]
        [::core::mem::offset_of!(xqc_fec_code_callback_s, xqc_fec_decode_one) - 24usize];
    ["Offset of field: xqc_fec_code_callback_s::xqc_fec_init_one"]
        [::core::mem::offset_of!(xqc_fec_code_callback_s, xqc_fec_init_one) - 32usize];
};
pub type xqc_fec_code_callback_t = xqc_fec_code_callback_s;
unsafe extern "C" {
    pub static xqc_xor_code_cb: xqc_fec_code_callback_t;
}
unsafe extern "C" {
    pub static xqc_reed_solomon_code_cb: xqc_fec_code_callback_t;
}
unsafe extern "C" {
    pub static xqc_packet_mask_code_cb: xqc_fec_code_callback_t;
}
#[doc = " @struct xqc_config_t\n QUIC config parameters"]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xqc_config_s {
    #[doc = " log level"]
    pub cfg_log_level: xqc_log_level_t,
    #[doc = " enable log based on event or not, non-zero for enable, 0 for not"]
    pub cfg_log_event: xqc_flag_t,
    #[doc = " qlog event importance"]
    pub cfg_qlog_importance: qlog_event_importance_t,
    #[doc = " print timestamp in log or not, non-zero for print, 0 for not"]
    pub cfg_log_timestamp: xqc_flag_t,
    #[doc = " print level name in log or not, non-zero for print, 0 for not"]
    pub cfg_log_level_name: xqc_flag_t,
    #[doc = " connection memory pool size, which will be used for congestion control"]
    pub conn_pool_size: usize,
    #[doc = " bucket size of stream hash table in xqc_connection_t"]
    pub streams_hash_bucket_size: usize,
    #[doc = " bucket size of connection hash table in engine"]
    pub conns_hash_bucket_size: usize,
    #[doc = " capacity of connection priority queue in engine"]
    pub conns_active_pq_capacity: usize,
    #[doc = " capacity of wakeup connection priority queue in engine"]
    pub conns_wakeup_pq_capacity: usize,
    #[doc = " supported quic version list, actually draft-29 and quic-v1 is supported"]
    pub support_version_list: [u32; 64usize],
    #[doc = " supported quic version count"]
    pub support_version_count: u32,
    #[doc = " default connection id length"]
    pub cid_len: u8,
    #[doc = " only for server, whether server will negotiate cid with client. non-zero for\n negotiate and 0 for not. when enable, server will not reuse client's original DCID,\n and generate its own cid.\n\n NOTICE: if length of client's original DCID is not equal to cid_len, server will\n always generate its own cid, despite of the enable of cid negotiation."]
    pub cid_negotiate: u8,
    #[doc = " used to generate stateless reset token"]
    pub reset_token_key: [::core::ffi::c_char; 256usize],
    pub reset_token_keylen: usize,
    #[doc = " sendmmsg switch. non-zero for enable, 0 for disable.\n if enabled, xquic will try to use write_mmsg callback function instead of\n write_socket.\n\n NOTICE: if sendmmsg is enabled, xquic will check write_mmsg callback function when\n creating engine. if write_mmsg is NULL and sendmmsg_on is non-zero,\n xqc_engine_create will fail"]
    pub sendmmsg_on: ::core::ffi::c_int,
    #[doc = " @brief enable h3 ext (default: 0)\n"]
    pub enable_h3_ext: u8,
    #[doc = " @brief manually call mainlogic after stream/request send\n"]
    pub manually_triggered_send: u8,
    #[doc = " for warning when the number of elements in one bucket exceeds the value of\n hash_conflict_threshold"]
    pub hash_conflict_threshold: u32,
    pub token_key_list: [[::core::ffi::c_uchar; 256usize]; 4usize],
    pub tk_len_list: [u16; 4usize],
    pub cur_tk_index: u8,
}
#[allow(clippy::unnecessary_operation, clippy::identity_op)]
const _: () = {
    ["Size of xqc_config_s"][::core::mem::size_of::<xqc_config_s>() - 1656usize];
    ["Alignment of xqc_config_s"][::core::mem::align_of::<xqc_config_s>() - 8usize];
    ["Offset of field: xqc_config_s::cfg_log_level"]
        [::core::mem::offset_of!(xqc_config_s, cfg_log_level) - 0usize];
    ["Offset of field: xqc_config_s::cfg_log_event"]
        [::core::mem::offset_of!(xqc_config_s, cfg_log_event) - 8usize];
    ["Offset of field: xqc_config_s::cfg_qlog_importance"]
        [::core::mem::offset_of!(xqc_config_s, cfg_qlog_importance) - 16usize];
    ["Offset of field: xqc_config_s::cfg_log_timestamp"]
        [::core::mem::offset_of!(xqc_config_s, cfg_log_timestamp) - 24usize];
    ["Offset of field: xqc_config_s::cfg_log_level_name"]
        [::core::mem::offset_of!(xqc_config_s, cfg_log_level_name) - 32usize];
    ["Offset of field: xqc_config_s::conn_pool_size"]
        [::core::mem::offset_of!(xqc_config_s, conn_pool_size) - 40usize];
    ["Offset of field: xqc_config_s::streams_hash_bucket_size"]
        [::core::mem::offset_of!(xqc_config_s, streams_hash_bucket_size) - 48usize];
    ["Offset of field: xqc_config_s::conns_hash_bucket_size"]
        [::core::mem::offset_of!(xqc_config_s, conns_hash_bucket_size) - 56usize];
    ["Offset of field: xqc_config_s::conns_active_pq_capacity"]
        [::core::mem::offset_of!(xqc_config_s, conns_active_pq_capacity) - 64usize];
    ["Offset of field: xqc_config_s::conns_wakeup_pq_capacity"]
        [::core::mem::offset_of!(xqc_config_s, conns_wakeup_pq_capacity) - 72usize];
    ["Offset of field: xqc_config_s::support_version_list"]
        [::core::mem::offset_of!(xqc_config_s, support_version_list) - 80usize];
    ["Offset of field: xqc_config_s::support_version_count"]
        [::core::mem::offset_of!(xqc_config_s, support_version_count) - 336usize];
    ["Offset of field: xqc_config_s::cid_len"]
        [::core::mem::offset_of!(xqc_config_s, cid_len) - 340usize];
    ["Offset of field: xqc_config_s::cid_negotiate"]
        [::core::mem::offset_of!(xqc_config_s, cid_negotiate) - 341usize];
    ["Offset of field: xqc_config_s::reset_token_key"]
        [::core::mem::offset_of!(xqc_config_s, reset_token_key) - 342usize];
    ["Offset of field: xqc_config_s::reset_token_keylen"]
        [::core::mem::offset_of!(xqc_config_s, reset_token_keylen) - 600usize];
    ["Offset of field: xqc_config_s::sendmmsg_on"]
        [::core::mem::offset_of!(xqc_config_s, sendmmsg_on) - 608usize];
    ["Offset of field: xqc_config_s::enable_h3_ext"]
        [::core::mem::offset_of!(xqc_config_s, enable_h3_ext) - 612usize];
    ["Offset of field: xqc_config_s::manually_triggered_send"]
        [::core::mem::offset_of!(xqc_config_s, manually_triggered_send) - 613usize];
    ["Offset of field: xqc_config_s::hash_conflict_threshold"]
        [::core::mem::offset_of!(xqc_config_s, hash_conflict_threshold) - 616usize];
    ["Offset of field: xqc_config_s::token_key_list"]
        [::core::mem::offset_of!(xqc_config_s, token_key_list) - 620usize];
    ["Offset of field: xqc_config_s::tk_len_list"]
        [::core::mem::offset_of!(xqc_config_s, tk_len_list) - 1644usize];
    ["Offset of field: xqc_config_s::cur_tk_index"]
        [::core::mem::offset_of!(xqc_config_s, cur_tk_index) - 1652usize];
};
#[doc = " @struct xqc_config_t\n QUIC config parameters"]
pub type xqc_config_t = xqc_config_s;
#[doc = " @brief engine callback functions."]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xqc_engine_callback_s {
    #[doc = " timer callback for event loop"]
    pub set_event_timer: xqc_set_event_timer_pt,
    #[doc = " write log file callback, REQUIRED"]
    pub log_callbacks: xqc_log_callbacks_t,
    #[doc = " custom cid generator, OPTIONAL for server"]
    pub cid_generate_cb: xqc_cid_generate_pt,
    #[doc = " tls secret callback, OPTIONAL"]
    pub keylog_cb: xqc_eng_keylog_pt,
    #[doc = " get realtime timestamp callback function. if not set, xquic will get timestamp\nwith inner function xqc_now, which relies on gettimeofday"]
    pub realtime_ts: xqc_timestamp_pt,
    #[doc = " get monotonic increasing timestamp callback function. if not set, xquic will get\ntimestamp with inner function xqc_now, which relies on gettimeofday"]
    pub monotonic_ts: xqc_timestamp_pt,
}
#[allow(clippy::unnecessary_operation, clippy::identity_op)]
const _: () = {
    ["Size of xqc_engine_callback_s"][::core::mem::size_of::<xqc_engine_callback_s>() - 64usize];
    ["Alignment of xqc_engine_callback_s"]
        [::core::mem::align_of::<xqc_engine_callback_s>() - 8usize];
    ["Offset of field: xqc_engine_callback_s::set_event_timer"]
        [::core::mem::offset_of!(xqc_engine_callback_s, set_event_timer) - 0usize];
    ["Offset of field: xqc_engine_callback_s::log_callbacks"]
        [::core::mem::offset_of!(xqc_engine_callback_s, log_callbacks) - 8usize];
    ["Offset of field: xqc_engine_callback_s::cid_generate_cb"]
        [::core::mem::offset_of!(xqc_engine_callback_s, cid_generate_cb) - 32usize];
    ["Offset of field: xqc_engine_callback_s::keylog_cb"]
        [::core::mem::offset_of!(xqc_engine_callback_s, keylog_cb) - 40usize];
    ["Offset of field: xqc_engine_callback_s::realtime_ts"]
        [::core::mem::offset_of!(xqc_engine_callback_s, realtime_ts) - 48usize];
    ["Offset of field: xqc_engine_callback_s::monotonic_ts"]
        [::core::mem::offset_of!(xqc_engine_callback_s, monotonic_ts) - 56usize];
};
#[doc = " @brief engine callback functions."]
pub type xqc_engine_callback_t = xqc_engine_callback_s;
#[doc = " @brief engine's ssl config"]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xqc_engine_ssl_config_s {
    #[doc = " private key file for server"]
    pub private_key_file: *mut ::core::ffi::c_char,
    #[doc = " certificate file for server"]
    pub cert_file: *mut ::core::ffi::c_char,
    pub ciphers: *mut ::core::ffi::c_char,
    pub groups: *mut ::core::ffi::c_char,
    #[doc = " session lifetime in second"]
    pub session_timeout: u32,
    #[doc = " session ticket key for server"]
    pub session_ticket_key_data: *mut ::core::ffi::c_char,
    #[doc = " session ticket key length for server"]
    pub session_ticket_key_len: usize,
}
#[allow(clippy::unnecessary_operation, clippy::identity_op)]
const _: () = {
    ["Size of xqc_engine_ssl_config_s"]
        [::core::mem::size_of::<xqc_engine_ssl_config_s>() - 56usize];
    ["Alignment of xqc_engine_ssl_config_s"]
        [::core::mem::align_of::<xqc_engine_ssl_config_s>() - 8usize];
    ["Offset of field: xqc_engine_ssl_config_s::private_key_file"]
        [::core::mem::offset_of!(xqc_engine_ssl_config_s, private_key_file) - 0usize];
    ["Offset of field: xqc_engine_ssl_config_s::cert_file"]
        [::core::mem::offset_of!(xqc_engine_ssl_config_s, cert_file) - 8usize];
    ["Offset of field: xqc_engine_ssl_config_s::ciphers"]
        [::core::mem::offset_of!(xqc_engine_ssl_config_s, ciphers) - 16usize];
    ["Offset of field: xqc_engine_ssl_config_s::groups"]
        [::core::mem::offset_of!(xqc_engine_ssl_config_s, groups) - 24usize];
    ["Offset of field: xqc_engine_ssl_config_s::session_timeout"]
        [::core::mem::offset_of!(xqc_engine_ssl_config_s, session_timeout) - 32usize];
    ["Offset of field: xqc_engine_ssl_config_s::session_ticket_key_data"]
        [::core::mem::offset_of!(xqc_engine_ssl_config_s, session_ticket_key_data) - 40usize];
    ["Offset of field: xqc_engine_ssl_config_s::session_ticket_key_len"]
        [::core::mem::offset_of!(xqc_engine_ssl_config_s, session_ticket_key_len) - 48usize];
};
#[doc = " @brief engine's ssl config"]
pub type xqc_engine_ssl_config_t = xqc_engine_ssl_config_s;
pub const XQC_TLS_CERT_FLAG_NEED_VERIFY: xqc_cert_verify_flag_e = 1;
pub const XQC_TLS_CERT_FLAG_ALLOW_SELF_SIGNED: xqc_cert_verify_flag_e = 2;
#[doc = " delegate the whole certificate decision to cert_verify_cb: the callback\n receives the chain exactly as the peer presented it (leaf first) on\n every full handshake (a resumed session carries the decision made when\n it was established) and its return value is final; the library\n performs no chain building, root-store lookup or hostname check of its\n own. Implies peer verification (SSL_VERIFY_PEER) even without\n XQC_TLS_CERT_FLAG_NEED_VERIFY; XQC_TLS_CERT_FLAG_ALLOW_SELF_SIGNED is\n ignored under this flag."]
pub const XQC_TLS_CERT_FLAG_APP_VERIFY: xqc_cert_verify_flag_e = 4;
pub type xqc_cert_verify_flag_e = ::core::ffi::c_uint;
pub const XQC_RED_NOT_USE: xqc_dgram_red_setting_e = 0;
pub const XQC_RED_SET_CLOSE: xqc_dgram_red_setting_e = 1;
pub type xqc_dgram_red_setting_e = ::core::ffi::c_uint;
pub const XQC_FEC_CONN_LEVEL: xqc_fec_level_e = 0;
pub const XQC_FEC_STREAM_LEVEL: xqc_fec_level_e = 1;
pub type xqc_fec_level_e = ::core::ffi::c_uint;
#[doc = " @brief connection tls config for client"]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xqc_conn_ssl_config_s {
    #[doc = " session ticket data buffer.\n\n session ticket is read from client's local storage, which is from save_session_cb\n callback and was stored after previous successful connection to a server"]
    pub session_ticket_data: *mut ::core::ffi::c_char,
    #[doc = " length of session_ticket_data"]
    pub session_ticket_len: usize,
    #[doc = " server's transport parameter, derived as well as session_ticket_data"]
    pub transport_parameter_data: *mut ::core::ffi::c_char,
    #[doc = " length of transport_parameter_data"]
    pub transport_parameter_data_len: usize,
    #[doc = " certificate verify flag. which is a bit-map flag defined in xqc_cert_verify_flag_e"]
    pub cert_verify_flag: u8,
    #[doc = " ssl curve list (groups). If not set, xquic will use the default engine-level value."]
    pub tls_groups: xqc_tls_group_type_t,
}
#[allow(clippy::unnecessary_operation, clippy::identity_op)]
const _: () = {
    ["Size of xqc_conn_ssl_config_s"][::core::mem::size_of::<xqc_conn_ssl_config_s>() - 40usize];
    ["Alignment of xqc_conn_ssl_config_s"]
        [::core::mem::align_of::<xqc_conn_ssl_config_s>() - 8usize];
    ["Offset of field: xqc_conn_ssl_config_s::session_ticket_data"]
        [::core::mem::offset_of!(xqc_conn_ssl_config_s, session_ticket_data) - 0usize];
    ["Offset of field: xqc_conn_ssl_config_s::session_ticket_len"]
        [::core::mem::offset_of!(xqc_conn_ssl_config_s, session_ticket_len) - 8usize];
    ["Offset of field: xqc_conn_ssl_config_s::transport_parameter_data"]
        [::core::mem::offset_of!(xqc_conn_ssl_config_s, transport_parameter_data) - 16usize];
    ["Offset of field: xqc_conn_ssl_config_s::transport_parameter_data_len"]
        [::core::mem::offset_of!(xqc_conn_ssl_config_s, transport_parameter_data_len) - 24usize];
    ["Offset of field: xqc_conn_ssl_config_s::cert_verify_flag"]
        [::core::mem::offset_of!(xqc_conn_ssl_config_s, cert_verify_flag) - 32usize];
    ["Offset of field: xqc_conn_ssl_config_s::tls_groups"]
        [::core::mem::offset_of!(xqc_conn_ssl_config_s, tls_groups) - 36usize];
};
#[doc = " @brief connection tls config for client"]
pub type xqc_conn_ssl_config_t = xqc_conn_ssl_config_s;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xqc_linger_s {
    #[doc = " close connection after all data sent and acked, default: 0"]
    pub linger_on: u32,
    #[doc = " 3*PTO if linger_timeout is 0"]
    pub linger_timeout: xqc_usec_t,
}
#[allow(clippy::unnecessary_operation, clippy::identity_op)]
const _: () = {
    ["Size of xqc_linger_s"][::core::mem::size_of::<xqc_linger_s>() - 16usize];
    ["Alignment of xqc_linger_s"][::core::mem::align_of::<xqc_linger_s>() - 8usize];
    ["Offset of field: xqc_linger_s::linger_on"]
        [::core::mem::offset_of!(xqc_linger_s, linger_on) - 0usize];
    ["Offset of field: xqc_linger_s::linger_timeout"]
        [::core::mem::offset_of!(xqc_linger_s, linger_timeout) - 8usize];
};
pub type xqc_linger_t = xqc_linger_s;
pub const XQC_ERR_MULTIPATH_VERSION: xqc_multipath_version_t = 0;
pub const XQC_MULTIPATH_10: xqc_multipath_version_t = 10;
pub const XQC_MULTIPATH_3E: xqc_multipath_version_t = 62;
pub type xqc_multipath_version_t = ::core::ffi::c_uint;
pub const XQC_ERR_FEC_VERSION: xqc_fec_version_t = 0;
pub const XQC_FEC_02: xqc_fec_version_t = 2;
pub type xqc_fec_version_t = ::core::ffi::c_uint;
#[doc = " @brief structures of connection settings"]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xqc_conn_settings_s {
    #[doc = " default: 0"]
    pub pacing_on: ::core::ffi::c_int,
    #[doc = " client sends PING to keepalive, default:0"]
    pub ping_on: ::core::ffi::c_int,
    #[doc = " default: xqc_cubic_cb"]
    pub cong_ctrl_callback: xqc_cong_ctrl_callback_t,
    pub cc_params: xqc_cc_params_t,
    #[doc = " socket option SO_SNDBUF, 0 for unlimited"]
    pub so_sndbuf: u32,
    #[doc = " default: XQC_SNDQ_PACKETS_USED_MAX.\n It should be set to buffer 2xBDP packets at least for performance consideration.\n The default value is 16000 pkts."]
    pub sndq_packets_used_max: u64,
    #[doc = " Max buffered out-of-order STREAM frame nodes per stream (reassembly\n cap, CWE-770 mitigation per RFC 9000 §21.7).\n\n 0 selects the built-in two-tier default: past 8192 nodes the density\n budget charges 256 bytes of payload for every buffered node except one\n reserved for a frame that fills the leftmost reassembly hole (so the\n average may sit just under 256), and 32768 nodes is the ceiling\n regardless of density. That lets a full receive window of packet-sized\n frames queue while still stopping sparse-fragment amplification.\n\n Any nonzero value is a single absolute cap on node count, density\n ignored. Lowering it bounds reassembly memory more tightly at the cost\n of more retransmissions under heavy cross-path reordering."]
    pub max_stream_frame_buffered_cnt: u64,
    pub linger: xqc_linger_t,
    #[doc = " QUIC protocol version"]
    pub proto_version: xqc_proto_version_t,
    #[doc = " initial idle timeout interval, effective before handshake completion"]
    pub init_idle_time_out: xqc_msec_t,
    #[doc = " idle timeout interval, effective after handshake completion"]
    pub idle_time_out: xqc_msec_t,
    pub fec_conn_queue_rpr_timeout: xqc_usec_t,
    pub spurious_loss_detect_on: i32,
    #[doc = " limit of anti-amplification, default 5"]
    pub anti_amplification_limit: u32,
    #[doc = " packet limit of a single 1-rtt key, 0 for unlimited"]
    pub keyupdate_pkt_threshold: u64,
    pub max_pkt_out_size: usize,
    pub probing_pkt_out_size: usize,
    #[doc = " datgram option\n 0: no support for datagram mode (default)\n >0: the max size of datagrams that the local end is willing to receive\n 65535: the local end is willing to receive a datagram with any length as long as it\n fits in a QUIC packet"]
    pub max_datagram_frame_size: u16,
    #[doc = " multipath option:\n https://datatracker.ietf.org/doc/html/draft-ietf-quic-multipath-05#section-3\n 0: don't support multipath\n 1: supports multipath (unified solution) - multiple PN spaces"]
    pub enable_multipath: u64,
    pub multipath_version: xqc_multipath_version_t,
    pub init_max_path_id: u64,
    pub least_available_cid_count: u64,
    #[doc = " reinjection option:\n 0: default, no reinjection\n bit0 = 1:\n    reinject unacked packets after scheduling packets to paths.\n bit1 = 1:\n    reinject unacked packets before scheduling packets to paths.\n bit2 = 1\n    reinject unacked packets after sending packets."]
    pub mp_enable_reinjection: ::core::ffi::c_int,
    #[doc = " deadline = max(low_bound, min(hard_deadline, srtt * srtt_factor))\n default values:\n   low_bound = 0\n   hard_deadline = INF\n   srtt_factor = 2.0"]
    pub reinj_flexible_deadline_srtt_factor: f64,
    pub reinj_hard_deadline: u64,
    pub reinj_deadline_lower_bound: u64,
    #[doc = " By default, XQUIC returns ACK_MPs on the path where the data\n is received unless the path is not avaliable anymore.\n\n Setting mp_ack_on_any_path to 1 can enable XQUIC to return ACK_MPs on any\n paths according to the scheduler."]
    pub mp_ack_on_any_path: u8,
    #[doc = " When sending a ping packet for connection keep-alive, we replicate the\n the packet on all acitve paths to keep all paths alive (disable:0, enable:1).\n The default value is 0."]
    pub mp_ping_on: u8,
    #[doc = " scheduler callback, default: xqc_minrtt_scheduler_cb"]
    pub scheduler_callback: xqc_scheduler_callback_t,
    pub scheduler_params: xqc_scheduler_params_t,
    #[doc = " reinj_ctl callback, default: xqc_default_reinj_ctl_cb"]
    pub reinj_ctl_callback: xqc_reinj_ctl_callback_t,
    #[doc = " ms"]
    pub standby_path_probe_timeout: xqc_msec_t,
    #[doc = " params for performance tuning */\n/** max ack delay: ms"]
    pub max_ack_delay: u32,
    #[doc = " generate an ACK if received ack-eliciting pkts >= ack_frequency"]
    pub ack_frequency: u32,
    pub adaptive_ack_frequency: u8,
    pub loss_detection_pkt_thresh: u64,
    pub pto_backoff_factor: f64,
    #[doc = " datagram redundancy: 0 disable, 1 enable, 2 only enable multipath redundancy"]
    pub datagram_redundancy: u8,
    pub datagram_force_retrans_on: u8,
    pub datagram_redundant_probe: u64,
    #[doc = " enable PMTUD:\n 0x0 disbale,\n 0x1 enable client probing,\n 0x2 enable server probing,\n 0x3 enable both ends probing\n NOTE: This option needs to be negotiated by both ends. The final decision\n is made by the logic AND operation of both ends' options, e.g. client:\n 0x3, server: 0x1 --> 0x1 (only enable client probing)."]
    pub enable_pmtud: u8,
    #[doc = " probing interval (us), default: 500000"]
    pub pmtud_probing_interval: u64,
    #[doc = " enable marking reinjected packets with reserved bits"]
    pub marking_reinjection: u8,
    #[doc = " The limitation on conn recv rate (only applied to stream data) in bytes per second.\n NOTE: the minimal rate limitation is (63000/RTT) Bps. For instance, if RTT is 60ms,\n the minimal valid rate limitation is about 1MBps. Any recv_rate_bytes_per_sec less\n than the minimal valid rate limitation will not be guaranteed.\n default: 0 (no limitation)."]
    pub recv_rate_bytes_per_sec: u64,
    #[doc = " The switch to enable stream-level recv rate throttling. Default: off (0)"]
    pub enable_stream_rate_limit: u8,
    #[doc = " initial recv window. Default: 0 (use the internal default value)"]
    pub init_recv_window: u32,
    #[doc = " initial flow control value"]
    pub is_interop_mode: xqc_bool_t,
    pub conn_option_str: [::core::ffi::c_char; 80usize],
    #[doc = " @brief intial_rtt (us). Default: 0 (use the internal default value -- 250000)\n"]
    pub initial_rtt: xqc_usec_t,
    #[doc = " @brief initial pto duration (us). Default: 0 (use the internal default value --\n 3xinitial_rtt)\n"]
    pub initial_pto_duration: xqc_usec_t,
    #[doc = " fec option:\n 0: don't support fec\n 1: supports fec"]
    pub enable_encode_fec: u64,
    pub enable_decode_fec: u64,
    pub fec_params: xqc_fec_params_t,
    pub fec_callback: xqc_fec_code_callback_t,
    pub close_dgram_redundancy: xqc_dgram_red_setting_e,
    #[doc = " @brief disable batch sending on the connection (default:0, not disable)"]
    pub disable_send_mmsg: u8,
    #[doc = " @brief control PTO value"]
    pub control_pto_value: u8,
    pub max_udp_payload_size: u64,
    #[doc = " encode fec on connection level or stream level ?\n 0: (default) connection level\n 1: stream level, only be applied to MOQ"]
    pub fec_level: xqc_fec_level_e,
    pub extended_ack_features: u64,
    pub max_receive_timestamps_per_ack: u64,
    pub receive_timestamps_exponent: u64,
    pub disable_pn_skipping: u8,
    pub specify_client_scid: u8,
    pub client_scid: [u8; 20usize],
    pub specify_client_dcid: u8,
    pub client_dcid: [u8; 20usize],
    pub max_streams_bidi: u64,
    pub max_streams_uni: u64,
    pub simulate_ecn: u8,
    pub max_path_id_grant_max_value: u64,
    #[doc = " Maximum blocked buffer size per stream (bytes) for QPACK decode blocking.\n This limits memory usage when QPACK decoding is blocked waiting for\n dynamic table updates. Default: 0 (use internal default: 1MB)"]
    pub max_blocked_buf_per_stream: usize,
    #[doc = " Maximum total blocked buffer size per connection (bytes) for QPACK decode blocking.\n This limits total memory usage across all blocked streams on a connection.\n Default: 0 (use internal default: 8MB)"]
    pub max_blocked_buf_per_conn: usize,
    #[doc = " Defer the connection flush that a send call normally performs before it\n returns. Covers both send kinds: the datagram entry points\n (xqc_datagram_send() / _send_on_path() / _send_multiple()) and the h3\n stream data path (xqc_h3_stream_send_data(), reached from\n xqc_h3_request_send_body() and from the ext-bytestream API).\n\n 0 (default) = unchanged: every send drives xqc_engine_conn_logic()\n before returning. A caller that writes one datagram per call therefore\n never accumulates more than one packet in the send queue, and the\n sendmmsg/GSO burst path can never form a batch. For streams the same\n limit applies ACROSS writes rather than within one: xqc_stream_send()\n loops until a write is consumed, so a large write already queues several\n packets, but each write still flushes separately.\n\n 1 = sends only queue packets; the flush happens on the caller's next\n xqc_engine_main_logic(). Intended for callers that write a run of\n packets and then drive the engine once — e.g. a tunnel reading a batch\n of packets per event-loop iteration.\n\n ONE knob for both kinds on purpose. A flush drives the whole connection\n and datagram and STREAM packet_outs share one send queue\n (xqc_send_queue_t.sndq_send_packets), so a per-kind knob could only\n select which SEND CALLS flush — never give each kind its own batching\n regime. On a connection carrying both, the non-deferred kind's sends\n would keep flushing the deferred kind's packets, so the split bought\n nothing but a way to misconfigure it.\n\n Coverage — only the two bulk paths named above defer. Every other\n xqc_engine_conn_logic() call site still flushes immediately, in three\n groups:\n - Control writes: HEADERS, the explicit FIN (xqc_h3_stream_send_finish),\n   GOAWAY, stream-type frames, PING, connect, close_path, stream close.\n   These are once-per-stream or once-per-connection with nothing to\n   batch, and deferring them would delay handshake and flow control for\n   no gain.\n - xqc_conn_continue_send_by_conn(), which exists precisely to resume\n   sending on demand; deferring it would defeat its purpose.\n - xqc_stream_send()'s own trailing flush. That one runs ONLY for streams\n   without XQC_STREAM_FLAG_HAS_H3 — h3 streams skip it and are flushed by\n   the h3 layer instead — so it is the bulk path of the raw transport\n   stream API. It would benefit from deferral on the same reasoning as\n   the h3 one, and is left out only because no consumer of this fork\n   drives it, which means the change could be neither measured nor\n   exercised. Route it through xqc_conn_flush_or_defer() if one appears.\n\n None of those omissions can strand a deferred packet: a flush drives the\n whole connection, so any immediate flush also transmits whatever was\n deferred earlier.\n\n Scope — this defers ALL of xqc_engine_process_conn(), not only the\n write: timer expiry, pending-ACK emission, PTO probes, retransmits and\n PMTUD probing move to the caller's next engine run too. Nothing is\n skipped and no wire format changes, but a peer's ACK can be emitted up\n to one full caller batch later than it would have been. Weigh that\n before enabling on a latency-sensitive path.\n\n The caller MUST run the engine after the run of sends. A wakeup is\n armed once per run as a backstop, but how much protection that actually\n buys depends on the caller's set_event_timer: it bounds the delay to\n one event-loop iteration only for implementations that arm a real timer\n from the callback. An implementation that merely records the requested\n deadline for the caller to poll later gets no bound at all, because\n nothing polls it until the engine is driven anyway.\n\n Stream specifics:\n - Only the DATA path defers. HEADERS (xqc_h3_stream_send_headers), the\n   explicit FIN (xqc_h3_stream_send_finish), GOAWAY and stream-type\n   frames keep flushing immediately — once-per-stream control writes with\n   nothing to batch, where deferral would delay handshake and flow\n   control for no gain. A fin-only body write\n   (xqc_h3_request_send_body(req, NULL, 0, 1)) does take the data path\n   and is deferred like any other write.\n - Backpressure is unchanged. A write returning -XQC_EAGAIN never reached\n   the flush in the first place, and the threshold does not move either:\n   sndq_packets_used drops when a packet_out is freed, not when it is\n   transmitted, and STREAM packets are ack-eliciting.\n - KNOWN LIMITATION — aborting a stream can discard a deferred write.\n   xqc_stream_close_with_error() drops this stream's queued packets\n   before sending RESET_STREAM, so bytes accepted by a write that has not\n   been flushed yet are lost: write-then-abort from the same callback\n   truncates by up to one write. Flush explicitly (drive the engine)\n   between the write and the abort if that matters.\n   Scope: the ABORT path only — xqc_stream_close() / xqc_h3_request_close()\n   and the peer-reset handler. Normal FIN completion retires a stream\n   through xqc_stream_maybe_need_close() and never comes here, and a\n   connection already CLOSING returns before the drop. The peer always\n   sees RESET_STREAM, so the truncation is visible rather than silent.\n   Flushing inside the close was tried and reverted: it re-enters timers\n   and notifications, letting xqc_timer_stream_close_timeout() destroy\n   the stream the caller still holds, and it no-ops anyway when the close\n   comes from inside an engine callback.\n\n ABI: appending this field enlarges xqc_conn_settings_t. Rebuilt\n consumers are source-compatible and default to 0, but this is NOT\n binary-compatible. A caller built against the older header passes a\n smaller object, and both entry points read past its end: xqc_conn_create\n assigns the whole struct on the client path, and\n xqc_server_set_conn_settings reads this field on the server path.\n Ship xquic and its consumers in lockstep, or version the shared library\n — libxquic currently carries no SOVERSION."]
    pub defer_send_flush: u8,
    #[doc = " Cap on implicitly opened stream ids. A peer stream id makes the\n connection keep an entry for every lower id it skipped; this bounds\n the entries currently held for ids no stream was created for (the\n count drops again when such an id is opened). Exceeding it closes the\n connection with TRA_STREAM_LIMIT_ERROR. 0 means the default, 16384.\n Same ABI caveat as defer_send_flush: appending enlarges the struct."]
    pub max_implicit_streams: u64,
}
#[allow(clippy::unnecessary_operation, clippy::identity_op)]
const _: () = {
    ["Size of xqc_conn_settings_s"][::core::mem::size_of::<xqc_conn_settings_s>() - 1024usize];
    ["Alignment of xqc_conn_settings_s"][::core::mem::align_of::<xqc_conn_settings_s>() - 8usize];
    ["Offset of field: xqc_conn_settings_s::pacing_on"]
        [::core::mem::offset_of!(xqc_conn_settings_s, pacing_on) - 0usize];
    ["Offset of field: xqc_conn_settings_s::ping_on"]
        [::core::mem::offset_of!(xqc_conn_settings_s, ping_on) - 4usize];
    ["Offset of field: xqc_conn_settings_s::cong_ctrl_callback"]
        [::core::mem::offset_of!(xqc_conn_settings_s, cong_ctrl_callback) - 8usize];
    ["Offset of field: xqc_conn_settings_s::cc_params"]
        [::core::mem::offset_of!(xqc_conn_settings_s, cc_params) - 120usize];
    ["Offset of field: xqc_conn_settings_s::so_sndbuf"]
        [::core::mem::offset_of!(xqc_conn_settings_s, so_sndbuf) - 176usize];
    ["Offset of field: xqc_conn_settings_s::sndq_packets_used_max"]
        [::core::mem::offset_of!(xqc_conn_settings_s, sndq_packets_used_max) - 184usize];
    ["Offset of field: xqc_conn_settings_s::max_stream_frame_buffered_cnt"]
        [::core::mem::offset_of!(xqc_conn_settings_s, max_stream_frame_buffered_cnt) - 192usize];
    ["Offset of field: xqc_conn_settings_s::linger"]
        [::core::mem::offset_of!(xqc_conn_settings_s, linger) - 200usize];
    ["Offset of field: xqc_conn_settings_s::proto_version"]
        [::core::mem::offset_of!(xqc_conn_settings_s, proto_version) - 216usize];
    ["Offset of field: xqc_conn_settings_s::init_idle_time_out"]
        [::core::mem::offset_of!(xqc_conn_settings_s, init_idle_time_out) - 224usize];
    ["Offset of field: xqc_conn_settings_s::idle_time_out"]
        [::core::mem::offset_of!(xqc_conn_settings_s, idle_time_out) - 232usize];
    ["Offset of field: xqc_conn_settings_s::fec_conn_queue_rpr_timeout"]
        [::core::mem::offset_of!(xqc_conn_settings_s, fec_conn_queue_rpr_timeout) - 240usize];
    ["Offset of field: xqc_conn_settings_s::spurious_loss_detect_on"]
        [::core::mem::offset_of!(xqc_conn_settings_s, spurious_loss_detect_on) - 248usize];
    ["Offset of field: xqc_conn_settings_s::anti_amplification_limit"]
        [::core::mem::offset_of!(xqc_conn_settings_s, anti_amplification_limit) - 252usize];
    ["Offset of field: xqc_conn_settings_s::keyupdate_pkt_threshold"]
        [::core::mem::offset_of!(xqc_conn_settings_s, keyupdate_pkt_threshold) - 256usize];
    ["Offset of field: xqc_conn_settings_s::max_pkt_out_size"]
        [::core::mem::offset_of!(xqc_conn_settings_s, max_pkt_out_size) - 264usize];
    ["Offset of field: xqc_conn_settings_s::probing_pkt_out_size"]
        [::core::mem::offset_of!(xqc_conn_settings_s, probing_pkt_out_size) - 272usize];
    ["Offset of field: xqc_conn_settings_s::max_datagram_frame_size"]
        [::core::mem::offset_of!(xqc_conn_settings_s, max_datagram_frame_size) - 280usize];
    ["Offset of field: xqc_conn_settings_s::enable_multipath"]
        [::core::mem::offset_of!(xqc_conn_settings_s, enable_multipath) - 288usize];
    ["Offset of field: xqc_conn_settings_s::multipath_version"]
        [::core::mem::offset_of!(xqc_conn_settings_s, multipath_version) - 296usize];
    ["Offset of field: xqc_conn_settings_s::init_max_path_id"]
        [::core::mem::offset_of!(xqc_conn_settings_s, init_max_path_id) - 304usize];
    ["Offset of field: xqc_conn_settings_s::least_available_cid_count"]
        [::core::mem::offset_of!(xqc_conn_settings_s, least_available_cid_count) - 312usize];
    ["Offset of field: xqc_conn_settings_s::mp_enable_reinjection"]
        [::core::mem::offset_of!(xqc_conn_settings_s, mp_enable_reinjection) - 320usize];
    ["Offset of field: xqc_conn_settings_s::reinj_flexible_deadline_srtt_factor"][::core::mem::offset_of!(
        xqc_conn_settings_s,
        reinj_flexible_deadline_srtt_factor
    ) - 328usize];
    ["Offset of field: xqc_conn_settings_s::reinj_hard_deadline"]
        [::core::mem::offset_of!(xqc_conn_settings_s, reinj_hard_deadline) - 336usize];
    ["Offset of field: xqc_conn_settings_s::reinj_deadline_lower_bound"]
        [::core::mem::offset_of!(xqc_conn_settings_s, reinj_deadline_lower_bound) - 344usize];
    ["Offset of field: xqc_conn_settings_s::mp_ack_on_any_path"]
        [::core::mem::offset_of!(xqc_conn_settings_s, mp_ack_on_any_path) - 352usize];
    ["Offset of field: xqc_conn_settings_s::mp_ping_on"]
        [::core::mem::offset_of!(xqc_conn_settings_s, mp_ping_on) - 353usize];
    ["Offset of field: xqc_conn_settings_s::scheduler_callback"]
        [::core::mem::offset_of!(xqc_conn_settings_s, scheduler_callback) - 360usize];
    ["Offset of field: xqc_conn_settings_s::scheduler_params"]
        [::core::mem::offset_of!(xqc_conn_settings_s, scheduler_params) - 408usize];
    ["Offset of field: xqc_conn_settings_s::reinj_ctl_callback"]
        [::core::mem::offset_of!(xqc_conn_settings_s, reinj_ctl_callback) - 456usize];
    ["Offset of field: xqc_conn_settings_s::standby_path_probe_timeout"]
        [::core::mem::offset_of!(xqc_conn_settings_s, standby_path_probe_timeout) - 496usize];
    ["Offset of field: xqc_conn_settings_s::max_ack_delay"]
        [::core::mem::offset_of!(xqc_conn_settings_s, max_ack_delay) - 504usize];
    ["Offset of field: xqc_conn_settings_s::ack_frequency"]
        [::core::mem::offset_of!(xqc_conn_settings_s, ack_frequency) - 508usize];
    ["Offset of field: xqc_conn_settings_s::adaptive_ack_frequency"]
        [::core::mem::offset_of!(xqc_conn_settings_s, adaptive_ack_frequency) - 512usize];
    ["Offset of field: xqc_conn_settings_s::loss_detection_pkt_thresh"]
        [::core::mem::offset_of!(xqc_conn_settings_s, loss_detection_pkt_thresh) - 520usize];
    ["Offset of field: xqc_conn_settings_s::pto_backoff_factor"]
        [::core::mem::offset_of!(xqc_conn_settings_s, pto_backoff_factor) - 528usize];
    ["Offset of field: xqc_conn_settings_s::datagram_redundancy"]
        [::core::mem::offset_of!(xqc_conn_settings_s, datagram_redundancy) - 536usize];
    ["Offset of field: xqc_conn_settings_s::datagram_force_retrans_on"]
        [::core::mem::offset_of!(xqc_conn_settings_s, datagram_force_retrans_on) - 537usize];
    ["Offset of field: xqc_conn_settings_s::datagram_redundant_probe"]
        [::core::mem::offset_of!(xqc_conn_settings_s, datagram_redundant_probe) - 544usize];
    ["Offset of field: xqc_conn_settings_s::enable_pmtud"]
        [::core::mem::offset_of!(xqc_conn_settings_s, enable_pmtud) - 552usize];
    ["Offset of field: xqc_conn_settings_s::pmtud_probing_interval"]
        [::core::mem::offset_of!(xqc_conn_settings_s, pmtud_probing_interval) - 560usize];
    ["Offset of field: xqc_conn_settings_s::marking_reinjection"]
        [::core::mem::offset_of!(xqc_conn_settings_s, marking_reinjection) - 568usize];
    ["Offset of field: xqc_conn_settings_s::recv_rate_bytes_per_sec"]
        [::core::mem::offset_of!(xqc_conn_settings_s, recv_rate_bytes_per_sec) - 576usize];
    ["Offset of field: xqc_conn_settings_s::enable_stream_rate_limit"]
        [::core::mem::offset_of!(xqc_conn_settings_s, enable_stream_rate_limit) - 584usize];
    ["Offset of field: xqc_conn_settings_s::init_recv_window"]
        [::core::mem::offset_of!(xqc_conn_settings_s, init_recv_window) - 588usize];
    ["Offset of field: xqc_conn_settings_s::is_interop_mode"]
        [::core::mem::offset_of!(xqc_conn_settings_s, is_interop_mode) - 592usize];
    ["Offset of field: xqc_conn_settings_s::conn_option_str"]
        [::core::mem::offset_of!(xqc_conn_settings_s, conn_option_str) - 593usize];
    ["Offset of field: xqc_conn_settings_s::initial_rtt"]
        [::core::mem::offset_of!(xqc_conn_settings_s, initial_rtt) - 680usize];
    ["Offset of field: xqc_conn_settings_s::initial_pto_duration"]
        [::core::mem::offset_of!(xqc_conn_settings_s, initial_pto_duration) - 688usize];
    ["Offset of field: xqc_conn_settings_s::enable_encode_fec"]
        [::core::mem::offset_of!(xqc_conn_settings_s, enable_encode_fec) - 696usize];
    ["Offset of field: xqc_conn_settings_s::enable_decode_fec"]
        [::core::mem::offset_of!(xqc_conn_settings_s, enable_decode_fec) - 704usize];
    ["Offset of field: xqc_conn_settings_s::fec_params"]
        [::core::mem::offset_of!(xqc_conn_settings_s, fec_params) - 712usize];
    ["Offset of field: xqc_conn_settings_s::fec_callback"]
        [::core::mem::offset_of!(xqc_conn_settings_s, fec_callback) - 824usize];
    ["Offset of field: xqc_conn_settings_s::close_dgram_redundancy"]
        [::core::mem::offset_of!(xqc_conn_settings_s, close_dgram_redundancy) - 864usize];
    ["Offset of field: xqc_conn_settings_s::disable_send_mmsg"]
        [::core::mem::offset_of!(xqc_conn_settings_s, disable_send_mmsg) - 868usize];
    ["Offset of field: xqc_conn_settings_s::control_pto_value"]
        [::core::mem::offset_of!(xqc_conn_settings_s, control_pto_value) - 869usize];
    ["Offset of field: xqc_conn_settings_s::max_udp_payload_size"]
        [::core::mem::offset_of!(xqc_conn_settings_s, max_udp_payload_size) - 872usize];
    ["Offset of field: xqc_conn_settings_s::fec_level"]
        [::core::mem::offset_of!(xqc_conn_settings_s, fec_level) - 880usize];
    ["Offset of field: xqc_conn_settings_s::extended_ack_features"]
        [::core::mem::offset_of!(xqc_conn_settings_s, extended_ack_features) - 888usize];
    ["Offset of field: xqc_conn_settings_s::max_receive_timestamps_per_ack"]
        [::core::mem::offset_of!(xqc_conn_settings_s, max_receive_timestamps_per_ack) - 896usize];
    ["Offset of field: xqc_conn_settings_s::receive_timestamps_exponent"]
        [::core::mem::offset_of!(xqc_conn_settings_s, receive_timestamps_exponent) - 904usize];
    ["Offset of field: xqc_conn_settings_s::disable_pn_skipping"]
        [::core::mem::offset_of!(xqc_conn_settings_s, disable_pn_skipping) - 912usize];
    ["Offset of field: xqc_conn_settings_s::specify_client_scid"]
        [::core::mem::offset_of!(xqc_conn_settings_s, specify_client_scid) - 913usize];
    ["Offset of field: xqc_conn_settings_s::client_scid"]
        [::core::mem::offset_of!(xqc_conn_settings_s, client_scid) - 914usize];
    ["Offset of field: xqc_conn_settings_s::specify_client_dcid"]
        [::core::mem::offset_of!(xqc_conn_settings_s, specify_client_dcid) - 934usize];
    ["Offset of field: xqc_conn_settings_s::client_dcid"]
        [::core::mem::offset_of!(xqc_conn_settings_s, client_dcid) - 935usize];
    ["Offset of field: xqc_conn_settings_s::max_streams_bidi"]
        [::core::mem::offset_of!(xqc_conn_settings_s, max_streams_bidi) - 960usize];
    ["Offset of field: xqc_conn_settings_s::max_streams_uni"]
        [::core::mem::offset_of!(xqc_conn_settings_s, max_streams_uni) - 968usize];
    ["Offset of field: xqc_conn_settings_s::simulate_ecn"]
        [::core::mem::offset_of!(xqc_conn_settings_s, simulate_ecn) - 976usize];
    ["Offset of field: xqc_conn_settings_s::max_path_id_grant_max_value"]
        [::core::mem::offset_of!(xqc_conn_settings_s, max_path_id_grant_max_value) - 984usize];
    ["Offset of field: xqc_conn_settings_s::max_blocked_buf_per_stream"]
        [::core::mem::offset_of!(xqc_conn_settings_s, max_blocked_buf_per_stream) - 992usize];
    ["Offset of field: xqc_conn_settings_s::max_blocked_buf_per_conn"]
        [::core::mem::offset_of!(xqc_conn_settings_s, max_blocked_buf_per_conn) - 1000usize];
    ["Offset of field: xqc_conn_settings_s::defer_send_flush"]
        [::core::mem::offset_of!(xqc_conn_settings_s, defer_send_flush) - 1008usize];
    ["Offset of field: xqc_conn_settings_s::max_implicit_streams"]
        [::core::mem::offset_of!(xqc_conn_settings_s, max_implicit_streams) - 1016usize];
};
#[doc = " without 0-RTT"]
pub const XQC_0RTT_NONE: xqc_0rtt_flag_t = 0;
#[doc = " 0-RTT was accepted"]
pub const XQC_0RTT_ACCEPT: xqc_0rtt_flag_t = 1;
#[doc = " 0-RTT was rejected"]
pub const XQC_0RTT_REJECT: xqc_0rtt_flag_t = 2;
pub type xqc_0rtt_flag_t = ::core::ffi::c_uint;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xqc_path_metrics_s {
    pub path_id: u64,
    pub path_pkt_recv_count: u64,
    pub path_pkt_send_count: u64,
    pub path_send_bytes: u64,
    pub path_send_reinject_bytes: u64,
    pub path_recv_bytes: u64,
    pub path_recv_reinject_bytes: u64,
    pub path_recv_effective_bytes: u64,
    pub path_recv_effective_reinject_bytes: u64,
    pub path_srtt: u64,
    pub path_app_status: u8,
    pub path_min_rtt: u64,
    pub path_cwnd: u64,
    pub path_bytes_in_flight: u64,
    pub path_est_bw: u64,
    pub path_pacing_rate: u64,
    pub path_lost_count: u32,
    pub path_state: u8,
}
#[allow(clippy::unnecessary_operation, clippy::identity_op)]
const _: () = {
    ["Size of xqc_path_metrics_s"][::core::mem::size_of::<xqc_path_metrics_s>() - 136usize];
    ["Alignment of xqc_path_metrics_s"][::core::mem::align_of::<xqc_path_metrics_s>() - 8usize];
    ["Offset of field: xqc_path_metrics_s::path_id"]
        [::core::mem::offset_of!(xqc_path_metrics_s, path_id) - 0usize];
    ["Offset of field: xqc_path_metrics_s::path_pkt_recv_count"]
        [::core::mem::offset_of!(xqc_path_metrics_s, path_pkt_recv_count) - 8usize];
    ["Offset of field: xqc_path_metrics_s::path_pkt_send_count"]
        [::core::mem::offset_of!(xqc_path_metrics_s, path_pkt_send_count) - 16usize];
    ["Offset of field: xqc_path_metrics_s::path_send_bytes"]
        [::core::mem::offset_of!(xqc_path_metrics_s, path_send_bytes) - 24usize];
    ["Offset of field: xqc_path_metrics_s::path_send_reinject_bytes"]
        [::core::mem::offset_of!(xqc_path_metrics_s, path_send_reinject_bytes) - 32usize];
    ["Offset of field: xqc_path_metrics_s::path_recv_bytes"]
        [::core::mem::offset_of!(xqc_path_metrics_s, path_recv_bytes) - 40usize];
    ["Offset of field: xqc_path_metrics_s::path_recv_reinject_bytes"]
        [::core::mem::offset_of!(xqc_path_metrics_s, path_recv_reinject_bytes) - 48usize];
    ["Offset of field: xqc_path_metrics_s::path_recv_effective_bytes"]
        [::core::mem::offset_of!(xqc_path_metrics_s, path_recv_effective_bytes) - 56usize];
    ["Offset of field: xqc_path_metrics_s::path_recv_effective_reinject_bytes"]
        [::core::mem::offset_of!(xqc_path_metrics_s, path_recv_effective_reinject_bytes) - 64usize];
    ["Offset of field: xqc_path_metrics_s::path_srtt"]
        [::core::mem::offset_of!(xqc_path_metrics_s, path_srtt) - 72usize];
    ["Offset of field: xqc_path_metrics_s::path_app_status"]
        [::core::mem::offset_of!(xqc_path_metrics_s, path_app_status) - 80usize];
    ["Offset of field: xqc_path_metrics_s::path_min_rtt"]
        [::core::mem::offset_of!(xqc_path_metrics_s, path_min_rtt) - 88usize];
    ["Offset of field: xqc_path_metrics_s::path_cwnd"]
        [::core::mem::offset_of!(xqc_path_metrics_s, path_cwnd) - 96usize];
    ["Offset of field: xqc_path_metrics_s::path_bytes_in_flight"]
        [::core::mem::offset_of!(xqc_path_metrics_s, path_bytes_in_flight) - 104usize];
    ["Offset of field: xqc_path_metrics_s::path_est_bw"]
        [::core::mem::offset_of!(xqc_path_metrics_s, path_est_bw) - 112usize];
    ["Offset of field: xqc_path_metrics_s::path_pacing_rate"]
        [::core::mem::offset_of!(xqc_path_metrics_s, path_pacing_rate) - 120usize];
    ["Offset of field: xqc_path_metrics_s::path_lost_count"]
        [::core::mem::offset_of!(xqc_path_metrics_s, path_lost_count) - 128usize];
    ["Offset of field: xqc_path_metrics_s::path_state"]
        [::core::mem::offset_of!(xqc_path_metrics_s, path_state) - 132usize];
};
pub type xqc_path_metrics_t = xqc_path_metrics_s;
#[doc = " @brief connection stats"]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xqc_conn_stats_s {
    pub send_count: u32,
    pub lost_count: u32,
    pub tlp_count: u32,
    pub spurious_loss_count: u32,
    #[doc = " how many datagram frames (pkts) are lost"]
    pub lost_dgram_count: u32,
    #[doc = " smoothed SRTT at present: initial value = 250000"]
    pub srtt: xqc_usec_t,
    #[doc = " minimum RTT until now: initial value = 0xFFFFFFFF"]
    pub min_rtt: xqc_usec_t,
    #[doc = " initial value = 0"]
    pub inflight_bytes: u64,
    pub early_data_flag: xqc_0rtt_flag_t,
    pub recv_count: u32,
    pub spurious_loss_detect_on: ::core::ffi::c_int,
    pub conn_err: ::core::ffi::c_int,
    pub ack_info: [::core::ffi::c_char; 50usize],
    #[doc = " @brief enable_multipath: 表示MP参数协商结果\n 0: 不支持MP\n 1: 支持MP, 采用 Single PNS\n 2: 支持MP, 采用 Multiple PNS"]
    pub enable_multipath: ::core::ffi::c_int,
    #[doc = " @brief 连接级别MP状态\n 0: 未尝试建立过双路 (create_path_count <= 1)\n 1: 成功建立起双路，对端验证成功 (create_path_count > 1 && validated_path_count > 1)\n 2: 尝试建立过双路，但没有探测成功 (create_path_count > 1 && validated_path_count <=\n 1)"]
    pub mp_state: ::core::ffi::c_int,
    pub total_rebind_count: ::core::ffi::c_int,
    pub total_rebind_valid: ::core::ffi::c_int,
    #[doc = " Active path metrics. Dynamically allocated by xquic.\n\n Ownership: xquic allocates the buffer; caller MUST free() (libc free,\n not xqc_free) the paths_info pointer after use to avoid leaking. On\n error returns (e.g. connection not found, allocation failure),\n paths_info == NULL and paths_info_count == 0; no free is required in\n that case. paths_info_count == 0 may be paired with a NULL paths_info;\n free(NULL) is safe.\n\n PR3 spec §4.3 Rev 4: replaces fixed-size paths_info array (was capped\n at 8 paths via the now-removed XQC_MAX_PATHS_COUNT macro)."]
    pub paths_info: *mut xqc_path_metrics_t,
    pub paths_info_count: u32,
    pub conn_info: [::core::ffi::c_char; 400usize],
    pub alpn: [::core::ffi::c_char; 256usize],
    pub extern_conn_info: [::core::ffi::c_char; 128usize],
    pub send_fec_cnt: u32,
    pub enable_fec: u8,
    #[doc = " only accounts for stream and datagram packets"]
    pub total_app_bytes: u64,
    pub standby_path_app_bytes: u64,
    pub max_acked_mtu: u32,
    pub fec_recover_pkt_cnt: u32,
    pub avg_close_time: xqc_usec_t,
}
#[allow(clippy::unnecessary_operation, clippy::identity_op)]
const _: () = {
    ["Size of xqc_conn_stats_s"][::core::mem::size_of::<xqc_conn_stats_s>() - 976usize];
    ["Alignment of xqc_conn_stats_s"][::core::mem::align_of::<xqc_conn_stats_s>() - 8usize];
    ["Offset of field: xqc_conn_stats_s::send_count"]
        [::core::mem::offset_of!(xqc_conn_stats_s, send_count) - 0usize];
    ["Offset of field: xqc_conn_stats_s::lost_count"]
        [::core::mem::offset_of!(xqc_conn_stats_s, lost_count) - 4usize];
    ["Offset of field: xqc_conn_stats_s::tlp_count"]
        [::core::mem::offset_of!(xqc_conn_stats_s, tlp_count) - 8usize];
    ["Offset of field: xqc_conn_stats_s::spurious_loss_count"]
        [::core::mem::offset_of!(xqc_conn_stats_s, spurious_loss_count) - 12usize];
    ["Offset of field: xqc_conn_stats_s::lost_dgram_count"]
        [::core::mem::offset_of!(xqc_conn_stats_s, lost_dgram_count) - 16usize];
    ["Offset of field: xqc_conn_stats_s::srtt"]
        [::core::mem::offset_of!(xqc_conn_stats_s, srtt) - 24usize];
    ["Offset of field: xqc_conn_stats_s::min_rtt"]
        [::core::mem::offset_of!(xqc_conn_stats_s, min_rtt) - 32usize];
    ["Offset of field: xqc_conn_stats_s::inflight_bytes"]
        [::core::mem::offset_of!(xqc_conn_stats_s, inflight_bytes) - 40usize];
    ["Offset of field: xqc_conn_stats_s::early_data_flag"]
        [::core::mem::offset_of!(xqc_conn_stats_s, early_data_flag) - 48usize];
    ["Offset of field: xqc_conn_stats_s::recv_count"]
        [::core::mem::offset_of!(xqc_conn_stats_s, recv_count) - 52usize];
    ["Offset of field: xqc_conn_stats_s::spurious_loss_detect_on"]
        [::core::mem::offset_of!(xqc_conn_stats_s, spurious_loss_detect_on) - 56usize];
    ["Offset of field: xqc_conn_stats_s::conn_err"]
        [::core::mem::offset_of!(xqc_conn_stats_s, conn_err) - 60usize];
    ["Offset of field: xqc_conn_stats_s::ack_info"]
        [::core::mem::offset_of!(xqc_conn_stats_s, ack_info) - 64usize];
    ["Offset of field: xqc_conn_stats_s::enable_multipath"]
        [::core::mem::offset_of!(xqc_conn_stats_s, enable_multipath) - 116usize];
    ["Offset of field: xqc_conn_stats_s::mp_state"]
        [::core::mem::offset_of!(xqc_conn_stats_s, mp_state) - 120usize];
    ["Offset of field: xqc_conn_stats_s::total_rebind_count"]
        [::core::mem::offset_of!(xqc_conn_stats_s, total_rebind_count) - 124usize];
    ["Offset of field: xqc_conn_stats_s::total_rebind_valid"]
        [::core::mem::offset_of!(xqc_conn_stats_s, total_rebind_valid) - 128usize];
    ["Offset of field: xqc_conn_stats_s::paths_info"]
        [::core::mem::offset_of!(xqc_conn_stats_s, paths_info) - 136usize];
    ["Offset of field: xqc_conn_stats_s::paths_info_count"]
        [::core::mem::offset_of!(xqc_conn_stats_s, paths_info_count) - 144usize];
    ["Offset of field: xqc_conn_stats_s::conn_info"]
        [::core::mem::offset_of!(xqc_conn_stats_s, conn_info) - 148usize];
    ["Offset of field: xqc_conn_stats_s::alpn"]
        [::core::mem::offset_of!(xqc_conn_stats_s, alpn) - 548usize];
    ["Offset of field: xqc_conn_stats_s::extern_conn_info"]
        [::core::mem::offset_of!(xqc_conn_stats_s, extern_conn_info) - 804usize];
    ["Offset of field: xqc_conn_stats_s::send_fec_cnt"]
        [::core::mem::offset_of!(xqc_conn_stats_s, send_fec_cnt) - 932usize];
    ["Offset of field: xqc_conn_stats_s::enable_fec"]
        [::core::mem::offset_of!(xqc_conn_stats_s, enable_fec) - 936usize];
    ["Offset of field: xqc_conn_stats_s::total_app_bytes"]
        [::core::mem::offset_of!(xqc_conn_stats_s, total_app_bytes) - 944usize];
    ["Offset of field: xqc_conn_stats_s::standby_path_app_bytes"]
        [::core::mem::offset_of!(xqc_conn_stats_s, standby_path_app_bytes) - 952usize];
    ["Offset of field: xqc_conn_stats_s::max_acked_mtu"]
        [::core::mem::offset_of!(xqc_conn_stats_s, max_acked_mtu) - 960usize];
    ["Offset of field: xqc_conn_stats_s::fec_recover_pkt_cnt"]
        [::core::mem::offset_of!(xqc_conn_stats_s, fec_recover_pkt_cnt) - 964usize];
    ["Offset of field: xqc_conn_stats_s::avg_close_time"]
        [::core::mem::offset_of!(xqc_conn_stats_s, avg_close_time) - 968usize];
};
#[doc = " @brief connection stats"]
pub type xqc_conn_stats_t = xqc_conn_stats_s;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xqc_conn_qos_stats_s {
    #[doc = " smoothed SRTT at present: initial value = 250000"]
    pub srtt: xqc_usec_t,
    #[doc = " minimum RTT until now: initial value = 0xFFFFFFFF"]
    pub min_rtt: xqc_usec_t,
    #[doc = " initial value = 0"]
    pub inflight_bytes: u64,
}
#[allow(clippy::unnecessary_operation, clippy::identity_op)]
const _: () = {
    ["Size of xqc_conn_qos_stats_s"][::core::mem::size_of::<xqc_conn_qos_stats_s>() - 24usize];
    ["Alignment of xqc_conn_qos_stats_s"][::core::mem::align_of::<xqc_conn_qos_stats_s>() - 8usize];
    ["Offset of field: xqc_conn_qos_stats_s::srtt"]
        [::core::mem::offset_of!(xqc_conn_qos_stats_s, srtt) - 0usize];
    ["Offset of field: xqc_conn_qos_stats_s::min_rtt"]
        [::core::mem::offset_of!(xqc_conn_qos_stats_s, min_rtt) - 8usize];
    ["Offset of field: xqc_conn_qos_stats_s::inflight_bytes"]
        [::core::mem::offset_of!(xqc_conn_qos_stats_s, inflight_bytes) - 16usize];
};
unsafe extern "C" {
    #[doc = " @brief Create new xquic engine.\n\n @param engine_type  XQC_ENGINE_SERVER or XQC_ENGINE_CLIENT\n @param engine_config config for basic framework, quic, network, etc.\n @param ssl_config basic ssl config\n @param engine_callback environment callback functions, including timer, socket, log,\n etc.\n @param transport_cbs transport callback functions\n @param conn_callback default connection callback functions"]
    pub fn xqc_engine_create(
        engine_type: xqc_engine_type_t,
        engine_config: *const xqc_config_t,
        ssl_config: *const xqc_engine_ssl_config_t,
        engine_callback: *const xqc_engine_callback_t,
        transport_cbs: *const xqc_transport_callbacks_t,
        user_data: *mut ::core::ffi::c_void,
    ) -> *mut xqc_engine_t;
}
unsafe extern "C" {
    #[doc = " @brief destroy engine. this is called after all connections are destroyed \\n\n NOTICE: MUST NOT be called in any xquic callback functions, for this function will\n destroy engine immediately, result in segmentation fault."]
    pub fn xqc_engine_destroy(engine: *mut xqc_engine_t);
}
unsafe extern "C" {
    #[doc = " @brief register alpn and connection and stream callbacks. user can implement his own\n application protocol by registering alpn, and taking quic connection and streams as\n application connection and request\n\n @param engine engine handler\n @param alpn Application-Layer-Protocol, for example, h3, hq-interop, or self-defined\n @param alpn_len length of Application-Layer-Protocol string\n @param ap_cbs connection and stream event callback functions for\n application-layer-protocol\n @param alp_ctx the context of the upper layer protocol (e.g. the callback functions and\n default settings of the upper layer protocol)\n @return XQC_EXPORT_PUBLIC_API"]
    pub fn xqc_engine_register_alpn(
        engine: *mut xqc_engine_t,
        alpn: *const ::core::ffi::c_char,
        alpn_len: usize,
        ap_cbs: *mut xqc_app_proto_callbacks_t,
        alp_ctx: *mut ::core::ffi::c_void,
    ) -> xqc_int_t;
}
unsafe extern "C" {
    #[doc = " @brief unregister an alpn and its quic connection callbacks\n\n @param engine engine handler\n @param alpn Application-Layer-Protocol, for example, h3, hq-interop, or self-defined\n @param alpn_len length of alpn\n @return XQC_EXPORT_PUBLIC_API"]
    pub fn xqc_engine_unregister_alpn(
        engine: *mut xqc_engine_t,
        alpn: *const ::core::ffi::c_char,
        alpn_len: usize,
    ) -> xqc_int_t;
}
unsafe extern "C" {
    #[doc = " @brief get the context an application layer protocol\n\n @param engine engine handler\n @param alpn Application-Layer-Protocol, for example, h3, hq-interop, or self-defined\n @param alpn_len length of alpn\n @return the context"]
    pub fn xqc_engine_get_alpn_ctx(
        engine: *mut xqc_engine_t,
        alpn: *const ::core::ffi::c_char,
        alpn_len: usize,
    ) -> *mut ::core::ffi::c_void;
}
unsafe extern "C" {
    #[doc = " @brief get the private context\n\n @param engine\n @return XQC_EXPORT_PUBLIC_API*"]
    pub fn xqc_engine_get_priv_ctx(engine: *mut xqc_engine_t) -> *mut ::core::ffi::c_void;
}
unsafe extern "C" {
    #[doc = " @brief save the private context\n\n @param engine\n @param priv_ctx\n @return XQC_EXPORT_PUBLIC_API"]
    pub fn xqc_engine_set_priv_ctx(
        engine: *mut xqc_engine_t,
        priv_ctx: *mut ::core::ffi::c_void,
    ) -> xqc_int_t;
}
unsafe extern "C" {
    #[doc = " Pass received UDP packet payload into xquic engine.\n @param recv_time   UDP packet received time in microsecond\n @param user_data   connection user_data, server is NULL"]
    pub fn xqc_engine_packet_process(
        engine: *mut xqc_engine_t,
        packet_in_buf: *const ::core::ffi::c_uchar,
        packet_in_size: usize,
        local_addr: *const sockaddr,
        local_addrlen: socklen_t,
        peer_addr: *const sockaddr,
        peer_addrlen: socklen_t,
        recv_time: xqc_usec_t,
        user_data: *mut ::core::ffi::c_void,
    ) -> xqc_int_t;
}
unsafe extern "C" {
    #[doc = " @brief Process all connections, application implements MUST call this function in timer\n callback"]
    pub fn xqc_engine_main_logic(engine: *mut xqc_engine_t);
}
unsafe extern "C" {
    #[doc = " @brief get default config of xquic"]
    pub fn xqc_engine_get_default_config(
        config: *mut xqc_config_t,
        engine_type: xqc_engine_type_t,
    ) -> xqc_int_t;
}
unsafe extern "C" {
    #[doc = " Modify engine config before engine created. Default config will be used otherwise.\n Item value 0 means use default value.\n @return 0 for success, <0 for error. default value is used if config item is illegal"]
    pub fn xqc_engine_set_config(
        engine: *mut xqc_engine_t,
        engine_config: *const xqc_config_t,
    ) -> xqc_int_t;
}
unsafe extern "C" {
    #[doc = " @brief Set server's connection settings. it can be called anytime. settings will take\n effect on new created connections"]
    pub fn xqc_server_set_conn_settings(
        engine: *mut xqc_engine_t,
        settings: *const xqc_conn_settings_t,
    );
}
unsafe extern "C" {
    #[doc = " @brief Set the log level of xquic\n\n @param log_level engine will print logs which level >= log_level"]
    pub fn xqc_engine_set_log_level(engine: *mut xqc_engine_t, log_level: xqc_log_level_t);
}
unsafe extern "C" {
    #[doc = " @brief enable/disable the log module of xquic\n @note  This function is not thread-safe.\n\n @param enable XQC_TRUE for disable, XQC_FALSE for enable"]
    pub fn xqc_log_disable(disable: xqc_bool_t);
}
unsafe extern "C" {
    #[doc = " user should call after a number of packet processed in xqc_engine_packet_process\n call after recv a batch packets, may destroy connection when error"]
    pub fn xqc_engine_finish_recv(engine: *mut xqc_engine_t);
}
unsafe extern "C" {
    #[doc = " @brief only useful for manually triggered send mode\n\n @param engine\n @return XQC_EXPORT_PUBLIC_API"]
    pub fn xqc_engine_finish_send(engine: *mut xqc_engine_t);
}
unsafe extern "C" {
    pub fn xqc_engine_get_conn_by_scid(
        engine: *mut xqc_engine_t,
        cid: *const xqc_cid_t,
    ) -> *mut xqc_connection_t;
}
unsafe extern "C" {
    #[doc = "  QUIC layer APIs\n/\n/**\n Client connect without http3\n @param engine return from xqc_engine_create\n @param conn_settings settings of connection\n @param token token receive from server, xqc_save_token_pt callback\n @param token_len\n @param server_host server domain\n @param no_crypto_flag 1: stop encrypt 0-RTT and 1-RTT packets. \\n\n This flag will add no_crypto transport parameter when initiating a connection, which is\n not an official parameter and might be modified or removed\n @param conn_ssl_config For handshake\n @param user_data application data, for connection usage\n @param peer_addr address of peer\n @param peer_addrlen length of peer_addr\n @param alpn Application-Layer-Protocol, MUST NOT be NULL\n @return user should copy cid to your own memory, in case of cid destroyed in xquic\n library"]
    pub fn xqc_connect(
        engine: *mut xqc_engine_t,
        conn_settings: *const xqc_conn_settings_t,
        token: *const ::core::ffi::c_uchar,
        token_len: ::core::ffi::c_uint,
        server_host: *const ::core::ffi::c_char,
        no_crypto_flag: ::core::ffi::c_int,
        conn_ssl_config: *const xqc_conn_ssl_config_t,
        peer_addr: *const sockaddr,
        peer_addrlen: socklen_t,
        alpn: *const ::core::ffi::c_char,
        user_data: *mut ::core::ffi::c_void,
    ) -> *const xqc_cid_t;
}
unsafe extern "C" {
    #[doc = " Send CONNECTION_CLOSE to peer, conn_close_notify will callback when connection\n destroyed\n @return 0 for success, <0 for error"]
    pub fn xqc_conn_close(engine: *mut xqc_engine_t, cid: *const xqc_cid_t) -> xqc_int_t;
}
unsafe extern "C" {
    #[doc = " @brief close connection with error code"]
    pub fn xqc_conn_close_with_error(conn: *mut xqc_connection_t, err_code: u64) -> xqc_int_t;
}
unsafe extern "C" {
    #[doc = " Get errno when conn_close_notify, 0 For no-error"]
    pub fn xqc_conn_get_errno(conn: *mut xqc_connection_t) -> xqc_int_t;
}
unsafe extern "C" {
    #[doc = " Get the namespace of an error received in the first CONNECTION_CLOSE frame.\n\n Pair this with xqc_conn_get_errno() when the connection was closed by the\n peer. XQC_CONN_ERR_TYPE_UNKNOWN is returned before a peer CONNECTION_CLOSE\n frame is received."]
    pub fn xqc_conn_get_err_type(conn: *mut xqc_connection_t) -> xqc_conn_err_type_t;
}
unsafe extern "C" {
    #[doc = " Get ssl handler of specified connection"]
    pub fn xqc_conn_get_ssl(conn: *mut xqc_connection_t) -> *mut ::core::ffi::c_void;
}
unsafe extern "C" {
    #[doc = " @brief get latest rtt sample of the initial path\n"]
    pub fn xqc_conn_get_lastest_rtt(engine: *mut xqc_engine_t, cid: *const xqc_cid_t)
    -> xqc_usec_t;
}
unsafe extern "C" {
    #[doc = " Server should set user_data when conn_create_notify callbacks"]
    pub fn xqc_conn_set_transport_user_data(
        conn: *mut xqc_connection_t,
        user_data: *mut ::core::ffi::c_void,
    );
}
unsafe extern "C" {
    #[doc = " @brief set application-layer-protocol user_data to xqc_connection_t. which will be used\n in xqc_conn_callbacks_t"]
    pub fn xqc_conn_set_alp_user_data(
        conn: *mut xqc_connection_t,
        proto_data: *mut ::core::ffi::c_void,
    );
}
unsafe extern "C" {
    #[doc = " Server should get peer addr when conn_create_notify callbacks\n @param peer_addr_len is a return value\n @return XQC_OK for success, others for failure"]
    pub fn xqc_conn_get_peer_addr(
        conn: *mut xqc_connection_t,
        addr: *mut sockaddr,
        addr_cap: socklen_t,
        peer_addr_len: *mut socklen_t,
    ) -> xqc_int_t;
}
unsafe extern "C" {
    #[doc = " Server should get local addr when conn_create_notify callbacks\n @param local_addr_len is a return value\n @return XQC_OK for success, others for failure"]
    pub fn xqc_conn_get_local_addr(
        conn: *mut xqc_connection_t,
        addr: *mut sockaddr,
        addr_cap: socklen_t,
        local_addr_len: *mut socklen_t,
    ) -> xqc_int_t;
}
unsafe extern "C" {
    #[doc = " Send PING to peer, if ack received, conn_ping_acked will callback with user_data\n @return 0 for success, <0 for error"]
    pub fn xqc_conn_send_ping(
        engine: *mut xqc_engine_t,
        cid: *const xqc_cid_t,
        ping_user_data: *mut ::core::ffi::c_void,
    ) -> xqc_int_t;
}
unsafe extern "C" {
    #[doc = " @return 1 for can send 0rtt, 0 for cannot send 0rtt"]
    pub fn xqc_conn_is_ready_to_send_early_data(conn: *mut xqc_connection_t) -> xqc_bool_t;
}
unsafe extern "C" {
    #[doc = " @brief set the packet filter callback function, and replace write_socket. \\n\n NOTICE: this function is not conflict with send_mmsg."]
    pub fn xqc_conn_set_pkt_filter_callback(
        conn: *mut xqc_connection_t,
        pf_cb: xqc_conn_pkt_filter_callback_pt,
        pf_cb_user_data: *mut ::core::ffi::c_void,
    );
}
unsafe extern "C" {
    #[doc = " @brief unset the packet filter callback function, and restore write_socket"]
    pub fn xqc_conn_unset_pkt_filter_callback(conn: *mut xqc_connection_t);
}
unsafe extern "C" {
    #[doc = " @brief get public local transport settings."]
    pub fn xqc_conn_get_public_local_trans_settings(
        conn: *mut xqc_connection_t,
    ) -> xqc_conn_public_local_trans_settings_t;
}
unsafe extern "C" {
    #[doc = " @brief set public local transport settings"]
    pub fn xqc_conn_set_public_local_trans_settings(
        conn: *mut xqc_connection_t,
        settings: *mut xqc_conn_public_local_trans_settings_t,
    );
}
unsafe extern "C" {
    #[doc = " @brief get public remote transport settings."]
    pub fn xqc_conn_get_public_remote_trans_settings(
        conn: *mut xqc_connection_t,
    ) -> xqc_conn_public_remote_trans_settings_t;
}
unsafe extern "C" {
    #[doc = " @brief set public remote transport settings"]
    pub fn xqc_conn_set_public_remote_trans_settings(
        conn: *mut xqc_connection_t,
        settings: *mut xqc_conn_public_remote_trans_settings_t,
    );
}
unsafe extern "C" {
    #[doc = " @brief Create new stream in quic connection.\n @param user_data  user_data for this stream"]
    pub fn xqc_stream_create(
        engine: *mut xqc_engine_t,
        cid: *const xqc_cid_t,
        settings: *mut xqc_stream_settings_t,
        user_data: *mut ::core::ffi::c_void,
    ) -> *mut xqc_stream_t;
}
unsafe extern "C" {
    pub fn xqc_stream_create_with_direction(
        conn: *mut xqc_connection_t,
        dir: xqc_stream_direction_t,
        user_data: *mut ::core::ffi::c_void,
    ) -> *mut xqc_stream_t;
}
unsafe extern "C" {
    pub fn xqc_stream_get_direction(strm: *mut xqc_stream_t) -> xqc_stream_direction_t;
}
unsafe extern "C" {
    #[doc = " Server should set user_data when stream_create_notify callbacks"]
    pub fn xqc_stream_set_user_data(stream: *mut xqc_stream_t, user_data: *mut ::core::ffi::c_void);
}
unsafe extern "C" {
    pub fn xqc_stream_update_settings(
        stream: *mut xqc_stream_t,
        settings: *mut xqc_stream_settings_t,
    ) -> xqc_int_t;
}
unsafe extern "C" {
    #[doc = " Get connection's user_data by stream"]
    pub fn xqc_get_conn_user_data_by_stream(stream: *mut xqc_stream_t) -> *mut ::core::ffi::c_void;
}
unsafe extern "C" {
    #[doc = " Get connection's app_proto_user_data by stream"]
    pub fn xqc_get_conn_alp_user_data_by_stream(
        stream: *mut xqc_stream_t,
    ) -> *mut ::core::ffi::c_void;
}
unsafe extern "C" {
    #[doc = " Get stream ID"]
    pub fn xqc_stream_id(stream: *mut xqc_stream_t) -> xqc_stream_id_t;
}
unsafe extern "C" {
    #[doc = " Send RESET_STREAM to peer, stream_close_notify will callback when stream destroyed\n @retval XQC_OK for success, others for failure"]
    pub fn xqc_stream_close(stream: *mut xqc_stream_t) -> xqc_int_t;
}
unsafe extern "C" {
    #[doc = " Recv data in stream.\n @return bytes read, -XQC_EAGAIN try next time, <0 for error"]
    pub fn xqc_stream_recv(
        stream: *mut xqc_stream_t,
        recv_buf: *mut ::core::ffi::c_uchar,
        recv_buf_size: usize,
        fin: *mut u8,
    ) -> isize;
}
unsafe extern "C" {
    #[doc = " Send data in stream.\n @param fin  0 or 1,  1 - final data block send in this stream.\n @return bytes sent, -XQC_EAGAIN try next time, <0 for error"]
    pub fn xqc_stream_send(
        stream: *mut xqc_stream_t,
        send_data: *mut ::core::ffi::c_uchar,
        send_data_size: usize,
        fin: u8,
    ) -> isize;
}
unsafe extern "C" {
    #[doc = " @brief the API to get the max length of the data that can be sent\n        via a single call of xqc_datagram_send;\n\n NOTE: if the DCID length could be changed during the lifetime of the connection,\n applications is suggested to call xqc_datagram_get_mss every time before send datagram\n data or when getting -XQC_EDGRAM_TOO_LARGE error from sending datagram data. In MPQUIC\n cases, the DCID of all paths MUST be the same. Otherwise, there might be unexpected\n errors.\n\n @param conn the connection handle\n @return 0 = the peer does not support datagram, >0 = the max length"]
    pub fn xqc_datagram_get_mss(conn: *mut xqc_connection_t) -> usize;
}
unsafe extern "C" {
    #[doc = " @brief get the path-specific maximum datagram payload size\n\n In multipath QUIC, different paths may have different MTUs.\n This function returns the effective MSS for a specific path,\n taking into account the path's max_pkt_out_size.\n\n @param conn the connection handle\n @param path_id the path identifier\n @return 0 = path not found or peer does not support datagram, >0 = the max length"]
    pub fn xqc_datagram_get_mss_on_path(conn: *mut xqc_connection_t, path_id: u64) -> usize;
}
unsafe extern "C" {
    #[doc = " Server should set datagram user_data when datagram callbacks\n @dgram_data: the user_data of all datagram callbacks"]
    pub fn xqc_datagram_set_user_data(
        conn: *mut xqc_connection_t,
        dgram_data: *mut ::core::ffi::c_void,
    );
}
unsafe extern "C" {
    #[doc = " @dgram_data: the user_data of all datagram callbacks"]
    pub fn xqc_datagram_get_user_data(conn: *mut xqc_connection_t) -> *mut ::core::ffi::c_void;
}
unsafe extern "C" {
    #[doc = " @brief the API to send a datagram over the QUIC connection\n\n @param conn the connection handle\n @param data the data to be sent\n @param data_len the length of the data\n @param *dgram_id the pointer to return the id the datagram\n @param qos level (must be the values defined in xqc_data_qos_level_t)\n @return <0 = error (-XQC_EAGAIN, -XQC_CLOSING, -XQC_EDGRAM_NOT_SUPPORTED,\n -XQC_EDGRAM_TOO_LARGE, ...), 0 success"]
    pub fn xqc_datagram_send(
        conn: *mut xqc_connection_t,
        data: *mut ::core::ffi::c_void,
        data_len: usize,
        dgram_id: *mut u64,
        qos_level: xqc_data_qos_level_t,
    ) -> xqc_int_t;
}
unsafe extern "C" {
    #[doc = " @brief the API to send a datagram over the QUIC connection\n\n @param conn the connection handle\n @param iov multiple data buffers need to be sent\n @param *dgram_id the pointer to return the list of dgram_id\n @param iov_size the size of iov list\n @param *sent_cnt the number of successfully sent datagrams\n @param *sent_bytes the total bytes of successfully sent datagrams\n @param qos level (must be the values defined in xqc_data_qos_level_t)\n @return <0 = error (-XQC_EAGAIN, -XQC_CLOSING, -XQC_EDGRAM_NOT_SUPPORTED,\n -XQC_EDGRAM_TOO_LARGE, ...), 0 success"]
    pub fn xqc_datagram_send_multiple(
        conn: *mut xqc_connection_t,
        iov: *mut iovec,
        dgram_id_list: *mut u64,
        iov_size: usize,
        sent_cnt: *mut usize,
        sent_bytes: *mut usize,
        qos_level: xqc_data_qos_level_t,
    ) -> xqc_int_t;
}
unsafe extern "C" {
    #[doc = " @brief send a datagram pinned to a specific path (multipath QUIC)\n\n Same as xqc_datagram_send but the datagram packet is pinned to the\n given path_id, bypassing the multipath scheduler.\n Use XQC_INITIAL_PATH_ID (0) for the initial path.\n\n @param conn the connection handle\n @param data the data to be sent\n @param data_len the length of the data\n @param dgram_id pointer to return the id of the datagram\n @param qos_level QoS level (must be the values defined in xqc_data_qos_level_t)\n @param path_id the path to pin this datagram to\n @return <0 = error, 0 = success"]
    pub fn xqc_datagram_send_on_path(
        conn: *mut xqc_connection_t,
        data: *mut ::core::ffi::c_void,
        data_len: usize,
        dgram_id: *mut u64,
        qos_level: xqc_data_qos_level_t,
        path_id: u64,
    ) -> xqc_int_t;
}
unsafe extern "C" {
    #[doc = " Get dcid and scid before process packet"]
    pub fn xqc_packet_parse_cid(
        dcid: *mut xqc_cid_t,
        scid: *mut xqc_cid_t,
        cid_len: u8,
        buf: *const ::core::ffi::c_uchar,
        size: usize,
    ) -> xqc_int_t;
}
unsafe extern "C" {
    #[doc = " @brief compare two cids\n @return XQC_OK if equal, others if not equal"]
    pub fn xqc_cid_is_equal(dst: *const xqc_cid_t, src: *const xqc_cid_t) -> xqc_int_t;
}
unsafe extern "C" {
    #[doc = " Get scid in hex, end with '\\0'\n @param scid is returned from xqc_connect or xqc_h3_connect\n @return user should copy return buffer to your own memory if you will access in the\n future"]
    pub fn xqc_scid_str(
        engine: *mut xqc_engine_t,
        scid: *const xqc_cid_t,
    ) -> *mut ::core::ffi::c_uchar;
}
unsafe extern "C" {
    pub fn xqc_dcid_str(
        engine: *mut xqc_engine_t,
        dcid: *const xqc_cid_t,
    ) -> *mut ::core::ffi::c_uchar;
}
unsafe extern "C" {
    pub fn xqc_dcid_str_by_scid(
        engine: *mut xqc_engine_t,
        scid: *const xqc_cid_t,
    ) -> *mut ::core::ffi::c_uchar;
}
unsafe extern "C" {
    pub fn xqc_engine_config_get_cid_len(engine: *mut xqc_engine_t) -> u8;
}
unsafe extern "C" {
    #[doc = " User should call xqc_conn_continue_send when write event ready"]
    pub fn xqc_conn_continue_send(engine: *mut xqc_engine_t, cid: *const xqc_cid_t) -> xqc_int_t;
}
unsafe extern "C" {
    #[doc = " User should call xqc_conn_continue_send when write event ready"]
    pub fn xqc_conn_continue_send_by_conn(conn: *mut xqc_connection_t);
}
unsafe extern "C" {
    #[doc = " User can get xqc_conn_stats_t by cid"]
    pub fn xqc_conn_get_stats(engine: *mut xqc_engine_t, cid: *const xqc_cid_t)
    -> xqc_conn_stats_t;
}
unsafe extern "C" {
    #[doc = " User can get xqc_conn_qos_stats_t by cid"]
    pub fn xqc_conn_get_qos_stats(
        engine: *mut xqc_engine_t,
        cid: *const xqc_cid_t,
    ) -> xqc_conn_qos_stats_t;
}
unsafe extern "C" {
    #[doc = " create new path for client\n @param cid scid for connection\n @param new_path_id if new path is created successfully, return new_path_id in this\n param\n @param path_status the initial status of the new path (1 = STANDBY, other values =\n AVAILABLE)\n @return XQC_OK (0) when success, <0 for error"]
    pub fn xqc_conn_create_path(
        engine: *mut xqc_engine_t,
        cid: *const xqc_cid_t,
        new_path_id: *mut u64,
        path_status: ::core::ffi::c_int,
    ) -> xqc_int_t;
}
unsafe extern "C" {
    #[doc = " Close a path\n @param cid scid for connection\n @param close_path_id path identifier for the closing path\n @return XQC_OK (0) when success, <0 for error"]
    pub fn xqc_conn_close_path(
        engine: *mut xqc_engine_t,
        cid: *const xqc_cid_t,
        closed_path_id: u64,
    ) -> xqc_int_t;
}
unsafe extern "C" {
    #[doc = " Mark a path as \"standby\", i.e., suggest that no traffic should be sent\n on that path if another path is available.\n @param cid scid for connection\n @param path_id path identifier for the path\n @return XQC_OK (0) when success, <0 for error"]
    pub fn xqc_conn_mark_path_standby(
        engine: *mut xqc_engine_t,
        cid: *const xqc_cid_t,
        path_id: u64,
    ) -> xqc_int_t;
}
unsafe extern "C" {
    #[doc = " Mark a path as \"available\", i.e., allow the peer to use its own logic\n to split traffic among available paths.\n @param cid scid for connection\n @param path_id path identifier for the path\n @return XQC_OK (0) when success, <0 for error"]
    pub fn xqc_conn_mark_path_available(
        engine: *mut xqc_engine_t,
        cid: *const xqc_cid_t,
        path_id: u64,
    ) -> xqc_int_t;
}
unsafe extern "C" {
    #[doc = " Mark a path as \"frozen\", i.e., both peers should not send any traffic on this path.\n @param cid scid for connection\n @param path_id path identifier for the path\n @return XQC_OK (0) when success, <0 for error"]
    pub fn xqc_conn_mark_path_frozen(
        engine: *mut xqc_engine_t,
        cid: *const xqc_cid_t,
        path_id: u64,
    ) -> xqc_int_t;
}
unsafe extern "C" {
    #[doc = " Calculate how many available paths on the current connection, i.e., paths which\n finished validation and is marked \"available\" status.\n @param engine xquic engine ctx\n @param cid scid for connection\n @return number of available paths when success, <0 for error"]
    pub fn xqc_conn_available_paths(engine: *mut xqc_engine_t, cid: *const xqc_cid_t) -> xqc_int_t;
}
unsafe extern "C" {
    pub fn xqc_conn_get_type(conn: *mut xqc_connection_t) -> xqc_conn_type_t;
}
unsafe extern "C" {
    #[doc = " Server should get peer addr when path_create_notify callbacks\n @param peer_addr_len is a return value\n @return XQC_OK for success, others for failure"]
    pub fn xqc_path_get_peer_addr(
        conn: *mut xqc_connection_t,
        path_id: u64,
        addr: *mut sockaddr,
        addr_cap: socklen_t,
        peer_addr_len: *mut socklen_t,
    ) -> xqc_int_t;
}
unsafe extern "C" {
    #[doc = " Server should get local addr when path_create_notify callbacks\n @param local_addr_len is a return value\n @return XQC_OK for success, others for failure"]
    pub fn xqc_path_get_local_addr(
        conn: *mut xqc_connection_t,
        path_id: u64,
        addr: *mut sockaddr,
        addr_cap: socklen_t,
        local_addr_len: *mut socklen_t,
    ) -> xqc_int_t;
}
unsafe extern "C" {
    #[doc = " @brief load balance cid encryption.\n According to Draft :\n https://datatracker.ietf.org/doc/html/draft-ietf-quic-load-balancers-13#section-4.3.2\n @param enc_len plaintext length.\n @param cid_buf the plaintext to be encrypted.\n @param out_buf the ciphertext of the plaintext encrypted.\n @param out_buf_len the length of the ciphertext to be encrypted.\n @param lb_cid_key  encryption secret.\n @param lb_cid_key_len secret length.\n @param engine engine from `xqc_engine_create`\n @return negative for failed, 0 for the success.\n\n The length of cid_buf must not exceed the maximum length of the cid (20 byte), the\n length of out_buf should be no less than cid_buf_length. The length of lb_cid_key\n should be exactly 16 bytes."]
    pub fn xqc_lb_cid_encryption(
        cid_buf: *mut u8,
        enc_len: usize,
        out_buf: *mut u8,
        out_buf_len: usize,
        lb_cid_key: *mut u8,
        lb_cid_key_len: usize,
        engine: *mut xqc_engine_t,
    ) -> xqc_int_t;
}
unsafe extern "C" {
    #[doc = " @brief client calls this API to check if it should delete 0rtt ticket according to\n the errorcode of xqc_conn in conn_close_notify\n @return XQC_TRUE = yes;"]
    pub fn xqc_conn_should_clear_0rtt_ticket(conn_err: xqc_int_t) -> xqc_bool_t;
}
unsafe extern "C" {
    #[doc = " @brief Users call this function to get a template of conn settings, which serves\n        as the starting point for users who want to refine conn settings according\n        to their needs\n @param settings_type there are different types of templates in XQUIC\n @return conn settings"]
    pub fn xqc_conn_get_conn_settings_template(
        settings_type: xqc_conn_settings_type_t,
    ) -> xqc_conn_settings_t;
}
#[doc = " nothing readable"]
pub const XQC_REQ_NOTIFY_READ_NULL: xqc_request_notify_flag_t = 0;
#[doc = " read header section flag, this will be set when the first HEADERS is processed"]
pub const XQC_REQ_NOTIFY_READ_HEADER: xqc_request_notify_flag_t = 1;
#[doc = " read body flag, this will be set when a DATA frame is processed"]
pub const XQC_REQ_NOTIFY_READ_BODY: xqc_request_notify_flag_t = 2;
#[doc = " read trailer section flag, this will be set when trailer HEADERS frame is processed"]
pub const XQC_REQ_NOTIFY_READ_TRAILER: xqc_request_notify_flag_t = 4;
#[doc = " read empty fin flag, notify callback will be triggered when a single fin frame is received\nwhile HEADERS and DATA were notified. This flag will NEVER be set with other flags"]
pub const XQC_REQ_NOTIFY_READ_EMPTY_FIN: xqc_request_notify_flag_t = 8;
#[doc = " @brief read flag of xqc_h3_request_read_notify_pt"]
pub type xqc_request_notify_flag_t = ::core::ffi::c_uint;
#[doc = " @brief definition for http3 connection state callback function. including create and close"]
pub type xqc_h3_conn_notify_pt = ::core::option::Option<
    unsafe extern "C" fn(
        h3_conn: *mut xqc_h3_conn_t,
        cid: *const xqc_cid_t,
        h3c_user_data: *mut ::core::ffi::c_void,
    ) -> ::core::ffi::c_int,
>;
pub type xqc_h3_handshake_finished_pt = ::core::option::Option<
    unsafe extern "C" fn(h3_conn: *mut xqc_h3_conn_t, h3c_user_data: *mut ::core::ffi::c_void),
>;
pub type xqc_h3_conn_ping_ack_notify_pt = ::core::option::Option<
    unsafe extern "C" fn(
        h3_conn: *mut xqc_h3_conn_t,
        cid: *const xqc_cid_t,
        ping_user_data: *mut ::core::ffi::c_void,
        h3c_user_data: *mut ::core::ffi::c_void,
    ),
>;
#[doc = " @brief connection settings for http3"]
pub type xqc_h3_conn_settings_t = xqc_h3_conn_settings_s;
#[doc = " @brief In this callback, only operations related to modifying current_settings is allowed.\n        This callback is triggered before the connection has been fully initialized.\n        PLEASE DO NOT call any XQUIC APIs in this callback."]
pub type xqc_h3_conn_init_settings_pt = ::core::option::Option<
    unsafe extern "C" fn(
        h3_conn: *mut xqc_h3_conn_t,
        current_settings: *mut xqc_h3_conn_settings_t,
        h3c_user_data: *mut ::core::ffi::c_void,
    ),
>;
#[doc = " @brief http3 request callbacks"]
pub type xqc_h3_request_notify_pt = ::core::option::Option<
    unsafe extern "C" fn(
        h3_request: *mut xqc_h3_request_t,
        h3s_user_data: *mut ::core::ffi::c_void,
    ) -> ::core::ffi::c_int,
>;
#[doc = " @brief read data callback function"]
pub type xqc_h3_request_read_notify_pt = ::core::option::Option<
    unsafe extern "C" fn(
        h3_request: *mut xqc_h3_request_t,
        flag: xqc_request_notify_flag_t,
        h3s_user_data: *mut ::core::ffi::c_void,
    ) -> ::core::ffi::c_int,
>;
pub type xqc_h3_request_closing_notify_pt = ::core::option::Option<
    unsafe extern "C" fn(
        h3_request: *mut xqc_h3_request_t,
        err: xqc_int_t,
        h3s_user_data: *mut ::core::ffi::c_void,
    ),
>;
#[doc = " no flag is set. encode header with default strategy."]
pub const XQC_HTTP_HEADER_FLAG_NONE: xqc_http3_nv_flag_s = 0;
#[doc = " header's name and value shall be encoded as literal, and shall never be indexed."]
pub const XQC_HTTP_HEADER_FLAG_NEVER_INDEX: xqc_http3_nv_flag_s = 1;
#[doc = " header's value is variant and shall never be put into dynamic table and be indexed. this\n will reduce useless data in dynamic table and might increase the hit rate.\n\n some headers might be frequent but with different values, it is a waste to put these value\n into dynamic table. application layer can use this flag to tell QPACK not to put value into\n dynamic table."]
pub const XQC_HTTP_HEADER_FLAG_NEVER_INDEX_VALUE: xqc_http3_nv_flag_s = 2;
#[doc = " @brief encode flags of http headers"]
pub type xqc_http3_nv_flag_s = ::core::ffi::c_uint;
#[doc = " @brief encode flags of http headers"]
pub use self::xqc_http3_nv_flag_s as xqc_http3_nv_flag_t;
#[doc = "< none is matched"]
pub const XQC_NV_HIT_NONE: xqc_http3_nv_hit_flag_s = 0;
#[doc = "< only name is matched"]
pub const XQC_NV_HIT_NAME: xqc_http3_nv_hit_flag_s = 1;
#[doc = "< both name and value are matched"]
pub const XQC_NV_HIT_BOTH: xqc_http3_nv_hit_flag_s = 2;
pub type xqc_http3_nv_hit_flag_s = ::core::ffi::c_uint;
pub use self::xqc_http3_nv_hit_flag_s as xqc_http3_nv_hit_flag_t;
pub type xqc_http_header_t = xqc_http_header_s;
#[repr(C)]
pub struct xqc_http_header_s {
    #[doc = " name of http header"]
    pub name: iovec,
    #[doc = " value of http header"]
    pub value: iovec,
    #[doc = " flags of xqc_http3_nv_flag_t with OR operator"]
    pub flags: u8,
    #[doc = " save the nv hit status or not (0 means do not save)"]
    pub save_nv_hit_flags: u8,
    #[doc = " flags of nv hit status (used as return values)"]
    pub nv_hit_flags: u8,
    #[doc = " src header (if this one is copied from another using xqc_h3_request_copy_header)"]
    pub src_header: *mut xqc_http_header_t,
}
#[allow(clippy::unnecessary_operation, clippy::identity_op)]
const _: () = {
    ["Size of xqc_http_header_s"][::core::mem::size_of::<xqc_http_header_s>() - 48usize];
    ["Alignment of xqc_http_header_s"][::core::mem::align_of::<xqc_http_header_s>() - 8usize];
    ["Offset of field: xqc_http_header_s::name"]
        [::core::mem::offset_of!(xqc_http_header_s, name) - 0usize];
    ["Offset of field: xqc_http_header_s::value"]
        [::core::mem::offset_of!(xqc_http_header_s, value) - 16usize];
    ["Offset of field: xqc_http_header_s::flags"]
        [::core::mem::offset_of!(xqc_http_header_s, flags) - 32usize];
    ["Offset of field: xqc_http_header_s::save_nv_hit_flags"]
        [::core::mem::offset_of!(xqc_http_header_s, save_nv_hit_flags) - 33usize];
    ["Offset of field: xqc_http_header_s::nv_hit_flags"]
        [::core::mem::offset_of!(xqc_http_header_s, nv_hit_flags) - 34usize];
    ["Offset of field: xqc_http_header_s::src_header"]
        [::core::mem::offset_of!(xqc_http_header_s, src_header) - 40usize];
};
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xqc_http_headers_s {
    #[doc = " array of http headers"]
    pub headers: *mut xqc_http_header_t,
    #[doc = " count of headers"]
    pub count: usize,
    #[doc = " capacity of headers"]
    pub capacity: usize,
    #[doc = " total byte count of headers"]
    pub total_len: usize,
}
#[allow(clippy::unnecessary_operation, clippy::identity_op)]
const _: () = {
    ["Size of xqc_http_headers_s"][::core::mem::size_of::<xqc_http_headers_s>() - 32usize];
    ["Alignment of xqc_http_headers_s"][::core::mem::align_of::<xqc_http_headers_s>() - 8usize];
    ["Offset of field: xqc_http_headers_s::headers"]
        [::core::mem::offset_of!(xqc_http_headers_s, headers) - 0usize];
    ["Offset of field: xqc_http_headers_s::count"]
        [::core::mem::offset_of!(xqc_http_headers_s, count) - 8usize];
    ["Offset of field: xqc_http_headers_s::capacity"]
        [::core::mem::offset_of!(xqc_http_headers_s, capacity) - 16usize];
    ["Offset of field: xqc_http_headers_s::total_len"]
        [::core::mem::offset_of!(xqc_http_headers_s, total_len) - 24usize];
};
pub type xqc_http_headers_t = xqc_http_headers_s;
#[doc = " @brief request statistics structure"]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xqc_request_stats_s {
    pub send_body_size: usize,
    pub recv_body_size: usize,
    #[doc = " plaintext header size"]
    pub send_header_size: usize,
    #[doc = " plaintext header size"]
    pub recv_header_size: usize,
    #[doc = " compressed header size"]
    pub send_hdr_compressed: usize,
    #[doc = " compressed header size"]
    pub recv_hdr_compressed: usize,
    #[doc = " QUIC layer error code, 0 for no error"]
    pub stream_err: ::core::ffi::c_int,
    #[doc = " time of h3 stream being blocked"]
    pub blocked_time: xqc_usec_t,
    #[doc = " time of h3 stream being unblocked"]
    pub unblocked_time: xqc_usec_t,
    #[doc = " time of receiving transport fin"]
    pub stream_fin_time: xqc_usec_t,
    #[doc = " time of creating request"]
    pub h3r_begin_time: xqc_usec_t,
    #[doc = " time of request fin"]
    pub h3r_end_time: xqc_usec_t,
    #[doc = " time of receiving HEADERS frame"]
    pub h3r_header_begin_time: xqc_usec_t,
    #[doc = " time of finishing processing HEADERS frame"]
    pub h3r_header_end_time: xqc_usec_t,
    #[doc = " time of receiving DATA frame"]
    pub h3r_body_begin_time: xqc_usec_t,
    pub h3r_header_send_time: xqc_usec_t,
    pub h3r_body_send_time: xqc_usec_t,
    pub stream_fin_send_time: xqc_usec_t,
    pub stream_fin_ack_time: xqc_usec_t,
    pub stream_close_msg: *const ::core::ffi::c_char,
    #[doc = " @brief 请求级别MP状态\n 0: 该请求所在连接当前仅有一条可用路径\n 1: 该请求所在连接当前有多条可用路径，该请求同时在 Available 和 Standby 路径传输\n 2: 该请求所在连接当前有多条可用路径，但该请求仅在  Standby  路径传输\n 3: 该请求所在连接当前有多条可用路径，但该请求仅在 Available 路径传输"]
    pub mp_state: ::core::ffi::c_int,
    pub mp_default_path_send_weight: f32,
    pub mp_default_path_recv_weight: f32,
    pub mp_standby_path_send_weight: f32,
    pub mp_standby_path_recv_weight: f32,
    pub rate_limit: u64,
    #[doc = " @brief 0RTT state\n 0: no 0RTT\n 1: 0RTT accept\n 2: 0RTT reject"]
    pub early_data_state: u8,
    pub stream_info: [::core::ffi::c_char; 128usize],
    pub extern_stream_info: [::core::ffi::c_char; 128usize],
    pub stream_fst_fin_snd_time: xqc_usec_t,
    #[doc = " @brief how long the request was blocked by congestion control (ms)"]
    pub cwnd_blocked_ms: xqc_msec_t,
    #[doc = " @brief the number of packet has been retransmitted"]
    pub retrans_cnt: u32,
    pub stream_fst_pkt_snd_time: xqc_usec_t,
    pub stream_fst_pkt_rcv_time: xqc_usec_t,
    pub sent_pkt_cnt: u32,
    pub max_pto_backoff: u8,
    #[doc = " @brief the number of lost/delayed packets recovered by fec module;"]
    pub fec_recov_cnt: u32,
    pub fst_rpr_time: xqc_usec_t,
    pub last_rpr_time: xqc_usec_t,
    pub is_fec_protected: u8,
    pub block_size_mode: u8,
    pub fec_blk_lack_num: xqc_int_t,
    pub fec_blk_lack_time: xqc_usec_t,
    pub fec_req_delay_time: xqc_usec_t,
    pub recv_time_with_fec: xqc_usec_t,
    pub final_packet_time: xqc_usec_t,
    pub stream_close_delay: xqc_usec_t,
}
#[allow(clippy::unnecessary_operation, clippy::identity_op)]
const _: () = {
    ["Size of xqc_request_stats_s"][::core::mem::size_of::<xqc_request_stats_s>() - 576usize];
    ["Alignment of xqc_request_stats_s"][::core::mem::align_of::<xqc_request_stats_s>() - 8usize];
    ["Offset of field: xqc_request_stats_s::send_body_size"]
        [::core::mem::offset_of!(xqc_request_stats_s, send_body_size) - 0usize];
    ["Offset of field: xqc_request_stats_s::recv_body_size"]
        [::core::mem::offset_of!(xqc_request_stats_s, recv_body_size) - 8usize];
    ["Offset of field: xqc_request_stats_s::send_header_size"]
        [::core::mem::offset_of!(xqc_request_stats_s, send_header_size) - 16usize];
    ["Offset of field: xqc_request_stats_s::recv_header_size"]
        [::core::mem::offset_of!(xqc_request_stats_s, recv_header_size) - 24usize];
    ["Offset of field: xqc_request_stats_s::send_hdr_compressed"]
        [::core::mem::offset_of!(xqc_request_stats_s, send_hdr_compressed) - 32usize];
    ["Offset of field: xqc_request_stats_s::recv_hdr_compressed"]
        [::core::mem::offset_of!(xqc_request_stats_s, recv_hdr_compressed) - 40usize];
    ["Offset of field: xqc_request_stats_s::stream_err"]
        [::core::mem::offset_of!(xqc_request_stats_s, stream_err) - 48usize];
    ["Offset of field: xqc_request_stats_s::blocked_time"]
        [::core::mem::offset_of!(xqc_request_stats_s, blocked_time) - 56usize];
    ["Offset of field: xqc_request_stats_s::unblocked_time"]
        [::core::mem::offset_of!(xqc_request_stats_s, unblocked_time) - 64usize];
    ["Offset of field: xqc_request_stats_s::stream_fin_time"]
        [::core::mem::offset_of!(xqc_request_stats_s, stream_fin_time) - 72usize];
    ["Offset of field: xqc_request_stats_s::h3r_begin_time"]
        [::core::mem::offset_of!(xqc_request_stats_s, h3r_begin_time) - 80usize];
    ["Offset of field: xqc_request_stats_s::h3r_end_time"]
        [::core::mem::offset_of!(xqc_request_stats_s, h3r_end_time) - 88usize];
    ["Offset of field: xqc_request_stats_s::h3r_header_begin_time"]
        [::core::mem::offset_of!(xqc_request_stats_s, h3r_header_begin_time) - 96usize];
    ["Offset of field: xqc_request_stats_s::h3r_header_end_time"]
        [::core::mem::offset_of!(xqc_request_stats_s, h3r_header_end_time) - 104usize];
    ["Offset of field: xqc_request_stats_s::h3r_body_begin_time"]
        [::core::mem::offset_of!(xqc_request_stats_s, h3r_body_begin_time) - 112usize];
    ["Offset of field: xqc_request_stats_s::h3r_header_send_time"]
        [::core::mem::offset_of!(xqc_request_stats_s, h3r_header_send_time) - 120usize];
    ["Offset of field: xqc_request_stats_s::h3r_body_send_time"]
        [::core::mem::offset_of!(xqc_request_stats_s, h3r_body_send_time) - 128usize];
    ["Offset of field: xqc_request_stats_s::stream_fin_send_time"]
        [::core::mem::offset_of!(xqc_request_stats_s, stream_fin_send_time) - 136usize];
    ["Offset of field: xqc_request_stats_s::stream_fin_ack_time"]
        [::core::mem::offset_of!(xqc_request_stats_s, stream_fin_ack_time) - 144usize];
    ["Offset of field: xqc_request_stats_s::stream_close_msg"]
        [::core::mem::offset_of!(xqc_request_stats_s, stream_close_msg) - 152usize];
    ["Offset of field: xqc_request_stats_s::mp_state"]
        [::core::mem::offset_of!(xqc_request_stats_s, mp_state) - 160usize];
    ["Offset of field: xqc_request_stats_s::mp_default_path_send_weight"]
        [::core::mem::offset_of!(xqc_request_stats_s, mp_default_path_send_weight) - 164usize];
    ["Offset of field: xqc_request_stats_s::mp_default_path_recv_weight"]
        [::core::mem::offset_of!(xqc_request_stats_s, mp_default_path_recv_weight) - 168usize];
    ["Offset of field: xqc_request_stats_s::mp_standby_path_send_weight"]
        [::core::mem::offset_of!(xqc_request_stats_s, mp_standby_path_send_weight) - 172usize];
    ["Offset of field: xqc_request_stats_s::mp_standby_path_recv_weight"]
        [::core::mem::offset_of!(xqc_request_stats_s, mp_standby_path_recv_weight) - 176usize];
    ["Offset of field: xqc_request_stats_s::rate_limit"]
        [::core::mem::offset_of!(xqc_request_stats_s, rate_limit) - 184usize];
    ["Offset of field: xqc_request_stats_s::early_data_state"]
        [::core::mem::offset_of!(xqc_request_stats_s, early_data_state) - 192usize];
    ["Offset of field: xqc_request_stats_s::stream_info"]
        [::core::mem::offset_of!(xqc_request_stats_s, stream_info) - 193usize];
    ["Offset of field: xqc_request_stats_s::extern_stream_info"]
        [::core::mem::offset_of!(xqc_request_stats_s, extern_stream_info) - 321usize];
    ["Offset of field: xqc_request_stats_s::stream_fst_fin_snd_time"]
        [::core::mem::offset_of!(xqc_request_stats_s, stream_fst_fin_snd_time) - 456usize];
    ["Offset of field: xqc_request_stats_s::cwnd_blocked_ms"]
        [::core::mem::offset_of!(xqc_request_stats_s, cwnd_blocked_ms) - 464usize];
    ["Offset of field: xqc_request_stats_s::retrans_cnt"]
        [::core::mem::offset_of!(xqc_request_stats_s, retrans_cnt) - 472usize];
    ["Offset of field: xqc_request_stats_s::stream_fst_pkt_snd_time"]
        [::core::mem::offset_of!(xqc_request_stats_s, stream_fst_pkt_snd_time) - 480usize];
    ["Offset of field: xqc_request_stats_s::stream_fst_pkt_rcv_time"]
        [::core::mem::offset_of!(xqc_request_stats_s, stream_fst_pkt_rcv_time) - 488usize];
    ["Offset of field: xqc_request_stats_s::sent_pkt_cnt"]
        [::core::mem::offset_of!(xqc_request_stats_s, sent_pkt_cnt) - 496usize];
    ["Offset of field: xqc_request_stats_s::max_pto_backoff"]
        [::core::mem::offset_of!(xqc_request_stats_s, max_pto_backoff) - 500usize];
    ["Offset of field: xqc_request_stats_s::fec_recov_cnt"]
        [::core::mem::offset_of!(xqc_request_stats_s, fec_recov_cnt) - 504usize];
    ["Offset of field: xqc_request_stats_s::fst_rpr_time"]
        [::core::mem::offset_of!(xqc_request_stats_s, fst_rpr_time) - 512usize];
    ["Offset of field: xqc_request_stats_s::last_rpr_time"]
        [::core::mem::offset_of!(xqc_request_stats_s, last_rpr_time) - 520usize];
    ["Offset of field: xqc_request_stats_s::is_fec_protected"]
        [::core::mem::offset_of!(xqc_request_stats_s, is_fec_protected) - 528usize];
    ["Offset of field: xqc_request_stats_s::block_size_mode"]
        [::core::mem::offset_of!(xqc_request_stats_s, block_size_mode) - 529usize];
    ["Offset of field: xqc_request_stats_s::fec_blk_lack_num"]
        [::core::mem::offset_of!(xqc_request_stats_s, fec_blk_lack_num) - 532usize];
    ["Offset of field: xqc_request_stats_s::fec_blk_lack_time"]
        [::core::mem::offset_of!(xqc_request_stats_s, fec_blk_lack_time) - 536usize];
    ["Offset of field: xqc_request_stats_s::fec_req_delay_time"]
        [::core::mem::offset_of!(xqc_request_stats_s, fec_req_delay_time) - 544usize];
    ["Offset of field: xqc_request_stats_s::recv_time_with_fec"]
        [::core::mem::offset_of!(xqc_request_stats_s, recv_time_with_fec) - 552usize];
    ["Offset of field: xqc_request_stats_s::final_packet_time"]
        [::core::mem::offset_of!(xqc_request_stats_s, final_packet_time) - 560usize];
    ["Offset of field: xqc_request_stats_s::stream_close_delay"]
        [::core::mem::offset_of!(xqc_request_stats_s, stream_close_delay) - 568usize];
};
#[doc = " @brief request statistics structure"]
pub type xqc_request_stats_t = xqc_request_stats_s;
#[doc = " @brief bytestream statistics\n"]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xqc_h3_ext_bytestream_stats_s {
    pub bytes_sent: usize,
    pub bytes_rcvd: usize,
    pub stream_err: ::core::ffi::c_int,
    pub stream_close_msg: *const ::core::ffi::c_char,
    pub create_time: xqc_usec_t,
    pub fin_rcvd_time: xqc_usec_t,
    pub fin_read_time: xqc_usec_t,
    pub fin_sent_time: xqc_usec_t,
    pub fin_acked_time: xqc_usec_t,
    pub first_byte_sent_time: xqc_usec_t,
    pub first_byte_rcvd_time: xqc_usec_t,
}
#[allow(clippy::unnecessary_operation, clippy::identity_op)]
const _: () = {
    ["Size of xqc_h3_ext_bytestream_stats_s"]
        [::core::mem::size_of::<xqc_h3_ext_bytestream_stats_s>() - 88usize];
    ["Alignment of xqc_h3_ext_bytestream_stats_s"]
        [::core::mem::align_of::<xqc_h3_ext_bytestream_stats_s>() - 8usize];
    ["Offset of field: xqc_h3_ext_bytestream_stats_s::bytes_sent"]
        [::core::mem::offset_of!(xqc_h3_ext_bytestream_stats_s, bytes_sent) - 0usize];
    ["Offset of field: xqc_h3_ext_bytestream_stats_s::bytes_rcvd"]
        [::core::mem::offset_of!(xqc_h3_ext_bytestream_stats_s, bytes_rcvd) - 8usize];
    ["Offset of field: xqc_h3_ext_bytestream_stats_s::stream_err"]
        [::core::mem::offset_of!(xqc_h3_ext_bytestream_stats_s, stream_err) - 16usize];
    ["Offset of field: xqc_h3_ext_bytestream_stats_s::stream_close_msg"]
        [::core::mem::offset_of!(xqc_h3_ext_bytestream_stats_s, stream_close_msg) - 24usize];
    ["Offset of field: xqc_h3_ext_bytestream_stats_s::create_time"]
        [::core::mem::offset_of!(xqc_h3_ext_bytestream_stats_s, create_time) - 32usize];
    ["Offset of field: xqc_h3_ext_bytestream_stats_s::fin_rcvd_time"]
        [::core::mem::offset_of!(xqc_h3_ext_bytestream_stats_s, fin_rcvd_time) - 40usize];
    ["Offset of field: xqc_h3_ext_bytestream_stats_s::fin_read_time"]
        [::core::mem::offset_of!(xqc_h3_ext_bytestream_stats_s, fin_read_time) - 48usize];
    ["Offset of field: xqc_h3_ext_bytestream_stats_s::fin_sent_time"]
        [::core::mem::offset_of!(xqc_h3_ext_bytestream_stats_s, fin_sent_time) - 56usize];
    ["Offset of field: xqc_h3_ext_bytestream_stats_s::fin_acked_time"]
        [::core::mem::offset_of!(xqc_h3_ext_bytestream_stats_s, fin_acked_time) - 64usize];
    ["Offset of field: xqc_h3_ext_bytestream_stats_s::first_byte_sent_time"]
        [::core::mem::offset_of!(xqc_h3_ext_bytestream_stats_s, first_byte_sent_time) - 72usize];
    ["Offset of field: xqc_h3_ext_bytestream_stats_s::first_byte_rcvd_time"]
        [::core::mem::offset_of!(xqc_h3_ext_bytestream_stats_s, first_byte_rcvd_time) - 80usize];
};
#[doc = " @brief bytestream statistics\n"]
pub type xqc_h3_ext_bytestream_stats_t = xqc_h3_ext_bytestream_stats_s;
#[doc = " @brief connection settings for http3"]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xqc_h3_conn_settings_s {
    #[doc = " MAX_FIELD_SECTION_SIZE of http3"]
    pub max_field_section_size: u64,
    #[doc = " MAX_PUSH_STREAMS"]
    pub max_pushes: u64,
    #[doc = " ENC_MAX_DYNAMIC_TABLE_CAPACITY"]
    pub qpack_enc_max_table_capacity: u64,
    #[doc = " DEC_MAX_DYNAMIC_TABLE_CAPACITY"]
    pub qpack_dec_max_table_capacity: u64,
    #[doc = " MAX_BLOCKED_STREAMS"]
    pub qpack_blocked_streams: u64,
    #[doc = " RFC 9220: SETTINGS_ENABLE_CONNECT_PROTOCOL (0x08). 1 = enable Extended CONNECT"]
    pub enable_connect_protocol: u64,
    #[doc = " RFC 9297: SETTINGS_H3_DATAGRAM (0x33). 1 = enable HTTP Datagrams"]
    pub h3_datagram: u64,
}
#[allow(clippy::unnecessary_operation, clippy::identity_op)]
const _: () = {
    ["Size of xqc_h3_conn_settings_s"][::core::mem::size_of::<xqc_h3_conn_settings_s>() - 56usize];
    ["Alignment of xqc_h3_conn_settings_s"]
        [::core::mem::align_of::<xqc_h3_conn_settings_s>() - 8usize];
    ["Offset of field: xqc_h3_conn_settings_s::max_field_section_size"]
        [::core::mem::offset_of!(xqc_h3_conn_settings_s, max_field_section_size) - 0usize];
    ["Offset of field: xqc_h3_conn_settings_s::max_pushes"]
        [::core::mem::offset_of!(xqc_h3_conn_settings_s, max_pushes) - 8usize];
    ["Offset of field: xqc_h3_conn_settings_s::qpack_enc_max_table_capacity"]
        [::core::mem::offset_of!(xqc_h3_conn_settings_s, qpack_enc_max_table_capacity) - 16usize];
    ["Offset of field: xqc_h3_conn_settings_s::qpack_dec_max_table_capacity"]
        [::core::mem::offset_of!(xqc_h3_conn_settings_s, qpack_dec_max_table_capacity) - 24usize];
    ["Offset of field: xqc_h3_conn_settings_s::qpack_blocked_streams"]
        [::core::mem::offset_of!(xqc_h3_conn_settings_s, qpack_blocked_streams) - 32usize];
    ["Offset of field: xqc_h3_conn_settings_s::enable_connect_protocol"]
        [::core::mem::offset_of!(xqc_h3_conn_settings_s, enable_connect_protocol) - 40usize];
    ["Offset of field: xqc_h3_conn_settings_s::h3_datagram"]
        [::core::mem::offset_of!(xqc_h3_conn_settings_s, h3_datagram) - 48usize];
};
#[doc = " @brief callback for h3 bytestream read\n @param h3_ext_bs bytestream\n @param data data to be read. NOTE, this could be a NULL pointer, please ONLY read it if data_len > 0.\n @param data_len length of data to be read\n @param fin the bytestream is finished\n @param bs_user_data bytestream user data\n @param data_recv_time time spent for receiving data"]
pub type xqc_h3_ext_bytestream_read_notify_pt = ::core::option::Option<
    unsafe extern "C" fn(
        h3_ext_bs: *mut xqc_h3_ext_bytestream_t,
        data: *const ::core::ffi::c_void,
        data_len: usize,
        fin: u8,
        bs_user_data: *mut ::core::ffi::c_void,
        data_recv_time: u64,
    ) -> ::core::ffi::c_int,
>;
#[doc = " @brief callbacks for extended h3 bytestream"]
pub type xqc_h3_ext_bytestream_notify_pt = ::core::option::Option<
    unsafe extern "C" fn(
        h3_ext_bs: *mut xqc_h3_ext_bytestream_t,
        bs_user_data: *mut ::core::ffi::c_void,
    ) -> ::core::ffi::c_int,
>;
#[doc = " @brief the callback API to notify the application that there is a datagram to be read\n\n @param conn the connection handle\n @param user_data the user_data set by xqc_h3_ext_datagram_set_user_data\n @param data the data delivered by this callback\n @param data_len the length of the delivered data\n @param data_recv_time time spent for receiving data"]
pub type xqc_h3_ext_datagram_read_notify_pt = ::core::option::Option<
    unsafe extern "C" fn(
        conn: *mut xqc_h3_conn_t,
        data: *const ::core::ffi::c_void,
        data_len: usize,
        user_data: *mut ::core::ffi::c_void,
        data_recv_time: u64,
    ),
>;
#[doc = " @brief the callback API to notify the application that datagrams can be sent\n\n @param conn the connection handle\n @param user_data the user_data set by xqc_h3_ext_datagram_set_user_data"]
pub type xqc_h3_ext_datagram_write_notify_pt = ::core::option::Option<
    unsafe extern "C" fn(conn: *mut xqc_h3_conn_t, user_data: *mut ::core::ffi::c_void),
>;
#[doc = " @brief the callback API to notify the application that a datagram is declared lost.\n However, the datagram could also be acknowledged later, as the underlying\n loss detection is not fully accurate. Applications should handle this type of\n spurious loss. The return value is used to ask the QUIC stack to retransmit the lost\n datagram packet.\n\n @param conn the connection handle\n @param user_data the user_data set by xqc_h3_ext_datagram_set_user_data\n @param dgram_id the id of the lost datagram\n @return 0, do not retransmit;\n         XQC_DGRAM_RETX_ASKED_BY_APP, retransmit;\n         others, ignored by the QUIC stack."]
pub type xqc_h3_ext_datagram_lost_notify_pt = ::core::option::Option<
    unsafe extern "C" fn(
        conn: *mut xqc_h3_conn_t,
        dgram_id: u64,
        user_data: *mut ::core::ffi::c_void,
    ) -> ::core::ffi::c_int,
>;
#[doc = " @brief the callback API to notify the application that a datagram is acked\n\n @param conn the connection handle\n @param user_data the user_data set by xqc_h3_ext_datagram_set_user_data\n @param dgram_id the id of the acked datagram"]
pub type xqc_h3_ext_datagram_acked_notify_pt = ::core::option::Option<
    unsafe extern "C" fn(
        conn: *mut xqc_h3_conn_t,
        dgram_id: u64,
        user_data: *mut ::core::ffi::c_void,
    ),
>;
#[doc = " @brief the callback to notify application the MSS of QUIC datagrams. Note,\n        the MSS of QUIC datagrams will never shrink. If the MSS is zero, it\n        means this connection does not support sending QUIC datagrams.\n\n @param conn the connection handle\n @param user_data the dgram_data set by xqc_h3_ext_datagram_set_user_data\n @param mss the MSS of QUIC datagrams"]
pub type xqc_h3_ext_datagram_mss_updated_notify_pt = ::core::option::Option<
    unsafe extern "C" fn(conn: *mut xqc_h3_conn_t, mss: usize, user_data: *mut ::core::ffi::c_void),
>;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xqc_h3_ext_dgram_callbacks_s {
    #[doc = " the return value is ignored by XQUIC stack"]
    pub dgram_read_notify: xqc_h3_ext_datagram_read_notify_pt,
    #[doc = " the return value is ignored by XQUIC stack"]
    pub dgram_write_notify: xqc_h3_ext_datagram_write_notify_pt,
    #[doc = " the return value is ignored by XQUIC stack"]
    pub dgram_acked_notify: xqc_h3_ext_datagram_acked_notify_pt,
    #[doc = " the return value is ignored by XQUIC stack"]
    pub dgram_lost_notify: xqc_h3_ext_datagram_lost_notify_pt,
    pub dgram_mss_updated_notify: xqc_h3_ext_datagram_mss_updated_notify_pt,
}
#[allow(clippy::unnecessary_operation, clippy::identity_op)]
const _: () = {
    ["Size of xqc_h3_ext_dgram_callbacks_s"]
        [::core::mem::size_of::<xqc_h3_ext_dgram_callbacks_s>() - 40usize];
    ["Alignment of xqc_h3_ext_dgram_callbacks_s"]
        [::core::mem::align_of::<xqc_h3_ext_dgram_callbacks_s>() - 8usize];
    ["Offset of field: xqc_h3_ext_dgram_callbacks_s::dgram_read_notify"]
        [::core::mem::offset_of!(xqc_h3_ext_dgram_callbacks_s, dgram_read_notify) - 0usize];
    ["Offset of field: xqc_h3_ext_dgram_callbacks_s::dgram_write_notify"]
        [::core::mem::offset_of!(xqc_h3_ext_dgram_callbacks_s, dgram_write_notify) - 8usize];
    ["Offset of field: xqc_h3_ext_dgram_callbacks_s::dgram_acked_notify"]
        [::core::mem::offset_of!(xqc_h3_ext_dgram_callbacks_s, dgram_acked_notify) - 16usize];
    ["Offset of field: xqc_h3_ext_dgram_callbacks_s::dgram_lost_notify"]
        [::core::mem::offset_of!(xqc_h3_ext_dgram_callbacks_s, dgram_lost_notify) - 24usize];
    ["Offset of field: xqc_h3_ext_dgram_callbacks_s::dgram_mss_updated_notify"]
        [::core::mem::offset_of!(xqc_h3_ext_dgram_callbacks_s, dgram_mss_updated_notify) - 32usize];
};
pub type xqc_h3_ext_dgram_callbacks_t = xqc_h3_ext_dgram_callbacks_s;
#[doc = " @brief http3 connection callbacks for application layer"]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xqc_h3_conn_callbacks_s {
    #[doc = " http3 connection creation callback, REQUIRED for server, OPTIONAL for client"]
    pub h3_conn_create_notify: xqc_h3_conn_notify_pt,
    #[doc = " http3 connection close callback"]
    pub h3_conn_close_notify: xqc_h3_conn_notify_pt,
    #[doc = " handshake finished callback. which will be triggered when HANDSHAKE_DONE is received"]
    pub h3_conn_handshake_finished: xqc_h3_handshake_finished_pt,
    #[doc = " ping callback. which will be triggered when ping is acked"]
    pub h3_conn_ping_acked: xqc_h3_conn_ping_ack_notify_pt,
    pub h3_conn_init_settings: xqc_h3_conn_init_settings_pt,
}
#[allow(clippy::unnecessary_operation, clippy::identity_op)]
const _: () = {
    ["Size of xqc_h3_conn_callbacks_s"]
        [::core::mem::size_of::<xqc_h3_conn_callbacks_s>() - 40usize];
    ["Alignment of xqc_h3_conn_callbacks_s"]
        [::core::mem::align_of::<xqc_h3_conn_callbacks_s>() - 8usize];
    ["Offset of field: xqc_h3_conn_callbacks_s::h3_conn_create_notify"]
        [::core::mem::offset_of!(xqc_h3_conn_callbacks_s, h3_conn_create_notify) - 0usize];
    ["Offset of field: xqc_h3_conn_callbacks_s::h3_conn_close_notify"]
        [::core::mem::offset_of!(xqc_h3_conn_callbacks_s, h3_conn_close_notify) - 8usize];
    ["Offset of field: xqc_h3_conn_callbacks_s::h3_conn_handshake_finished"]
        [::core::mem::offset_of!(xqc_h3_conn_callbacks_s, h3_conn_handshake_finished) - 16usize];
    ["Offset of field: xqc_h3_conn_callbacks_s::h3_conn_ping_acked"]
        [::core::mem::offset_of!(xqc_h3_conn_callbacks_s, h3_conn_ping_acked) - 24usize];
    ["Offset of field: xqc_h3_conn_callbacks_s::h3_conn_init_settings"]
        [::core::mem::offset_of!(xqc_h3_conn_callbacks_s, h3_conn_init_settings) - 32usize];
};
#[doc = " @brief http3 request callbacks for application layer"]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xqc_h3_request_callbacks_s {
    #[doc = " request creation notify. it will be triggered after a request was created, and is required\nfor server, optional for client"]
    pub h3_request_create_notify: xqc_h3_request_notify_pt,
    #[doc = " request close notify. which will be triggered after a request was closed"]
    pub h3_request_close_notify: xqc_h3_request_notify_pt,
    #[doc = " request read notify callback. which will be triggered after received http headers or body"]
    pub h3_request_read_notify: xqc_h3_request_read_notify_pt,
    #[doc = " request write notify callback. when triggered, users can continue to send headers or body"]
    pub h3_request_write_notify: xqc_h3_request_notify_pt,
    #[doc = " request closing notify callback, will be triggered when request is closing"]
    pub h3_request_closing_notify: xqc_h3_request_closing_notify_pt,
}
#[allow(clippy::unnecessary_operation, clippy::identity_op)]
const _: () = {
    ["Size of xqc_h3_request_callbacks_s"]
        [::core::mem::size_of::<xqc_h3_request_callbacks_s>() - 40usize];
    ["Alignment of xqc_h3_request_callbacks_s"]
        [::core::mem::align_of::<xqc_h3_request_callbacks_s>() - 8usize];
    ["Offset of field: xqc_h3_request_callbacks_s::h3_request_create_notify"]
        [::core::mem::offset_of!(xqc_h3_request_callbacks_s, h3_request_create_notify) - 0usize];
    ["Offset of field: xqc_h3_request_callbacks_s::h3_request_close_notify"]
        [::core::mem::offset_of!(xqc_h3_request_callbacks_s, h3_request_close_notify) - 8usize];
    ["Offset of field: xqc_h3_request_callbacks_s::h3_request_read_notify"]
        [::core::mem::offset_of!(xqc_h3_request_callbacks_s, h3_request_read_notify) - 16usize];
    ["Offset of field: xqc_h3_request_callbacks_s::h3_request_write_notify"]
        [::core::mem::offset_of!(xqc_h3_request_callbacks_s, h3_request_write_notify) - 24usize];
    ["Offset of field: xqc_h3_request_callbacks_s::h3_request_closing_notify"]
        [::core::mem::offset_of!(xqc_h3_request_callbacks_s, h3_request_closing_notify) - 32usize];
};
#[doc = " @brief http3 request callbacks for application layer"]
pub type xqc_h3_request_callbacks_t = xqc_h3_request_callbacks_s;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xqc_h3_ext_bytestream_callbacks_s {
    #[doc = " the return value is ignored by XQUIC stack"]
    pub bs_create_notify: xqc_h3_ext_bytestream_notify_pt,
    #[doc = " the return value is ignored by XQUIC stack"]
    pub bs_close_notify: xqc_h3_ext_bytestream_notify_pt,
    #[doc = " negative return values will cause the connection to be closed"]
    pub bs_read_notify: xqc_h3_ext_bytestream_read_notify_pt,
    #[doc = " negative return values will cause the connection to be closed"]
    pub bs_write_notify: xqc_h3_ext_bytestream_notify_pt,
}
#[allow(clippy::unnecessary_operation, clippy::identity_op)]
const _: () = {
    ["Size of xqc_h3_ext_bytestream_callbacks_s"]
        [::core::mem::size_of::<xqc_h3_ext_bytestream_callbacks_s>() - 32usize];
    ["Alignment of xqc_h3_ext_bytestream_callbacks_s"]
        [::core::mem::align_of::<xqc_h3_ext_bytestream_callbacks_s>() - 8usize];
    ["Offset of field: xqc_h3_ext_bytestream_callbacks_s::bs_create_notify"]
        [::core::mem::offset_of!(xqc_h3_ext_bytestream_callbacks_s, bs_create_notify) - 0usize];
    ["Offset of field: xqc_h3_ext_bytestream_callbacks_s::bs_close_notify"]
        [::core::mem::offset_of!(xqc_h3_ext_bytestream_callbacks_s, bs_close_notify) - 8usize];
    ["Offset of field: xqc_h3_ext_bytestream_callbacks_s::bs_read_notify"]
        [::core::mem::offset_of!(xqc_h3_ext_bytestream_callbacks_s, bs_read_notify) - 16usize];
    ["Offset of field: xqc_h3_ext_bytestream_callbacks_s::bs_write_notify"]
        [::core::mem::offset_of!(xqc_h3_ext_bytestream_callbacks_s, bs_write_notify) - 24usize];
};
pub type xqc_h3_ext_bytestream_callbacks_t = xqc_h3_ext_bytestream_callbacks_s;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xqc_h3_callbacks_s {
    #[doc = " http3 connection callbacks"]
    pub h3c_cbs: xqc_h3_conn_callbacks_t,
    #[doc = " http3 request callbacks"]
    pub h3r_cbs: xqc_h3_request_callbacks_t,
    #[doc = " datagram callbacks"]
    pub h3_ext_dgram_cbs: xqc_h3_ext_dgram_callbacks_t,
    #[doc = " bytestream callbacks"]
    pub h3_ext_bs_cbs: xqc_h3_ext_bytestream_callbacks_t,
}
#[allow(clippy::unnecessary_operation, clippy::identity_op)]
const _: () = {
    ["Size of xqc_h3_callbacks_s"][::core::mem::size_of::<xqc_h3_callbacks_s>() - 152usize];
    ["Alignment of xqc_h3_callbacks_s"][::core::mem::align_of::<xqc_h3_callbacks_s>() - 8usize];
    ["Offset of field: xqc_h3_callbacks_s::h3c_cbs"]
        [::core::mem::offset_of!(xqc_h3_callbacks_s, h3c_cbs) - 0usize];
    ["Offset of field: xqc_h3_callbacks_s::h3r_cbs"]
        [::core::mem::offset_of!(xqc_h3_callbacks_s, h3r_cbs) - 40usize];
    ["Offset of field: xqc_h3_callbacks_s::h3_ext_dgram_cbs"]
        [::core::mem::offset_of!(xqc_h3_callbacks_s, h3_ext_dgram_cbs) - 80usize];
    ["Offset of field: xqc_h3_callbacks_s::h3_ext_bs_cbs"]
        [::core::mem::offset_of!(xqc_h3_callbacks_s, h3_ext_bs_cbs) - 120usize];
};
pub type xqc_h3_callbacks_t = xqc_h3_callbacks_s;
unsafe extern "C" {
    #[doc = " @brief init h3 context into xqc_engine_t, this MUST BE called before create any http3 connection\n\n @param engine the engine handler created by xqc_engine_create\n @return xqc_int_t XQC_OK for success, others for failure"]
    pub fn xqc_h3_ctx_init(engine: *mut xqc_engine_t, h3_cbs: *mut xqc_h3_callbacks_t)
    -> xqc_int_t;
}
unsafe extern "C" {
    pub fn xqc_h3_ctx_destroy(engine: *mut xqc_engine_t) -> xqc_int_t;
}
unsafe extern "C" {
    #[doc = " @brief set max h3 max dynamic table capacity. It MUST only be called after\n        xqc_h3_ctx_init.\n\n @param engine the engine handler created by xqc_engine_create\n @param value capacity of dynamic table, 0 for disable dynamic table"]
    pub fn xqc_h3_engine_set_max_dtable_capacity(engine: *mut xqc_engine_t, capacity: usize);
}
unsafe extern "C" {
    #[doc = " @brief @deprecated use xqc_h3_engine_set_max_dtable_capacity instead.\n        It MUST only be called after xqc_h3_ctx_init.\n\n @param engine the engine handler created by xqc_engine_create\n @param value 0:disable dynamic table"]
    pub fn xqc_h3_engine_set_dec_max_dtable_capacity(engine: *mut xqc_engine_t, value: usize);
}
unsafe extern "C" {
    #[doc = " @brief @deprecated use xqc_h3_engine_set_max_dtable_capacity instead.\n        It MUST only be called after xqc_h3_ctx_init.\n\n @param engine the engine handler created by xqc_engine_create\n @param value 0:disable dynamic table"]
    pub fn xqc_h3_engine_set_enc_max_dtable_capacity(engine: *mut xqc_engine_t, value: usize);
}
unsafe extern "C" {
    #[doc = " @brief set max h3 field section size.\n        It MUST only be called after xqc_h3_ctx_init.\n\n @param engine the engine handler created by xqc_engine_create\n @param size size of field section size"]
    pub fn xqc_h3_engine_set_max_field_section_size(engine: *mut xqc_engine_t, size: usize);
}
unsafe extern "C" {
    #[doc = " @brief set the limit for qpack blocked streams.\n        It MUST only be called after xqc_h3_ctx_init.\n\n @param engine\n @param value\n @return XQC_EXPORT_PUBLIC_API"]
    pub fn xqc_h3_engine_set_qpack_blocked_streams(engine: *mut xqc_engine_t, value: usize);
}
unsafe extern "C" {
    #[doc = " User can set h3 settings when h3_conn_create_notify callbacks"]
    pub fn xqc_h3_engine_set_local_settings(
        engine: *mut xqc_engine_t,
        h3_conn_settings: *const xqc_h3_conn_settings_t,
    );
}
unsafe extern "C" {
    #[doc = " @brief create and http3 connection\n\n @param engine return from xqc_engine_create\n @param conn_settings Include all the connection settings, which should be customized according to the actual needs, and will be defaultly set to internal_default_conn_settings if not specified.\n @param token token receive from server, xqc_save_token_pt callback\n @param token_len length of token\n @param server_host server domain\n @param no_crypto_flag 1:without crypto\n @param conn_ssl_config For handshake\n @param peer_addr address of peer\n @param peer_addrlen length of peer_addr\n @param user_data returned in connection callback functions\n @return cid of the connection; user should copy cid to your own memory, in case of cid destroyed\n in xquic library"]
    pub fn xqc_h3_connect(
        engine: *mut xqc_engine_t,
        conn_settings: *const xqc_conn_settings_t,
        token: *const ::core::ffi::c_uchar,
        token_len: ::core::ffi::c_uint,
        server_host: *const ::core::ffi::c_char,
        no_crypto_flag: ::core::ffi::c_int,
        conn_ssl_config: *const xqc_conn_ssl_config_t,
        peer_addr: *const sockaddr,
        peer_addrlen: socklen_t,
        user_data: *mut ::core::ffi::c_void,
    ) -> *const xqc_cid_t;
}
unsafe extern "C" {
    #[doc = " @brief manually close a http3 connection\n\n @param engine engine handler created by xqc_engine_create\n @param cid connection id of http3 connection\n @return XQC_OK for success, others for failure"]
    pub fn xqc_h3_conn_close(engine: *mut xqc_engine_t, cid: *const xqc_cid_t) -> xqc_int_t;
}
unsafe extern "C" {
    #[doc = " @brief get QUIC connection handler\n\n @param h3c http3 connection handler\n @return quic_connection on which h3_conn rely"]
    pub fn xqc_h3_conn_get_xqc_conn(h3c: *mut xqc_h3_conn_t) -> *mut xqc_connection_t;
}
unsafe extern "C" {
    #[doc = " @brief get http3 protocol error number\n\n @param h3c handler of http3 connection\n @return error number of http3 connection, HTTP_NO_ERROR(0x100) For no-error"]
    pub fn xqc_h3_conn_get_errno(h3c: *mut xqc_h3_conn_t) -> xqc_int_t;
}
unsafe extern "C" {
    #[doc = " @brief get ssl handler of http3 connection\n\n @param h3c handler of http3 connection\n @return ssl handler of http3 connection"]
    pub fn xqc_h3_conn_get_ssl(h3c: *mut xqc_h3_conn_t) -> *mut ::core::ffi::c_void;
}
unsafe extern "C" {
    #[doc = " @brief set user_data for http3 connection, user_data could be the application layer context of\n http3 connection\n\n @param h3c handler of http3 connection\n @param user_data should set user_data when h3_conn_create_notify callbacks, which will be\n returned as parameter of http3 connection callback functions"]
    pub fn xqc_h3_conn_set_user_data(h3c: *mut xqc_h3_conn_t, user_data: *mut ::core::ffi::c_void);
}
unsafe extern "C" {
    #[doc = " @brief get user_data for http3 connection, user_data could be the application layer context of\n http3 connection\n\n @param h3c handler of http3 connection\n @return user_data"]
    pub fn xqc_h3_conn_get_user_data(h3_conn: *mut xqc_h3_conn_t) -> *mut ::core::ffi::c_void;
}
unsafe extern "C" {
    #[doc = " @brief get peer address information, server should call this when h3_conn_create_notify triggers\n\n @param h3c handler of http3 connection\n @param addr [out] output address of peer\n @param addr_cap capacity of addr\n @param peer_addr_len [out] output length of addr\n @return XQC_OK for success, others for failure"]
    pub fn xqc_h3_conn_get_peer_addr(
        h3c: *mut xqc_h3_conn_t,
        addr: *mut sockaddr,
        addr_cap: socklen_t,
        peer_addr_len: *mut socklen_t,
    ) -> xqc_int_t;
}
unsafe extern "C" {
    #[doc = " @brief get local address information, server should call this when h3_conn_create_notify triggers\n\n @param h3c handler of http3 connection\n @param addr [out] output address of peer\n @param addr_cap capacity of addr\n @param peer_addr_len [out] output length of addr\n @return XQC_OK for success, others for failure"]
    pub fn xqc_h3_conn_get_local_addr(
        h3c: *mut xqc_h3_conn_t,
        addr: *mut sockaddr,
        addr_cap: socklen_t,
        local_addr_len: *mut socklen_t,
    ) -> xqc_int_t;
}
unsafe extern "C" {
    #[doc = " @brief Send PING to peer, if ack received, h3_conn_ping_acked will callback with user_data\n\n @param engine handler of engine\n @param cid connection id of http3 connection, which is generated by xqc_h3_connect\n @param ping_user_data\n @return XQC_OK for success, < 0 for error"]
    pub fn xqc_h3_conn_send_ping(
        engine: *mut xqc_engine_t,
        cid: *const xqc_cid_t,
        ping_user_data: *mut ::core::ffi::c_void,
    ) -> xqc_int_t;
}
unsafe extern "C" {
    #[doc = " @brief check if h3 connection is ready to send 0rtt data\n @param h3c h3 connection handler\n @return XQC_TRUE for can send 0rtt, XQC_FALSE for can not"]
    pub fn xqc_h3_conn_is_ready_to_send_early_data(h3c: *mut xqc_h3_conn_t) -> xqc_bool_t;
}
unsafe extern "C" {
    #[doc = " @brief set the dynamic table capacity of an existing h3 connection\n @param h3c h3 connection handler\n @param capacity capacity of dynamic table, 0 for disable dynamic table\n @return XQC_OK for success, others for failure"]
    pub fn xqc_h3_conn_set_qpack_dtable_cap(h3c: *mut xqc_h3_conn_t, capacity: usize) -> xqc_int_t;
}
unsafe extern "C" {
    #[doc = " @brief create a http3 request\n @param engine handler created by xqc_engine_create\n @param cid connection id of http3 connection\n @param user_data For request\n @param settings stream settings\n @return handler of http3 request"]
    pub fn xqc_h3_request_create(
        engine: *mut xqc_engine_t,
        cid: *const xqc_cid_t,
        settings: *mut xqc_stream_settings_t,
        user_data: *mut ::core::ffi::c_void,
    ) -> *mut xqc_h3_request_t;
}
unsafe extern "C" {
    #[doc = " @brief get statistics of a http3 request user can get it before request destroyed\n\n @param h3_request handler of http3 request\n @return statistics information of request"]
    pub fn xqc_h3_request_get_stats(h3_request: *mut xqc_h3_request_t) -> xqc_request_stats_t;
}
unsafe extern "C" {
    #[doc = " @brief write important information into str\n @return the number of characters printed"]
    pub fn xqc_h3_request_stats_print(
        h3_request: *mut xqc_h3_request_t,
        str_: *mut ::core::ffi::c_char,
        size: usize,
    ) -> xqc_int_t;
}
unsafe extern "C" {
    #[doc = " @brief set user_data of a http3 request, which will be used as parameter of request\n callback functions. server should set user_data when h3_request_create_notify triggers\n\n @param h3_request handler of http3 request\n @param user_data user data of request callback functions"]
    pub fn xqc_h3_request_set_user_data(
        h3_request: *mut xqc_h3_request_t,
        user_data: *mut ::core::ffi::c_void,
    );
}
unsafe extern "C" {
    #[doc = " @brief close request, send QUIC RESET_STREAM frame to peer. h3_request_close_notify will\n triggered when request is finally destroyed\n\n @param h3_request handler of http3 request\n @return XQC_OK for success, others for error"]
    pub fn xqc_h3_request_close(h3_request: *mut xqc_h3_request_t) -> xqc_int_t;
}
unsafe extern "C" {
    pub fn xqc_h3_request_update_settings(
        h3_request: *mut xqc_h3_request_t,
        settings: *mut xqc_stream_settings_t,
    ) -> xqc_int_t;
}
unsafe extern "C" {
    #[doc = " @brief send http headers to peer\n\n @param h3_request handler of http3 request\n @param headers http headers\n @param fin request finish flag, 1 for finish. if set here, it means request has no body\n @return > 0 for Bytes sent，-XQC_EAGAIN try next time, < 0 for error, 0 for request finished"]
    pub fn xqc_h3_request_send_headers(
        h3_request: *mut xqc_h3_request_t,
        headers: *mut xqc_http_headers_t,
        fin: u8,
    ) -> isize;
}
unsafe extern "C" {
    #[doc = " @brief send http body to peer\n\n @param h3_request handler of http3 request\n @param data content of body\n @param data_size length of body\n @param fin request finish flag, 1 for finish.\n @return > 0 for Bytes sent，-XQC_EAGAIN try next time, < 0 for error, 0 for request finished"]
    pub fn xqc_h3_request_send_body(
        h3_request: *mut xqc_h3_request_t,
        data: *mut ::core::ffi::c_uchar,
        data_size: usize,
        fin: u8,
    ) -> isize;
}
unsafe extern "C" {
    #[doc = " @brief finish request. if fin is not sent yet, and application has nothing to send anymore, call\n this function to send a QUIC STREAM frame with only fin\n\n @return > 0 for Bytes sent，-XQC_EAGAIN try next time, < 0 for error, 0 for request finished"]
    pub fn xqc_h3_request_finish(h3_request: *mut xqc_h3_request_t) -> isize;
}
unsafe extern "C" {
    #[doc = " @brief receive headers of a request\n\n @param h3_request handler of http3 request\n @param fin request finish flag, 1 for finish. if not 0, it means request has no body\n @return request headers. user should copy headers to your own memory，NULL for error"]
    pub fn xqc_h3_request_recv_headers(
        h3_request: *mut xqc_h3_request_t,
        fin: *mut u8,
    ) -> *mut xqc_http_headers_t;
}
unsafe extern "C" {
    #[doc = " @brief receive body of a request\n\n @param h3_request handler of http3 request\n @param fin request finish flag, 1 for finish\n @return Bytes read，-XQC_EAGAIN try next time, <0 for error"]
    pub fn xqc_h3_request_recv_body(
        h3_request: *mut xqc_h3_request_t,
        recv_buf: *mut ::core::ffi::c_uchar,
        recv_buf_size: usize,
        fin: *mut u8,
    ) -> isize;
}
unsafe extern "C" {
    #[doc = " @brief get connection's user_data by request\n\n @param h3_request handler of http3 request\n @return user_data set by user"]
    pub fn xqc_h3_get_conn_user_data_by_request(
        h3_request: *mut xqc_h3_request_t,
    ) -> *mut ::core::ffi::c_void;
}
unsafe extern "C" {
    #[doc = " @brief Get QUIC stream ID by request\n\n @param h3_request handler of http3 request\n @return QUIC stream id"]
    pub fn xqc_h3_stream_id(h3_request: *mut xqc_h3_request_t) -> xqc_stream_id_t;
}
unsafe extern "C" {
    #[doc = " @brief RFC 9218 HTTP Priority"]
    pub fn xqc_h3_priority_init(prio: *mut xqc_h3_priority_t);
}
unsafe extern "C" {
    pub fn xqc_write_http_priority(
        prio: *mut xqc_h3_priority_t,
        dst: *mut u8,
        dstcap: usize,
    ) -> usize;
}
unsafe extern "C" {
    pub fn xqc_parse_http_priority(
        dst: *mut xqc_h3_priority_t,
        str_: *const u8,
        str_len: usize,
    ) -> xqc_int_t;
}
unsafe extern "C" {
    pub fn xqc_h3_request_set_priority(
        h3r: *mut xqc_h3_request_t,
        prio: *mut xqc_h3_priority_t,
    ) -> xqc_int_t;
}
unsafe extern "C" {
    #[doc = " @brief create a bytestream based on extended H3\n @param engine handler created by xqc_engine_create\n @param cid connection id of http3 connection\n @param user_data For bytestream\n @return handler of bytestream"]
    pub fn xqc_h3_ext_bytestream_create(
        engine: *mut xqc_engine_t,
        cid: *const xqc_cid_t,
        user_data: *mut ::core::ffi::c_void,
    ) -> *mut xqc_h3_ext_bytestream_t;
}
unsafe extern "C" {
    #[doc = " @brief close bytestream, send QUIC RESET_STREAM frame to peer. h3_ext_bytestream_close_notify will\n triggered when bytestream is finally destroyed\n\n @param xqc_h3_ext_bytestream_t handler of bytestream\n @return XQC_OK for success, others for error"]
    pub fn xqc_h3_ext_bytestream_close(h3_ext_bs: *mut xqc_h3_ext_bytestream_t) -> xqc_int_t;
}
unsafe extern "C" {
    #[doc = " @brief finish bytestream. if fin is not sent yet, and application has nothing to send anymore, call\n this function to send a QUIC STREAM frame with only fin\n\n @return > 0 for Bytes sent，-XQC_EAGAIN try next time, < 0 for error, 0 for bytestream finished"]
    pub fn xqc_h3_ext_bytestream_finish(h3_ext_bs: *mut xqc_h3_ext_bytestream_t) -> isize;
}
unsafe extern "C" {
    #[doc = " @brief set user_data of a bytestream, which will be used as the parameter of the bytestream\n callback functions. server should set user_data when h3_ext_bytestream_create_notify triggers\n\n @param xqc_h3_ext_bytestream_t handler of the bytestream\n @param user_data user data of the bytestream callback functions"]
    pub fn xqc_h3_ext_bytestream_set_user_data(
        h3_ext_bs: *mut xqc_h3_ext_bytestream_t,
        user_data: *mut ::core::ffi::c_void,
    );
}
unsafe extern "C" {
    #[doc = " @brief get the user data associcated with the bytestream object\n\n @param xqc_h3_ext_bytestream_t handler of the bytestream\n @param user_data user data of the bytestream callback functions\n @return the pointer of user data"]
    pub fn xqc_h3_ext_bytestream_get_user_data(
        h3_ext_bs: *mut xqc_h3_ext_bytestream_t,
    ) -> *mut ::core::ffi::c_void;
}
unsafe extern "C" {
    #[doc = " @brief get statistics of a bytestream\n\n @param xqc_h3_ext_bytestream_t handler of the bytestream\n @return statistics information of the bytestream"]
    pub fn xqc_h3_ext_bytestream_get_stats(
        h3_ext_bs: *mut xqc_h3_ext_bytestream_t,
    ) -> xqc_h3_ext_bytestream_stats_t;
}
unsafe extern "C" {
    #[doc = " @brief send data\n\n @param xqc_h3_ext_bytestream_t handler of the bytestream\n @param data content\n @param data_size data length\n @param fin request finish flag, 1 for finish.\n @param qos level (must be the values defined in xqc_data_qos_level_t)\n @return > 0 for bytes sent，-XQC_EAGAIN try next time, < 0 for error, 0 for bytestream finished"]
    pub fn xqc_h3_ext_bytestream_send(
        h3_ext_bs: *mut xqc_h3_ext_bytestream_t,
        data: *mut ::core::ffi::c_uchar,
        data_size: usize,
        fin: u8,
        qos_level: xqc_data_qos_level_t,
    ) -> isize;
}
unsafe extern "C" {
    #[doc = " @brief Get QUIC stream ID by a bytestream\n\n @param xqc_h3_ext_bytestream_t handler of a bytestream\n @return QUIC stream id"]
    pub fn xqc_h3_ext_bytestream_id(h3_ext_bs: *mut xqc_h3_ext_bytestream_t) -> xqc_stream_id_t;
}
unsafe extern "C" {
    #[doc = " @brief get the h3 connection associated with a bytestream\n\n @param xqc_h3_ext_bytestream_t handler of a bytestream\n @return an h3 connection"]
    pub fn xqc_h3_ext_bytestream_get_h3_conn(
        h3_ext_bs: *mut xqc_h3_ext_bytestream_t,
    ) -> *mut xqc_h3_conn_t;
}
unsafe extern "C" {
    #[doc = " @brief the API to get the max length of the data that can be sent\n        via a single call of xqc_datagram_send\n\n @param conn the connection handle\n @return 0 = the peer does not support datagram, >0 = the max length"]
    pub fn xqc_h3_ext_datagram_get_mss(conn: *mut xqc_h3_conn_t) -> usize;
}
unsafe extern "C" {
    #[doc = " Server should set datagram user_data when datagram callbacks\n @dgram_data: the user_data of all datagram callbacks"]
    pub fn xqc_h3_ext_datagram_set_user_data(
        conn: *mut xqc_h3_conn_t,
        user_data: *mut ::core::ffi::c_void,
    );
}
unsafe extern "C" {
    #[doc = " @return the user_data of all datagram callbacks"]
    pub fn xqc_h3_ext_datagram_get_user_data(conn: *mut xqc_h3_conn_t) -> *mut ::core::ffi::c_void;
}
unsafe extern "C" {
    #[doc = " @brief the API to send a datagram over the h3 connection\n\n @param conn the connection handle\n @param data the data to be sent\n @param data_len the length of the data\n @param *dgram_id the pointer to return the id the datagram\n @param qos level (must be the values defined in xqc_data_qos_level_t)\n @return <0 = error (-XQC_EAGAIN, -XQC_CLOSING, -XQC_DGRAM_NOT_SUPPORTED, -XQC_DGRAM_TOO_LARGE, ...),\n         0 success"]
    pub fn xqc_h3_ext_datagram_send(
        conn: *mut xqc_h3_conn_t,
        data: *mut ::core::ffi::c_void,
        data_len: usize,
        dgram_id: *mut u64,
        qos_level: xqc_data_qos_level_t,
    ) -> xqc_int_t;
}
unsafe extern "C" {
    #[doc = " @brief the API to send a datagram over the h3 connection\n\n @param conn the connection handle\n @param iov multiple data buffers need to be sent\n @param *dgram_id the pointer to return the list of dgram_id\n @param iov_size the size of iov list\n @param *sent_cnt the number of successfully sent datagrams\n @param *sent_bytes the total bytes of successfully sent datagrams\n @param qos level (must be the values defined in xqc_data_qos_level_t)\n @return <0 = error (-XQC_EAGAIN, -XQC_CLOSING, -XQC_DGRAM_NOT_SUPPORTED, -XQC_DGRAM_TOO_LARGE, ...),\n         0 success"]
    pub fn xqc_h3_ext_datagram_send_multiple(
        conn: *mut xqc_h3_conn_t,
        iov: *mut iovec,
        dgram_id_list: *mut u64,
        iov_size: usize,
        sent_cnt: *mut usize,
        sent_bytes: *mut usize,
        qos_level: xqc_data_qos_level_t,
    ) -> xqc_int_t;
}
unsafe extern "C" {
    #[doc = " @brief send a datagram pinned to a specific path (multipath QUIC)\n\n Same as xqc_h3_ext_datagram_send but the datagram packet is pinned to the\n given path_id, bypassing the multipath scheduler.\n Use XQC_INITIAL_PATH_ID (0) for the initial path."]
    pub fn xqc_h3_ext_datagram_send_on_path(
        conn: *mut xqc_h3_conn_t,
        data: *mut ::core::ffi::c_void,
        data_len: usize,
        dgram_id: *mut u64,
        qos_level: xqc_data_qos_level_t,
        path_id: u64,
    ) -> xqc_int_t;
}
unsafe extern "C" {
    #[doc = " Frame a UDP/IP payload into an HTTP Datagram buffer (RFC 9297).\n Prepends [Quarter-Stream-ID : varint][Context-ID=0 : varint]."]
    pub fn xqc_h3_ext_masque_frame_udp(
        out: *mut u8,
        outlen: usize,
        written: *mut usize,
        stream_id: u64,
        payload: *const u8,
        paylen: usize,
    ) -> xqc_int_t;
}
unsafe extern "C" {
    #[doc = " Unframe an HTTP Datagram (RFC 9297).\n Returns a pointer to the payload within the input buffer."]
    pub fn xqc_h3_ext_masque_unframe_udp(
        buf: *const u8,
        buflen: usize,
        quarter_stream_id: *mut u64,
        context_id: *mut u64,
        payload: *mut *const u8,
        payload_len: *mut usize,
    ) -> xqc_int_t;
}
unsafe extern "C" {
    #[doc = " Calculate the maximum payload size for a single HTTP Datagram."]
    pub fn xqc_h3_ext_masque_udp_mss(dgram_mss: usize, stream_id: u64) -> usize;
}
unsafe extern "C" {
    #[doc = " Encode a capsule: [Type : varint][Length : varint][Payload] (RFC 9297)."]
    pub fn xqc_h3_ext_capsule_encode(
        out: *mut u8,
        outlen: usize,
        written: *mut usize,
        type_: u64,
        payload: *const u8,
        paylen: usize,
    ) -> xqc_int_t;
}
unsafe extern "C" {
    #[doc = " Decode a capsule header and return a pointer to the payload (RFC 9297)."]
    pub fn xqc_h3_ext_capsule_decode(
        buf: *const u8,
        buflen: usize,
        type_: *mut u64,
        payload: *mut *const u8,
        payload_len: *mut usize,
        bytes_consumed: *mut usize,
    ) -> xqc_int_t;
}
unsafe extern "C" {
    #[doc = " Parse a single entry from an ADDRESS_ASSIGN capsule payload (RFC 9484).\n Call in a loop, advancing by bytes_consumed each iteration, to handle\n capsules containing multiple assigned addresses."]
    pub fn xqc_h3_ext_connectip_parse_address_assign(
        payload: *const u8,
        paylen: usize,
        request_id: *mut u64,
        ip_version: *mut u8,
        ip_addr: *mut u8,
        ip_addr_len: *mut usize,
        prefix_len: *mut u8,
        bytes_consumed: *mut usize,
    ) -> xqc_int_t;
}
unsafe extern "C" {
    #[doc = " Build an ADDRESS_REQUEST capsule payload (RFC 9484)."]
    pub fn xqc_h3_ext_connectip_build_address_request(
        buf: *mut u8,
        buflen: usize,
        written: *mut usize,
        request_id: u64,
        ip_version: u8,
        ip_addr: *const u8,
        prefix_len: u8,
    ) -> xqc_int_t;
}
unsafe extern "C" {
    #[doc = " Parse a single ROUTE_ADVERTISEMENT entry (RFC 9484).\n Call in a loop, advancing by bytes_consumed each iteration."]
    pub fn xqc_h3_ext_connectip_parse_route_advertisement(
        payload: *const u8,
        paylen: usize,
        ip_version: *mut u8,
        start_ip: *mut u8,
        end_ip: *mut u8,
        ip_addr_len: *mut usize,
        ip_protocol: *mut u8,
        bytes_consumed: *mut usize,
    ) -> xqc_int_t;
}
unsafe extern "C" {
    #[doc = " Validate an IP packet extracted from an HTTP Datagram (RFC 9484 Section 4.6).\n Checks IP version field (must be 4 or 6) and minimum header length.\n Returns XQC_OK if valid, -XQC_EPARAM if invalid."]
    pub fn xqc_h3_ext_masque_validate_ip_packet(
        payload: *const u8,
        payload_len: usize,
    ) -> xqc_int_t;
}
unsafe extern "C" {
    #[doc = " Validate a full ROUTE_ADVERTISEMENT capsule payload (RFC 9484 §4.7.3).\n Verifies ordering and non-overlapping ranges."]
    pub fn xqc_h3_ext_connectip_validate_route_advertisement(
        payload: *const u8,
        paylen: usize,
    ) -> xqc_int_t;
}
unsafe extern "C" {
    #[doc = " Check that IPv6 tunnel MTU meets the RFC 9484 §7.2 minimum of 1280 bytes."]
    pub fn xqc_h3_ext_masque_check_ipv6_mtu(tunnel_mtu: usize) -> xqc_int_t;
}
