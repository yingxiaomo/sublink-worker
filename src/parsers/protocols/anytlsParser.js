import { parseServerInfo, parseUrlParams, createTlsConfig } from '../../utils.js';

/**
 * Parse anytls://password@host:port?...#name share links.
 * Example:
 * anytls://uuid@host:41700?security=tls&sni=host&insecure=0&type=tcp#name
 */
export function parseAnytls(url) {
    const { addressPart, params, name } = parseUrlParams(url);
    const [passwordPart, serverInfo] = addressPart.split('@');
    const { host, port } = parseServerInfo(serverInfo);

    // AnyTLS is TLS-based; default to tls when omitted
    if (!params.security) params.security = 'tls';
    const tls = createTlsConfig(params);

    return {
        type: 'anytls',
        tag: name,
        server: host,
        server_port: port,
        password: decodeURIComponent(passwordPart || ''),
        tls,
        udp: true
    };
}
