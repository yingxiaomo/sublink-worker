import { parseServerInfo, parseUrlParams, parseBool } from '../../utils.js';

/**
 * Parse naive:// or naive+https:// share links.
 * Formats seen in the wild:
 *   naive+https://user:pass@host:port?...#name
 *   naive://user:pass@host:port?...#name
 */
export function parseNaive(url) {
    // Normalize scheme: naive+https:// -> naive://
    const normalized = url.replace(/^naive\+https?:\/\//i, 'naive://').replace(/^naive\+http:\/\//i, 'naive://');
    const { addressPart, params, name } = parseUrlParams(normalized);

    let userinfo = '';
    let serverInfo = addressPart;
    if (addressPart.includes('@')) {
        const at = addressPart.lastIndexOf('@');
        userinfo = addressPart.slice(0, at);
        serverInfo = addressPart.slice(at + 1);
    }

    const { host, port } = parseServerInfo(serverInfo);
    const decoded = decodeURIComponent(userinfo || '');
    const colon = decoded.indexOf(':');
    const username = colon >= 0 ? decoded.slice(0, colon) : decoded;
    const password = colon >= 0 ? decoded.slice(colon + 1) : '';

    const insecure = parseBool(
        params.insecure ?? params.allowInsecure ?? params.allow_insecure ?? params['skip-cert-verify'],
        false
    );

    return {
        type: 'naive',
        tag: name,
        server: host,
        server_port: port,
        username,
        password,
        // Naive over HTTPS is the common case for naive+https://
        scheme: url.startsWith('naive+http://') ? 'http' : 'https',
        sni: params.sni || params.host || host,
        insecure: !!insecure
    };
}
