use super::*;

fn query_envelope(packet: &[u8], domain: &TunnelDomain) -> Envelope {
    let query = dns::parse_query(packet).unwrap();
    let prefix = query.zone_prefix(domain).unwrap();
    Envelope::decode(
        &query.tunnel_payload(prefix).unwrap(),
        Direction::ClientToServer,
    )
    .unwrap()
}

fn respond(packet: &[u8], env: Envelope) -> Vec<u8> {
    dns::parse_query(packet)
        .unwrap()
        .tunnel_response(&env.encode())
        .unwrap()
}

#[test]
fn authenticates_server_before_establishing_or_dialing_and_then_encrypts_without_expansion() {
    let domain = TunnelDomain::parse("t.example.com").unwrap();
    let secret = SharedSecret::new(vec![7; 32]).unwrap();
    let mut core = ClientCore::new(domain.clone(), secret.clone()).unwrap();
    let t0 = Instant::now();
    let hello_packet = core.poll(t0).remove(0);
    let hello = query_envelope(&hello_packet, &domain);
    let Frame::Hello { client_nonce } = hello.frames[0] else {
        panic!()
    };
    let sn = [9; 16];
    let sizes = domain.sizes().unwrap();
    let input = CookieInput {
        domain_wire: domain.wire(),
        client_nonce: &client_nonce,
        server_nonce: &sn,
        u: sizes.u as u16,
        d: sizes.d as u16,
    };
    let cookie = input.make(&[11; 32], 1_700_000_030);
    core.handle_datagram(
        &respond(
            &hello_packet,
            Envelope::server(
                0,
                hello.exchange_id,
                vec![Frame::Challenge {
                    server_nonce: sn,
                    u: input.u,
                    d: input.d,
                    cookie,
                }],
            ),
        ),
        t0,
    );
    let echo_packet = core.poll(t0).remove(0);
    let echo = query_envelope(&echo_packet, &domain);
    let Frame::CookieEcho { proof, .. } = echo.frames[0] else {
        panic!()
    };
    assert!(secret.verify_client(&input, &cookie, &proof));
    assert_eq!(echo.encoded_len(), 96);
    let sid = 0x12345678;
    // A resolver/attacker's fabricated ACCEPT cannot authorize reverse dialing.
    core.handle_datagram(
        &respond(
            &echo_packet,
            Envelope::server(
                0,
                echo.exchange_id,
                vec![Frame::Accept {
                    session_id: sid,
                    proof: [0; 32],
                }],
            ),
        ),
        t0,
    );
    assert_eq!(core.established(), None);
    assert!(core.transport.crypto.is_none());
    assert!(core.take_actions().is_empty());
    let later = t0 + HANDSHAKE_TIMEOUT;
    let retry_packet = core.poll(later).remove(0);
    let retry = query_envelope(&retry_packet, &domain);
    assert_eq!(
        retry.frames, echo.frames,
        "retry keeps nonce/cookie/proof identity"
    );
    core.handle_datagram(
        &respond(
            &retry_packet,
            Envelope::server(
                0,
                retry.exchange_id,
                vec![Frame::Accept {
                    session_id: sid,
                    proof: secret.server_proof(&input, &cookie, sid),
                }],
            ),
        ),
        later,
    );
    assert_eq!(core.established(), Some(sid));
    let packet = core.poll(later + Duration::from_secs(1)).remove(0);
    let query = dns::parse_query(&packet).unwrap();
    let mut bytes = query
        .tunnel_payload(query.zone_prefix(&domain).unwrap())
        .unwrap();
    let ciphertext = bytes.clone();
    let keys = secret.session_keys(&input, &cookie, sid);
    keys.apply(&mut bytes, Direction::ClientToServer).unwrap();
    assert_ne!(bytes[9..], ciphertext[9..]);
    assert_eq!(bytes.len(), ciphertext.len());
    let env = Envelope::decode(&bytes, Direction::ClientToServer).unwrap();
    assert_eq!(
        (env.session_id, env.exchange_id, env.rx_lag),
        (sid, 1, Some(255))
    );
}
