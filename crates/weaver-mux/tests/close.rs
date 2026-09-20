mod common;

use common::*;
use weaver_mux::{
    Class, CloseCode, CloseReason, Compress, Event, Frame, FrameType, ProtocolError,
    RST_CODE_CONNECTION_CLOSED, StreamError,
};

#[test]
fn close_key_revoked() {
    let mut p = Pair::authenticated();
    let a = p.server.open(Class::Interactive).unwrap();
    let b = p.client.open(Class::Interactive).unwrap();
    send(&mut p.server, a, b"pending bulk");
    p.pump();
    p.drain_events(Side::Client);
    p.drain_events(Side::Server);
    // Queue more data so the scheduler has a backlog GOAWAY must beat.
    send(&mut p.server, a, &[7u8; 60_000]);

    p.server.close(CloseReason {
        code: CloseCode::KeyRevoked,
        message: Some("key rotated".into()),
    });
    let now = p.clock.now();
    let mut buf = Vec::new();
    assert!(p.server.poll_transmit(now, &mut buf));
    assert_eq!(Frame::parse(&buf).unwrap().frame_type, FrameType::Goaway);

    let events = p.drain_events(Side::Server);
    assert_eq!(
        events,
        vec![
            Event::Reset {
                id: b,
                code: RST_CODE_CONNECTION_CLOSED
            },
            Event::Reset {
                id: a,
                code: RST_CODE_CONNECTION_CLOSED
            },
            Event::Closed {
                reason: CloseReason {
                    code: CloseCode::KeyRevoked,
                    message: Some("key rotated".into()),
                }
            },
        ]
    );
    // Nothing more after the close on the server side.
    assert_eq!(p.server.open(Class::Interactive), Err(StreamError::Closed));
    assert_eq!(
        p.server.send(a, b"x", Compress::Auto),
        Err(StreamError::Closed)
    );

    // Deliver GOAWAY (and trailing RSTs) to the client.
    p.client.recv(now, &buf).unwrap_err_or_ok();
    p.pump();
    let client_events = p.drain_events(Side::Client);
    assert!(
        client_events
            .iter()
            .any(|e| matches!(e, Event::Reset { id, .. } if *id == a))
    );
    assert!(
        client_events
            .iter()
            .any(|e| matches!(e, Event::Reset { id, .. } if *id == b))
    );
    assert!(matches!(
        client_events.last(),
        Some(Event::Closed { reason }) if reason.code == CloseCode::KeyRevoked
            && reason.message.as_deref() == Some("key rotated")
    ));
    assert_eq!(p.client.open(Class::Interactive), Err(StreamError::Closed));
    assert!(
        !p.client.poll_transmit(now, &mut buf),
        "peer-initiated close sends nothing"
    );
    assert_eq!(p.client.next_timeout(), None);
}

trait UnwrapErrOrOk {
    fn unwrap_err_or_ok(self);
}
impl<T, E> UnwrapErrOrOk for Result<T, E> {
    fn unwrap_err_or_ok(self) {}
}

#[test]
fn close_is_idempotent_and_recv_after_close_is_rejected() {
    let mut p = Pair::authenticated();
    p.client.close(CloseReason::new(CloseCode::Shutdown));
    p.client.close(CloseReason::new(CloseCode::Superseded));
    let events = p.drain_events(Side::Client);
    assert_eq!(events.len(), 1);
    assert!(matches!(&events[0], Event::Closed { reason } if reason.code == CloseCode::Shutdown));
    let now = p.clock.now();
    let ping = Frame {
        stream_id: 0,
        frame_type: FrameType::Ping,
        payload: vec![1],
    };
    assert_eq!(p.client.recv(now, &encode(&ping)), Ok(()));
    assert!(p.drain_events(Side::Client).is_empty());
}

#[test]
fn every_close_code_round_trips() {
    for code in [
        CloseCode::KeyRevoked,
        CloseCode::Rejected,
        CloseCode::Superseded,
        CloseCode::Shutdown,
        CloseCode::ProtocolError,
        CloseCode::Timeout,
    ] {
        let mut p = Pair::authenticated();
        p.client.close(CloseReason::new(code));
        p.pump();
        assert!(matches!(
            p.drain_events(Side::Server).last(),
            Some(Event::Closed { reason }) if reason.code == code
        ));
    }
}

#[test]
fn protocol_error_closes_with_goaway_protocol_error() {
    let mut p = Pair::authenticated();
    let now = p.clock.now();
    let garbage = Frame {
        stream_id: 0,
        frame_type: FrameType::Pong,
        payload: vec![0xff; 20],
    };
    let err = p.client.recv(now, &encode(&garbage)).unwrap_err();
    assert_eq!(err, ProtocolError::Decode(FrameType::Pong));
    p.pump();
    assert!(matches!(
        p.drain_events(Side::Server).last(),
        Some(Event::Closed { reason }) if reason.code == CloseCode::ProtocolError
    ));
}
