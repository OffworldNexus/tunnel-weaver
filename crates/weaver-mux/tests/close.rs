mod common;

use common::*;
use weaver_mux::{
    CloseCode, Event, Frame, FrameType, GoAway, Head, ProtocolError, RST_CODE_CONNECTION_CLOSED,
    StreamError,
};

#[test]
fn close_key_revoked() {
    let mut p = Pair::authenticated();
    let a = p.server.open(Head::default()).unwrap();
    let b = p.client.open(Head::default()).unwrap();
    p.server.write(a, b"pending bulk").unwrap();
    p.pump();
    p.drain_events(Side::Client);
    p.drain_events(Side::Server);
    // Queue more data so the scheduler has a backlog GOAWAY must beat.
    p.server.write(a, &[7u8; 60_000]).unwrap();

    p.server.close(GoAway {
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
                reason: GoAway {
                    code: CloseCode::KeyRevoked,
                    message: Some("key rotated".into()),
                }
            },
        ]
    );
    // Nothing more after the close on the server side.
    assert_eq!(p.server.open(Head::default()), Err(StreamError::Closed));
    assert_eq!(p.server.write(a, b"x"), Err(StreamError::Closed));

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
    assert_eq!(p.client.open(Head::default()), Err(StreamError::Closed));
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
    p.client.close(GoAway::new(CloseCode::Shutdown));
    p.client.close(GoAway::new(CloseCode::Superseded));
    let events = p.drain_events(Side::Client);
    assert_eq!(events.len(), 1);
    assert!(matches!(&events[0], Event::Closed { reason } if reason.code == CloseCode::Shutdown));
    let now = p.clock.now();
    let ping = Frame {
        stream_id: 0,
        frame_type: FrameType::Ping,
        payload: vec![1],
    };
    assert_eq!(
        p.client.recv(now, &ping.encode()),
        Err(ProtocolError::Closed)
    );
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
        p.client.close(GoAway::new(code));
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
    let err = p.client.recv(now, &garbage.encode()).unwrap_err();
    assert_eq!(err, ProtocolError::Decode(FrameType::Pong));
    p.pump();
    assert!(matches!(
        p.drain_events(Side::Server).last(),
        Some(Event::Closed { reason }) if reason.code == CloseCode::ProtocolError
    ));
}
