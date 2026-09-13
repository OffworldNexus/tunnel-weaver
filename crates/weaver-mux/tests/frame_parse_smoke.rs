use weaver_mux::{Frame, FrameType, ProtocolError};

#[test]
fn test_frame_round_trip() {
    let frame = Frame {
        stream_id: 1,
        frame_type: FrameType::Open,
        payload: b"test payload".to_vec(),
    };
    let encoded = frame.encode();
    let decoded = Frame::parse(&encoded).expect("valid frame parse");
    assert_eq!(frame, decoded);
}

#[test]
fn test_frame_truncated() {
    let bytes = [0, 0, 0];
    assert_eq!(Frame::parse(&bytes), Err(ProtocolError::Truncated(3)));
}

#[test]
fn test_frame_unknown_type() {
    let bytes = [0, 0, 0, 1, 0xff, 10, 20];
    assert_eq!(
        Frame::parse(&bytes),
        Err(ProtocolError::UnknownFrameType(0xff))
    );
}
