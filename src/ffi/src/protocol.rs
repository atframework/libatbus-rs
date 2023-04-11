// Copyright 2023 atframework
// Licensed under the MIT licenses.

use libatbus_protocol;

use bitflags::bitflags;

use super::common::{CString, DataBlock, StringView};

pub const PROTOCOL_VERSION: i32 = 3;
pub const PROTOCOL_MAX_PACKET_TYPE: i32 = 100;

bitflags! {
  #[repr(C)]
  pub struct PacketFlag: i32 {
      const None = 0;
      const FinishStream = 1;
      const FinishConnection = 2;
      const ResetOffset = 4;
      const TlsHandshake = 8;
  }
}

bitflags! {
  #[repr(C)]
  pub struct PacketFragmentFlag: i32 {
      const None = 0;
      const HasMore = 1;
  }
}

#[repr(i32)]
pub enum CloseReason {
    Unknown = 0,
    /// Shutdown by API
    Shutdown = 1,
    /// Lost connection
    PeerReset = 2,
    /// Unauthorized
    Unauthorized = 3,
    /// Router not found
    RouterNotFound = 4,
}

#[repr(i32)]
pub enum PacketType {
    Data = 0,
    Command = 1,
    Handshake = 2,
}

/// cbindgen:field-names=[x, y]
#[repr(packed, C)]
pub struct StreamMessage<'a> {
    data: &'a libatbus_protocol::StreamMessage,
}

#[no_mangle]
pub extern "C" fn libatbus_stream_message_get_data(message: Option<&StreamMessage>) -> DataBlock {
    if let Some(x) = message {
        DataBlock {
            data: x.data.data.as_ptr(),
            length: x.data.data.len() as u64,
        }
    } else {
        DataBlock {
            data: std::ptr::null(),
            length: 0,
        }
    }
}

#[no_mangle]
pub extern "C" fn libatbus_stream_message_get_packet_type(message: Option<&StreamMessage>) -> i32 {
    if let Some(x) = message {
        x.data.packet_type
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn libatbus_stream_message_get_packet_flag(message: Option<&StreamMessage>) -> i32 {
    if let Some(x) = message {
        x.data.flags
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn libatbus_stream_message_check_packet_flag(
    message: Option<&StreamMessage>,
    checked: PacketFlag,
) -> bool {
    if let Some(x) = message {
        x.data.flags & checked.bits() != 0
    } else {
        false
    }
}

#[no_mangle]
pub extern "C" fn libatbus_stream_message_has_close_reason(
    message: Option<&StreamMessage>,
) -> bool {
    if let Some(x) = message {
        x.data.close_reason.is_some()
    } else {
        false
    }
}

#[no_mangle]
pub extern "C" fn libatbus_stream_message_get_close_reason_code(
    message: Option<&StreamMessage>,
) -> i32 {
    if let Some(x) = message {
        if let Some(y) = x.data.close_reason.as_ref() {
            y.code
        } else {
            0
        }
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn libatbus_stream_message_get_close_reason_message(
    message: Option<&StreamMessage>,
) -> StringView {
    if let Some(x) = message {
        if let Some(y) = x.data.close_reason.as_ref() {
            StringView {
                data: y.message.as_ptr() as CString,
                length: y.message.len() as u64,
            }
        } else {
            StringView {
                data: std::ptr::null(),
                length: 0,
            }
        }
    } else {
        StringView {
            data: std::ptr::null(),
            length: 0,
        }
    }
}

#[no_mangle]
pub extern "C" fn libatbus_protocol_get_max_packet_type() -> i32 {
    libatbus_protocol::proto::atbus::protocol::AtbusProtocolConst::InternalPacketType as i32
}

#[no_mangle]
pub extern "C" fn libatbus_protocol_get_version() -> i32 {
    libatbus_protocol::proto::atbus::protocol::AtbusProtocolConst::Version as i32
}

#[no_mangle]
pub extern "C" fn libatbus_protocol_unused_root(
    _cr: CloseReason,
    _pt: PacketType,
    _pff: PacketFragmentFlag,
) {
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_consts() {
        assert_eq!(
            PROTOCOL_VERSION,
            libatbus_protocol::proto::atbus::protocol::AtbusProtocolConst::Version as i32
        );

        assert_eq!(
            PROTOCOL_MAX_PACKET_TYPE,
            libatbus_protocol::proto::atbus::protocol::AtbusProtocolConst::InternalPacketType
                as i32
        );
    }

    #[test]
    fn check_packet_flag() {
        assert_eq!(
            PacketFlag::None.bits(),
            libatbus_protocol::proto::atbus::protocol::AtbusPacketFlagType::None as i32
        );
        assert_eq!(
            PacketFlag::FinishStream.bits(),
            libatbus_protocol::proto::atbus::protocol::AtbusPacketFlagType::FinishStream as i32
        );
        assert_eq!(
            PacketFlag::FinishConnection.bits(),
            libatbus_protocol::proto::atbus::protocol::AtbusPacketFlagType::FinishConnection as i32
        );
        assert_eq!(
            PacketFlag::ResetOffset.bits(),
            libatbus_protocol::proto::atbus::protocol::AtbusPacketFlagType::ResetOffset as i32
        );
        assert_eq!(
            PacketFlag::TlsHandshake.bits(),
            libatbus_protocol::proto::atbus::protocol::AtbusPacketFlagType::TlsHandshake as i32
        );
    }

    #[test]
    fn check_packet_fragment_flag() {
        assert_eq!(
            PacketFragmentFlag::None.bits(),
            libatbus_protocol::proto::atbus::protocol::AtbusPacketFragmentFlagType::None as i32
        );
        assert_eq!(
            PacketFragmentFlag::HasMore.bits(),
            libatbus_protocol::proto::atbus::protocol::AtbusPacketFragmentFlagType::HasMore as i32
        );
    }

    #[test]
    fn check_close_reason() {
        assert_eq!(
            CloseReason::Unknown as i32,
            libatbus_protocol::proto::atbus::protocol::AtbusCloseReason::Unknown as i32
        );
        assert_eq!(
            CloseReason::Shutdown as i32,
            libatbus_protocol::proto::atbus::protocol::AtbusCloseReason::Shutdown as i32
        );
        assert_eq!(
            CloseReason::PeerReset as i32,
            libatbus_protocol::proto::atbus::protocol::AtbusCloseReason::PeerReset as i32
        );
        assert_eq!(
            CloseReason::Unauthorized as i32,
            libatbus_protocol::proto::atbus::protocol::AtbusCloseReason::Unauthorized as i32
        );
        assert_eq!(
            CloseReason::RouterNotFound as i32,
            libatbus_protocol::proto::atbus::protocol::AtbusCloseReason::RouterNotFound as i32
        );
    }

    #[test]
    fn check_packet_type() {
        assert_eq!(
            PacketType::Data as i32,
            libatbus_protocol::proto::atbus::protocol::AtbusPacketType::Data as i32
        );
        assert_eq!(
            PacketType::Command as i32,
            libatbus_protocol::proto::atbus::protocol::AtbusPacketType::Command as i32
        );
        assert_eq!(
            PacketType::Handshake as i32,
            libatbus_protocol::proto::atbus::protocol::AtbusPacketType::Handshake as i32
        );
    }
}
