/*
 * Copyright (c) 2024 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use bitflags::bitflags;

// https://www.freetds.org/tds.html
#[derive(Clone, Copy, Debug, Default, PartialEq)]
#[repr(u8)]
enum MessageType {
    #[default]
    SqlBatch = 1,
    Response = 4,
}

impl TryFrom<u8> for MessageType {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::SqlBatch),
            4 => Ok(Self::Response),
            _ => Err("invalid packet"),
        }
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    struct Status: u8 {
        const END_OF_MESSAGE = 0b00000001;
        const IGNORE_THIS_EVENT = 0b00000010;
        const EVENT_NOTIFICATION = 0b00000100;
        const RESET_CONNECTION = 0b00001000;
        const RESET_CONNECTION_KEEPING_TRANSACTION_STATE = 0b00010000;
    }
}

#[derive(Default)]
struct TDSHeader {
    message_type: MessageType,
    status: Status,
    message_length: u16,
    channel: u16,
    packet_number: u8,
    window: u8,

    content: &[u8],
}

impl TryFrom<&[u8]> for TDSHeader {
    type Error = &'static str;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() < Self::HEADER_SIZE as usize {
            return Err("Insufficient length");
        }

        let mut header = TDSHeader::default();
        // TDS ProtocoL Header:
        // 0        8        16                32
        // +--------+--------+-----------------+
        // | type   | status | length          |
        // +-----------------+--------+--------+
        // | channel         | number | window |
        // +-----------------+--------+--------+

        let Ok(message_type) = MessageType::try_from(value[0]) else {
            return Err("invalid packet");
        };
        header.message_type = message_type;
        let Some(status) = Status::from_bits(value[1]) else {
            return Err("invalid packet");
        };
        header.status = status;
        header.message_length = read_u16_be(&value[2..]);
        header.channel = read_u16_be(&value[4..]);
        header.packet_number = value[6];
        header.window = value[7];
        //header.content = &value[8..];

        if header.is_invalid() {
            return Err("invalid packet");
        }

        Ok(header)
    }
}

impl TDSHeader {
    const HEADER_SIZE: u16 = 8;

    const MESSAGE_TYPE_SQL_BATCH: u8 = 1;
    const MESSAGE_TYPE_RESPONSE: u8 = 4;

    fn is_invalid(&self) -> bool {
        self.window != 0 || self.message_length < Self::HEADER_SIZE
    }


    fn decode_sql_batch(&mut self, payload: &[u8]) -> Result<(), &'static str> {

        Ok(())
    }

    fn decode_response(&mut self, payload: &[u8]) -> Result<(), &'static str> {

        Ok(())
    }

    
    fn decode(&mut self, payload: &[u8]) -> Result<(), &'static str> {
        match self.message_type {
            MessageType::Response => self.decode_sql_batch(payload),
            MessageType::SqlBatch => self.decode_response(payload),
        }
    }
}