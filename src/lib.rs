pub mod v5 {
    use std::net::Ipv4Addr;
    use std::result::{
        Result,
    };
    use chrono::{ DateTime, Duration, TimeZone, Utc };

    fn read_u8(bytes: &[u8]) -> Result<(&[u8], u8), &'static str> {
        if bytes.len() < 1 {
            Err("not enough bytes")
        } else {
            Ok((&bytes[1..], bytes[0]))
        }
    }

    fn read_u16(bytes: &[u8]) -> Result<(&[u8], u16), &'static str> {
        if bytes.len() < 2 {
            Err("not enough bytes")
        } else {
            Ok((&bytes[2..], u16::from_be_bytes([bytes[0], bytes[1]])))
        }
    }

    fn read_u32(bytes: &[u8]) -> Result<(&[u8], u32), &'static str> {
        if bytes.len() < 4 {
            Err("not enough bytes")
        } else {
            Ok((&bytes[4..], u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])))
        }
    }

    // https://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/3-6/user/guide/format.html#wp1006108
    #[derive(Debug, PartialEq)]
    pub struct V5Header {
        pub version: u16,
        pub count: u16,
        pub sys_uptime: u32,
        pub unix_secs: u32,
        pub unix_nsecs: u32,
        pub flow_sequence: u32,
        pub engine_type: u8,
        pub engine_id: u8,
        pub sampling_interval: u16,
        // Derrived fields
        pub datetime: DateTime<Utc>,
    }

    impl V5Header {

        pub fn from_bytes(bytes: &[u8]) -> Result<(&[u8], Self), &'static str> {
            let (rest, _version) = read_u16(&bytes)?;
            let (rest, count) = read_u16(&rest)?;
            let (rest, sys_uptime) = read_u32(&rest)?;
            let (rest, unix_secs) = read_u32(&rest)?;
            let (rest, unix_nsecs) = read_u32(&rest)?;
            let (rest, flow_sequence) = read_u32(&rest)?;
            let (rest, engine_type) = read_u8(&rest)?;
            let (rest, engine_id) = read_u8(&rest)?;
            let (rest, sampling_interval) = read_u16(&rest)?;


            Ok((rest, Self {
                version: 5,
                count: count,
                sys_uptime: sys_uptime,
                unix_secs: unix_secs,
                unix_nsecs: unix_nsecs,
                flow_sequence: flow_sequence,
                engine_type: engine_type,
                engine_id: engine_id,
                sampling_interval: sampling_interval,

                datetime: Utc.timestamp(unix_secs as i64, unix_nsecs),
            }))
        }
    }

    // https://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/3-6/user/guide/format.html#wp1006186
    #[derive(Debug, PartialEq)]
    pub struct V5Flow {
        pub ipv4_src_addr: Ipv4Addr,
        pub ipv4_dst_addr: Ipv4Addr,
        pub next_hop: Ipv4Addr,
        pub input: u16,
        pub output: u16,
        pub d_packets: u32,
        pub d_octets: u32,
        pub first: u32,
        pub last: u32,
        pub src_port: u16,
        pub dst_port: u16,
        pub tcp_flags: u8,
        pub prot: u8,
        pub tos: u8,
        pub src_as: u16,
        pub dst_as: u16,
        pub src_mask: u8,
        pub dst_mask: u8,
    }

    impl V5Flow {

        pub fn from_bytes(bytes: &[u8]) -> Result<(&[u8], Self), &'static str> {
            let (rest, ipv4_src_addr) = read_u32(&bytes)?;
            let (rest, ipv4_dst_addr) = read_u32(&rest)?;
            let (rest, next_hop) = read_u32(&rest)?;
            let (rest, input) = read_u16(&rest)?;
            let (rest, output) = read_u16(&rest)?;
            let (rest, d_packets) = read_u32(&rest)?;
            let (rest, d_octets) = read_u32(&rest)?;
            let (rest, first) = read_u32(&rest)?;
            let (rest, last) = read_u32(&rest)?;
            let (rest, src_port) = read_u16(&rest)?;
            // skipping pad1
            let (rest, dst_port) = read_u16(&rest[1..])?;
            let (rest, tcp_flags) = read_u8(&rest)?;
            let (rest, prot) = read_u8(&rest)?;
            let (rest, tos) = read_u8(&rest)?;
            let (rest, src_as) = read_u16(&rest)?;
            let (rest, dst_as) = read_u16(&rest)?;
            let (rest, src_mask) = read_u8(&rest)?;
            let (rest, dst_mask) = read_u8(&rest)?;

            // skipping pad2
            Ok((&rest[2..], Self {
                ipv4_src_addr: Ipv4Addr::new(
                   (ipv4_src_addr >> 24       ) as u8,
                   (ipv4_src_addr >> 16 & 0xff) as u8,
                   (ipv4_src_addr >>  8 & 0xff) as u8,
                   (ipv4_src_addr       & 0xff) as u8,
                ),
                ipv4_dst_addr: Ipv4Addr::new(
                   (ipv4_dst_addr >> 24       ) as u8,
                   (ipv4_dst_addr >> 16 & 0xff) as u8,
                   (ipv4_dst_addr >>  8 & 0xff) as u8,
                   (ipv4_dst_addr       & 0xff) as u8,
                ),
                next_hop: Ipv4Addr::new(
                   (next_hop >> 24       ) as u8,
                   (next_hop >> 16 & 0xff) as u8,
                   (next_hop >>  8 & 0xff) as u8,
                   (next_hop       & 0xff) as u8,
                ),
                input: input,
                output: output,
                d_packets: d_packets,
                d_octets: d_octets,
                first: first,
                last: last,
                src_port: src_port,
                dst_port: dst_port,
                tcp_flags: tcp_flags,
                prot: prot,
                tos: tos,
                src_as: src_as,
                dst_as: dst_as,
                src_mask: src_mask,
                dst_mask: dst_mask,
            }))
        }

        pub fn when(self: &Self, header: &V5Header) -> (DateTime<Utc>, DateTime<Utc>) {
            (
                header.datetime + Duration::seconds((self.first as i64) - header.sys_uptime as i64), 
                header.datetime + Duration::seconds((self.last as i64) - header.sys_uptime as i64), 
            )
        }
    }

    #[derive(Debug, PartialEq)]
    pub struct V5 {
        pub header: V5Header,
        pub flows: Vec<V5Flow>,
    }

    impl V5 {
        pub fn from_bytes(bytes: &[u8]) -> Result<(&[u8], Self), &'static str> {
            let (mut rest, header) = V5Header::from_bytes(bytes)?;
            let mut flows: Vec<V5Flow> = Vec::new();
            for _ in 0..header.count {
                let (inner_rest, flow) = V5Flow::from_bytes(rest)?;
                flows.push(flow);
                rest = inner_rest;
            }

            Ok((rest, Self {
                header: header,
                flows: flows,
            }))
        }
    }
}


#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use crate::v5::{ V5, V5Flow, V5Header };
    use chrono::{ Duration, TimeZone, Utc };
    
    const V5_HEADER: [u8; 24] = [
        // version
        0x00, 0x05, 
        // count
        0x00, 0x02, 
        // sys_uptime
        0x00, 0x00, 0x00, 0x04,
        // unix_secs
        0x00, 0x00, 0x00, 0x10,
        // unix_nsecs
        0x00, 0x00, 0x00, 0x11,
        // flow_sequence
        0x00, 0x00, 0x00, 0x12,
        // engine type
        0x20,
        // engine id
        0x44,
        // sampling interval
        0x00, 0x10,
    ];

    fn v5_header() -> V5Header {
        V5Header {
            version: 5,
            count: 2,
            sys_uptime: 4,
            unix_secs: 16,
            unix_nsecs: 17,
            flow_sequence: 18,
            engine_type: 32,
            engine_id: 68,
            sampling_interval: 16,

            datetime: Utc.timestamp(16, 17),
        }
    }

    const V5_FLOW: [u8; 48] = [
        // ipv4_src_addr
        0xc0, 0xa8, 0x01, 0x2a,
        // ipv4_dst_addr
        0xc0, 0xa8, 0x01, 0x2c,
        // next_hop
        0xc0, 0xa8, 0x01, 0x2e,
        // input
        0x00, 0x08,
        // output
        0x00, 0x10,
        // d_packets
        0x00, 0x00, 0x00, 0x28,
        // d_octets
        0x00, 0x00, 0xa1, 0xf3,
        // first
        0x00, 0x00, 0x00, 0x10,
        // last
        0x00, 0x00, 0x00, 0x1a,
        // src_port
        0x00, 0x35,
        // dst_port
        0x5b, 0x73,
        // pad1
        0x00,
        // tcp_flags
        0x00,
        // prot
        0x11,
        // tos
        0x01,
        // src_as
        0xfc, 0x00,
        // dst_as
        0xfc, 0x00,
        // src_mask
        0xff,
        // dst_mask
        0xff,
        // pad2
        0x00, 0x00,
    ];

    fn v5_flow() -> V5Flow {
        V5Flow {
            ipv4_src_addr: Ipv4Addr::new(192, 168, 1, 42),
            ipv4_dst_addr: Ipv4Addr::new(192, 168, 1, 44),
            next_hop: Ipv4Addr::new(192, 168, 1, 46),
            input: 8,
            output: 16,
            d_packets: 40,
            d_octets: 41459,
            first: 16,
            last: 26,
            src_port: 53,
            dst_port: 29440,
            tcp_flags: 0x00,
            tos: 1,
            prot: 17,
            src_as: 64512,
            dst_as: 64512,
            src_mask: 255,
            dst_mask: 255,
        }
    }

    #[test]
    fn test_v5_header() {
        match V5Header::from_bytes(&V5_HEADER) {
            Ok((rest, header)) => {
                assert_eq!(v5_header(), header);
                assert_eq!(0, rest.len());
            },
            Err(error) => panic!("Parsing of header failed error={}", error),
        }
    }

    #[test]
    fn test_v5_flow() {
        match V5Flow::from_bytes(&V5_FLOW) {
            Ok((rest, flow)) => {
                assert_eq!(v5_flow(), flow);
                assert_eq!(0, rest.len());

                assert_eq!((
                        Utc.timestamp(28, 17), 
                        Utc.timestamp(38, 17), 
                ), flow.when(&v5_header()));
            },
            Err(error) => panic!("Parsing of flow failed error={}", error),
        }
    }

    #[test]
    fn test_v5() {
        let mut msg = V5_HEADER.to_vec();
        msg.append(&mut V5_FLOW.to_vec());
        msg.append(&mut V5_FLOW.to_vec());
        match V5::from_bytes(msg.as_slice()) {
            Ok((rest, v5)) => {
                assert_eq!(v5_header(), v5.header);
                assert_eq!(2, v5.flows.len());
                let flow = v5_flow();
                assert_eq!(flow, v5.flows[0]);
                assert_eq!(flow, v5.flows[1]);
                assert_eq!(0, rest.len());
            }
            Err(error) => panic!("Parsing of flow failed error={}", error),
        }
    }

    #[test]
    fn test_v5_from_python() {
        // ported from https://github.com/bitkeks/python-netflow-v9-softflowd/blob/3b207c35685d69c255657872683f96a77e927b14/tests/lib.py#L109-L114
        // Example export for v5 which contains three flows, two for ICMP ping and one multicast on interface (224.0.0.251)
        let packet_v5: [u8; 168] = [
            0x00, 0x05, 0x00, 0x03, 0x00, 0x03, 0x79, 0xa3, 0x5e, 0x80, 0xc5, 0x86, 0x22, 0xa5,
            0x5a, 0xb0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xac, 0x11, 0x00, 0x02,
            0xac, 0x11, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x0a, 0x00, 0x00, 0x03, 0x48, 0x00, 0x00, 0x2f, 0x4c, 0x00, 0x00, 0x52, 0x76,
            0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0xac, 0x11, 0x00, 0x01, 0xac, 0x11, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x03, 0x48, 0x00, 0x00,
            0x2f, 0x4c, 0x00, 0x00, 0x52, 0x76, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xac, 0x11, 0x00, 0x01, 0xe0, 0x00,
            0x00, 0xfb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0xa9, 0x00, 0x00, 0xe0, 0x1c, 0x00, 0x00, 0xe0, 0x1c, 0x14, 0xe9,
            0x14, 0xe9, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        ];

        // mostly a smoke test on parsing, but we'll spot check a few things
        match V5::from_bytes(&packet_v5) {
            Ok((rest, v5)) => {
                assert_eq!(5, v5.header.version);
                assert_eq!(3, v5.header.count);
                // first is old and last is more recent, both before the header's sys_uptime
                assert_eq!((
                        v5.header.datetime - Duration::seconds(215639),
                        v5.header.datetime - Duration::seconds(206637),
                ), v5.flows[0].when(&v5.header));
                assert_eq!(0, rest.len());
            }
            Err(error) => panic!("Parsing of flow failed error={}", error),
        }

    }
}
