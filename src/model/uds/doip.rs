use colored::Colorize;
use tokio::net::TcpStream;
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use std::time::Duration;
use std::net::SocketAddr;
use std::vec;
use tokio::sync::Mutex;

struct DoipMsg {
    doip_ver_: u8,
    doip_inverse_ver_: u8,
    doip_payload_type_: u16,
}

pub struct Doip {
    addr_: SocketAddr,
    stream_: Option<TcpStream>,
    doip_msg_head_: DoipMsg,
    source_addr_: u16,
    target_addr_: u16,
    lock_: Mutex<()>,
}

impl Doip {
    pub fn new(ip: &str, port: u16, ta: &str, sa: &str) -> Self {
        let server = format!("{}:{}", ip, port).parse().unwrap();
        let err_msg = "failed to parse TA string: ".to_string() + ta;
        let target_addr = u16::from_str_radix(ta, 16).expect(&err_msg);
        let source_addr = u16::from_str_radix(sa, 16).expect(&err_msg);
        let doip_msg_head: DoipMsg= DoipMsg {
            doip_ver_: 0x02,
            doip_inverse_ver_: 0xfd,
            doip_payload_type_: 0x0000,
        };
        Doip {addr_: server, 
              stream_: None,
              doip_msg_head_: doip_msg_head,
              source_addr_: source_addr,
              target_addr_: target_addr,
              lock_: Mutex::new(()),}
    }

    async fn is_connected(&mut self) -> bool {
        // let mut buf = BytesMut::with_capacity(1);
        // if let Some(stream) =  &mut self.stream_{
        //     match stream.read_buf(&mut buf).await {
        //         Ok(1) => true,
        //         Ok(0) => false,
        //         Err(_) => false,
        //         _ => false,
        //     }
        // } else {
        //     false
        // }
        false
    }

    async fn socket_connect(&mut self)  -> Result<(), Box<dyn std::error::Error>> {
        self.stream_ = Some(TcpStream::connect(&self.addr_).await.expect("Could not connect to server"));
        Ok(())
    }

    async fn send_routine_activation(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.doip_msg_head_.doip_payload_type_ = 0x0005;
        let mut doip_ra_msg = Vec::<u8>::new();
        let activation_type: u8 = 0x00;
        doip_ra_msg.push(((self.source_addr_ >> 8) & 0xff) as u8);
        doip_ra_msg.push(self.source_addr_ as u8);
        doip_ra_msg.push(activation_type);
        doip_ra_msg.extend(vec![0x00, 0x00, 0x00, 0x00]);
        Doip::send_data(&self.doip_msg_head_, &mut self.stream_,&doip_ra_msg).await?;
        let mut buf = Vec::<u8>::new();
        buf.resize(17, 0);
        Doip::receive_data(&mut self.stream_, &mut buf).await?;
        let mut ra_res = vec![self.doip_msg_head_.doip_ver_, self.doip_msg_head_.doip_inverse_ver_];
        let ra_res_payload_type: Vec<u8> = vec![0x00, 0x06];
        let ra_res_payload_len: Vec<u8> = vec![0x00, 0x00, 0x00, 0x09];
        let ra_res_code: u8 = 0x10;
        ra_res.extend(ra_res_payload_type);
        ra_res.extend(ra_res_payload_len);
        ra_res.push(((self.source_addr_ >> 8) & 0xff) as u8);
        ra_res.push(self.source_addr_ as u8);
        ra_res.push(((self.target_addr_ >> 8) & 0xff) as u8);
        ra_res.push(self.target_addr_ as u8);
        ra_res.push(ra_res_code);
        ra_res.extend(vec![0x00, 0x00, 0x00, 0x00]);
        if buf.to_vec() != ra_res {
            let buf_str = buf.iter().map(|byte| format!("{:02x}", byte)).collect::<Vec<String>>().join(" ");
            let ra_res_str = ra_res.iter().map(|byte| format!("{:02x}", byte)).collect::<Vec<String>>().join(" ");
            let err_str = format!("ra_res is error expected:{}---ra_res:{}", ra_res_str, buf_str);
            return Err(err_str.into());
        }
        println!("ra_res is ok");
        Ok(())
    }

    pub async fn create_connect(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if self.is_connected().await {
            println!("");
        } else {
            self.socket_connect().await?;
            self.send_routine_activation().await?;
        }
        Ok(())
    }

    pub async fn send_diagnostic_msg(&mut self, data: &Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
        self.doip_msg_head_.doip_payload_type_ = 0x8001;
        let _guard = self.lock_.lock();
        let mut doip_ra_msg = Vec::<u8>::new();
        doip_ra_msg.push(((self.source_addr_ >> 8) & 0xff) as u8);
        doip_ra_msg.push(self.source_addr_ as u8);
        doip_ra_msg.push(((self.target_addr_ >> 8) & 0xff) as u8);
        doip_ra_msg.push(self.target_addr_ as u8);

        doip_ra_msg.extend(data);
        Doip::send_data(&self.doip_msg_head_, &mut self.stream_,&doip_ra_msg).await?;
        let mut buf = Vec::<u8>::new();
        buf.resize(13, 0);
        Doip::receive_data(&mut self.stream_, &mut buf).await?;
        let mut diag_res = vec![self.doip_msg_head_.doip_ver_, self.doip_msg_head_.doip_inverse_ver_];
        let diag_res_payload_type: Vec<u8> = vec![0x80, 0x02];
        let diag_res_payload_len: Vec<u8> = vec![0x00, 0x00, 0x00, 0x05];
        let diag_res_code: u8 = 0x00;
        diag_res.extend(diag_res_payload_type);
        diag_res.extend(diag_res_payload_len);
        diag_res.push(((self.target_addr_ >> 8) & 0xff) as u8);
        diag_res.push(self.target_addr_ as u8);
        diag_res.push(((self.source_addr_ >> 8) & 0xff) as u8);
        diag_res.push(self.source_addr_ as u8);
        diag_res.push(diag_res_code);
        if buf != diag_res {
            let buf_str = buf.iter().map(|byte| format!("{:02x}", byte)).collect::<Vec<String>>().join(" ");
            let diag_res_str = diag_res.iter().map(|byte| format!("{:02x}", byte)).collect::<Vec<String>>().join(" ");
            let err_str = format!("ra_res is error expected:{}---ra_res:{}", diag_res_str, buf_str);
            return Err(err_str.into());
        }
        Ok(())
    }

    pub async fn recv_diagnostic_msg(&mut self, data: &mut Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
        let mut buf = Vec::<u8>::new();
        let mut data_len:usize;
        buf.resize(1024*1024+8, 0);
        loop {
            Doip::receive_data(&mut self.stream_, &mut buf).await?;
            // data_len = (buf[4] as usize) << 24 + (buf[5] as usize) << 16 + (buf[6] as usize) << 8 + (buf[7] as usize) + 8;
            data_len = ((buf[6] as usize) << 8) + (buf[7] as usize) + 8;
            *data = buf[12..data_len].to_vec();
            if data.len() < 1 {
                let err_str = format!("diag_res is error {:?}", data);
                return Err(err_str.into());
            } 
            if data[0] == 0x7f && data.len() == 3 && data[2] == 0x78 {
                println!("{}", "diag_res is pending...".yellow());
                continue;
            }
            let data_str = data.iter().map(|byte| format!("{:02x}", byte)).collect::<Vec<String>>().join(" ");
            if data[0] == 0x7f {
                println!("diag_res is error {}", data_str.red());
            } else {
                println!("diag_res is {}", data_str.green());
            }
            break;

        }
        Ok(())
    }

    fn add_doip_msg_head_(in_doip_msg_head: &DoipMsg, doip_msg: &mut Vec<u8>, doip_payload_len: u32) {
        doip_msg.push(in_doip_msg_head.doip_ver_);
        doip_msg.push(in_doip_msg_head.doip_inverse_ver_);
        doip_msg.push(((in_doip_msg_head.doip_payload_type_ >> 8) & 0xff) as u8);
        doip_msg.push(in_doip_msg_head.doip_payload_type_ as u8);
        doip_msg.push(((doip_payload_len >> 24) & 0xff) as u8);
        doip_msg.push(((doip_payload_len >> 16) & 0xff) as u8);
        doip_msg.push(((doip_payload_len >> 8) & 0xff) as u8);
        doip_msg.push(doip_payload_len as u8);
    }
    
    async fn send_data(in_doip_msg_head_: &DoipMsg, in_stream: &mut Option<TcpStream>, data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        let mut doip_msg = Vec::<u8>::new();
        Doip::add_doip_msg_head_(in_doip_msg_head_, &mut doip_msg, data.len().try_into().unwrap());
        if let Some(stream) =  in_stream{
            doip_msg.extend(data);
            stream.write_all(&doip_msg).await?;
        } else {

        }
        Ok(())
    }

    async fn receive_data(in_stream: &mut Option<TcpStream>, buffer: &mut [u8]) -> Result<(), Box<dyn std::error::Error>> {
        let timeout_duration: Duration = Duration::from_secs(5);
        if let Some(stream) = in_stream{
            let _ = tokio::time::timeout(timeout_duration, stream.read(buffer)).await??;
        } else {

        }
        Ok(())
    }
}