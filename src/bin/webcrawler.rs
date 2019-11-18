use std::collections::{HashMap, VecDeque};
extern crate clap;
use clap::{App, Arg};
use std::time::{Duration, Instant};

use std::io::prelude::*;
use std::iter::repeat;
use std::net::TcpStream;

extern crate pretty_env_logger;
#[macro_use] extern crate log;
#[macro_use] extern crate html5ever;
#[macro_use] extern crate markup5ever;

use html5ever::{ParseOpts, parse_document};
use html5ever::tree_builder::TreeBuilderOpts;
use html5ever::rcdom::{Handle, NodeData, RcDom};
use html5ever::serialize::{SerializeOpts, serialize};
use html5ever::tendril::TendrilSink;
use std::panic::resume_unwind;

macro_rules! hashmap {
    ($( $key: expr => $val: expr ),*) => {{
         let mut map = ::std::collections::HashMap::new();
         $( map.insert($key, $val); )*
         map
    }}
}

#[derive(PartialEq, Clone, Debug)]
struct Request<'a> {
    method: &'a str,
    uri: &'a str,
    host: &'a str,
    headers: HashMap<&'a str, &'a str>,
    body: Vec<u8>,
}

impl<'a> Request<'a> {
    fn encode(&self) -> Vec<u8> {
        let mut output_s = [self.method.clone(), self.uri.clone(), "HTTP/1.1\n".into()].join(" ");
        output_s += format!("Host: {}\n", self.host).as_str();
        for (key, val) in self.headers.iter() {
            output_s += format!("{}: {}\n", key, val).as_str();
        }
        if self.body.len() != 0 {
            output_s += format!("Content-Length: {}\n", self.body.len()).as_str();
        }
        output_s += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\n";
        output_s += "\n";
        let mut output = Vec::new();
        output.extend(output_s.as_bytes());
        output.extend(self.body.clone());
        output
    }
}

#[derive(PartialEq, Clone, Debug)]
struct Response {
    status: String,
    headers: HashMap<String, String>,
    set_cookies: Vec<String>,
    body: String,
}

impl Response {
    fn decode(input: Vec<u8>, stream: &mut TcpStream) -> Response {
        let mut output = Response {
            status: String::new(),
            headers: HashMap::new(),
            set_cookies: vec![],
            body: String::new(),
        };
        let input_s;
        unsafe {
            input_s = String::from_utf8_unchecked(input);
        };
        let mut header_ended = false;
        let mut chunked = false;
        let mut body = String::new();
        let mut flip = false;
        let mut end_found = false;
        let mut content_bytes = 0;
        for (i,line) in input_s.lines().enumerate() {
            if i == 0 {
                let loc_res = line.find(' ');
                if loc_res == None {
                    info!("Can't parse (len: {}): {}", input_s.len(), input_s);
                    output.status = "500".to_string();
                } else {
                    let loc = loc_res.unwrap();
                    output.status = line[loc+1..loc+4].to_string();
                }
            }
            else if header_ended {
                if !chunked {
                    output.body += line.trim_matches(char::from(0));
//                    output.body += "\r\n";
                } else {
                    if flip {
                        output.body += line.trim_matches(char::from(0));
                    } else {
                        if line.len() == 0 || line.chars().nth(0).unwrap() == '0' {
                            end_found = true;
                            break;
                        }
                    }
                    flip = !flip;
                }
            } else {
                if line.len() == 0 {
                    header_ended = true;
                    if output.headers.contains_key("Transfer-Encoding") && output.headers.get("Transfer-Encoding").unwrap() == "chunked" {
                        info!("Chunked encoding found.");
                        chunked = true;
                    }
                } else {
                    let loc_res = line.find(':');
                    if loc_res == None {
                        error!("Parse failed on line: {}", line);
                    } else {
                        let loc = loc_res.unwrap();
                        if &line[..loc] == "Set-Cookie" {
                            output.set_cookies.push(line[loc+2..].to_string());
                        } else {
                            output.headers.insert(line[..loc].to_string(), line[loc+2..].to_string());
                        }
                    }
                }
            }
        }
        while chunked == true && end_found == false {
            let input_s2;
            let mut buf = vec![0 as u8; 4000];
            stream.read(&mut buf).expect("Receiving Request failed");
            unsafe {
                input_s2 = String::from_utf8_unchecked(buf);
            };
            for line in input_s.lines() {
                if flip {
                    output.body += line.trim_matches(char::from(0));
                } else {
                    if line.len() == 0 || line.chars().nth(0).unwrap() == '0' {
                        end_found = true;
                        break;
                    }
                }
                flip = !flip;
            }
        }
        output.body = output.body.trim_matches(char::from(0)).into();
        output
    }
}

fn find_csrf(node: &Handle) -> Option<String> {
    let mut name_found = false;
    match node.data {
        NodeData::Element {
            ref name,
            ref attrs,
            ..
        } => {
            if name.local == local_name!("input") {
                for attr in attrs.borrow().iter() {
                    if attr.name.local == local_name!("name") && attr.value == "csrfmiddlewaretoken".into() {
                        name_found = true;
                    }
                    if name_found && attr.name.local == local_name!("value") {
                        return Some(attr.value.clone().into());
                    }
                }
            }
        },
        _ => {}
    }
    for child in node.children.borrow().iter() {
        let result = find_csrf(child);
        if result != None { return result; }
    }
    return None;
}

fn find_links(node: &Handle) -> Vec<String> {
    let mut output = Vec::new();
    match node.data {
        NodeData::Element {
            ref name,
            ref attrs,
            ..
        } => {
            if name.local == local_name!("a") {
                for attr in attrs.borrow().iter() {
                    if attr.name.local == local_name!("href") {
                        let link :String = attr.value.clone().into();
                        if link.len() < 6 || ( &link[..6] != "http:/" && &link[..6] != "mailto" ) {
                            output.push(link);
                        }
                    }
                }
            }
        },
        _ => {}
    }
    for child in node.children.borrow().iter() {
        let mut result = find_links(child);
        output.append(&mut result);
    }
    output
}

fn find_flags(node: &Handle, mut flag_found: bool) -> Option<String> {
    match node.data {
        NodeData::Element {
            ref name,
            ref attrs,
            ..
        } => {
            for attr in attrs.borrow().iter() {
                if attr.name.local == local_name!("class") && attr.value == "secret_flag".into() {
                    flag_found = true;
                }
            }
        },
        NodeData::Text { ref contents } => {
            if flag_found {
                warn!("Found flag: {}", contents.borrow().to_string());
                return Some(contents.borrow().to_string());
            }
        },
        _ => {}
    }
    for child in node.children.borrow().iter() {
        let result = find_flags(child, flag_found);
        if result != None { return result; }
    }
    return None;
}

fn update_cookies(cookies: &mut HashMap<String, String>, response: &Response) {
    for line in response.set_cookies.iter() {
        cookies.insert(line[..line.find('=').unwrap()].to_string(), line[line.find("=").unwrap()+1..line.find(";").unwrap()].to_string());
    }
    info!("Updated Cookies:");
    for cookie in cookies.iter() {
        info!("{:?}", cookie);
    }
}

fn send_cookies(cookies: &HashMap<String, String>) -> String {
    let mut output = String::new();
    for (name, value) in cookies.iter() {
        output += format!("{}={}; ", name, value).as_str();
    }
    output
}

fn main() {
    pretty_env_logger::init();
    debug!("Webcrawler Started");
    let args = App::new("CS3700 Project 4")
        .author("Nelson Chan <chan.chak@husky.neu.edu>")
        .arg(
            Arg::with_name("username")
                .index(1)
                .required(false)
                .help("Username on Fakebook"),
        )
        .arg(
            Arg::with_name("password")
                .index(2)
                .required(false)
                .help("Password on Fakebook"),
        )
        .get_matches();
    let username = args.value_of("username").unwrap_or("001084838");
    let password = args.value_of("password").unwrap_or("BHCE395P");

    let mut stream = TcpStream::connect("129.10.113.143:80").expect("cannot connect");
    stream.set_nonblocking(false).expect("set_nonblocking call failed");

    let mut cookies = HashMap::new();

    let init_request = Request {
        method: "GET".into(),
        uri: "/accounts/login/?next=/fakebook/".into(),
        host: "fring.ccs.neu.edu".into(),
        headers: hashmap!["Connection" => "Keep-Alive"],
        body: vec![],
    };

    stream.write_all(&init_request.encode()).expect("Sending Request failed");
    let mut buf = vec![0 as u8; 4000];
    stream.read(&mut buf).expect("Receiving Request failed");
    let response = Response::decode(buf, &mut stream);
    info!("Got response: {:?}", response);

    update_cookies(&mut cookies, &response);

    let opts = ParseOpts {
        tree_builder: TreeBuilderOpts {
            drop_doctype: true,
            ..Default::default()
        },
        ..Default::default()
    };

    let dom = parse_document(RcDom::default(), opts.clone())
        .from_utf8()
        .read_from(&mut response.body.as_bytes())
        .unwrap();

    let login_csrf = find_csrf(&dom.document).expect("cannot find CSRF");

    let cookies_s = send_cookies(&cookies);
    let login_request = Request {
        method: "POST",
        uri: "/accounts/login/",
        host: "fring.ccs.neu.edu",
        headers: hashmap!["Connection" => "Keep-Alive", "Cookie" => cookies_s.as_str(), "Content-Type" => "application/x-www-form-urlencoded"],
        body: format!("username={}&password={}&csrfmiddlewaretoken={}&next=%2Ffakebook%2F",username, password, login_csrf).into_bytes(),
    };

    info!("Sending request: {}", String::from_utf8(login_request.encode()).unwrap());
    stream.write_all(&login_request.encode()).expect("Sending Request failed");
    let mut buf = vec![0 as u8; 4000];
    stream.read(&mut buf).expect("Receiving Request failed");
    let response = Response::decode(buf, &mut stream);
    info!("Got response: {:?}", response);
    update_cookies(&mut cookies, &response);

    if response.status != "302" { panic!("Login Failed"); }
    let cookies_s = send_cookies(&cookies);

    let mut frontier = VecDeque::<String>::new();
    frontier.push_back("/fakebook/".into());
    let mut visited = HashMap::new();
    let mut flags = HashMap::new();

    while flags.len() < 5 && frontier.len() > 0 {
        let current_target = frontier.pop_front().unwrap();
        let request = Request {
            method: "GET",
            uri: current_target.as_str(),
            host: "fring.ccs.neu.edu",
            headers: hashmap!["Connection" => "Keep-Alive", "Cookie" => cookies_s.as_str()],
            body: vec![],
        };
        info!("Sending request: {}", String::from_utf8(request.encode()).unwrap());
        stream.write_all(&request.encode()).expect("Sending Request failed");
        let mut buf = vec![0 as u8; 4000];
        stream.read(&mut buf).expect("Receiving Request failed");
        let mut response = Response::decode(buf, &mut stream);
        info!("Got response: {:?}", response);
        if response.status == "500" {
            frontier.push_back(current_target.clone());
            if response.headers.contains_key("Connection") && response.headers.get("Connection").unwrap() == "close" {
                stream = TcpStream::connect("129.10.113.143:80").expect("cannot connect");
                warn!("Reconnecting...");
            }
            continue;
        } else if response.status == "404" || response.status == "403" {
            visited.insert(current_target, true);
            continue;
        } else if response.status == "301" {
            visited.insert(current_target, true);
            frontier.push_back(response.headers.get("Location").expect("No redirect found for 301").clone());
            continue;
        }
        if response.headers.contains_key("Connection") && response.headers.get("Connection").unwrap() == "close" {
            stream = TcpStream::connect("129.10.113.143:80").expect("cannot connect");
            warn!("Reconnecting...");
        }

        visited.insert(current_target, true);
        let dom = parse_document(RcDom::default(), opts.clone())
            .from_utf8()
            .read_from(&mut response.body.as_bytes())
            .unwrap();
        let flag_result = find_flags(&dom.document, false);
        if flag_result != None {
            let flag = flag_result.unwrap();
            let loc = flag.find(':').unwrap();
            flags.insert(flag[loc + 2 ..].to_string(), true);
        }
        let links = find_links(&dom.document);
        info!("Found links: {:?}", links);
        for link in links.iter() {
            if !visited.contains_key(link.as_str()) {
                frontier.push_back(link.clone());
            }
        }
    }
    for (flag, got) in flags.iter() {
        println!("{}", flag);
    }
}
