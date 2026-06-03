use std::net::IpAddr;

use nfsview::sampler::mountstats::parse_mountstats;
use nfsview::sampler::sockets::{parse_tcp_lines, SocketObs};

#[test]
fn mountstats_fixture_parses() {
    let s = include_str!("fixtures/mountstats_v41.txt");
    let mounts = parse_mountstats(s).expect("parse");
    assert_eq!(mounts.len(), 1);
    assert_eq!(mounts[0].nconnect, Some(4));
}

#[test]
fn tcp_v4_fixture_filters_state_and_port() {
    let s = include_str!("fixtures/proc_net_tcp.txt");
    let mut out = SocketObs::default();
    parse_tcp_lines(s, false, &[2049], &mut out);

    let ip_a: IpAddr = "10.1.1.2".parse().unwrap();
    let ip_b: IpAddr = "10.1.1.3".parse().unwrap();

    assert_eq!(out.by_remote_ip.get(&ip_a), Some(&2), "two ESTABLISHED conns to 10.1.1.2:2049");
    assert_eq!(out.by_remote_ip.get(&ip_b), Some(&1), "one ESTABLISHED conn to 10.1.1.3:2049");
    assert_eq!(out.by_remote_ip.len(), 2, "port 22 and LISTEN state must be filtered");
    assert_eq!(out.raw_matches.len(), 3);
}

#[test]
fn tcp_v6_fixture_parses_loopback() {
    let s = include_str!("fixtures/proc_net_tcp6.txt");
    let mut out = SocketObs::default();
    parse_tcp_lines(s, true, &[20049], &mut out);

    let lo: IpAddr = "::1".parse().unwrap();
    assert_eq!(out.by_remote_ip.get(&lo), Some(&1));
}
