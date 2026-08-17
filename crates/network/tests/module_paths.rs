use std::any::TypeId;

fn assert_same_type<T: 'static, U: 'static>() {
    assert_eq!(TypeId::of::<T>(), TypeId::of::<U>());
}

#[test]
fn legacy_module_paths_alias_canonical_modules() {
    assert_same_type::<
        microsandbox_network::backend::SmoltcpBackend,
        microsandbox_network::netstack::backend::SmoltcpBackend,
    >();
    assert_same_type::<
        microsandbox_network::device::SmoltcpDevice,
        microsandbox_network::netstack::device::SmoltcpDevice,
    >();
    assert_same_type::<
        microsandbox_network::shared::SharedState,
        microsandbox_network::netstack::shared::SharedState,
    >();
    assert_same_type::<
        microsandbox_network::stack::GatewayIps,
        microsandbox_network::netstack::poll::GatewayIps,
    >();
    assert_same_type::<
        microsandbox_network::publisher::PortPublisher,
        microsandbox_network::ports::PortPublisher,
    >();
    assert_same_type::<
        microsandbox_network::builder::NetworkBuilder,
        microsandbox_network::config::NetworkBuilder,
    >();
    assert_same_type::<
        microsandbox_network::conn::ConnectionTracker,
        microsandbox_network::tcp::connection::ConnectionTracker,
    >();
    assert_same_type::<
        microsandbox_network::icmp_relay::IcmpRelay,
        microsandbox_network::icmp::relay::IcmpRelay,
    >();
    assert_same_type::<
        microsandbox_network::udp_relay::UdpRelay,
        microsandbox_network::udp::relay::UdpRelay,
    >();

    let _legacy_proxy = microsandbox_network::proxy::spawn_tcp_proxy;
    let _canonical_proxy = microsandbox_network::tcp::proxy::spawn_tcp_proxy;
}
