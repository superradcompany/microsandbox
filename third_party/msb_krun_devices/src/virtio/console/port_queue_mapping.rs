#[derive(Debug, Eq, PartialEq)]
pub(crate) enum QueueDirection {
    Rx,
    Tx,
}

#[must_use]
pub(crate) fn port_id_to_queue_idx(queue_direction: QueueDirection, port_id: usize) -> usize {
    match queue_direction {
        QueueDirection::Rx if port_id == 0 => 0,
        QueueDirection::Rx => 2 + 2 * port_id,
        QueueDirection::Tx if port_id == 0 => 1,
        QueueDirection::Tx => 2 + 2 * port_id + 1,
    }
}

#[must_use]
pub(crate) fn queue_idx_to_port_id(queue_index: usize) -> (QueueDirection, usize) {
    let port_id = match queue_index {
        0 | 1 => 0,
        2 | 3 => {
            panic!("Invalid argument: {queue_index} is not a valid receiveq nor transmitq index!")
        }
        _ => queue_index / 2 - 1,
    };

    let direction = if queue_index.is_multiple_of(2) {
        QueueDirection::Rx
    } else {
        QueueDirection::Tx
    };

    (direction, port_id)
}

pub(crate) fn num_queues(num_ports: usize) -> usize {
    // 2 control queues and then an rx and tx queue for each port
    2 + 2 * num_ports
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_port_id_to_queue_idx() {
        assert_eq!(port_id_to_queue_idx(QueueDirection::Rx, 0), 0);
        assert_eq!(port_id_to_queue_idx(QueueDirection::Tx, 0), 1);
        assert_eq!(port_id_to_queue_idx(QueueDirection::Rx, 1), 4);
        assert_eq!(port_id_to_queue_idx(QueueDirection::Tx, 1), 5);
    }

    #[test]
    fn test_queue_idx_to_port_id_ok() {
        assert_eq!(queue_idx_to_port_id(0), (QueueDirection::Rx, 0));
        assert_eq!(queue_idx_to_port_id(1), (QueueDirection::Tx, 0));
        assert_eq!(queue_idx_to_port_id(4), (QueueDirection::Rx, 1));
        assert_eq!(queue_idx_to_port_id(5), (QueueDirection::Tx, 1));
        assert_eq!(queue_idx_to_port_id(6), (QueueDirection::Rx, 2));
        assert_eq!(queue_idx_to_port_id(7), (QueueDirection::Tx, 2));
    }

    #[test]
    #[should_panic]
    fn test_queue_idx_to_port_id_panic_rx_control() {
        let _ = queue_idx_to_port_id(2);
    }

    #[test]
    #[should_panic]
    fn test_queue_idx_to_port_id_panic_tx_control() {
        let _ = queue_idx_to_port_id(3);
    }
}
